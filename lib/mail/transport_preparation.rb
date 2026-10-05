# encoding: utf-8
# frozen_string_literal: true

module Mail
  TransportBlockReason = Struct.new(:code, :message, :details, keyword_init: true) do
    def to_s
      message
    end
    alias_method :reason, :message
  end

  TransportPreparation = Struct.new(:message, :reasons, :required_extensions, keyword_init: true) do
    def self.success(message, required_extensions = [])
      new(message: message, reasons: [], required_extensions: required_extensions)
    end

    def self.blocked(reasons, required_extensions = [])
      new(message: nil, reasons: Array(reasons), required_extensions: required_extensions)
    end

    def blocked?
      !reasons.empty?
    end

    def success?
      !blocked?
    end

    def required_extensions
      self[:required_extensions] || []
    end

    alias_method :blocked_reasons, :reasons
  end

  class TransportPreparer
    KNOWN_TRANSFER_ENCODINGS = %w[7bit 8bit binary quoted-printable base64 x-uuencode uuencode x-uue].freeze
    BOUNDARY_MAXIMUM_LENGTH = 70
    SIGNATURE_RESIGN_CODE = :signature_requires_resign

    def self.prepare(message, capabilities: {})
      new(message, capabilities).prepare
    end

    def initialize(message, capabilities)
      @original = message
      @capabilities = Mail::TransportCapabilities.coerce(capabilities)
      @reasons = []
    end

    def prepare
      source_copy = @original.dup
      preserve_source_transfer_encodings(source_copy)
      source_copy.transport_smtp_utf8 = @capabilities.smtp_utf8

      validate_declared_transfer_encodings(source_copy)
      return blocked_result if blocked?

      source_copy_source = materialize(source_copy, @capabilities.smtp_utf8)

      candidate = source_copy.dup
      use_target_transfer_encodings(candidate, @capabilities.target_transfer_encoding)
      candidate.transport_smtp_utf8 = @capabilities.smtp_utf8

      begin
        candidate_source = materialize(candidate, @capabilities.smtp_utf8)
      rescue UnknownEncodingType, ArgumentError => error
        add_reason(:unsupported_transfer_encoding, error.message)
        return blocked_result
      end

      envelope_blockers(source_copy)
      reference_message = Mail.new(source_copy_source)
      candidate_message = Mail.new(candidate_source)

      validate_mime(reference_message)
      preserve_attachments(reference_message, candidate_message)
      check_signatures(source_copy, candidate, reference_message, candidate_message)
      check_transfer_encoding_requirements(candidate_message)
      validate_wire_safety(candidate_message)

      return blocked_result if blocked?

      TransportPreparation.success(candidate, success_required_extensions(candidate_message))
    end

    private

    def materialize(message, _smtp_utf8)
      message.encoded
    end

    def preserve_source_transfer_encodings(entity)
      encoding = entity.header[:content_transfer_encoding]
      entity.transport_encoding = encoding && !encoding.value.to_s.empty? ? encoding.to_s : '7bit'
      entity.preserve_transfer_encodings = true
      entity.parts.each { |part| preserve_source_transfer_encodings(part) }
    end

    def use_target_transfer_encodings(entity, encoding)
      entity.transport_encoding = encoding
      entity.preserve_transfer_encodings = false
      entity.parts.each { |part| use_target_transfer_encodings(part, encoding) }
    end

    def envelope_blockers(message)
      addresses = []
      addresses.concat(Array(message.smtp_envelope_from))
      addresses.concat(Array(message.smtp_envelope_to))

      message.header_fields.each do |field|
        next unless field.respond_to?(:addrs)
        addresses.concat(field.addrs.map { |address| address.address }) rescue next
      end

      addresses.compact.uniq.each do |address|
        add_reason(:smtputf8_required,
                   "Internationalized envelope address #{address.inspect} requires SMTPUTF8; no transliteration was attempted",
                   address: address) if !address.ascii_only? && !@capabilities.smtp_utf8
      end
    end

    def validate_mime(message)
      boundaries = []
      leaf_payloads = []

      walk_message(message) do |entity|
        collect_boundary(entity, boundaries, leaf_payloads)
      end

      boundaries.group_by(&:last).each do |_, occurrences|
        boundary = occurrences.first.last
        add_reason(:duplicate_mime_boundary, "MIME boundary #{boundary.inspect} is used more than once", boundary: boundary) if occurrences.size > 1
      end

      boundaries.each do |entity, boundary|
        unless valid_boundary?(boundary)
          add_reason(:invalid_mime_boundary, "MIME boundary #{boundary.inspect} is not transport-safe", boundary: boundary)
        end
        check_boundary_occurrences(entity, boundary)
      end

      check_boundary_collisions(boundaries.map(&:last).uniq, leaf_payloads)
    end

    def collect_boundary(entity, boundaries, leaf_payloads)
      return unless entity.multipart?

      boundary = entity.boundary
      add_reason(:missing_mime_boundary, "Multipart entity has no MIME boundary", content_type: entity.mime_type) if boundary.nil? || boundary.empty?
      boundaries << [entity, boundary.to_s] if boundary

      entity.parts.each do |part|
        if part.multipart?
          next
        elsif embedded_message?(part)
          walk_message(Mail.new(part.body.decoded)) { |nested| collect_boundary(nested, boundaries, leaf_payloads) }
        else
          leaf_payloads << part.encoded
        end
      end
    end

    def check_boundary_occurrences(entity, boundary)
      source = entity.encoded
      header, body = source.split(/\r\n\r\n/, 2)
      return if body.nil?

      expected = entity.parts.size + 1
      actual = body.scan(/(?:\A|\r?\n)--#{Regexp.escape(boundary)}(?:--)?(?=\r?\n|\z)/).size
      if actual != expected
        add_reason(:invalid_mime_boundary,
                   "MIME boundary #{boundary.inspect} appears #{actual} times, expected #{expected}",
                   boundary: boundary, expected: expected, actual: actual)
      end
    end

    def check_boundary_collisions(boundaries, leaf_payloads)
      boundaries.each do |boundary|
        pattern = /(?:\A|\r?\n)--#{Regexp.escape(boundary)}(?:--)?(?:\r?\n|\z)/
        leaf_payloads.each do |payload|
          if pattern.match?(payload)
            add_reason(:mime_boundary_collision,
                       "MIME boundary #{boundary.inspect} occurs inside a MIME leaf part",
                       boundary: boundary)
          end
        end
      end
    end

    def valid_boundary?(boundary)
      return false unless boundary.ascii_only?
      return false if boundary.empty? || boundary.bytesize > BOUNDARY_MAXIMUM_LENGTH
      return false if boundary =~ /[\x00-\x08\x0a-\x1f\x7f]/
      return false if boundary =~ /[^A-Za-z0-9'()+_,\-.\/:=? ]/
      return false if boundary =~ /\s\z/
      true
    end

    def preserve_attachments(reference, candidate)
      original_attachments = non_signature_attachments(reference)
      candidate_attachments = non_signature_attachments(candidate)

      if original_attachments.size != candidate_attachments.size
        add_reason(:attachment_lost,
                   "Expected #{original_attachments.size} attachments but found #{candidate_attachments.size}",
                   expected: original_attachments.size, actual: candidate_attachments.size)
        return
      end

      original_attachments.each_with_index do |original_attachment, index|
        prepared_attachment = candidate_attachments[index]
        if original_attachment.filename != prepared_attachment.filename
          add_reason(:attachment_modified,
                     "Attachment filename changed from #{original_attachment.filename.inspect} to #{prepared_attachment.filename.inspect}",
                     index: index)
        end

        original_bytes = original_attachment.body.decoded
        prepared_bytes = prepared_attachment.body.decoded
        unless original_bytes == prepared_bytes
          add_reason(:attachment_modified,
                     "Attachment #{original_attachment.filename.inspect || index} bytes were modified",
                     index: index, filename: original_attachment.filename)
        end
      end
    end

    def non_signature_attachments(message)
      message.attachments.reject { |attachment| signature_part?(attachment) }
    end

    def signature_part?(part)
      mime_type = part.mime_type.to_s.downcase
      mime_type == 'application/pgp-signature' ||
        mime_type == 'application/pkcs7-signature'
    end

    def check_transfer_encoding_requirements(message)
      walk_message(message) do |entity|
        next if entity.multipart?

        encoding_field = entity.header[:content_transfer_encoding]
        next unless encoding_field && !encoding_field.value.to_s.empty?
        encoding = encoding_field.to_s.downcase
        unless KNOWN_TRANSFER_ENCODINGS.include?(encoding)
          add_reason(:unsupported_transfer_encoding,
                     "Content-Transfer-Encoding #{encoding.inspect} cannot be downgraded for this transport",
                     encoding: encoding)
          next
        end

        next unless %w[8bit binary].include?(encoding)
        required = encoding == 'binary' ? :binarymime : :'8bitmime'
        unless @capabilities.supports?(required) || @capabilities.supports?(:binarymime)
          extension = encoding == 'binary' ? 'BINARYMIME' : '8BITMIME'
          add_reason(encoding == 'binary' ? :binarymime_required : :eightbitmime_required,
                     "#{extension} is required by Content-Transfer-Encoding #{encoding}",
                     encoding: encoding)
        end
      end
    end

    def validate_declared_transfer_encodings(entity)
      unless entity.multipart?
        field = entity.header[:content_transfer_encoding]
        if field && !field.value.to_s.empty? && !KNOWN_TRANSFER_ENCODINGS.include?(field.to_s.downcase)
          add_reason(:unsupported_transfer_encoding,
                     "Content-Transfer-Encoding #{field.to_s.inspect} cannot be converted for this transport",
                     encoding: field.to_s)
        end
      end

      entity.parts.each { |part| validate_declared_transfer_encodings(part) }
    end

    def validate_wire_safety(entity)
      if !entity.multipart? && !embedded_message?(entity)
        wire_body = wire_body_for(entity)
        if wire_body.include?("\0") || wire_body.lines.find { |line| line.chomp("\r\n").bytesize > 998 }
          unless @capabilities.binary_mime
            add_reason(:binarymime_required,
                       "BINARYMIME is required by a body containing NUL octets or lines longer than 998 octets",
                       content_type: entity.mime_type)
          end
        elsif !wire_body.ascii_only? && !@capabilities.eight_bit_mime && !@capabilities.binary_mime
          add_reason(:eightbitmime_required,
                     "8BITMIME is required by a non-7-bit #{entity.mime_type || 'body'} part",
                     content_type: entity.mime_type)
        end
      end

      entity.parts.each do |part|
        if embedded_message?(part)
          validate_wire_safety(Mail.new(part.body.decoded))
        else
          validate_wire_safety(part)
        end
      end
    end

    def wire_body_for(entity)
      entity.body.encoded.to_s.dup.force_encoding(Encoding::BINARY)
    rescue StandardError
      entity.body.raw_source.to_s.dup.force_encoding(Encoding::BINARY)
    end

    def success_required_extensions(message)
      extensions = []
      extensions << 'SMTPUTF8' if @capabilities.smtp_utf8 && requires_smtp_utf8?(message)
      walk_message(message) do |entity|
        next if entity.multipart?
        encoding = entity.content_transfer_encoding.to_s.downcase
        extensions << '8BITMIME' if encoding == '8bit'
        extensions << 'BINARYMIME' if encoding == 'binary'
      end
      extensions.uniq
    end

    def requires_smtp_utf8?(message)
      addresses = [message.smtp_envelope_from, message.smtp_envelope_to].flatten.compact
      message.header_fields.each do |field|
        next unless field.respond_to?(:addrs)
        addresses.concat(field.addrs.map { |address| address.address }) rescue next
      end
      addresses.any? { |address| address && !address.ascii_only? }
    end

    def check_signatures(reference, candidate, reference_message, candidate_message)
      check_mime_signatures(reference, candidate)
      check_dkim_signatures(reference, candidate)
    end

    def check_mime_signatures(reference, candidate)
      walk_pairs(reference, candidate) do |original_entity, prepared_entity|
        next unless mime_signed?(original_entity)
        next if original_entity.parts.empty? || prepared_entity.parts.empty?
        unless signed_payload(original_entity) == signed_payload(prepared_entity)
          add_signature_reason("A multipart/signed MIME body was modified and must be resigned")
        end
      end
    end

    def signed_payload(entity)
      _, body = split_message(entity.encoded)
      return body unless body

      boundary = entity.boundary
      match = body.match(/\A(?:\r?\n)?--#{Regexp.escape(boundary)}\r?\n(.*?)\r?\n--#{Regexp.escape(boundary)}(?:--)?(?:\r?\n|\z)/m)
      match ? match[1] : body
    end

    def check_dkim_signatures(reference_message, candidate_message)
      reference_source = reference_message.encoded
      candidate_source = candidate_message.encoded
      return unless has_dkim_signature?(reference_source)

      reference_headers, reference_body = split_message(reference_source)
      candidate_headers, candidate_body = split_message(candidate_source)

      covered_names = dkim_covered_header_names(reference_headers)
      header_changed = covered_names.any? do |name|
        header_lines(reference_headers, name) != header_lines(candidate_headers, name)
      end

      if header_changed || reference_body != candidate_body
        add_signature_reason("A DKIM signature covers modified headers or body and must be resigned")
      end
    end

    def mime_signed?(entity)
      entity.multipart? && entity.sub_type.to_s.downcase == 'signed'
    end

    def embedded_message?(part)
      part.mime_type.to_s.downcase == 'message/rfc822'
    end

    def walk_message(message, &block)
      yield message
      message.parts.each do |part|
        if part.multipart?
          walk_message(part, &block)
        else
          yield part
        end
      end
    end

    def walk_pairs(reference, candidate, &block)
      yield reference, candidate
      reference.parts.each_with_index do |original_part, index|
        prepared_part = candidate.parts[index]
        next unless prepared_part

        if embedded_message?(original_part)
          walk_pairs(Mail.new(original_part.body.decoded), Mail.new(prepared_part.body.decoded), &block)
        elsif original_part.multipart?
          walk_pairs(original_part, prepared_part, &block)
        else
          yield original_part, prepared_part
        end
      end
    end

    def has_dkim_signature?(source)
      source =~ /\ADKIM-Signature:|\r\nDKIM-Signature:/i
    end

    def dkim_covered_header_names(headers_source)
      unfolded = headers_source.gsub(/\r?\n[\t ]+/, ' ')
      blocks = unfolded.scan(/^DKIM-Signature:.*?(?=\r?\n(?:[!-9;-~]+:|\z))/im).flatten
      blocks = [unfolded] if blocks.empty? && has_dkim_tag?(unfolded)
      names = blocks.flat_map do |block|
        match = block.match(/\bh=([^;\r\n]+)/i)
        match ? match[1].split(':') : :all
      end
      names = names.reject { |name| name == :all || name.empty? }.map(&:downcase).uniq
      return names unless names.include?(:all)
      headers_source.scan(/^([!-9;-~]+):/i).flatten.map(&:downcase).reject { |name| name == 'dkim-signature' }.uniq
    end

    def has_dkim_tag?(unfolded_headers)
      unfolded_headers =~ /^DKIM-Signature:/im
    end

    def header_lines(headers_source, name)
      headers_source.scan(/^#{Regexp.escape(name)}:.*?(?:\r?\n(?![\t ])|\z)/im)
    end

    def split_message(source)
      source.split(/\r\n\r\n/, 2)
    end

    def add_signature_reason(message)
      return if @reasons.any? { |reason| reason.code == SIGNATURE_RESIGN_CODE }
      add_reason(SIGNATURE_RESIGN_CODE, message)
    end

    def add_reason(code, message, details = nil)
      @reasons << TransportBlockReason.new(code: code, message: message, details: details)
    end

    def blocked?
      !@reasons.empty?
    end

    def blocked_result
      required = @reasons.map { |reason| extension_for_reason(reason.code) }.compact.uniq
      TransportPreparation.blocked(@reasons, required)
    end

    def extension_for_reason(code)
      case code
      when :smtputf8_required then 'SMTPUTF8'
      when :eightbitmime_required then '8BITMIME'
      when :binarymime_required then 'BINARYMIME'
      end
    end
  end
end
