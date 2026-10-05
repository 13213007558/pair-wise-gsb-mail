# encoding: utf-8
# frozen_string_literal: true

require 'set'

module Mail
  class TransportPreparation
    SMTPUTF8 = 'SMTPUTF8'
    EIGHT_BIT_MIME = '8BITMIME'
    BINARY_MIME = 'BINARYMIME'

    SIGNATURE_HEADERS = %w[dkim-signature domainkey-signature].freeze
    ADDRESS_HEADERS = %w[
      from sender reply-to to cc bcc
      resent-from resent-sender resent-to resent-cc resent-bcc
      return-path
    ].freeze

    BlockedTransport = Class.new(StandardError)

    class Capabilities
      def initialize(capabilities)
        case capabilities
        when String, Symbol, Hash
          capabilities = [capabilities]
        end

        values = Array(capabilities).flat_map do |capability|
          case capability
          when Hash
            capability.select { |_, enabled| enabled }.keys
          when Symbol, String
            capability
          else
            capability.to_s
          end
        end

        @capabilities = values.map { |value| value.to_s.upcase.tr('_', '-') }.to_set
        @capabilities.add(EIGHT_BIT_MIME) if @capabilities.include?(BINARY_MIME)
      end

      def enabled?(name)
        @capabilities.include?(name.to_s.upcase.tr('_', '-'))
      end

      def smtputf8?
        enabled?(SMTPUTF8)
      end

      def eight_bit_mime?
        enabled?(EIGHT_BIT_MIME)
      end

      def binary_mime?
        enabled?(BINARY_MIME)
      end
    end

    class Result
      attr_reader :message, :reasons
      alias transport_copy message
      alias copy message

      def initialize(message, reasons = [], signed: false, resign_required: false, changed: false)
        @message = message
        @reasons = reasons
        @signed = signed
        @resign_required = resign_required
        @changed = changed
      end

      def blocked?
        !reasons.empty?
      end

      def success?
        !blocked?
      end

      alias ok? success?
      alias ready? success?


      def signed?
        @signed
      end

      def resign_required?
        @resign_required
      end

      def signature_preserved?
        !resign_required?
      end

      alias signature_retained? signature_preserved?

      def changed?
        @changed
      end

      def to_message
        blocked? ? nil : message
      end

      def reason
        reasons.first
      end

      alias blocking_reason reason
      alias blocking_reasons reasons

      def raise_if_blocked!
        raise BlockedTransport, reasons.join('; ') if blocked?
        self
      end
    end

    def self.prepare(message, capabilities, **options)
      new(message, capabilities, **options).prepare
    end

    def initialize(message, capabilities, allow_resign: false, **)
      @original = message
      @capabilities = Capabilities.new(capabilities)
      @allow_resign = allow_resign
      @reasons = []
      @changes = []
    end

    def prepare
      copy = @original.dup
      structure_repaired = copy.body.multipart? && !copy.multipart?
      copy.ensure_mime_structure!
      signed = signed?(copy)
      if structure_repaired
        add_change(copy, :mime_structure, "multipart content type is required", resign_required: header_signature?(copy))
      end

      inspect_message(copy, signed_ancestor: header_signature?(copy), root: true)

      if blocking_reasons.any?
        return Result.new(
          copy,
          blocking_reasons,
          signed: signed,
          resign_required: signed && @changes.any? { |change| change[:resign_required] },
          changed: @changes.any?
        )
      end

      transform_message(copy, signed_ancestor: header_signature?(copy))

      Result.new(
        copy,
        [],
        signed: signed,
        resign_required: signed && @changes.any? { |change| change[:resign_required] },
        changed: @changes.any?
      )
    end

    private

    def inspect_message(message, signed_ancestor:, root: false)
      materialize(message)

      if message.multipart?
        inspect_multipart(message, signed_ancestor)
      else
        inspect_leaf(message, signed_ancestor)
      end

      inspect_required_fields(message, signed_ancestor, root)
      inspect_envelope(message) if root
      inspect_headers(message)
    end

    def transform_message(message, signed_ancestor:)
      materialize(message)
      message.transport_encoding = maximum_transfer_encoding

      if message.multipart?
        transform_multipart(message, signed_ancestor)
      else
        transform_leaf(message, signed_ancestor)
      end
    end

    def inspect_multipart(message, signed_ancestor)
      boundary = message.boundary

      if boundary.nil? || boundary.empty?
        add_reason(message, "multipart content type is missing a boundary")
        return
      end

      unless message.body.parts.any?
        add_reason(message, "multipart body does not contain any parsed parts")
      end

      message.parts.each_with_index do |part, index|
        signed_payload = multipart_signed?(message) && index.zero?
        inspect_message(part, signed_ancestor: signed_ancestor || signed_payload, root: false)
      end
      inspect_boundary_collisions(message)
    end

    def inspect_leaf(message, signed_ancestor)
      source_encoding = source_transfer_encoding(message)
      maximum_encoding = maximum_transfer_encoding

      unless source_encoding
        add_reason(message, "unknown content transfer encoding #{message.body.encoding.inspect}")
        return
      end

      if source_encoding == Mail::Encodings::Binary && !@capabilities.binary_mime?
        add_change(
          message,
          :content_transfer_encoding,
          "binary content requires BINARYMIME or content encoding",
          resign_required: signed_ancestor
        )
      elsif source_encoding == Mail::Encodings::EightBit && !@capabilities.eight_bit_mime?
        add_change(
          message,
          :content_transfer_encoding,
          "8bit content requires 8BITMIME or content encoding",
          resign_required: signed_ancestor
        )
      elsif !maximum_encoding.can_transport?(source_encoding)
        add_change(
          message,
          :content_transfer_encoding,
          "#{source_encoding} content exceeds transport capability",
          resign_required: signed_ancestor
        )
      end

      inspect_message_rfc822(message, signed_ancestor, false)
    end

    def inspect_message_rfc822(message, signed_ancestor, root)
      return unless message.mime_type == 'message/rfc822'

      nested = Mail.new(message.body.raw_source)
      inspect_message(nested, signed_ancestor: signed_ancestor, root: root)
    rescue => error
      add_reason(message, "invalid message/rfc822 body: #{error.message}")
    end

    def inspect_required_fields(message, signed_ancestor, root)
      return unless signed_ancestor

      missing_fields = []
      if root || message.mime_type == 'message/rfc822'
        missing_fields << 'date' unless message.has_date?
        missing_fields << 'mime-version' unless message.has_mime_version?
        missing_fields << 'message-id' unless message.has_message_id?
      end

      unless message.multipart?
        missing_fields << 'content-type' unless message.has_content_type?
        missing_fields << 'content-type charset' if message.text? && !message.has_charset? && !message.body.empty?
        missing_fields << 'content-transfer-encoding' unless message.has_content_transfer_encoding?
      end

      missing_fields.uniq.each do |field|
        add_change(message, :header, "missing #{field} must be added inside signed content", resign_required: true)
      end
    end

    def transform_multipart(message, signed_ancestor)
      message.parts.each_with_index do |part, index|
        signed_payload = multipart_signed?(message) && index.zero?
        transform_message(part, signed_ancestor: signed_ancestor || signed_payload)
      end
    end

    def transform_leaf(message, signed_ancestor)
      source_encoding = source_transfer_encoding(message)

      if message.mime_type == 'message/rfc822'
        transform_message_rfc822(message, signed_ancestor)
      elsif needs_encoding_change?(source_encoding)
        target_encoding = message.body.negotiate_best_encoding(maximum_transfer_encoding)
        message.content_transfer_encoding = target_encoding.to_s
        message.transport_encoding = target_encoding
      end
    end

    def transform_message_rfc822(message, signed_ancestor)
      nested = Mail.new(message.body.raw_source)
      transform_message(nested, signed_ancestor: signed_ancestor)
      encoded_nested = nested.encoded
      nested_body = message.body
      nested_body.raw_source.replace(encoded_nested)
      nested_body.encoding = '7bit'
      message.content_transfer_encoding = '7bit'
    end

    def inspect_envelope(message)
      return if @capabilities.smtputf8?

      envelope_addresses(message).each do |field_name, address|
        if non_ascii_address?(address)
          add_reason(
            message,
            "SMTPUTF8 is required for non-ASCII #{field_name} envelope address #{address}"
          )
        end
      end
    end

    def inspect_headers(message)
      message.header.fields.each do |field|
        encoded = field.encoded.to_s
        unless encoded.ascii_only?
          unless @capabilities.smtputf8?
            add_reason(
              message,
              "#{field.name} header cannot be represented as ASCII without SMTPUTF8"
            )
          end
        end

        inspect_header_addresses(message, field)
      end
    end

    def inspect_header_addresses(message, field)
      return if @capabilities.smtputf8?
      return unless ADDRESS_HEADERS.include?(field.name.to_s.downcase)

      Array(field.addrs).each do |address|
        if non_ascii_address?(address.address)
          add_reason(
            message,
            "SMTPUTF8 is required for non-ASCII address #{address.address} in #{field.name}"
          )
        end
      end
    rescue NoMethodError
      nil
    end

    def inspect_boundary_collisions(message)
      boundaries = Set.new

      collect_boundary_messages(message).each do |part, boundary|
        unless boundaries.add?(boundary)
          add_reason(part, "MIME boundary #{boundary.inspect} is reused")
        end

        delimiter = "--#{boundary}"
        collision_targets(message).each do |other, serialized|
          next if other.equal?(part)
          decoded = begin
            source_transfer_encoding(other).decode(serialized)
          rescue
            serialized
          end

          [serialized, decoded].each do |candidate|
            has_delimiter = candidate.lines.any? do |line|
              line.chomp == delimiter || line.chomp == "#{delimiter}--"
            end
            if has_delimiter
              add_reason(other, "MIME boundary #{boundary.inspect} appears inside another part")
            end
          end
        end
      end
    end

    def collect_boundary_messages(message)
      messages = []
      walk_messages(message) do |part|
        boundary = part.boundary.to_s
        messages << [part, boundary] unless boundary.empty?
      end
      messages
    end

    def collision_targets(message)
      messages = []
      walk_messages(message) do |part|
        if part.multipart?
          messages << [part, part.body.preamble.to_s] unless part.body.preamble.nil?
          messages << [part, part.body.epilogue.to_s] unless part.body.epilogue.nil?
        else
          messages << [part, part.body.raw_source.to_s]
        end
      end
      messages
    end

    def walk_messages(message, &block)
      return to_enum(:walk_messages, message) unless block_given?

      yield message
      materialize(message)
      message.parts.each do |part|
        if part.mime_type == 'message/rfc822'
          nested = Mail.new(part.body.raw_source)
          yield part
          walk_messages(nested, &block)
        else
          walk_messages(part, &block)
        end
      end
    end

    def envelope_addresses(message)
      addresses = []
      addresses << ['MAIL FROM', message.smtp_envelope_from] if message.smtp_envelope_from
      Array(message.smtp_envelope_to).each { |address| addresses << ['RCPT TO', address] }
      addresses.flat_map do |label, value|
        value.nil? ? [] : [[label, value.to_s]]
      end
    end

    def non_ascii_address?(address)
      address = address.to_s
      return false if address.empty? || address.ascii_only?

      parsed = Mail::Address.new(address)
      !parsed.address.ascii_only?
    rescue
      true
    end

    def needs_encoding_change?(source_encoding)
      return false unless source_encoding

      if source_encoding == Mail::Encodings::Binary
        !@capabilities.binary_mime?
      elsif source_encoding == Mail::Encodings::EightBit
        !@capabilities.eight_bit_mime?
      else
        !maximum_transfer_encoding.can_transport?(source_encoding)
      end
    end

    def source_transfer_encoding(message)
      header_encoding = message.header[:content_transfer_encoding]
      if header_encoding && !header_encoding.errors.any?
        Mail::Encodings.get_encoding(header_encoding.encoding)
      else
        Mail::Encodings.get_encoding(message.body.encoding.to_s)
      end
    end

    def maximum_transfer_encoding
      if @capabilities.binary_mime?
        Mail::Encodings::Binary
      elsif @capabilities.eight_bit_mime?
        Mail::Encodings::EightBit
      else
        Mail::Encodings::SevenBit
      end
    end

    def multipart_signed?(message)
      message.multipart? && message.sub_type.to_s.downcase == 'signed'
    end

    def signed?(message)
      signed_tree?(message)
    end

    def header_signature?(message)
      message.header.fields.any? { |field| SIGNATURE_HEADERS.include?(field.name.to_s.downcase) }
    end

    def signed_tree?(message)
      materialize(message)
      return true if multipart_signed?(message) || header_signature?(message)

      message.parts.any? do |part|
        if part.mime_type == 'message/rfc822'
          signed_tree?(Mail.new(part.body.raw_source)) rescue false
        else
          signed_tree?(part)
        end
      end
    end

    def materialize(message)
      message.body
      message.parts
    end

    def add_change(message, scope, reason, resign_required:)
      @changes << {
        message: message,
        scope: scope,
        reason: reason,
        resign_required: resign_required
      }
      if resign_required && !@allow_resign
        add_reason(message, "#{reason}; resigning existing signature is required")
      end
    end

    def add_reason(message, reason)
      location = message_location(message)
      @reasons << (location.empty? ? reason : "#{location}: #{reason}")
    end

    def blocking_reasons
      @reasons
    end

    def message_location(message)
      content_type = message.mime_type || 'message'
      filename = message.filename rescue nil
      filename ? "#{content_type} (#{filename})" : content_type
    end
  end
end
