# frozen_string_literal: true

module Mail
  class DKIM
    # Header and body canonicalization algorithms defined by
    # RFC 6376 sections 3.4 (Simple) and 3.4.2/3.4.4 (Relaxed).
    #
    # Every method here operates on raw, binary email bytes (Encoding
    # BINARY/ASCII-8BIT). Inputs are normalized so that a bare LF (the line
    # ending used internally by many Unix mail agents) is treated the same as
    # CRLF, which is the only line ending permitted on the wire.
    module Canonicalization
      CRLF = "\r\n".b.freeze
      WSP = /[ \t]/.freeze
      SIGNATURE_HEADER = 'dkim-signature'.freeze

      module_function

      # Convert every line ending to CRLF and return the result as binary.
      def to_crlf(raw)
        bytes = raw.to_s.dup.force_encoding(Encoding::BINARY)
        bytes.gsub(/\r\n|\r|\n/, CRLF)
      end

      # Split a raw header block (or raw message) into [header_block, body]
      # where header_block ends with CRLF and body is everything following the
      # first empty line. If there is no header/body separator the whole input
      # is treated as headers and the body is empty.
      def split_message(raw)
        message = to_crlf(raw)
        if (idx = message.index(/\r\n\r\n/))
          [message[0, idx + 2], message[(idx + 4)..-1] || ''.b]
        elsif message.end_with?(CRLF)
          [message, ''.b]
        else
          ["#{message}#{CRLF}".b, ''.b]
        end
      end

      # Parse a raw header block into an ordered list of [name, unfolded_value]
      # pairs. Folding whitespace (CRLF immediately followed by WSP) is
      # removed per RFC 5322 2.2.3 and RFC 6376 3.4.5.
      def parse_headers(header_block)
        normalized = to_crlf(header_block)

        # Join folded continuation lines: split on physical CRLF boundaries
        # and append any line that starts with WSP to the preceding logical
        # line (RFC 5322 2.2.3). The fold CRLF is removed below while the
        # continuation WSP is retained.
        physical_lines = normalized.split("\r\n", -1)
        # split yields one trailing empty element for the final CRLF.
        physical_lines.pop if normalized.end_with?(CRLF)

        logical_lines = []
        physical_lines.each do |physical_line|
          if !logical_lines.empty? && physical_line =~ /\A[ \t]/
            logical_lines[-1] << "\r\n" << physical_line
          else
            logical_lines << physical_line.dup
          end
        end

        fields = []
        logical_lines.each do |line|
          next if line.empty?
          colon = line.index(':')
          next unless colon && colon > 0
          name = line[0, colon]
          next unless /\A[\x21-\x39\x3b-\x7e]+\z/.match?(name)
          value = line[(colon + 1)..-1].to_s
          # Remove fold line breaks; the continuation WSP is retained.
          value = value.gsub(/\r\n(?=[ \t])/, '').delete("\r\n")
          # The single WSP conventionally separating the colon from a field
          # body is not part of the folded value for the DKIM-Signature
          # field. Removing it here makes canonicalization identical whether
          # the received field was written "Name:value" or "Name: value".
          value = value.sub(/\A[ \t]/, '') if name.downcase == SIGNATURE_HEADER
          fields << [name, value]
        end
        fields
      end

      # Canonicalize a single header field (name + unfolded value) using the
      # given header algorithm (:simple or :relaxed). The returned string does
      # NOT include a trailing CRLF.
      def canonical_header(name, value, algorithm)
        case algorithm
        when :relaxed
          name = name.to_s.dup.force_encoding(Encoding::BINARY).downcase
          value = relaxed_value(value)
          "#{name}:#{value}".b
        when :simple
          "#{name}:#{value}".b
        else
          raise ArgumentError, "unknown header canonicalization: #{algorithm.inspect}"
        end
      end

      # Build the canonicalized header block (RFC 6376 3.7).
      #
      # fields:: parsed [name, value] pairs in message order
      # signed_headers:: header names in the order given by the h= tag
      # algorithm:: :simple or :relaxed
      # dkim_value:: unfolded DKIM-Signature value with b= emptied (optional)
      def canonical_headers(fields, signed_headers, algorithm, dkim_value = nil)
        indexed = {}
        fields.each do |name, value|
          key = name.downcase
          (indexed[key] ||= []) << value
        end
        # Pop from the end so that repeated names are consumed from the
        # bottom-most occurrence upwards, as mandated by RFC 6376 5.4.2.
        cursors = {}
        out = String.new.force_encoding(Encoding::BINARY)
        signed_headers.each do |header_name|
          key = header_name.downcase
          values = indexed[key]
          idx = cursors[key]
          if values
            idx = values.size - 1 if idx.nil?
            if idx >= 0
              out << canonical_header(key, values[idx], algorithm)
              out << CRLF
              cursors[key] = idx - 1
              next
            end
          end
          # Header named in h= but not present: contributes an empty header,
          # RFC 6376 3.7/5.4.2.
          out << canonical_header(key, '', algorithm)
          out << CRLF
        end
        if dkim_value
          # RFC 6376 3.7: the field name used for canonicalization is the
          # lower-case "dkim-signature"; the value (with b= emptied) is passed
          # through the selected header canonicalization.
          out << canonical_header(SIGNATURE_HEADER, dkim_value, algorithm)
          out << CRLF
        end
        out
      end

      # Canonicalize a raw body.
      #
      # algorithm:: :simple or :relaxed
      # length:: when non-nil, only the first +length+ raw body octets are
      #          canonicalized (RFC 6376 3.4.3 body length count).
      def canonical_body(body, algorithm, length = nil)
        body = to_crlf(body)
        body = body[0, length] if length && length >= 0
        case algorithm
        when :simple
          simple_body(body)
        when :relaxed
          relaxed_body(body)
        else
          raise ArgumentError, "unknown body canonicalization: #{algorithm.inspect}"
        end
      end

      # RFC 6376 3.4.3 Simple Body Canonicalization:
      # "Ignores all empty lines at the end of the body" and ensures the body
      # ends with a single CRLF.
      def simple_body(body)
        body = body.dup.force_encoding(Encoding::BINARY)
        body = body.sub(/\r\n\z/, '') while body.end_with?("\r\n\r\n")
        body << CRLF unless body.end_with?(CRLF)
        body
      end

      # RFC 6376 3.4.4 Relaxed Body Canonicalization.
      def relaxed_body(body)
        body = body.dup.force_encoding(Encoding::BINARY)
        lines = body.split("\r\n", -1)
        # The final element after a trailing CRLF represents the empty line
        # which terminates the body; canonicalization strips trailing empty
        # lines, so drop it along with any other trailing empties.
        lines.pop while lines.size > 1 && lines.last.empty?
        canon = lines.map { |line| relaxed_body_line(line) }
        return CRLF if canon.empty?
        canon.join(CRLF) << CRLF
      end

      def relaxed_body_line(line)
        line = line.dup
        line.gsub!(/[ \t]+/, ' ')
        line.sub!(/\A /, '')
        line.sub(/ \z/, '')
      end

      # Relaxed header value: unfold (already done), reduce WSP runs, strip
      # WSP around the value.
      def relaxed_value(value)
        value = value.to_s.dup.force_encoding(Encoding::BINARY)
        value = value.gsub(/[ \t]+/, ' ')
        value = value.sub(/\A[ \t]+/, '').sub(/[ \t]+\z/, '')
        value
      end

      class << self
        # Parse a "c=" tag value such as "relaxed/simple".
        def algorithms(c_tag, default_header: :simple, default_body: :simple)
          header_alg = default_header
          body_alg = default_body
          if c_tag
            header_name, body_name = c_tag.split('/', 2)
            header_alg = header_name.to_sym if header_name
            body_alg = body_name.to_sym if body_name
          end
          unless [:simple, :relaxed].include?(header_alg) &&
                 [:simple, :relaxed].include?(body_alg)
            raise ArgumentError, "unsupported canonicalization: #{c_tag.inspect}"
          end
          [header_alg, body_alg]
        end
      end
    end
  end
end
