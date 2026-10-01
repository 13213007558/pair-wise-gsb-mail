# frozen_string_literal: true

module Mail
  module DKIM
    # Canonicalization per RFC 6376 section 3.4.
    #
    # All methods operate on binary encoded strings (ASCII-8BIT) so that
    # messages containing 8bit transfer encodings are handled byte for
    # byte, which is what verification of received messages requires.
    module Canonicalization
      WSP = /[ \t]/n
      CRLF = "\r\n".b
      EMPTY = ''.b

      module_function

      # Normalise all line endings of a raw message (or message fragment)
      # to CRLF.  RFC 5322 messages are normally already CRLF separated,
      # but Mail accepts bare LF input and verification MUST work on the
      # exact received bytes, so we only touch lone CR/LF.
      def to_crlf(string)
        result = string.to_s.dup.force_encoding(Encoding::BINARY)
        # CR not followed by LF, and LF not preceded by CR, become CRLF.
        result = result.gsub(/\r(?!\n)/n, CRLF)
        result = result.gsub(/(?<!\r)\n/n, CRLF)
        result
      end

      # Split a raw RFC 5322 message into [header_block, body].
      def split_message(raw)
        raw = to_crlf(raw)
        index = raw.index(/\r\n\r\n/n)
        if index
          [raw[0, index], raw[(index + 4)..-1] || EMPTY]
        else
          # No header/body separator: the whole message is headers and
          # the body is empty (RFC 6376 3.4.4 note).
          [raw.chomp(CRLF), EMPTY]
        end
      end

      # Parse a header block into an ordered list of [name, raw_value]
      # pairs.  raw_value retains the exact folded field body lines
      # (without the terminating CRLF), which is required by the "simple"
      # header algorithm.
      def parse_headers(header_block)
        headers = []
        current = nil
        header_block.split(CRLF, -1).each do |line|
          if line.match?(/\A[ \t]/n)
            # Folded continuation of the preceding field.
            current[1] << CRLF << line if current
          elsif (match = line.match(/\A([!-9;-\x7e]+):(.*)\z/n))
            current = [match[1], match[2]]
            headers << current
          end
          # Lines that are neither a field nor a continuation are not
          # legal in a header block; they are skipped.
        end
        headers
      end

      # Unfold a field body: remove CRLF immediately followed by WSP.
      def unfold(string)
        string.gsub(/\r\n([ \t])/n, '\\1'.b)
      end

      # Section 3.4.1 - relaxed header canonicalization.
      def relaxed_header(name, raw_value)
        body = unfold(raw_value)
        body = body.gsub(/[ \t]+/n, ' '.b)
        body = body.gsub(/^[ \t]+|[ \t]+$/n, EMPTY)
        "#{name.downcase.strip}:#{body}#{CRLF}".b
      end

      # Section 3.4.2 - simple header canonicalization.
      def simple_header(name, raw_value)
        "#{name}:#{raw_value}#{CRLF}".b
      end

      def canonical_header(algorithm, name, raw_value)
        case algorithm
        when :relaxed then relaxed_header(name, raw_value)
        when :simple  then simple_header(name, raw_value)
        else
          raise ArgumentError, "Unknown header canonicalization: #{algorithm.inspect}"
        end
      end

      # Section 3.4.3 - simple body canonicalization.
      #
      # Ignores all empty lines at the end of the body and ensures a
      # single trailing CRLF.
      def simple_body(body, length = nil)
        canonical = body.to_s.dup
        canonical = canonical.sub(/(?:\r\n)+\z/n, EMPTY)
        canonical << CRLF
        truncate_body(canonical, length)
      end

      # Section 3.4.4 - relaxed body canonicalization.
      def relaxed_body(body, length = nil)
        canonical = String.new
        lines = body.to_s.split(CRLF, -1)
        # Ignore all empty lines at the end of the body.
        lines.pop while lines.size > 1 && lines.last.empty?

        lines.each do |line|
          line = line.gsub(/[ \t]+/n, ' '.b)
          line = line.gsub(/[ \t]+\z/n, EMPTY)
          line = line.sub(/\A[ \t]+/n, EMPTY)
          canonical << line << CRLF
        end
        # The body of a message is conceptually terminated with CRLF, so
        # even a completely empty body canonicalizes to one CRLF
        # (RFC 6376 3.4.4).
        canonical << CRLF if canonical.empty?
        truncate_body(canonical, length)
      end

      def canonical_body(header_algorithm, body, length = nil)
        case header_algorithm
        when :relaxed then relaxed_body(body, length)
        when :simple  then simple_body(body, length)
        else
          raise ArgumentError, "Unknown body canonicalization: #{header_algorithm.inspect}"
        end
      end

      # Build the canonicalized header data for +header_names+ using
      # +headers+ (an ordered list as returned by #parse_headers).
      #
      # Duplicate header instances are selected from the bottom of the
      # header block upwards (RFC 6376 3.7 / 5.4.2).  A named header that
      # has no remaining unused instance contributes a single CRLF.
      def canonical_headers(header_algorithm, headers, header_names)
        remaining = headers.dup
        buffer = String.new
        header_names.each do |wanted|
          key = wanted.downcase
          found = nil
          found_index = nil
          (remaining.size - 1).downto(0) do |i|
            name, value = remaining[i]
            if name.downcase == key
              found = [name, value]
              found_index = i
              break
            end
          end
          if found
            remaining.delete_at(found_index)
            buffer << canonical_header(header_algorithm, found[0], found[1])
          else
            # Missing header: single CRLF for both algorithms.
            buffer << CRLF
          end
        end
        buffer
      end

      # Canonicalize the DKIM-Signature header for signing/verification:
      # header name lower cased (relaxed) or unchanged (simple), header
      # field body unfolded with the b= tag value emptied.
      def signature_header(header_algorithm, raw_value)
        body = empty_b_tag(unfold(raw_value))
        if header_algorithm == :relaxed
          body = body.gsub(/[ \t]+/n, ' '.b)
          body = body.gsub(/^[ \t]+|[ \t]+$/n, EMPTY)
          "dkim-signature:#{body}#{CRLF}".b
        else
          "dkim-signature:#{empty_b_tag(raw_value)}#{CRLF}".b
        end
      end

      # Remove the value of the b= tag, leaving the tag itself (b=) in
      # place.  FWS inside the (folded) base64 value is removed along
      # with the data.
      def empty_b_tag(unfolded_or_folded_value)
        # b must be the last tag we produce, but for verifying arbitrary
        # signatures we accept a following ; separated tag as well.
        unfolded_or_folded_value.sub(/(b=)[^;]*/in, '\\1'.b)
      end

      # Section 3.7: if an l= tag is present, only the first l bytes of
      # the canonicalized body are hashed.  The canonical body must be at
      # least l bytes long; signers guaranteeing truncation safety is a
      # separate concern.
      def truncate_body(canonical, length)
        return canonical if length.nil?
        canonical.byteslice(0, length)
      end
    end
  end
end
