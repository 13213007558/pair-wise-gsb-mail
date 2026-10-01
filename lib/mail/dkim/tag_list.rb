# frozen_string_literal: true

module Mail
  module DKIM
    # Parses the tag-value list used both in DKIM-Signature header fields
    # (RFC 6376 3.2) and in DKIM DNS TXT records (3.6.1).
    #
    # General syntax:
    #
    #   tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
    #   tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
    #
    # Per section 3.2: tag names are case sensitive and MUST be lowercase,
    # duplicate tags are a syntax error, and trailing semicolons are
    # allowed.  FWS is stripped from both ends of tag values; FWS within
    # values is preserved here (the b= / bh= base64 values are stripped of
    # all WSP by their callers).
    class TagList < Hash
      class ParseError < StandardError; end

      VALID_TAG_NAME = /\A[a-z][a-z0-9_]*\z/n

      def self.parse(string, base64_tags: [])
        list = new
        entries = string.to_s.split(';', -1)
        # A single trailing empty element is the optional final ";" and
        # is permitted.  Any other empty spec is a syntax error.
        entries.each_with_index do |spec, index|
          if spec.strip.empty?
            if index == entries.size - 1
              next
            else
              raise ParseError, "empty tag specification at position #{index}"
            end
          end

          name, sep, value = spec.partition('=')
          raise ParseError, "missing '=' in tag specification #{spec.inspect}" if sep.empty?

          name = name.gsub(/[ \t\r\n]+/n, ''.b)
          unless name.match?(VALID_TAG_NAME)
            raise ParseError, "invalid or non-lowercase tag name #{name.inspect}"
          end
          raise ParseError, "duplicate tag #{name.inspect}" if list.key?(name)

          value = strip_fws(value)
          if base64_tags.include?(name)
            # Base64 values ignore all whitespace (including FWS).
            value = value.gsub(/[ \t\r\n]+/n, ''.b)
          end
          list[name] = value
        end
        list
      end

      def self.strip_fws(string)
        string.gsub(/\r\n[ \t]/n, ''.b).gsub(/\A[ \t]+|[ \t]+\z/n, ''.b)
      end

      # Strict base64 decode used for b/bh: whitespace has already been
      # stripped; any non-base64 character makes the tag malformed.
      def self.decode_base64(value)
        raise ParseError, 'invalid base64' unless value.match?(/\A[A-Za-z0-9+\/]*={0,2}\z/n) && (value.bytesize % 4).zero?
        value.unpack1('m0')
      end
    end
  end
end
