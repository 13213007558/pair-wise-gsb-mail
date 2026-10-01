# frozen_string_literal: true

module Mail
  class DKIM
    # Helpers for the semicolon delimited tag=value lists used by DKIM
    # signatures (RFC 6376 3.2) and published public key records
    # (RFC 6376 3.6.1).
    module TagList
      # Raised when a tag list illegally names the same tag twice.
      class DuplicateTag < StandardError; end

      module_function

      # Parse a tag value list into an insertion-ordered downcased-name =>
      # raw value hash. By default a duplicate tag raises (RFC 6376 3.2 makes
      # duplicates in the signature tag list a protocol error); public key
      # TXT records are assembled from multiple RRs, so callers may opt to
      # keep the first occurrence instead.
      def parse(raw, on_duplicate: :raise)
        tags = {}
        raw.to_s.split(';').each do |spec|
          spec = spec.dup.force_encoding(Encoding::BINARY)
          eq = spec.index('=')
          next unless eq
          name = spec[0, eq].gsub(/[ \t\r\n]+/, '').downcase
          value = spec[(eq + 1)..-1].to_s
          value = value.sub(/\A[ \t\r\n]+/, '').sub(/[ \t\r\n]+\z/, '')
          if tags.key?(name)
            case on_duplicate
            when :raise
              raise DuplicateTag, "duplicate DKIM tag: #{name}"
            when :keep_first
              next
            end
          end
          tags[name] = value
        end
        tags
      end

      # Join [name, value] pairs into "name=value; ..." form without folding.
      def encode(pairs)
        pairs.map { |name, value| "#{name}=#{value}" }.join('; ')
      end
    end
  end
end
