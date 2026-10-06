# frozen_string_literal: true

module Mail
  module ARC
    module Tags
      module_function

      def parse(value)
        tags = {}
        value.to_s.split(';').each do |part|
          match = part.match(/\A\s*([A-Za-z]+)\s*=\s*(.*)\z/m)
          next unless match
          tags[match[1].downcase] = match[2].strip.gsub(/\s+/, ' ')
        end
        tags
      end

      def dump(tags)
        tags.map { |name, value| "#{name}=#{value}" }.join('; ')
      end

      def instance(value)
        match = parse(value)['i'].to_s[/\A\d+\z/]
        match && match.to_i
      end

      def without_signature(value)
        value.to_s.sub(/(^|;)\s*b\s*=\s*[^;]*/i, '\1 b=')
      end

      def signature(value)
        raw = parse(value).fetch('b', '').gsub(/\s+/, '')
        return nil unless raw.match?(/\A[A-Za-z0-9+\/]*={0,2}\z/)
        Base64.strict_decode64(raw)
      rescue ArgumentError, TypeError
        nil
      end
    end
  end
end
