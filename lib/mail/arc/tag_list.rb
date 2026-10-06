# frozen_string_literal: true

require 'base64'

module Mail
  module ARC
    class TagList
      def self.parse(value)
        tags = {}
        value.to_s.split(/;(?:\s|$)/).each do |part|
          part = part.strip
          next if part.empty?

          name, value = part.split('=', 2)
          next if name.nil? || value.nil?

          tags[name.strip.downcase] = value.strip
        end
        new(tags)
      end

      def initialize(tags = {})
        @tags = tags.each_with_object({}) do |(name, value), result|
          result[name.to_s.downcase] = value.to_s
        end
      end

      def [](name)
        @tags[name.to_s.downcase]
      end

      def []=(name, value)
        @tags[name.to_s.downcase] = value.to_s
      end

      def fetch(name)
        @tags.fetch(name.to_s.downcase)
      rescue KeyError
        raise MalformedHeader, "missing required ARC tag #{name}"
      end

      def key?(name)
        @tags.key?(name.to_s.downcase)
      end

      def integer(name)
        value = fetch(name)
        raise MalformedHeader, "ARC tag #{name} must be an integer" unless /\A[0-9]+\z/.match?(value)

        Integer(value, 10)
      end

      def decoded_b
        Base64.strict_decode64(fetch('b').gsub(/\s+/, ''))
      rescue ArgumentError
        raise MalformedHeader, 'ARC tag b is not valid base64'
      end

      def with_b_blank
        self.class.new(@tags.merge('b' => ''))
      end

      def render(order)
        order.select { |name| key?(name) }.map { |name| "#{name}=#{self[name]}" }.join('; ')
      end

      def to_h
        @tags.dup
      end
    end
  end
end
