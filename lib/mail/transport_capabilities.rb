# encoding: utf-8
# frozen_string_literal: true

module Mail
  class TransportCapabilities
    attr_reader :smtp_utf8, :eight_bit_mime, :binary_mime

    def self.coerce(capabilities = {})
      case capabilities
      when self
        capabilities
      when Hash
        new(capabilities)
      when Array
        new(capabilities)
      when nil
        new
      else
        if capabilities.respond_to?(:to_hash)
          new(capabilities.to_hash)
        else
          raise ArgumentError, 'SMTP capabilities must be a Hash, Array, or Mail::TransportCapabilities'
        end
      end
    end

    def initialize(capabilities = {})
      values = normalize(capabilities)
      @smtp_utf8 = enabled?(values, :smtputf8)
      @eight_bit_mime = enabled?(values, :'8bitmime')
      @binary_mime = enabled?(values, :binarymime)
    end

    def supports?(capability)
      case normalized_name(capability)
      when :smtputf8 then smtp_utf8
      when :'8bitmime' then eight_bit_mime
      when :binarymime then binary_mime
      else
        false
      end
    end

    def target_transfer_encoding
      if binary_mime
        'binary'
      elsif eight_bit_mime
        '8bit'
      else
        '7bit'
      end
    end

    private

    def normalize(capabilities)
      case capabilities
      when Array
        capabilities.each_with_object({}) do |capability, result|
          result[normalized_name(capability)] = true
        end
      else
        capabilities.each_with_object({}) do |(key, value), result|
          result[normalized_name(key)] = value
        end
      end
    end

    def enabled?(values, *keys)
      keys.any? { |key| truthy?(values[key]) }
    end

    def truthy?(value)
      value == true || value.to_s.match?(/\A(1|true|yes|on|enabled?)\z/i)
    end

    def normalized_name(name)
      name.to_s.downcase.gsub(/[^a-z0-9]+/, '').to_sym
    end

  end
end
