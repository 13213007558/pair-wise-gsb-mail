# frozen_string_literal: true

module Mail
  module DKIM
    # A parsed DKIM DNS TXT record (RFC 6376 3.6.1).
    class KeyRecord
      class ParseError < StandardError; end

      attr_reader :tags, :raw, :error

      def self.parse(txt)
        new(txt)
      end

      def initialize(txt)
        @raw = txt
        @tags = TagList.parse(txt.to_s, base64_tags: %w[p])
        @error = nil
        validate
      rescue TagList::ParseError => e
        @tags ||= {}
        @error = e
      end

      def valid?
        @error.nil?
      end

      # v= is required in newly created records; a missing v is allowed
      # (3.6.1) but a present v must be DKIM1.
      def version_ok?
        !@tags.key?('v') || @tags['v'] == 'DKIM1'
      end

      def revoked?
        @tags.key?('p') && @tags['p'].empty?
      end

      def key_type
        (@tags['k'] || 'rsa').downcase
      end

      # Acceptable key types for an rsa-sha256 signature.
      def rsa?
        key_type == 'rsa'
      end

      # g= is deprecated (RFC 4871bis / RFC 6371); t= and g= are not used
      # to constrain verification by this implementation.
      def public_key
        return nil unless @tags['p'] && !@tags['p'].empty?
        der = TagList.decode_base64(@tags['p'])
        KeyLoader.parse_public_der(der)
      rescue TagList::ParseError, ArgumentError, OpenSSL::ASN1::ASN1Error,
             OpenSSL::PKey::PKeyError
        nil
      end

      private

      def validate
        return if @error
        unless version_ok?
          @error = ParseError.new("unsupported key record version #{@tags['v'].inspect}")
        end
        unless @tags.key?('p')
          @error = ParseError.new('key record is missing required p= tag')
        end
      end
    end
  end
end
