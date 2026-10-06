# frozen_string_literal: true

require 'openssl'
require 'base64'

module Mail
  module ARC
    module Cryptography
      module_function

      ALGORITHM = 'rsa-sha256'

      def digest_name(algorithm = ALGORITHM)
        raise MalformedHeader, "unsupported ARC algorithm #{algorithm}" unless algorithm == ALGORITHM

        'SHA256'
      end

      def sign(key, data, algorithm = ALGORITHM)
        key = private_key(key)
        Base64.strict_encode64(key.sign(OpenSSL::Digest.new(digest_name(algorithm)), data))
      end

      def verify(key, signature, data, algorithm = ALGORITHM)
        key = public_key(key)
        key.verify(OpenSSL::Digest.new(digest_name(algorithm)), signature, data)
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        false
      end

      def body_hash(body, algorithm = ALGORITHM)
        Base64.strict_encode64(OpenSSL::Digest.digest(digest_name(algorithm), Canonicalization.relaxed_body(body)))
      end

      def resolve_key(value)
        return if value.nil?

        case value
        when OpenSSL::PKey::PKey
          value
        when String
          parse_pem_or_der(value)
        when Array
          value.lazy.map { |candidate| resolve_key(candidate) rescue nil }.find(&:itself)
        when Hash
          resolve_key(value[:key] || value['key'] || value[:private_key] || value['public_key'])
        end
      end

      def parse_pem_or_der(value)
        OpenSSL::PKey.read(value)
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        begin
          OpenSSL::PKey::RSA.new(value)
        rescue OpenSSL::PKey::RSAError
          nil
        end
      end

      def private_key(value)
        key = resolve_key(value)
        raise MissingKey, 'ARC signing key was not found' unless key
        return key if key.respond_to?(:sign)

        raise MissingKey, 'the supplied ARC key is not a private key'
      end

      def public_key(value)
        key = resolve_key(value)
        raise MissingKey, 'ARC verification key was not found' unless key
        return key.public_key if key.respond_to?(:private?) && key.private?

        key
      end
    end
  end
end
