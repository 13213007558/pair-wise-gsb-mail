# frozen_string_literal: true

require 'resolv'

module Mail
  class DKIM
    # DKIM public keys are published as TXT records at
    # "<selector>._domainkey.<domain>" (RFC 6376 3.6.2).
    #
    # Real DNS access is never performed implicitly: the verifier accepts any
    # object responding to +call(domain)+ or +txt(domain)+ returning the
    # concatenated TXT record string (or nil when no record exists). This
    # keeps verification deterministic and fully testable offline while still
    # shipping a resolver backed by Resolv::DNS for production use.
    module DNS
      # The minimum supported RSA public key modulus (RFC 6376 3.3.3).
      MINIMUM_KEY_BITS = 1024

      module_function

      def record_name(selector, domain)
        "#{selector}._domainkey.#{domain}".sub(/\.\z/, '')
      end

      # Fetch a TXT record through +resolver+. Returns nil when the name has
      # no TXT records. Raises VerificationError-like +nil+ only as nil.
      def fetch(selector, domain, resolver)
        name = record_name(selector, domain)
        record = invoke(resolver, name)
        normalize(record)
      end

      # Turn anything a resolver may return into the single binary TXT
      # string a verifier expects. Multiple character-strings of one TXT RR
      # are concatenated without spaces (RFC 6376 3.6.2.2).
      def normalize(record)
        return nil if record.nil?
        case record
        when String
          record.dup.force_encoding(Encoding::BINARY)
        when Array
          record.flatten.map { |part| part.to_s.dup.force_encoding(Encoding::BINARY) }.join
        else
          record.to_s.dup.force_encoding(Encoding::BINARY)
        end
      end

      # Default resolver using the Ruby standard library. Each lookup opens
      # and closes its own Resolv::DNS so callers do not leak sockets.
      class Resolver
        def initialize(config = nil)
          @config = config
        end

        def call(name)
          txt(name)
        end

        def txt(name)
          dns = @config ? Resolv::DNS.new(@config) : Resolv::DNS.new
          begin
            resource = dns.getresource(name, Resolv::DNS::Resource::IN::TXT)
            Array(resource.strings).join
          rescue Resolv::ResolvError
            nil
          end
        ensure
          dns&.close
        end
      end

      private_class_method def self.invoke(resolver, name)
        if resolver.respond_to?(:call)
          resolver.call(name)
        elsif resolver.respond_to?(:txt)
          resolver.txt(name)
        else
          raise ArgumentError,
                "DKIM resolver must respond to #call or #txt: #{resolver.inspect}"
        end
      end

      # Decode the base64 p= value of a public key record into an
      # OpenSSL::PKey::RSA. Both SubjectPublicKeyInfo and PKCS#1 RSA PUBLIC KEY
      # encodings are accepted.
      def self.public_key(base64_der)
        der = Base64.strict_decode64(base64_der.to_s.gsub(/\s+/, ''))
        begin
          OpenSSL::PKey.read(der)
        rescue OpenSSL::PKey::PKeyError
          OpenSSL::PKey::RSA.new(der)
        end
      end
    end
  end
end
