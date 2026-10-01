# frozen_string_literal: true
require 'openssl'
require 'base64'
require 'digest'
require 'time'

module Mail
  module DKIM
    # Loads RSA keys from the forms callers are likely to inject:
    # OpenSSL key objects, PEM strings or raw DER.
    module KeyLoader
      module_function

      def load_private(key)
        case key
        when OpenSSL::PKey::RSA then key
        when String
          load_private_string(key)
        else
          if key.respond_to?(:to_pem)
            load_private_string(key.to_pem)
          else
            raise ArgumentError, "unsupported private key: #{key.class}"
          end
        end
      end

      def parse_public_der(der)
        # Public keys may be a bare RSAPublicKey (PKCS #1) or a
        # SubjectPublicKeyInfo structure (RFC 3280/5280).
        asn1 = OpenSSL::ASN1.decode(der)
        if asn1.is_a?(OpenSSL::ASN1::Sequence) && asn1.value.size == 2
          OpenSSL::PKey::RSA.new(der)
        else
          rsa_public_key_to_spki(der)
        end
      rescue OpenSSL::ASN1::ASN1Error, OpenSSL::PKey::PKeyError, ArgumentError
        nil
      end

      # -- internal -----------------------------------------------------

      def load_private_string(string)
        stripped = string.strip
        if stripped.include?('-----BEGIN')
          OpenSSL::PKey::RSA.new(string)
        else
          # Assume base64 encoded PEM or DER first, then raw DER.
          begin
            decoded = stripped.unpack1('m0')
            OpenSSL::PKey::RSA.new(decoded)
          rescue ArgumentError, OpenSSL::PKey::PKeyError
            OpenSSL::PKey::RSA.new(stripped)
          end
        end
      end

      # Wrap a bare PKCS #1 RSAPublicKey into SubjectPublicKeyInfo so that
      # OpenSSL::PKey::RSA will accept it.
      def rsa_public_key_to_spki(pkcs1_der)
        rsa_algorithm_identifier = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new('rsaEncryption'),
          OpenSSL::ASN1::Null.new(nil)
        ])
        spki = OpenSSL::ASN1::Sequence.new([
          rsa_algorithm_identifier,
          OpenSSL::ASN1::BitString.new(pkcs1_der)
        ])
        OpenSSL::PKey::RSA.new(spki.to_der)
      end
    end

    # RFC 6376 RSA-SHA256 signer.
    #
    # The signer works on the exact bytes that will be transmitted; call
    # it on a fully encoded message (Mail::Message#encoded already
    # applies CRLF and transfer encodings).
    class Signer
      ALGORITHM = 'rsa-sha256'
      QUERY = 'dns/txt'
      VERSION = 'DKIM1'

      # Order of preference for the default h= tag.  Headers that are not
      # present in the message are skipped.  From is the only header that
      # RFC 6376 says SHOULD always be signed.
      DEFAULT_HEADER_ORDER = %w[
        From Sender Reply-To Subject Date
        To Cc MIME-Version Content-Type Content-Transfer-Encoding
        Content-ID Content-Description Content-Disposition Content-Location
        Message-ID In-Reply-To References
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        Resent-Message-ID
        List-Id List-Help List-Unsubscribe List-Subscribe
        List-Post List-Owner List-Archive
      ].freeze

      FOLD = "\r\n ".b
      CRLF = "\r\n".b
      EMPTY = ''.b

      attr_reader :domain, :selector, :private_key, :identity, :time,
                  :expiration, :header_canon, :body_canon, :headers, :length

      # Options:
      #   domain:, selector:, private_key:  (required)
      #   identity:            default "@<domain>"
      #   time:                Time object (default now)
      #   expiration:          Time object (x= tag)
      #   header_canon/body_canon: :simple or :relaxed (default relaxed)
      #   canonicalization:    "relaxed/relaxed" style override
      #   headers:             explicit h= array
      #   length:              Integer l= tag (body length count)
      def initialize(domain:, selector:, private_key:, **options)
        @domain = domain
        @selector = selector
        @private_key = KeyLoader.load_private(private_key)
        @identity = options[:identity] || "@#{domain}"
        @time = options[:time]
        @expiration = options[:expiration]
        @headers = options[:headers]
        @length = options[:length] || options[:body_length]
        parse_canon(options)
      end

      # Returns the signed message as raw bytes.  The DKIM-Signature is
      # prepended to the header block (trace-header placement).
      def sign(message)
        raw = message.respond_to?(:encoded) ? message.encoded : message.to_s
        sign_raw(raw)
      end

      def sign_raw(raw)
        raw = Canonicalization.to_crlf(raw)
        header_block, body = Canonicalization.split_message(raw)
        headers = Canonicalization.parse_headers(header_block)

        signed_names = @headers || default_signed_headers(headers)
        ensure_from_signed!(signed_names, headers)

        canonical_body = Canonicalization.canonical_body(body_canon, body, @length)
        body_hash = OpenSSL::Digest::SHA256.digest(canonical_body)
        bh = [body_hash].pack('m0')

        template_tags = tags(signed_names, bh, '')
        # The field body as transmitted starts after ": "; simple
        # canonicalization preserves that space, so it must be present
        # in the signed template as well.
        template = ' ' + fold_value(template_tags)

        header_data =
          Canonicalization.canonical_headers(header_canon, headers, signed_names) <<
          Canonicalization.signature_header(header_canon, template)

        signature = rsa_sign(header_data)
        b = [signature].pack('m0')
        final_value = ' ' + fold_value(tags(signed_names, bh, b))

        separator = header_block.empty? ? EMPTY : CRLF
        "#{'DKIM-Signature:'.b}#{final_value}\r\n#{header_block}#{separator}\r\n#{body}".b
      end

      private

      def parse_canon(options)
        combined = options[:canonicalization]
        if combined
          h, b = combined.downcase.split('/')
          @header_canon = h.to_sym
          @body_canon = (b || h).to_sym
        else
          @header_canon = (options[:header_canon] || :relaxed).to_sym
          @body_canon = (options[:body_canon] || :relaxed).to_sym
        end
        valid = [:simple, :relaxed]
        unless valid.include?(@header_canon) && valid.include?(@body_canon)
          raise ArgumentError, "unsupported canonicalization #{@header_canon}/#{@body_canon}"
        end
      end

      def rsa_sign(data)
        @private_key.sign(OpenSSL::Digest::SHA256.new, data)
      end

      def default_signed_headers(headers)
        present = headers.map { |name, _| name.downcase }
        chosen = []
        DEFAULT_HEADER_ORDER.each do |name|
          while present.include?(name)
            chosen << name
            present.delete_at(present.index(name))
          end
        end
        # Any remaining (custom) headers, in message order.
        chosen.concat(present.reject { |name| name == 'dkim-signature' })
        chosen
      end

      def ensure_from_signed!(names, headers)
        has_from = headers.any? { |name, _| name.downcase == 'from' }
        if has_from && !names.map(&:downcase).include?('from')
          raise ArgumentError, 'the From header must be signed (RFC 6376 5.4.1)'
        end
      end

      def tags(signed_names, bh, b)
        h = signed_names.join(':')
        list = [
          ['v', VERSION],
          ['a', ALGORITHM],
          ['q', QUERY],
          ['s', @selector],
          ['t', (@time || Time.now).to_i.to_s],
          ['c', "#{@header_canon}/#{@body_canon}"],
          ['d', @domain],
          ['i', @identity]
        ]
        list << ['x', @expiration.to_i.to_s] if @expiration
        list << ['h', h]
        list << ['l', @length.to_s] unless @length.nil?
        list << ['bh', bh]
        list << ['b', b]
        list
      end

      # Fold a tag list: break before each tag (FWS after ';'), put each
      # h= member on its own line, and wrap the b= base64 in 72 character
      # chunks.  All folds are removed/collapsed by verifier
      # canonicalization, so the layout only has to stay byte stable
      # between signing and transmission.
      def fold_value(tags)
        rendered = tags.map do |name, value|
          folded =
            case name
            when 'h'
              # One header name per line: legal at any length and byte
              # stable, while keeping physical lines short.
              value.split(':', -1).join(":#{FOLD}")
            when 'b'
              value.scan(/.{1,72}/m).join(FOLD)
            else
              value
            end
          "#{name}=#{folded}"
        end
        rendered.join(';'.b + FOLD)
      end
    end
  end
end
