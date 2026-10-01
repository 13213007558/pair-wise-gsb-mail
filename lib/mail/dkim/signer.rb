# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'time'

module Mail
  class DKIM
    # Produces an RFC 6376 RSA-SHA256 DKIM-Signature header for a Mail
    # message.
    #
    #   signer = Mail::DKIM::Signer.new(
    #     domain: 'example.com',
    #     selector: 'sel',
    #     private_key: File.read('key.pem'),
    #     header_canonicalization: 'relaxed',
    #     body_canonicalization: 'relaxed'
    #   )
    #   signer.sign!(mail)
    class Signer
      HEADERS_SIGNED_BY_DEFAULT = %w[
        From Reply-To Subject Date To Cc
        Message-ID MIME-Version Content-Type Content-Transfer-Encoding
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        In-Reply-To References List-Id List-Help List-Unsubscribe
        List-Subscribe List-Post List-Owner List-Archive
      ].freeze

      attr_accessor :domain, :selector, :private_key, :identity,
                    :header_canonicalization, :body_canonicalization,
                    :time, :length, :headers

      def initialize(domain: nil, selector: nil, private_key: nil, identity: nil,
                     header_canonicalization: 'simple',
                     body_canonicalization: 'simple',
                     headers: nil, time: nil, length: nil)
        @domain = domain
        @selector = selector
        @private_key = private_key
        @identity = identity
        @header_canonicalization = header_canonicalization
        @body_canonicalization = body_canonicalization
        @headers = headers
        @time = time
        @length = length
      end

      # Sign a Mail::Message in place and return it. The generated
      # DKIM-Signature field is inserted as an actual header so that the exact
      # bytes that were signed are the bytes later delivered by
      # Message#encoded (and therefore by the SMTP/file/sendmail delivery
      # methods).
      def sign!(message)
        mail = to_message(message)
        signature = signature_for(mail)
        insert_signature(mail, signature)
        mail
      end

      # Sign and return the fully encoded message as a binary string.
      def signed_raw(message)
        sign!(message)
        message.encoded.dup.force_encoding(Encoding::BINARY)
      end

      # Sign raw RFC 5322 message bytes directly, without parsing them with
      # Mail. This preserves features the Mail parser normalizes away (for
      # example genuinely repeated Subject fields) and returns the signed
      # bytes. When +headers+ is not given, all non-DKIM header fields are
      # signed in their original order.
      def sign_bytes(raw)
        raw = raw.to_s.dup.force_encoding(Encoding::BINARY)
        header_block, body = Canonicalization.split_message(raw)
        fields = Canonicalization.parse_headers(header_block)
        h_names =
          if @headers
            Array(@headers).map(&:to_s)
          else
            fields.reject { |name, _| name.downcase == 'dkim-signature' }
                  .map { |name, _| name }
          end
        unless h_names.any? { |n| n.downcase == 'from' }
          raise ArgumentError, 'cannot DKIM sign a message without a From header'
        end
        signature = signature_for_parts(fields, body, h_names)
        insert_signature_into_bytes(raw, signature)
      end

      def header_algorithm
        @header_canonicalization.to_s
      end

      def body_algorithm
        @body_canonicalization.to_s
      end

      private

      def to_message(object)
        case object
        when Mail::Message then object
        when String then Mail.new(object)
        else
          raise ArgumentError, "cannot DKIM sign #{object.class}"
        end
      end

      def rsa_key
        @rsa_key ||= begin
          key = @private_key
          key = OpenSSL::PKey::RSA.new(key) if key.is_a?(String)
          unless key.is_a?(OpenSSL::PKey::RSA)
            raise ArgumentError, 'DKIM signing requires an RSA private key'
          end
          key
        end
      end

      def validate_configuration!
        raise ArgumentError, 'DKIM signing requires a domain (d=)' if domain.nil? || domain.to_s.empty?
        raise ArgumentError, 'DKIM signing requires a selector (s=)' if selector.nil? || selector.to_s.empty?
        rsa_key
      end

      # Force MIME-Version/Content-Type/etc. to materialize so the header set
      # is stable across the later delivery encode.
      def encoded_parts(mail)
        raw = mail.encoded.dup.force_encoding(Encoding::BINARY)
        Canonicalization.split_message(raw)
      end

      def present_header_names(fields)
        fields.map { |name, _| name.downcase }
      end

      def select_headers(fields)
        names =
          if @headers
            Array(@headers).map(&:to_s)
          else
            present = present_header_names(fields)
            HEADERS_SIGNED_BY_DEFAULT.select { |name| present.include?(name.downcase) }
          end
        # From MUST be present and signed (RFC 6376 5.4.1). We do not emit a
        # placeholder empty header: the message must actually carry From.
        unless names.any? { |name| name.downcase == 'from' }
          raise ArgumentError, 'cannot DKIM sign a message without a From header'
        end
        names
      end

      def signature_for(mail)
        header_block, body = encoded_parts(mail)
        fields = Canonicalization.parse_headers(header_block)
        h_names = select_headers(fields)
        signature_for_parts(fields, body, h_names)
      end

      def signature_for_parts(fields, body, forced_headers = nil)
        validate_configuration!
        h_names = forced_headers || select_headers(fields)

        h_tag = h_names.map { |name| name.downcase }.join(':')
        c_tag = "#{header_algorithm}/#{body_algorithm}"

        signed_length = compute_length(body)
        body_hash = digest(
          Canonicalization.canonical_body(body, body_algorithm.to_sym, signed_length)
        )
        bh_tag = b64(body_hash)

        tags = signature_tags(c_tag, h_tag, bh_tag, signed_length)
        # Append the empty b= tag before computing the signature over the
        # header block, exactly as required by RFC 6376 3.7. The leading
        # space matches the field value as it will be emitted after
        # "DKIM-Signature:", which simple header canonicalization preserves.
        tags << ['b', '']
        unfolded = TagList.encode(tags)
        signing_value = " #{unfolded}"

        header_data = Canonicalization.canonical_headers(
          fields, h_names.map(&:downcase), header_algorithm.to_sym, signing_value
        )
        signature = rsa_key.sign(OpenSSL::Digest::SHA256.new, header_data)
        b_tag = b64(signature)

        # Fill in the computed signature; the field stays on one unfolded
        # line so simple header canonicalization is unambiguous (folds are
        # always legal for relaxed receivers).
        tags[-1] = ['b', b_tag]
        # No trailing semicolon is emitted: TagList-based verifiers parse it
        # away and RFC 6376 3.2 does not require it.
        "DKIM-Signature: #{TagList.encode(tags)}"
      end

      def signature_tags(c_tag, h_tag, bh_tag, signed_length)
        tags = [
          ['v', '1'],
          ['a', 'rsa-sha256'],
          ['c', c_tag],
          ['d', domain.to_s]
        ]
        tags << ['i', identity.to_s] unless identity.nil?
        tags << ['l', signed_length.to_s] unless signed_length.nil?
        tags << ['q', 'dns/txt']
        tags << ['s', selector.to_s]
        tags << ['t', (@time || Time.now).to_i.to_s]
        tags << ['h', h_tag]
        tags << ['bh', bh_tag]
        tags
      end

      def compute_length(body)
        case @length
        when nil then nil
        when true then body.bytesize
        when Numeric then Integer(@length)
        else
          raise ArgumentError, "invalid l= option: #{@length.inspect}"
        end
      end

      def insert_signature(mail, raw_field)
        # Build a dedicated field by name/value so the unfolded tag list is
        # emitted verbatim (see DkimSignatureField#do_encode).
        name, value = raw_field.split(':', 2)
        field = Mail::Field.new(name, value.lstrip)
        # A message may carry several DKIM-Signature fields (RFC 6376 3.5);
        # each signing adds an independent one. Fields are prepended in
        # signing order (RFC 6376 5.5 recommends prepending).
        mail.header.fields.unshift(field)
        field
      end

      # Prepend the signature field to raw message bytes.
      def insert_signature_into_bytes(raw, raw_field)
        crlf = Canonicalization::CRLF
        sep = "#{crlf}#{crlf}"
        if (idx = raw.index(sep))
          "#{raw_field}#{crlf}#{raw[0, idx]}#{raw[idx..-1]}".b
        elsif raw.end_with?(crlf)
          "#{raw_field}#{crlf}#{raw}".b
        else
          "#{raw_field}#{crlf}#{raw}#{crlf}".b
        end
      end

      def digest(data)
        OpenSSL::Digest::SHA256.digest(data)
      end

      def b64(data)
        Base64.strict_encode64(data)
      end
    end
  end
end
