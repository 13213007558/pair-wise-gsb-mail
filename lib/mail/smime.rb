# frozen_string_literal: true
require 'openssl'
#
module Mail
  # S/MIME signing and encryption backed by Ruby OpenSSL (PKCS#7/CMS).
  #
  # No external +openssl+ command is ever invoked; all certificates, keys and
  # trust anchors are supplied by the caller.
  #
  #   certificate = OpenSSL::X509::Certificate.new(File.binread('alice.cer'))
  #   key         = OpenSSL::PKey::RSA.new(File.binread('alice.key'))
  #   signed      = Mail::SMIME.sign(mail, certificate, key)
  #   result      = Mail::SMIME.verify_signed(signed, trusted_certificates)
  #
  #   encrypted   = Mail::SMIME.encrypt(mail, recipient_certificates)
  #   decrypted   = Mail::SMIME.decrypt(encrypted, my_key, my_certificate)
  module SMIME
    CRLF = "\r\n"
    SIGNATURE_CONTENT_TYPE = 'application/pkcs7-signature'
    ENCRYPTED_CONTENT_TYPE = 'application/pkcs7-mime'
    DEFAULT_CIPHER = 'aes-256-cbc'
    #
    class Error < StandardError; end
    #
    # Outcome of verifying a +multipart/signed+ message. The cryptographic
    # signature, the certificate chain trust and message parsing are reported
    # independently:
    #
    # * +signature_valid?+ - the CMS detached signature matches the exact
    #   signed bytes and was made by the embedded signer certificate.
    # * +trusted?+ - the signer certificate chains to one of the supplied
    #   trust anchors (implies +signature_valid?+).
    # * +mail+ - the signed inner message parsed from the original bytes.
    # * +signer_certificate+ - the certificate that created the signature.
    class SignatureResult
      attr_reader :mail, :signer_certificate, :signature_error, :trust_error
      #
      def initialize(mail, signer_certificate, signature_valid, signature_error,
                     trusted, trust_error)
        @mail = mail
        @signer_certificate = signer_certificate
        @signature_valid = signature_valid
        @signature_error = signature_error
        @trusted = trusted
        @trust_error = trust_error
      end
      #
      def signature_valid?
        @signature_valid
      end
      #
      def trusted?
        @trusted
      end
    end
    #
    # Outcome of decrypting an +application/pkcs7-mime+ message.
    class DecryptionResult
      attr_reader :mail, :error
      #
      def initialize(mail, error)
        @mail = mail
        @error = error
      end
      #
      def success?
        @error.nil?
      end
    end
    #
    class << self
      # Build a +multipart/signed+ message containing a CMS detached
      # signature over +mail+.
      #
      # +certificate+ and +private_key+ identify the signer. +chain+
      # optionally contains additional certificates (intermediates and the
      # signer certificate itself) embedded in the signature.
      def sign(mail, certificate, private_key, chain: [certificate])
        signed_content = canonical(mail.encoded)
        p7 = OpenSSL::PKCS7.sign(
          certificate, private_key, signed_content, Array(chain),
          OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY
        )
        assemble_signed(signed_content, p7.to_der)
      end
      #
      # Verify a +multipart/signed+ message produced by .sign (or any other
      # standards-compliant S/MIME implementation).
      #
      # +message+ may be a String of raw bytes or a parsed Mail::Message; the
      # signed body part is extracted from the original bytes so that
      # re-serialization can never silently substitute the signature input.
      #
      # +trust_anchors+ is an array of OpenSSL::X509::Certificate objects the
      # signer chain is validated against. When empty, only the cryptographic
      # signature is checked and +trusted?+ is always false.
      def verify_signed(message, trust_anchors = [])
        raw, envelope = raw_and_mail(message)
        unless multipart_signed?(envelope)
          raise Error, 'not a multipart/signed message'
        end
        signature_part = envelope.parts[1]
        if signature_part.nil?
          raise Error, 'multipart/signed message is missing the signature part'
        end
        signature_der = signature_part.body.decoded
        signed_bytes = extract_first_part(raw, envelope)
        inner_mail = Mail.read_from_string(signed_bytes)
        signer = find_signer_certificate(OpenSSL::PKCS7.new(signature_der))
        sig_ok, sig_error = check_signature(signature_der, signed_bytes)
        trusted, trust_error =
          if sig_ok && !Array(trust_anchors).empty?
            check_trust(signature_der, signed_bytes, trust_anchors)
          else
            [false, nil]
          end
        SignatureResult.new(inner_mail, signer, sig_ok, sig_error,
                            trusted, trust_error)
      end
      #
      # Build an +application/pkcs7-mime+ enveloped message for every
      # recipient certificate. All recipients can decrypt the resulting
      # message with their own private key.
      def encrypt(mail, recipient_certificates, cipher: DEFAULT_CIPHER)
        recipients = Array(recipient_certificates)
        if recipients.empty?
          raise ArgumentError, 'at least one recipient certificate is required'
        end
        plaintext = canonical(mail.encoded)
        p7 = OpenSSL::PKCS7.encrypt(
          recipients, plaintext, OpenSSL::Cipher.new(cipher),
          OpenSSL::PKCS7::BINARY
        )
        assemble_enveloped(mail, p7.to_der)
      end
      #
      # Decrypt an +application/pkcs7-mime+ message using the recipient's
      # private key and certificate. Decryption failures are returned, not
      # raised, via DecryptionResult#success? and #error.
      def decrypt(message, private_key, certificate)
        _raw, envelope = raw_and_mail(message)
        unless enveloped?(envelope)
          raise Error, 'not an application/pkcs7-mime message'
        end
        p7 = OpenSSL::PKCS7.new(envelope.body.decoded)
        begin
          plaintext = p7.decrypt(private_key, certificate)
          DecryptionResult.new(Mail.read_from_string(plaintext), nil)
        rescue OpenSSL::PKCS7::PKCS7Error => e
          DecryptionResult.new(nil, e)
        end
      end
      #
      private
      #
      def canonical(string)
        string.to_s.dup.force_encoding(Encoding::BINARY).gsub(/\r?\n/, CRLF)
      end
      #
      def multipart_signed?(mail)
        mail.mime_type == 'multipart/signed'
      end
      #
      def enveloped?(mail)
        mail.mime_type == 'application/pkcs7-mime'
      end
      #
      def raw_and_mail(message)
        case message
        when String
          raw = message.dup.force_encoding(Encoding::BINARY)
          [raw, Mail.read_from_string(raw)]
        when Mail::Message
          raw =
            if message.raw_source
              message.raw_source.dup.force_encoding(Encoding::BINARY)
            else
              canonical(message.encoded)
            end
          [raw, message]
        else
          raise ArgumentError, 'expected a String or Mail::Message'
        end
      end
      #
      def assemble_signed(signed_content, signature_der)
        boundary = Mail::ContentTypeField.generate_boundary
        headers = [
          'MIME-Version: 1.0',
          'Content-Type: multipart/signed;',
          ' protocol="' + SIGNATURE_CONTENT_TYPE + '";',
          ' micalg="sha-256";',
          ' boundary="' + boundary + '"'
        ].join(CRLF)
        signature_headers = [
          'Content-Type: ' + SIGNATURE_CONTENT_TYPE + '; name="smime.p7s"',
          'Content-Transfer-Encoding: base64',
          'Content-Disposition: attachment; filename="smime.p7s"'
        ].join(CRLF)
        body = [
          '--' + boundary, signed_content, '',
          '--' + boundary, signature_headers, '',
          fold_base64(signature_der),
          '--' + boundary + '--', ''
        ].join(CRLF)
        headers + CRLF + CRLF + body
      end
      #
      def assemble_enveloped(original, der)
        message = Mail.new
        original.header.fields.each do |field|
          next if field.name == 'MIME-Version'
          next if %w[content-type content-transfer-encoding].include?(field.name.downcase)
          message.header[field.name] = field.value
        end
        message.headers('MIME-Version' => '1.0')
        message.content_type = ENCRYPTED_CONTENT_TYPE +
                               '; smime-type=enveloped-data; name="smime.p7m"'
        message.content_transfer_encoding = 'base64'
        message.body = fold_base64(der)
        canonical(message.encoded)
      end
      #
      def fold_base64(der)
        [der].pack('m0').scan(/.{1,76}/).join(CRLF)
      end
      #
      # Extract the exact bytes of the first MIME part from the raw message,
      # using the parsed header only as an anchor to locate the multipart
      # body. The returned bytes are never produced by re-encoding a parsed
      # Mail object.
      def extract_first_part(raw, envelope)
        boundary = envelope.content_type_parameters['boundary']
        raise Error, 'multipart message has no boundary' if boundary.nil? || boundary.empty?
        body_start = body_start_index(raw, envelope)
        delim = '--' + boundary
        first = raw.index(delim, body_start) or
          raise Error, 'first multipart boundary not found'
        first_line_end = /\r?\n/.match(raw, first + delim.bytesize) or
          raise Error, 'malformed multipart boundary'
        second = /\r?\n#{Regexp.escape(delim)}(?=--|\r?\n)/
                 .match(raw, first_line_end.end(0)) or
          raise Error, 'second multipart boundary not found'
        part_end = second.begin(0)
        part_end -= 1 if raw.getbyte(part_end - 1) == 10
        part_end -= 1 if raw.getbyte(part_end - 1) == 13
        raw.byteslice(first_line_end.end(0), part_end - first_line_end.end(0))
      end
      #
      def body_start_index(raw, envelope)
        header_source = envelope.header.raw_source.to_s
        index = raw.index(header_source)
        raise Error, 'could not locate parsed headers in raw message' if index.nil?
        i = index + header_source.bytesize
        if raw.getbyte(i) == 13 && raw.getbyte(i + 1) == 10
          i + 2
        elsif raw.getbyte(i) == 10
          i + 1
        else
          i
        end
      end
      #
      def find_signer_certificate(p7)
        info = p7.signers.first
        return nil unless info
        p7.certificates.find do |cert|
          cert.issuer.to_s == info.issuer.to_s && cert.serial == info.serial
        end
      end
      #
      def check_signature(signature_der, signed_bytes)
        p7 = OpenSSL::PKCS7.new(signature_der)
        store = OpenSSL::X509::Store.new
        if p7.verify(p7.certificates, store, signed_bytes, OpenSSL::PKCS7::NOVERIFY)
          [true, nil]
        else
          [false, verification_error(p7)]
        end
      end
      #
      def check_trust(signature_der, signed_bytes, anchors)
        p7 = OpenSSL::PKCS7.new(signature_der)
        store = OpenSSL::X509::Store.new
        Array(anchors).each { |anchor| store.add_cert(anchor) }
        if p7.verify(p7.certificates, store, signed_bytes, OpenSSL::PKCS7::NOINTERN)
          [true, nil]
        else
          [false, verification_error(p7)]
        end
      end
      #
      def verification_error(p7)
        message = p7.error_string
        message = 'signature verification failed' if message.nil? || message.empty?
        message
      end
    end
  end
end
