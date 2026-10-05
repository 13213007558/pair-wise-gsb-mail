# encoding: utf-8
# frozen_string_literal: true
require 'openssl'

module Mail
  # = SMIME
  #
  # S/MIME support for Mail using Ruby's OpenSSL bindings only. No external
  # +openssl+ command is ever invoked; certificates and private keys are
  # always supplied by the caller.
  #
  # Capabilities:
  #
  # * create and verify +multipart/signed+ messages carrying a CMS (PKCS#7)
  #   detached signature
  # * create and read +application/pkcs7-mime+ enveloped (encrypted) messages
  #
  # Verification keeps the original bytes of the signed entity. The signed
  # data is sliced out of the raw message source; a parsed-then-reserialized
  # message is never used as signature input, because serialization is not
  # guaranteed to reproduce the exact bytes that were signed.
  #
  #   signed = Mail::SMIME.sign(mail, certificate: cert, key: key,
  #                             ca_certificates: [intermediate])
  #
  #   result = Mail::SMIME.verify(received_mail, ca_certificates: [root])
  #   result.signature_valid?     # cryptographic signature matches
  #   result.certificate_trusted? # signer chains to a trusted CA
  #   result.valid?               # both of the above
  #
  #   encrypted = Mail::SMIME.encrypt(mail, certificates: [cert1, cert2])
  #   result = Mail::SMIME.decrypt(received_mail, key: key, certificate: cert1)
  #   result.success? # decryption worked
  #   result.mail     # the recovered Mail::Message
  module SMIME
    # Raised when a message cannot be processed as S/MIME at all (for
    # example a missing MIME boundary or no raw source to verify against).
    class Error < StandardError; end

    # Outcome of verifying a +multipart/signed+ message. Signature validity
    # and certificate chain trust are reported separately.
    class VerificationResult
      # Certificates of the signers found in the signature.
      attr_reader :signer_certificates

      # Underlying error, if verification could not be performed.
      attr_reader :error

      def initialize(signature_valid:, certificate_trusted:, signer_certificates: [], error: nil)
        @signature_valid = signature_valid
        @certificate_trusted = certificate_trusted
        @signer_certificates = signer_certificates
        @error = error
      end

      # True when the CMS signature cryptographically matches the signed
      # content, regardless of whether the signer is trusted.
      def signature_valid?
        @signature_valid
      end

      # True when the signer's certificate chains up to one of the trusted
      # CA certificates given to the verifier.
      def certificate_trusted?
        @certificate_trusted
      end

      # True only when the signature is valid *and* the signer is trusted.
      def valid?
        signature_valid? && certificate_trusted?
      end
    end

    # Outcome of decrypting an +application/pkcs7-mime+ message.
    class DecryptionResult
      # The recovered Mail::Message when decryption succeeded, else nil.
      attr_reader :mail

      # Underlying error, if decryption failed.
      attr_reader :error

      def initialize(success:, mail: nil, error: nil)
        @success = success
        @mail = mail
        @error = error
      end

      # True when the message was successfully decrypted.
      def success?
        @success
      end
    end

    # Digest algorithm OIDs (DER encoded) used to announce the correct
    # +micalg+ parameter for the signature actually produced by OpenSSL.
    DIGEST_OIDS = {
      "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01".b => 'sha-256',
      "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02".b => 'sha-384',
      "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03".b => 'sha-512',
      "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04".b => 'sha-224',
      "\x06\x05\x2b\x0e\x03\x02\x1a".b                 => 'sha-1'
    }.freeze

    module_function

    # Signs +message+ with a CMS detached signature and returns a new
    # Mail::Message of type +multipart/signed+.
    #
    # +certificate+ and +key+ are the signer's OpenSSL::X509::Certificate
    # and OpenSSL::PKey. +ca_certificates+ are extra certificates (for
    # example intermediates) bundled into the signature so recipients can
    # build a chain to their trusted root.
    def sign(message, certificate:, key:, ca_certificates: [])
      content = canonicalize(message.to_s)
      pkcs7 = OpenSSL::PKCS7.sign(certificate, key, content,
                                  Array(ca_certificates),
                                  OpenSSL::PKCS7::DETACHED)
      micalg = detect_micalg(pkcs7)
      boundary = Mail::ContentTypeField.generate_boundary

      raw = +''.b
      raw << entity_headers(message)
      raw << "MIME-Version: 1.0\r\n"
      raw << %(Content-Type: multipart/signed; protocol="application/pkcs7-signature";)
      raw << %( micalg="#{micalg}"; boundary="#{boundary}"\r\n)
      raw << "\r\n"
      raw << "This is an S/MIME signed message.\r\n"
      raw << "\r\n--#{boundary}\r\n"
      raw << content
      raw << "\r\n--#{boundary}\r\n"
      raw << %(Content-Type: application/pkcs7-signature; name="smime.p7s"\r\n)
      raw << "Content-Transfer-Encoding: base64\r\n"
      raw << %(Content-Disposition: attachment; filename="smime.p7s"\r\n)
      raw << "\r\n"
      raw << Mail::Encodings::Base64.encode(pkcs7.to_der)
      raw << "\r\n--#{boundary}--\r\n"

      Mail.new(raw)
    end

    # Verifies a +multipart/signed+ message and returns a
    # VerificationResult reporting signature validity and certificate
    # chain trust separately.
    #
    # +message+ may be a raw String or a Mail::Message. A Mail::Message
    # must still carry its original raw source (as it does right after
    # parsing); the signed entity is sliced out of those original bytes,
    # never out of a reserialization.
    #
    # +ca_certificates+ are the trusted roots (and any intermediates the
    # caller wants to trust directly). An explicit OpenSSL::X509::Store
    # may be passed as +store+ instead.
    def verify(message, ca_certificates: [], store: nil)
      raw = raw_source_of(message)
      mail = message.is_a?(Mail::Message) ? message : Mail.new(raw)

      boundary = mail.boundary
      raise Error, 'message is not multipart; no boundary found' unless boundary

      _header, body = split_header_body(raw)
      data = extract_signed_data(body, boundary)
      pkcs7 = signature_pkcs7(mail)

      signature_valid = verify_signature(pkcs7, data)
      signers = signer_certificates(pkcs7)
      trusted = verify_trust(signers, pkcs7.certificates || [], ca_certificates, store)

      VerificationResult.new(signature_valid: signature_valid,
                             certificate_trusted: trusted,
                             signer_certificates: signers)
    rescue Error, OpenSSL::OpenSSLError => e
      VerificationResult.new(signature_valid: false,
                             certificate_trusted: false,
                             error: e)
    end

    # Encrypts +message+ for one or more recipients and returns a new
    # Mail::Message of type +application/pkcs7-mime+ (enveloped-data).
    #
    # +certificates+ is an OpenSSL::X509::Certificate (or array of them)
    # for each recipient; any of the corresponding private keys can later
    # decrypt the message.
    def encrypt(message, certificates:, cipher: nil)
      content = canonicalize(message.to_s)
      cipher ||= OpenSSL::Cipher.new('aes-256-cbc')
      pkcs7 = OpenSSL::PKCS7.encrypt(Array(certificates), content, cipher,
                                     OpenSSL::PKCS7::BINARY)

      raw = +''.b
      raw << entity_headers(message)
      raw << "MIME-Version: 1.0\r\n"
      raw << %(Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\r\n)
      raw << "Content-Transfer-Encoding: base64\r\n"
      raw << %(Content-Disposition: attachment; filename="smime.p7m"\r\n)
      raw << "\r\n"
      raw << Mail::Encodings::Base64.encode(pkcs7.to_der)
      raw << "\r\n"

      Mail.new(raw)
    end

    # Decrypts an +application/pkcs7-mime+ message with the recipient's
    # private +key+ and +certificate+. Returns a DecryptionResult; check
    # +success?+ and then use +mail+ for the recovered message.
    def decrypt(message, key:, certificate:)
      mail = message.is_a?(Mail::Message) ? message : Mail.new(message)
      pkcs7 = OpenSSL::PKCS7.new(mail.body.decoded)
      plaintext = pkcs7.decrypt(key, certificate, OpenSSL::PKCS7::BINARY)
      DecryptionResult.new(success: true, mail: Mail.new(plaintext))
    rescue Error, OpenSSL::OpenSSLError => e
      DecryptionResult.new(success: false, error: e)
    end

    # -- internal helpers ------------------------------------------------

    # Canonicalizes text to CRLF line endings as required for S/MIME
    # signed and enveloped content.
    def canonicalize(text)
      text.gsub(/\r\n|\r|\n/, "\r\n")
    end

    # Encoded copies of the non-MIME headers of +message+, so addressing
    # and subject headers stay visible on the outer S/MIME message.
    def entity_headers(message)
      raw = +''.b
      message.header.fields.each do |field|
        next if field.name.to_s =~ /\A(content-|mime-version)/i
        raw << field.encoded
      end
      raw
    end

    def detect_micalg(pkcs7)
      der = pkcs7.to_der
      DIGEST_OIDS.each do |oid, name|
        return name if der.include?(oid)
      end
      'sha-256'
    end

    def raw_source_of(message)
      case message
      when String
        message
      when Mail::Message
        raw = message.raw_source
        if raw.to_s.empty?
          raise Error, 'cannot verify a message without its original raw source; ' \
                       'pass the raw message text or a freshly parsed Mail::Message'
        end
        raw
      else
        raise ArgumentError, "cannot verify #{message.class}; expected a String or Mail::Message"
      end
    end

    def split_header_body(raw)
      parts = raw.split(/\r\n\r\n|\n\n/, 2)
      raise Error, 'malformed message: no header/body separator' unless parts.length == 2
      parts
    end

    # Slices the exact bytes of the first MIME entity (the signed content)
    # out of the raw multipart body. The CRLF immediately preceding a
    # boundary delimiter belongs to the delimiter, not to the content.
    def extract_signed_data(body, boundary)
      delimiter = Regexp.escape("--#{boundary}")
      first = body.match(/(?:\A|\r\n|\n)#{delimiter}[ \t]*(?:\r\n|\n)/)
      raise Error, 'boundary delimiter not found in message body' unless first

      rest = body[first.end(0)..-1] || +''
      stop = rest.match(/\r\n#{delimiter}|\n#{delimiter}/)
      raise Error, 'closing boundary delimiter not found in message body' unless stop

      rest[0...stop.begin(0)]
    end

    # Extracts the CMS signature from the second MIME part of a
    # multipart/signed message.
    def signature_pkcs7(mail)
      part = mail.parts[1]
      raise Error, 'multipart/signed message has no signature part' unless part
      OpenSSL::PKCS7.new(part.body.decoded)
    end

    # Cryptographic verification of the detached signature only; certificate
    # trust is intentionally not checked here.
    def verify_signature(pkcs7, data)
      flags = OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::NOVERIFY
      pkcs7.verify([], OpenSSL::X509::Store.new, data, flags)
    rescue OpenSSL::OpenSSLError
      false
    end

    def signer_certificates(pkcs7)
      included = pkcs7.certificates || []
      pkcs7.signers.map do |signer|
        included.find do |cert|
          cert.issuer == signer.issuer && cert.serial == signer.serial
        end
      end.compact
    end

    def verify_trust(signers, chain, ca_certificates, store)
      return false if signers.empty?

      store ||= begin
        s = OpenSSL::X509::Store.new
        Array(ca_certificates).each { |cert| s.add_cert(cert) }
        s
      end

      signers.any? do |signer|
        store.verify(signer, chain - [signer])
      end
    rescue OpenSSL::OpenSSLError
      false
    end
  end
end
