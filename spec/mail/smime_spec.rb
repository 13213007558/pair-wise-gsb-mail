# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'openssl'
#
module SMIMESpecHelpers
  module_function
  # Builds a short, self-contained CA + leaf certificate chain entirely in
  # memory. The certificates are real X.509 objects validated by OpenSSL
  # itself, not mocked.
  def build_ca(subject)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end
  #
  def build_leaf(ca, ca_key, subject, serial)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = ca.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = ca
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.add_extension(factory.create_extension('keyUsage',
      'digitalSignature,keyEncipherment', true))
    cert.add_extension(factory.create_extension('extendedKeyUsage',
      'emailProtection'))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
    cert.add_extension(factory.create_extension('authorityKeyIdentifier',
      'keyid:always'))
    cert.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end
end
#
RSpec.describe Mail::SMIME do
  let(:ca) { SMIMESpecHelpers.build_ca('/CN=Spec Root CA') }
  let(:other_ca) { SMIMESpecHelpers.build_ca('/CN=Spec Other CA') }
  let(:signer) { SMIMESpecHelpers.build_leaf(ca[0], ca[1], '/CN=Spec Signer', 2) }
  let(:recipient_one) do
    SMIMESpecHelpers.build_leaf(ca[0], ca[1], '/CN=Spec Recipient One', 3)
  end
  let(:recipient_two) do
    SMIMESpecHelpers.build_leaf(ca[0], ca[1], '/CN=Spec Recipient Two', 4)
  end
  #
  let(:signer_cert) { signer[0] }
  let(:signer_key) { signer[1] }
  let(:recipient_one_cert) { recipient_one[0] }
  let(:recipient_one_key) { recipient_one[1] }
  let(:recipient_two_cert) { recipient_two[0] }
  let(:recipient_two_key) { recipient_two[1] }
  #
  let(:long_line) do
    'the quick brown fox jumps over the lazy dog and keeps on running far ' +
      'past where any reasonable single email line should ever have ended'
  end
  #
  let(:inner_mail) do
    content = long_line
    Mail.new do
      from 'signer@example.com'
      to 'one@example.com, two@example.com'
      subject 'S/MIME round trip'
      body "first line\n#{content}\nlast line"
    end
  end
  #
  def signed_part_bytes(raw)
    envelope = Mail.read_from_string(raw)
    described_class.send(:extract_first_part, raw, envelope)
  end
  #
  describe '.sign / .verify_signed' do
    let(:signed) do
      described_class.sign(inner_mail, signer_cert, signer_key,
                            chain: [signer_cert, ca[0]])
    end
    #
    it 'produces a multipart/signed message with a pkcs7-signature part' do
      mail = Mail.read_from_string(signed)
      expect(mail.mime_type).to eq 'multipart/signed'
      expect(mail.content_type_parameters['protocol'])
        .to eq 'application/pkcs7-signature'
      expect(mail.parts.length).to eq 2
      expect(mail.parts[1].mime_type).to eq 'application/pkcs7-signature'
      signature = OpenSSL::PKCS7.new(mail.parts[1].body.decoded)
      expect(signature).to be_detached
    end
    #
    it 'verifies the signature and chain independently against a trusted CA' do
      result = described_class.verify_signed(signed, [ca[0]])
      expect(result).to be_signature_valid
      expect(result).to be_trusted
      expect(result.signer_certificate.subject.to_s).to eq '/CN=Spec Signer'
    end
    #
    it 'reports a valid signature but untrusted chain with another trust anchor' do
      result = described_class.verify_signed(signed, [other_ca[0]])
      expect(result).to be_signature_valid
      expect(result).not_to be_trusted
      expect(result.trust_error).to include('certificate')
    end
    #
    it 'checks the signature without trust anchors and never marks it trusted' do
      result = described_class.verify_signed(signed)
      expect(result).to be_signature_valid
      expect(result).not_to be_trusted
    end
    #
    it 'returns the signed inner message parsed from the original bytes' do
      result = described_class.verify_signed(signed, [ca[0]])
      expect(result.mail).to be_a(Mail::Message)
      expect(result.mail.subject).to eq 'S/MIME round trip'
      expect(result.mail.body.to_s).to include(long_line)
    end
    #
    it 'verifies using the exact signed bytes, not a re-serialized part' do
      envelope = Mail.read_from_string(signed)
      raw_part = described_class.send(:extract_first_part, signed, envelope)
      # The canonical signed bytes use CRLF, while a re-serialized part
      # produced by the parser is regenerated (Date, folding and whitespace
      # are reconstructed) and must not be treated as the CMS input.
      reparsed_part = envelope.parts[0].encoded
      expect(raw_part).to include("\r\n")
      p7 = OpenSSL::PKCS7.new(envelope.parts[1].body.decoded)
      expect(p7.verify(p7.certificates, OpenSSL::X509::Store.new,
                       raw_part, OpenSSL::PKCS7::NOVERIFY)).to eq(true)
      reparsed_p7 = OpenSSL::PKCS7.new(envelope.parts[1].body.decoded)
      expect(
        reparsed_p7.verify(p7.certificates, OpenSSL::X509::Store.new,
                           reparsed_part, OpenSSL::PKCS7::NOVERIFY)
      ).to eq(false)
    end
    #
    it 'rejects the signature when signed line endings change to bare LF' do
      raw_part = signed_part_bytes(signed)
      tampered = signed.sub(raw_part, raw_part.gsub("\r\n", "\n"))
      result = described_class.verify_signed(tampered, [ca[0]])
      expect(result).not_to be_signature_valid
      expect(result).not_to be_trusted
    end
    #
    it 'rejects the signature when the body is refolded differently' do
      raw_part = signed_part_bytes(signed)
      raw_part =~ /\A(.*?\r?\n\r?\n)(.+)\z/m
      headers, body = Regexp.last_match(1), Regexp.last_match(2)
      refolded_body =
        body.gsub(/\r?\n/, ' ')
            .gsub(/.{1,45}/) { |line| line + "\r\n" }
            .sub(/\r?\n\z/, '')
      tampered = signed.sub(raw_part, headers + refolded_body)
      result = described_class.verify_signed(tampered, [ca[0]])
      expect(result).not_to be_signature_valid
    end
    #
    it 'verifies a parsed Mail::Message passed in directly' do
      parsed = Mail.read_from_string(signed)
      result = described_class.verify_signed(parsed, [ca[0]])
      expect(result).to be_signature_valid
      expect(result).to be_trusted
    end
    #
    it 'raises on a non-signed message' do
      expect { described_class.verify_signed(inner_mail.encoded, [ca[0]]) }
        .to raise_error(described_class::Error, /multipart\/signed/)
    end
  end
  #
  describe '.encrypt / .decrypt' do
    let(:encrypted) do
      described_class.encrypt(inner_mail,
                              [recipient_one_cert, recipient_two_cert])
    end
    #
    it 'produces an application/pkcs7-mime enveloped message' do
      mail = Mail.read_from_string(encrypted)
      expect(mail.mime_type).to eq 'application/pkcs7-mime'
      expect(mail.content_type_parameters['smime-type'])
        .to eq 'enveloped-data'
      expect(mail.content_transfer_encoding).to eq 'base64'
      expect { OpenSSL::PKCS7.new(mail.body.decoded) }.not_to raise_error
    end
    #
    it 'lets every recipient decrypt with their own private key' do
      one = described_class.decrypt(encrypted, recipient_one_key,
                                    recipient_one_cert)
      two = described_class.decrypt(encrypted, recipient_two_key,
                                    recipient_two_cert)
      expect(one).to be_success
      expect(two).to be_success
      expect(one.mail.subject).to eq 'S/MIME round trip'
      expect(two.mail.body.to_s).to include(long_line)
    end
    #
    it 'includes a RecipientInfo for each recipient' do
      mail = Mail.read_from_string(encrypted)
      p7 = OpenSSL::PKCS7.new(mail.body.decoded)
      expect(p7.recipients.length).to eq 2
    end
    #
    it 'accepts a parsed Mail::Message for decryption' do
      parsed = Mail.read_from_string(encrypted)
      result = described_class.decrypt(parsed, recipient_two_key,
                                       recipient_two_cert)
      expect(result).to be_success
      expect(result.mail.subject).to eq 'S/MIME round trip'
    end
    #
    it 'does not let a non-recipient decrypt the message' do
      result = described_class.decrypt(encrypted, signer_key, signer_cert)
      expect(result).not_to be_success
      expect(result.mail).to be_nil
      expect(result.error).to be_a(OpenSSL::PKCS7::PKCS7Error)
    end
    #
    it 'round-trips a signed and then encrypted message' do
      signed = described_class.sign(inner_mail, signer_cert, signer_key,
                                    chain: [signer_cert, ca[0]])
      sealed = described_class.encrypt(Mail.read_from_string(signed),
                                        [recipient_one_cert])
      opened = described_class.decrypt(sealed, recipient_one_key,
                                       recipient_one_cert)
      expect(opened).to be_success
      verified = described_class.verify_signed(opened.mail.encoded, [ca[0]])
      expect(verified).to be_signature_valid
      expect(verified).to be_trusted
    end
    #
    it 'raises on a non-encrypted message' do
      expect { described_class.decrypt(inner_mail.encoded,
                                       recipient_one_key,
                                       recipient_one_cert) }
        .to raise_error(described_class::Error, /pkcs7-mime/)
    end
  end
end
