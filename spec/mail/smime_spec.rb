# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::SMIME do
  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  # Builds a certificate signed by +issuer_cert+/+issuer_key+. When
  # +issuer_cert+ is nil the certificate is self-signed (a root CA).
  def build_certificate(subject_dn, issuer_cert, issuer_key, public_key, serial, ca: false)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse(subject_dn)
    cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
    cert.public_key = public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    if ca
      cert.add_extension factory.create_extension('basicConstraints', 'CA:TRUE', true)
      cert.add_extension factory.create_extension('keyUsage', 'keyCertSign, cRLSign', true)
    else
      cert.add_extension factory.create_extension('basicConstraints', 'CA:FALSE', true)
      cert.add_extension factory.create_extension('keyUsage', 'digitalSignature, keyEncipherment', true)
      cert.add_extension factory.create_extension('extendedKeyUsage', 'emailProtection', false)
    end
    cert.add_extension factory.create_extension('subjectKeyIdentifier', 'hash')
    cert.add_extension factory.create_extension('authorityKeyIdentifier', 'keyid:always')

    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  # A short, locally generated chain: root CA -> intermediate CA -> leaves.
  before(:all) do
    @root_key = generate_key
    @root_cert = build_certificate('/CN=SMIME Test Root CA', nil,
                                   @root_key, @root_key.public_key, 1, ca: true)

    @intermediate_key = generate_key
    @intermediate_cert = build_certificate('/CN=SMIME Test Intermediate CA', @root_cert,
                                           @root_key, @intermediate_key.public_key, 2, ca: true)

    @signer_key = generate_key
    @signer_cert = build_certificate('/CN=signer@example.com', @intermediate_cert,
                                     @intermediate_key, @signer_key.public_key, 3)

    @recipient_one_key = generate_key
    @recipient_one_cert = build_certificate('/CN=one@example.com', @intermediate_cert,
                                            @intermediate_key, @recipient_one_key.public_key, 4)

    @recipient_two_key = generate_key
    @recipient_two_cert = build_certificate('/CN=two@example.com', @intermediate_cert,
                                            @intermediate_key, @recipient_two_key.public_key, 5)

    @attacker_key = generate_key
    @attacker_cert = build_certificate('/CN=attacker@example.com', @intermediate_cert,
                                       @intermediate_key, @attacker_key.public_key, 6)
  end

  def sample_message
    Mail.new do
      from 'sender@example.com'
      to 'one@example.com'
      subject 'A rather long subject line that will definitely need to be folded by the encoder somewhere'
      body "Hello,\r\nthis is the signed body.\r\n"
    end
  end

  describe '.sign and .verify' do
    let(:signed) do
      Mail::SMIME.sign(sample_message,
                       certificate: @signer_cert,
                       key: @signer_key,
                       ca_certificates: [@intermediate_cert])
    end

    it 'produces a multipart/signed message with a detached signature part' do
      expect(signed.mime_type).to eq 'multipart/signed'
      expect(signed.content_type_parameters['protocol']).to eq 'application/pkcs7-signature'
      expect(signed.content_type_parameters['micalg']).to eq 'sha-256'
      expect(signed.parts.length).to eq 2
      expect(signed.parts[1].mime_type).to eq 'application/pkcs7-signature'
    end

    it 'verifies a good signature with a trusted chain' do
      result = Mail::SMIME.verify(signed, ca_certificates: [@root_cert])
      expect(result.signature_valid?).to be true
      expect(result.certificate_trusted?).to be true
      expect(result.valid?).to be true
      expect(result.signer_certificates.map(&:subject)).to include(@signer_cert.subject)
    end

    it 'verifies after the message is serialized and parsed again' do
      reparsed = Mail.new(signed.to_s)
      result = Mail::SMIME.verify(reparsed, ca_certificates: [@root_cert])
      expect(result.valid?).to be true
    end

    it 'accepts a raw message string' do
      result = Mail::SMIME.verify(signed.to_s, ca_certificates: [@root_cert])
      expect(result.valid?).to be true
    end

    it 'reports signature validity separately from certificate chain trust' do
      result = Mail::SMIME.verify(signed)
      expect(result.signature_valid?).to be true
      expect(result.certificate_trusted?).to be false
      expect(result.valid?).to be false
    end

    it 'rejects a message whose signed content was re-folded after signing' do
      raw = signed.to_s
      delimiter = "--#{signed.boundary}\r\n"
      preamble, signed_entity = raw.split(delimiter, 2)

      # Unfold the folded Subject header inside the signed entity.
      tampered_entity = signed_entity.sub(/(Subject: [^\r\n]+)\r\n /, '\\1 ')
      expect(tampered_entity).not_to eq signed_entity
      tampered = preamble + delimiter + tampered_entity

      # Parsing and reserializing regenerates the original folding, which is
      # exactly why verification must use the preserved raw bytes.
      expect(Mail.new(tampered).to_s).to eq raw

      result = Mail::SMIME.verify(Mail.new(tampered), ca_certificates: [@root_cert])
      expect(result.signature_valid?).to be false
      expect(result.valid?).to be false
    end

    it 'returns an error result for a message without a signature' do
      result = Mail::SMIME.verify(sample_message.to_s, ca_certificates: [@root_cert])
      expect(result.valid?).to be false
      expect(result.error).not_to be_nil
    end
  end

  describe '.encrypt and .decrypt' do
    let(:encrypted) do
      Mail::SMIME.encrypt(sample_message,
                          certificates: [@recipient_one_cert, @recipient_two_cert])
    end

    it 'produces an application/pkcs7-mime enveloped-data message' do
      expect(encrypted.mime_type).to eq 'application/pkcs7-mime'
      expect(encrypted.content_type_parameters['smime-type']).to eq 'enveloped-data'
    end

    it 'can be decrypted by every recipient' do
      [[@recipient_one_key, @recipient_one_cert],
       [@recipient_two_key, @recipient_two_cert]].each do |key, cert|
        result = Mail::SMIME.decrypt(encrypted, key: key, certificate: cert)
        expect(result.success?).to be true
        expect(result.error).to be_nil
        expect(result.mail.subject).to eq sample_message.subject
        expect(result.mail.body.decoded).to include 'this is the signed body'
      end
    end

    it 'decrypts after the message is serialized and parsed again' do
      reparsed = Mail.new(encrypted.to_s)
      result = Mail::SMIME.decrypt(reparsed, key: @recipient_one_key, certificate: @recipient_one_cert)
      expect(result.success?).to be true
      expect(result.mail.body.decoded).to include 'this is the signed body'
    end

    it 'fails cleanly with the wrong private key' do
      result = Mail::SMIME.decrypt(encrypted, key: @attacker_key, certificate: @attacker_cert)
      expect(result.success?).to be false
      expect(result.mail).to be_nil
      expect(result.error).not_to be_nil
    end
  end
end
