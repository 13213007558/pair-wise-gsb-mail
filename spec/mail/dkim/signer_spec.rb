# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require_relative 'dkim_spec_helper'

RSpec.describe Mail::DKIM::Signer do
  include DKIMSpecHelpers

  def build_mail
    Mail.new do
      from 'jane@example.com'
      to   'joe@example.org'
      subject 'Signed'
      body 'payload'
    end
  end

  describe '#sign!' do
    it 'adds a DKIM-Signature field to the message' do
      mail = build_mail
      described_class.new(
        domain: 'example.com', selector: 'sel', private_key: private_pem
      ).sign!(mail)
      expect(mail.encoded).to include('DKIM-Signature:')
    end

    it 'emits the required tags' do
      raw = dkim_signed(build_mail)
      field = raw[/DKIM-Signature: [^\r]+/]
      expect(field).to include('v=1')
      expect(field).to include('a=rsa-sha256')
      expect(field).to include('d=example.com')
      expect(field).to include('s=sel')
      expect(field).to include('q=dns/txt')
      expect(field).to match(/bh=[A-Za-z0-9+\/=]+/)
      expect(field).to match(/b=[A-Za-z0-9+\/=]+/)
      expect(field).to include('h=')
    end

    it 'signs the From header (RFC 6376 5.4.1)' do
      raw = dkim_signed(build_mail)
      expect(raw[/h=([^;\r]+)/, 1].split(':')).to include('from')
    end

    it 'accepts an OpenSSL key object as private_key' do
      mail = build_mail
      described_class.new(
        domain: 'example.com', selector: 'sel', private_key: rsa_key, time: 1
      ).sign!(mail)
      expect(verify(mail.encoded).first.status).to eq(:pass)
    end

    it 'uses simple/simple by default' do
      raw = dkim_signed(build_mail)
      expect(raw).to include('c=simple/simple')
    end

    it 'includes an identity tag when provided' do
      raw = dkim_signed(build_mail, identity: 'jane@example.com')
      expect(raw).to include('i=jane@example.com')
    end

    it 'omits the i= tag by default' do
      expect(dkim_signed(build_mail)).not_to include('i=')
    end

    it 'emits l= when asked for a body length' do
      raw = dkim_signed(build_mail, length: true)
      expect(raw).to match(/l=\d+/)
    end

    it 'raises without a private key' do
      expect do
        described_class.new(domain: 'x', selector: 'y').sign!(build_mail)
      end.to raise_error(ArgumentError)
    end

    it 'raises without a domain or selector' do
      expect do
        described_class.new(selector: 'y', private_key: private_pem).sign!(build_mail)
      end.to raise_error(ArgumentError, /domain/)
      expect do
        described_class.new(domain: 'x', private_key: private_pem).sign!(build_mail)
      end.to raise_error(ArgumentError, /selector/)
    end

    it 'refuses to sign a message that has no From header' do
      mail = Mail.new { to 'b@example.org'; body 'x' }
      expect do
        described_class.new(domain: 'x', selector: 'y',
                            private_key: private_pem).sign!(mail)
      end.to raise_error(ArgumentError, /From/)
    end
  end

  describe 'signed bytes remain deliverable' do
    it 'survives the SMTP envelope encoding unchanged' do
      mail = build_mail
      dkim_signed(mail)
      envelope = Mail::SmtpEnvelope.new(mail)
      expect(verify(envelope.message).first.status).to eq(:pass)
    end

    it 'survives the test delivery method' do
      Mail.defaults { delivery_method :test }
      Mail::TestMailer.deliveries.clear
      mail = build_mail
      mail.dkim_sign!(domain: 'example.com', selector: 'sel',
                      private_key: private_pem, time: 1)
      mail.deliver
      delivered = Mail::TestMailer.deliveries.first
      expect(delivered.encoded).to include('DKIM-Signature:')
      expect(verify(delivered.encoded).first.status).to eq(:pass)
    end
  end

  describe '.sign_bytes' do
    it 'preserves repeated Subject headers and produces a valid signature' do
      raw = "From: jane@example.com\r\nTo: joe@example.org\r\n" \
            "Subject: one\r\nSubject: two\r\n\r\nbody"
      signed = Mail::DKIM.sign_bytes(
        raw, domain: 'example.com', selector: 'sel', private_key: private_pem,
        headers: %w[Subject Subject From To], time: 1,
        header_canonicalization: 'relaxed', body_canonicalization: 'relaxed'
      )
      expect(signed.scan(/Subject:/).size).to eq(2)
      expect(verify(signed).first.status).to eq(:pass)
    end
  end
end
