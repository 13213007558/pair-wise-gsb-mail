# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require_relative 'dkim_spec_helper'

RSpec.describe 'Mail DKIM integration' do
  include DKIMSpecHelpers

  describe 'Message#dkim_sign!' do
    it 'returns the message so chaining works' do
      mail = Mail.new { from 'a@example.com'; to 'b@example.org'; body 'x' }
      returned = mail.dkim_sign!(domain: 'example.com', selector: 'sel',
                                 private_key: private_pem, time: 1)
      expect(returned).to equal(mail)
    end

    it 'produces a signature that verifies against the encoded bytes' do
      mail = Mail.new do
        from 'jane@example.com'
        to 'joe@example.org'
        subject 'Integrated'
        body 'payload'
      end
      mail.dkim_sign!(domain: 'example.com', selector: 'sel',
                      private_key: private_pem,
                      header_canonicalization: 'relaxed',
                      body_canonicalization: 'relaxed', time: 1)
      expect(mail.dkim_verify(resolver: dns_resolver).first.status).to eq(:pass)
      expect(mail.dkim_valid?(resolver: dns_resolver)).to eq(true)
    end
  end

  describe 'Mail::DKIM facade' do
    it 'signs a message in place via .sign' do
      mail = Mail.new { from 'jane@example.com'; to 'b@x'; body 'y' }
      Mail::DKIM.sign(mail, domain: 'example.com', selector: 'sel',
                      private_key: private_pem, time: 1)
      expect(mail.encoded).to include('DKIM-Signature:')
    end

    it 'verifies raw bytes via .verify' do
      raw = dkim_signed('hi')
      expect(Mail::DKIM.verify(raw, resolver: dns_resolver).first.status).to eq(:pass)
    end
  end

  describe 'multipart message' do
    it 'signs and verifies a multipart/alternative message' do
      mail = Mail.new do
        from 'jane@example.com'
        to 'joe@example.org'
        subject 'Alternative'
        text_part { body 'plain' }
        html_part { body '<p>html</p>' }
      end
      mail.dkim_sign!(domain: 'example.com', selector: 'sel',
                      private_key: private_pem,
                      header_canonicalization: 'relaxed',
                      body_canonicalization: 'relaxed', time: 1)
      raw = mail.encoded
      expect(raw).to include('multipart/alternative')
      expect(verify(raw).first.status).to eq(:pass)
    end
  end

  describe 'eager autoloading' do
    it 'loads DKIM constants under eager_autoload!' do
      expect { Mail.eager_autoload! }.not_to raise_error
      expect(Mail::DKIM::Signer).not_to be_nil
      expect(Mail::DKIM::Verifier).not_to be_nil
      expect(Mail::DKIM::Canonicalization).not_to be_nil
    end
  end
end
