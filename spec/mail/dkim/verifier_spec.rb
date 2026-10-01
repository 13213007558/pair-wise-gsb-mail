# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require_relative 'dkim_spec_helper'

RSpec.describe Mail::DKIM::Verifier do
  include DKIMSpecHelpers

  def signer_for(selector:, key:, domain: 'example.com', **opts)
    Mail::DKIM::Signer.new(
      domain: domain, selector: selector, private_key: key,
      header_canonicalization: 'relaxed', body_canonicalization: 'relaxed',
      time: 1_700_000_000, **opts
    )
  end

  describe '#verify on the received raw bytes' do
    it 'passes a correctly signed message' do
      results = verify(dkim_signed('Hello'))
      expect(results).to contain_exactly(have_attributes(status: :pass))
    end

    it 'fails when a signed header is modified' do
      signed = dkim_signed('Hello')
      tampered = signed.sub('Subject: Hi', 'Subject: Ho')
      results = verify(tampered)
      expect(results.first).to have_attributes(
        status: :permerror, reason: /signature did not verify/
      )
    end

    it 'fails when the body is modified' do
      signed = dkim_signed('Hello')
      tampered = signed.sub('Hello', 'HELLO')
      expect(verify(tampered).first).to have_attributes(
        status: :permerror, reason: /body hash did not verify/
      )
    end

    it 'still verifies a message whose CRLFs were normalized to bare LF' do
      signed = dkim_signed('Hello').gsub("\r\n", "\n")
      expect(verify(signed).first.status).to eq(:pass)
    end

    it 'returns an empty list when no signature is present' do
      raw = Mail.new { from 'a'; to 'b'; body 'c' }.encoded
      expect(verify(raw)).to eq([])
    end

    it 'reports permerror when h= omits the From header (message has From)' do
      signed = dkim_signed('Hello').sub(/h=[^;]+/, 'h=to')
      expect(verify(signed).first.reason).to include('From')
    end

    it 'reports permerror when a received signature never signed From' do
      raw = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; " \
            "d=example.com; s=sel; h=to; bh=#{Base64.strict_encode64('x')}; " \
            "b=#{Base64.strict_encode64('y')}\r\nTo: b@x\r\n\r\nbody"
      expect(verify(raw).first.reason).to include('From')
    end
  end

  describe 'DNS / key injection' do
    it 'reports temperror when the TXT record is missing' do
      signed = dkim_signed('Hello')
      results = described_class.new(resolver: ->(_) { nil }).verify(signed)
      expect(results.first.status).to eq(:temperror)
      expect(results.first.reason).to include('no DKIM public key')
    end

    it 'accepts a resolver object responding to #txt' do
      record = dns_txt
      resolver = Object.new
      resolver.define_singleton_method(:txt) { |_name| record }
      expect(described_class.new(resolver: resolver).verify(dkim_signed('Hello')).first.status)
        .to eq(:pass)
    end

    it 'rejects a key for the wrong domain' do
      signed = dkim_signed('Hello')
      other = OpenSSL::PKey::RSA.new(2048)
      wrong_records = { 'example.com' => { 'sel' => dns_txt(other) } }
      result = described_class.new(resolver: dns_resolver(wrong_records)).verify(signed).first
      expect(result.status).to eq(:permerror)
      expect(result.reason).to include('signature did not verify')
    end

    it 'treats a revoked key (empty p=) as permerror' do
      signed = dkim_signed('Hello')
      records = { 'example.com' => { 'sel' => 'v=DKIM1; p=' } }
      result = described_class.new(resolver: dns_resolver(records)).verify(signed).first
      expect(result.status).to eq(:permerror)
      expect(result.reason).to include('revoked')
    end

    it 'enforces g= granularity against the i= local-part' do
      signed = Mail::DKIM.sign_bytes(
        "From: jane@example.com\r\nTo: b@example.org\r\n\r\nbody",
        domain: 'example.com', selector: 'sel', private_key: private_pem,
        identity: 'jane@example.com', time: 1,
        header_canonicalization: 'relaxed', body_canonicalization: 'relaxed'
      )
      records_ok = { 'example.com' => { 'sel' => dns_txt(rsa_key).sub('; k=rsa;', '; g=jane; k=rsa;') } }
      expect(described_class.new(resolver: dns_resolver(records_ok)).verify(signed).first.status)
        .to eq(:pass)

      records_bad = { 'example.com' => { 'sel' => dns_txt(rsa_key).sub('; k=rsa;', '; g=bob; k=rsa;') } }
      bad = described_class.new(resolver: dns_resolver(records_bad)).verify(signed).first
      expect(bad.status).to eq(:permerror)
      expect(bad.reason).to include('g=')
    end

    it 'rejects signatures from a short (<1024 bit) key' do
      small = OpenSSL::PKey::RSA.new(512)
      signed = signer_for(selector: 'sel', key: small).sign_bytes(
        "From: a@example.com\r\nTo: b@example.org\r\n\r\nx"
      )
      records = { 'example.com' => { 'sel' => dns_txt(small) } }
      result = described_class.new(resolver: dns_resolver(records)).verify(signed).first
      expect(result.status).to eq(:permerror)
      expect(result.reason).to include('too short')
    end

    it 'caches DNS lookups across signatures on one message' do
      calls = []
      resolver = lambda do |name|
        calls << name
        dns_txt
      end
      mail = Mail.new { from 'jane@example.com'; to 'joe@example.org'; subject 's'; body 'b' }
      signer_for(selector: 'sel', key: private_pem).sign!(mail)
      described_class.new(resolver: resolver).verify(mail.encoded)
      expect(calls.uniq.size).to eq(calls.size).or eq(1)
      expect(calls).to eq(['sel._domainkey.example.com'])
    end
  end

  describe 'multiple signatures are evaluated independently' do
    let(:key2) { OpenSSL::PKey::RSA.new(2048) }

    def two_signatures
      mail = Mail.new do
        from 'jane@example.com'; to 'joe@example.org'; subject 's'; body 'b'
      end
      signer_for(selector: 's1', key: private_pem).sign!(mail)
      signer_for(selector: 's2', key: key2).sign!(mail)
      records = {
        'example.com' => {
          's1' => dns_txt(rsa_key),
          's2' => dns_txt(key2)
        }
      }
      [mail.encoded, records]
    end

    it 'returns one result per signature' do
      raw, records = two_signatures
      results = described_class.new(resolver: dns_resolver(records)).verify(raw)
      expect(results.size).to eq(2)
      expect(results.map(&:selector)).to contain_exactly('s1', 's2')
      expect(results).to all(have_attributes(status: :pass))
    end

    it 'keeps the other signature passing when one b= is corrupted' do
      raw, records = two_signatures
      corrupted = raw.sub(/(s1[^\r]*?b=)[A-Za-z0-9+\/=]+/m, '\1XXXX')
      results = described_class.new(resolver: dns_resolver(records)).verify(corrupted)
      by_selector = results.map { |r| [r.selector, r.status] }.to_h
      expect(by_selector['s1']).to eq(:permerror)
      expect(by_selector['s2']).to eq(:pass)
    end

    it 'keeps an independent pass when one key is unavailable' do
      raw, records = two_signatures
      records['example.com']['s1'] = nil
      results = described_class.new(resolver: dns_resolver(records)).verify(raw)
      by_selector = results.map { |r| [r.selector, r.status] }.to_h
      expect(by_selector['s1']).to eq(:temperror)
      expect(by_selector['s2']).to eq(:pass)
    end

    it 'does not raise when a signature is structurally broken' do
      raw, records = two_signatures
      broken = raw.sub(/(DKIM-Signature:[^\r]*?d=)example\.com/, '\1')
      expect { described_class.new(resolver: dns_resolver(records)).verify(broken) }
        .not_to raise_error
    end
  end

  describe 'validation details' do
    it 'reports permerror for an unsupported version' do
      signed = dkim_signed('Hello').sub(/v=1/, 'v=2')
      expect(verify(signed).first.status).to eq(:permerror)
    end

    it 'is neutral for an unsupported algorithm' do
      signed = dkim_signed('Hello').sub('a=rsa-sha256', 'a=rsa-sha1')
      expect(verify(signed).first.status).to eq(:neutral)
    end

    it 'reports permerror for an expired x= tag' do
      signed = dkim_signed('Hello')
      # inject an x= tag in the past, immediately after s=
      signed = signed.sub('s=sel;', 's=sel; x=1;')
      expect(verify(signed).first.status).to eq(:permerror)
      expect(verify(signed).first.reason).to include('expired')
    end

    it 'rejects an i= identity outside the signing domain' do
      signed = dkim_signed('Hello')
      signed = signed.sub('s=sel;', 'i=jane@evil.example.net; s=sel;')
      expect(verify(signed).first.status).to eq(:permerror)
    end
  end
end
