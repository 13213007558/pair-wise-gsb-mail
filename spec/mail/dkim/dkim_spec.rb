# frozen_string_literal: true
require 'spec_helper'
require 'openssl'

RSpec.describe Mail::DKIM do
  FIXTURE_DIR = File.expand_path('../../fixtures/dkim', __dir__)
  let(:private_pem) { File.read(File.join(FIXTURE_DIR, 'private.pem')) }
  let(:private_key) { OpenSSL::PKey::RSA.new(private_pem) }
  let(:spki_b64) { File.read(File.join(FIXTURE_DIR, 'public_spki.b64')).gsub(/\s+/, '') }
  let(:pkcs1_b64) { File.read(File.join(FIXTURE_DIR, 'public_pkcs1.b64')).gsub(/\s+/, '') }
  let(:now) { Time.at(1_500_000_000) }

  let(:resolver) do
    {
      'mail._domainkey.example.com' => "v=DKIM1; k=rsa; p=#{spki_b64}",
      'mail._domainkey.pkcs1.example.com' => "v=DKIM1; p=#{pkcs1_b64}"
    }
  end

  def sign(message, **options)
    Mail::DKIM.sign(message,
                    domain: options.delete(:domain) || 'example.com',
                    selector: 'mail',
                    private_key: private_pem,
                    time: now - 10,
                    **options)
  end

  def verify(signed, extra_records = {})
    Mail::DKIM.verify(signed,
                      resolver: resolver.merge(extra_records),
                      now: now)
  end

  def expect_pass(signed, extra_records = {})
    results = verify(signed, extra_records)
    expect(results.size).to eq(1)
    expect(results.first).to be_pass
    results
  end

  def expect_fail(signed, reason, extra_records = {})
    results = verify(signed, extra_records)
    expect(results.size).to eq(1)
    expect(results.first).to be_fail
    expect(results.first.reason).to eq(reason)
    results
  end

  describe 'signing and verification round trip' do
    CANON_COMBOS = %w[simple/simple simple/relaxed relaxed/simple relaxed/relaxed].freeze

    CANON_COMBOS.each do |canon|
      it "round trips with #{canon} canonicalization" do
        message = "From: alice@example.com\r\nTo: bob@example.org\r\n" \
                  "Subject: Canon test\r\n\r\nBody line one\r\nBody line two\r\n"
        signed = sign(message, canonicalization: canon)
        results = expect_pass(signed)
        result = results.first
        expect(result.domain).to eq('example.com')
        expect(result.selector).to eq('mail')
        expect(result.algorithm).to eq('rsa-sha256')
        expect(result.header_canonicalization).to eq(canon.split('/').first.to_sym)
        expect(result.body_canonicalization).to eq(canon.split('/').last.to_sym)
      end
    end

    it 'accepts a key published as a bare PKCS#1 RSAPublicKey' do
      message = "From: alice@example.com\r\nSubject: Pkcs1\r\n\r\nhi\r\n"
      signed = sign(message, domain: 'pkcs1.example.com')
      expect_pass(signed)
    end

    it 'accepts a private key supplied as an OpenSSL key object' do
      message = "From: alice@example.com\r\nSubject: Key\r\n\r\nhi\r\n"
      signed = Mail::DKIM.sign(message, domain: 'example.com', selector: 'mail',
                               private_key: private_key, time: now - 10)
      expect_pass(signed)
    end

    it 'verifies a message carrying bare LF input after normalisation' do
      message = "From: alice@example.com\nSubject: Bare\n\nbody\n"
      signed = sign(message)
      expect_pass(signed)
    end

    it 'produces exactly one DKIM-Signature header and a valid tag list' do
      signed = sign("From: alice@example.com\r\nSubject: T\r\n\r\nb\r\n")
      expect(signed.scan(/^DKIM-Signature:/).size).to eq(1)
      value = signed.slice(/\ADKIM-Signature:(.*?)(?:\r\n(?!\s))/m, 1)
      tags = Mail::DKIM::TagList.parse(Mail::DKIM::Canonicalization.unfold(value.to_s),
                                       base64_tags: %w[b bh])
      expect(tags['v']).to eq('DKIM1')
      expect(tags['a']).to eq('rsa-sha256')
      expect(tags['d']).to eq('example.com')
      expect(tags['s']).to eq('mail')
      expect(tags['q']).to eq('dns/txt')
      expect(tags['c']).to eq('relaxed/relaxed')
      expect(tags['b'].bytesize).to eq(344) # 2048 bit RSA signature, base64
    end

    it 'queries the selector TXT name constructed from s= and d=' do
      seen = []
      query = ->(name) { seen << name; resolver[name] }
      signed = sign("From: alice@example.com\r\n\r\nb\r\n")
      Mail::DKIM.verify(signed, resolver: query, now: now)
      expect(seen).to eq(['mail._domainkey.example.com'])
    end
  end

  describe 'offline fixed-key vectors' do
    # These vectors pin which changes MUST break a signature and which
    # MUST NOT.  They use the committed keypair in spec/fixtures/dkim.

    describe 'trailing empty body lines' do
      let(:signed) do
        sign("From: alice@example.com\r\nSubject: T\r\n\r\nreal body\r\n\r\n")
      end

      it 'still verifies when extra CRLFs are appended after receipt' do
        received = "#{signed}\r\n\r\n\r\n"
        expect_pass(received)
      end

      it 'still verifies after appending CRLFs with simple/simple too' do
        base = sign("From: alice@example.com\r\n\r\nreal body\r\n",
                    canonicalization: 'simple/simple')
        expect_pass("#{base}\r\n\r\n")
      end

      it 'fails when the real body text is altered' do
        expect_fail(signed.sub('real', 'fake'), :body_hash_mismatch)
      end
    end

    describe 'repeated Subject headers' do
      # Both instances are signed; the verifier picks bottom up.
      let(:message) do
        "Subject: first\r\nSubject: second\r\nFrom: alice@example.com\r\n\r\nb\r\n"
      end
      let(:signed) { sign(message, headers: %w[from subject subject]) }

      it 'verifies the untouched message' do
        expect_pass(signed)
      end

      it 'fails when the bottom Subject (used first, bottom up) changes' do
        expect_fail(signed.sub('Subject: second', 'Subject: changed'),
                    :signature_mismatch)
      end

      it 'fails when the top Subject changes' do
        expect_fail(signed.sub('Subject: first', 'Subject: changed'),
                    :signature_mismatch)
      end

      it 'still verifies when an extra Subject is prepended (selection is bottom up)' do
        expect_pass("Subject: injected\r\n#{signed}")
      end

      it 'fails when an extra Subject is appended (shifts bottom up selection)' do
        expect_fail(signed.sub("From: alice", "Subject: injected\r\nFrom: alice"),
                    :signature_mismatch)
      end
    end

    describe 'body length l=' do
      # Canonical body is "hello\r\n" (7 bytes), so l=7 signs the whole
      # canonicalized body.
      let(:signed) do
        sign("From: alice@example.com\r\n\r\nhello\r\n", length: 7)
      end

      it 'verifies the untouched message' do
        results = expect_pass(signed)
        expect(results.first.body_length).to eq(7)
      end

      it 'allows extra body text appended after the signed count' do
        appended = "#{signed}appended by list\r\n"
        results = expect_pass(appended)
        expect(results.first.warnings).to include(a_string_matching(/l=/))
      end

      it 'does not warn when only empty lines are appended after the count' do
        results = expect_pass("#{signed}\r\n\r\n")
        expect(results.first.warnings).to be_empty
      end

      it 'fails if a byte inside the signed prefix changes' do
        expect_fail(signed.sub('hello', 'hallo'), :body_hash_mismatch)
      end

      it 'fails if the received body is shorter than l=' do
        expect_fail(signed.sub("hello\r\n", "hel\r\n"), :body_length_too_short)
      end
    end

    describe 'changes that MUST break the signature' do
      let(:signed) do
        sign("From: alice@example.com\r\nSubject: Orig\r\n\r\nbody\r\n")
      end

      it 'fails when a signed header value changes' do
        expect_fail(signed.sub('Orig', 'Tampered'), :signature_mismatch)
      end

      it 'fails when the body changes' do
        expect_fail(signed.sub('body', 'b0dy'), :body_hash_mismatch)
      end

      it 'fails when a byte of the b= signature is flipped' do
        tampered = signed.sub(/b=([A-Za-z0-9+\/])/m) do
          ch = Regexp.last_match(1)
          "b=#{ch == 'A' ? 'B' : 'A'}"
        end
        expect_fail(tampered, :signature_mismatch)
      end

      it 'fails when a signed header line is removed' do
        expect_fail(signed.sub("Subject: Orig\r\n", ''), :signature_mismatch)
      end
    end

    describe 'header folding tolerance (relaxed)' do
      let(:signed) do
        sign("From: alice@example.com\r\nX-Notes: a   b\r\n\r\nb\r\n",
             headers: %w[from x-notes])
      end

      it 'verifies when WSP inside a signed relaxed header is refolded' do
        refolded = signed.sub("X-Notes: a   b\r\n",
                              "X-Notes:\r\n a b\r\n")
        expect_pass(refolded)
      end
    end
  end

  describe 'multiple signatures are independent' do
    let(:key_two) { OpenSSL::PKey::RSA.new(2048) }
    let(:pub_two) { [key_two.public_key.to_der].pack('m0') }
    let(:two_resolver) do
      resolver.merge('mail._domainkey.other.org' => "v=DKIM1; p=#{pub_two}")
    end

    let(:message) { "From: alice@example.com\r\nSubject: multi\r\n\r\nhi\r\n" }

    def sign_twice
      first = sign(message, domain: 'example.com',
                            headers: %w[from subject])
      Mail::DKIM.sign(first, domain: 'other.org', selector: 'mail',
                             private_key: key_two, time: now - 5,
                             headers: %w[from subject dkim-signature])
    end

    it 'returns a result per signature' do
      results = Mail::DKIM.verify(sign_twice, resolver: two_resolver, now: now)
      expect(results.size).to eq(2)
      expect(results.map(&:domain)).to contain_exactly('example.com', 'other.org')
      expect(results).to all(be_pass)
      expect(results).to be_pass
    end

    it 'keeps the valid signature result when the other one fails' do
      both = sign_twice
      # Corrupt the outer (topmost) signature's b value only: flip the
      # first base64 character after the first b= tag.
      tampered = both.dup
      idx = tampered.index('b=') + 2
      tampered.setbyte(idx, tampered.getbyte(idx) == 'A'.ord ? 'B'.ord : 'A'.ord)

      results = Mail::DKIM.verify(tampered, resolver: two_resolver, now: now)
      expect(results.size).to eq(2)
      by_domain = results.to_h { |r| [r.domain, r.status] }
      expect(by_domain['other.org']).to eq(:fail)
      expect(by_domain['example.com']).to eq(:pass)
    end

    it 'reports the second signature independently when its key is missing' do
      both = sign_twice
      results = Mail::DKIM.verify(both, resolver: resolver, now: now)
      by_domain = results.to_h { |r| [r.domain, r.status] }
      expect(by_domain['example.com']).to eq(:pass)
      expect(by_domain['other.org']).to eq(:fail)
      expect(results.find { |r| r.domain == 'other.org' }.reason).to eq(:key_unknown)
    end
  end

  describe 'failure reasons' do
    let(:message) { "From: alice@example.com\r\nSubject: x\r\n\r\nb\r\n" }

    def with_signature(tag_text)
      "DKIM-Signature: #{tag_text}\r\n#{message}"
    end

    let(:valid_tags) do
      'v=DKIM1; a=rsa-sha256; d=example.com; s=mail; h=from; ' \
        'bh=AAAA; b=AAAA'
    end

    it 'reports no signatures when none are present' do
      results = Mail::DKIM.verify(message, resolver: resolver, now: now)
      expect(results.size).to eq(0)
      expect(results).not_to be_pass
    end

    it 'fails with signature_syntax_error on duplicate tags' do
      expect_fail(with_signature(valid_tags.sub('h=from', 'h=from; h=to')),
                  :signature_syntax_error)
    end

    it 'fails with incompatible_version for v=DKIM2' do
      expect_fail(with_signature(valid_tags.sub('DKIM1', 'DKIM2')),
                  :incompatible_version)
    end

    it 'fails with unsupported_algorithm for rsa-sha1' do
      expect_fail(with_signature(valid_tags.sub('rsa-sha256', 'rsa-sha1')),
                  :unsupported_algorithm)
    end

    it 'fails with unsupported_canonicalization for an unknown c= value' do
      tags = valid_tags.sub('h=from', 'c=nope/nope; h=from')
      expect_fail(with_signature(tags), :unsupported_canonicalization)
    end

    it 'fails when the mandatory tags are missing' do
      expect_fail(with_signature(valid_tags.sub('; h=from', '')),
                  :signature_missing_tag)
    end

    it 'fails when From is not covered by h=' do
      expect_fail(with_signature(valid_tags.sub('h=from', 'h=subject')),
                  :from_not_signed)
    end

    it 'fails with key_unknown on NXDOMAIN' do
      signed = sign(message)
      results = Mail::DKIM.verify(signed, resolver: {}, now: now)
      expect(results.first.reason).to eq(:key_unknown)
    end

    it 'fails with key_revoked on an empty p=' do
      signed = sign(message)
      expect_fail(signed, :key_revoked,
                  'mail._domainkey.example.com' => 'v=DKIM1; p=')
    end

    it 'fails with incompatible_key_type for an ed25519 key' do
      expect_fail(with_signature(valid_tags), :incompatible_key_type,
                  'mail._domainkey.example.com' => 'v=DKIM1; k=ed25519; p=AAAA')
    end

    it 'fails with public_key_invalid when p= is not valid base64/key' do
      expect_fail(with_signature(valid_tags), :public_key_invalid,
                  'mail._domainkey.example.com' => 'v=DKIM1; p=@@@@')
    end

    it 'fails with signature_expired after x=' do
      signed = sign(message, time: now - 100, expiration: now - 1)
      expect_fail(signed, :signature_expired)
    end

    it 'surfaces resolver exceptions as key_dns_error' do
      crashing = ->(_name) { raise 'network unreachable' }
      signed = sign(message)
      results = Mail::DKIM.verify(signed, resolver: crashing, now: now)
      expect(results.first.reason).to eq(:key_dns_error)
      expect(results.first.error.message).to match(/network unreachable/)
    end
  end
end
