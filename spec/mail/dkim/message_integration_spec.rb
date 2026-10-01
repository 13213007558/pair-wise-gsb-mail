# frozen_string_literal: true
require 'spec_helper'
require 'openssl'
require 'tmpdir'

RSpec.describe 'Mail::Message DKIM integration' do
  let(:private_pem) { File.read(File.expand_path('../../fixtures/dkim/private.pem', __dir__)) }
  let(:spki_b64) { File.read(File.expand_path('../../fixtures/dkim/public_spki.b64', __dir__)).gsub(/\s+/, '') }
  let(:resolver) do
    { 'mail._domainkey.example.com' => "v=DKIM1; p=#{spki_b64}" }
  end
  let(:fixed_time) { Time.at(1_500_000_000) }

  def build_message
    Mail.new do
      from 'alice@example.com'
      to 'bob@example.org'
      subject 'Hello from the mail gem'
      body 'A signed body.'
    end
  end

  it 'signs in process and the signed bytes verify afterwards' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    expect(mail).to be_dkim_signed
    results = mail.dkim_verify(resolver: resolver, now: fixed_time + 10)
    expect(results).to be_pass
  end

  it 'exposes the DKIM-Signature header for inspection' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    field = mail.header['DKIM-Signature']
    expect(field.field).to be_a(Mail::DkimSignatureField)
    expect(field.value).to include('a=rsa-sha256')
    expect(field.value).to include('d=example.com')
  end

  it 'returns the same bytes on repeated calls to #encoded' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    expect(mail.encoded).to eq(mail.encoded)
    expect(mail.encoded).to start_with("DKIM-Signature:")
  end

  it 'transmits exactly the signed bytes through TestMailer delivery' do
    Mail.defaults { delivery_method :test }
    Mail::TestMailer.deliveries.clear
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    signed_bytes = mail.encoded
    mail.deliver!
    delivered = Mail::TestMailer.deliveries.last
    expect(delivered).to be_a(Mail::Message)
    expect(delivered.encoded).to eq(signed_bytes)
    expect(delivered.encoded).to include("DKIM-Signature:")
  end

  it 'can be sent through the file delivery method without altering the signature' do
    Dir.mktmpdir do |dir|
      Mail.defaults { delivery_method :file, location: dir }
      mail = build_message
      mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                      private_key: private_pem, time: fixed_time)
      signed_bytes = mail.encoded
      mail.deliver!
      written = File.read(File.join(dir, 'bob@example.org'))
      expect(written).to start_with(signed_bytes)
      expect(written).to include("DKIM-Signature:")
    end
  end

  it 'signs multipart messages over their fully encoded transfer bytes' do
    mail = Mail.new do
      from    'alice@example.com'
      to      'bob@example.org'
      subject 'Multipart signed'
    end
    mail.text_part { body 'plain text' }
    mail.html_part do
      content_type 'text/html; charset=UTF-8'
      body '<p>html text</p>'
    end
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    results = mail.dkim_verify(resolver: resolver, now: fixed_time + 10)
    expect(results).to be_pass
    expect(mail.encoded).to include('multipart/alternative')
  end

  it 'verifies a received (parsed) message against its untouched raw source' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    raw = mail.encoded
    received = Mail.new(raw)
    results = received.dkim_verify(resolver: resolver, now: fixed_time + 10)
    expect(results).to be_pass
  end

  it 'does not verify a received message whose body was changed after parsing' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    received = Mail.new(mail.encoded.sub('A signed body.', 'Changed body.'))
    results = received.dkim_verify(resolver: resolver, now: fixed_time + 10)
    expect(results.first.reason).to eq(:body_hash_mismatch)
  end

  it 'raises when the From header is not in the signed header list' do
    mail = build_message
    expect do
      mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                      private_key: private_pem, time: fixed_time,
                      headers: %w[subject to])
    end.to raise_error(ArgumentError, /From/)
  end

  it 'allows re-signing after the message changes (memo is rebuilt)' do
    mail = build_message
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    expect(mail).to be_dkim_signed
    mail.subject = 'Changed subject'
    # The old signature no longer covers the rebuilt message; signing
    # again produces a fresh valid signature.
    mail.dkim_sign!(domain: 'example.com', selector: 'mail',
                    private_key: private_pem, time: fixed_time)
    results = mail.dkim_verify(resolver: resolver, now: fixed_time + 10)
    expect(results).to be_pass
  end

  it 'does not sign until dkim_sign! is called' do
    mail = build_message
    expect(mail).not_to be_dkim_signed
    expect(mail.encoded).not_to include('DKIM-Signature')
  end
end
