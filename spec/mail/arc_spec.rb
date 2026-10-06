# frozen_string_literal: true

require 'openssl'

RSpec.describe Mail::ARC do
  let(:first_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:second_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:keys) do
    {
      'first.example' => first_key,
      'second.example' => second_key
    }
  end
  let(:key_queries) { [] }
  let(:key_fetcher) do
    lambda do |domain, selector, context|
      key_queries << [domain, selector, context]
      key = keys.fetch(domain)
      context[:signing] ? key : key.public_key
    end
  end

  def mail_with_two_hops
    mail = Mail.new do
      from 'alice@origin.example'
      to 'bob@destination.example'
      subject 'ARC forwarding'
      body 'original body'
    end

    mail.arc_seal(
      authentication_results: 'spf=pass smtp.mailfrom=origin.example',
      domain: 'first.example',
      selector: 'selector-one',
      key_fetcher: key_fetcher
    )
    mail.body = 'forwarded body'
    mail.arc_seal(
      authentication_results: 'dkim=pass header.i=@origin.example',
      domain: 'second.example',
      selector: 'selector-two',
      key_fetcher: key_fetcher
    )
    Mail.new(mail.to_s)
  end

  it 'reports no ARC chain when no ARC headers are present' do
    mail = Mail.new { body 'plain' }

    result = mail.arc_verify(key_fetcher)

    expect(result.status).to eq(:none)
    expect(result).to be_none
    expect(result.instances).to be_empty
  end

  it 'validates a single hop and exposes its instance-level state' do
    mail = Mail.new { body 'original body' }
    mail.arc_seal(
      authentication_results: 'spf=pass',
      domain: 'first.example',
      selector: 'selector-one',
      key_fetcher: key_fetcher
    )
    verified = Mail.new(mail.to_s).arc_verify(key_fetcher)
    hop = verified[1]

    expect(verified).to be_pass
    expect(verified.failure_instance).to be_nil
    expect(hop).to be_pass
    expect(hop).to be_active
    expect(hop.claimed_status).to eq('none')
    expect(hop.seal_status).to eq(:pass)
    expect(hop.header_status).to eq(:pass)
    expect(hop.body_status).to eq(:pass)
    expect(hop.authentication_results).to eq('spf=pass')
  end

  it 'allows a correctly resealed second hop that changes the body' do
    mail = mail_with_two_hops

    result = mail.arc_verify(key_fetcher)

    expect(result).to be_pass
    expect(result.failure_instance).to be_nil
    expect(result.instances.map(&:instance)).to eq([1, 2])
    expect(result[1]).to be_pass
    expect(result[1]).not_to be_active
    expect(result[1].seal_status).to eq(:pass)
    expect(result[1].header_status).to eq(:superseded)
    expect(result[1].body_status).to eq(:superseded)
    expect(result[2]).to be_pass
    expect(result[2]).to be_active
    expect(result[2].claimed_status).to eq('pass')
    expect(result[2].seal_status).to eq(:pass)
    expect(result[2].header_status).to eq(:pass)
    expect(result[2].body_status).to eq(:pass)
  end

  it 'locates the first broken seal even when the final instance also fails' do
    mail = mail_with_two_hops
    first_seal = mail.header.fields.find do |field|
      field.name == 'ARC-Seal' && field.value.include?('i=1')
    end
    first_seal.value = first_seal.value.sub(/(?<=b=)[A-Za-z0-9+\/=]{4}/) do |value|
      value.sub(/[A-Za-z]/) { |character| character == 'A' ? 'B' : 'A' }
    end

    result = mail.arc_verify(key_fetcher)

    expect(result).to be_fail
    expect(result.failure_instance).to eq(1)
    expect(result[1].seal_status).to eq(:fail)
    expect(result[1].seal_error).to include('signature verification failed')
    expect(result[2].seal_status).to eq(:fail)
  end

  it 'looks up each verification key through the supplied callback' do
    mail = mail_with_two_hops
    mail.arc_verify(key_fetcher)

    verification_queries = key_queries.reject { |_domain, _selector, context| context[:signing] }
    expect(verification_queries.map { |_domain, selector, _context| selector }).to include(
      'selector-one', 'selector-two'
    )
    expect(verification_queries).to all([
      an_instance_of(String),
      an_instance_of(String),
      include(:i, :instance, :kind, :signing)
    ])
  end

  it 'prepends one ordered ARC block for each forwarding hop' do
    mail = mail_with_two_hops

    arc_headers = mail.header.fields.map(&:name).grep(/\AARC-/)

    expect(arc_headers).to eq([
      'ARC-Seal',
      'ARC-Message-Signature',
      'ARC-Authentication-Results',
      'ARC-Seal',
      'ARC-Message-Signature',
      'ARC-Authentication-Results'
    ])
  end
end
