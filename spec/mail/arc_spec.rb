# frozen_string_literal: true
require 'spec_helper'

RSpec.describe 'Authenticated Received Chain' do
  let(:hop1_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:hop2_key) { OpenSSL::PKey::RSA.new(2048) }

  let(:keys) do
    {
      ['hop1.example', 'arc'] => hop1_key,
      ['hop2.example', 'arc'] => hop2_key
    }
  end

  let(:key_finder) do
    lambda do |domain, selector|
      keys.fetch([domain, selector])
    end
  end

  def original_message
    Mail.new(
      "From: alice@origin.example\r\n" \
      "To: list@forwarder.example\r\n" \
      "Subject: ARC test\r\n" \
      "Message-ID: <original@origin.example>\r\n" \
      "Date: Mon, 06 Oct 2026 00:00:00 +0800\r\n" \
      "MIME-Version: 1.0\r\n" \
      "Content-Type: text/plain; charset=UTF-8\r\n" \
      "Content-Transfer-Encoding: 7bit\r\n" \
      "\r\n" \
      "Original body\r\n"
    )
  end

  def seal_first_hop(message)
    message.append_arc(
      authentication_results: 'hop1.example; spf=pass smtp.mailfrom=alice@origin.example',
      domain: 'hop1.example',
      selector: 'arc',
      key_finder: key_finder
    )
    message
  end

  def seal_second_hop(message, &change)
    message.append_arc(
      authentication_results: 'hop2.example; dkim=pass header.d=origin.example',
      domain: 'hop2.example',
      selector: 'arc',
      key_finder: key_finder,
      &change
    )
    message
  end

  def arc_fields(message, name, instance)
    message.header.fields.select do |field|
      field.responsible_for?(name) && field.value =~ /(?:^|;)\s*i=#{instance}(?:;|\s|$)/
    end
  end

  it 'appends and verifies the first ARC hop' do
    message = seal_first_hop(original_message)
    result = message.verify_arc(key_finder)

    expect(result).to be_valid
    expect(result.instances.map(&:i)).to eq([1])
    expect(result.instances.first.status).to eq(:pass)
    expect(result.instances.first.aar_status).to eq(:valid)
    expect(result.instances.first.ams_status).to eq(:valid)
    expect(result.instances.first.as_status).to eq(:valid)
    expect(message.header.fields.map(&:name).grep(/^ARC-/)).to eq([
      'ARC-Seal',
      'ARC-Message-Signature',
      'ARC-Authentication-Results'
    ])
  end

  it 'keeps a two-hop chain valid after the second hop changes and reseals the body' do
    first_hop = seal_first_hop(original_message)
    second_hop = Mail.new(first_hop.to_s)

    seal_second_hop(second_hop) do |message|
      message.body = "Changed body\r\n"
    end

    result = second_hop.verify_arc(key_finder)

    expect(second_hop.body.to_s).to eq("Changed body\n")
    expect(result).to be_valid
    expect(result.status).to eq(:pass)
    expect(result.instances.map(&:i)).to eq([1, 2])
    expect(result.instances.map(&:status)).to eq([:body_modified, :pass])
    expect(result.instances.map(&:aar_status)).to eq([:valid, :valid])
    expect(result.instances.map(&:ams_status)).to eq([:body_modified, :valid])
    expect(result.instances.map(&:as_status)).to eq([:valid, :valid])
    expect(result.break).to be_nil
  end

  it 'can append the second hop after the local body change has already happened' do
    first_hop = seal_first_hop(original_message)
    second_hop = Mail.new(first_hop.to_s)
    second_hop.body = "Locally changed body\r\n"
    seal_second_hop(second_hop)

    result = second_hop.verify_arc(key_finder)

    expect(result).to be_valid
    expect(result.instances.map(&:ams_status)).to eq([:body_modified, :valid])
    expect(result.instances.map { |instance| instance.seal['cv'] }).to eq(['none', 'pass'])
  end

  it 'locates the first broken seal even when the newest seal itself verifies' do
    first_hop = seal_first_hop(original_message)
    second_hop = Mail.new(first_hop.to_s)
    seal_second_hop(second_hop) { |message| message.body = "Changed body\r\n" }

    tampered = Mail.new(second_hop.to_s)
    first_seal = arc_fields(tampered, 'ARC-Seal', 1).first
    first_seal.value = first_seal.value.sub(/b=([A-Za-z0-9+\/]+)/) { "b=X#{$1}" }

    result = tampered.verify_arc(key_finder)

    expect(result).not_to be_valid
    expect(result.status).to eq(:fail)
    expect(result.break.fetch(:instance)).to eq(1)
    expect(result.break.fetch(:field)).to eq('ARC-Seal')
    expect(result.instances[0].as_status).to eq(:invalid)
    expect(result.instances[1].as_status).to eq(:valid)
    expect(result.instances[1].ams_status).to eq(:invalid)
  end

  it 'resolves verification keys through the supplied callback' do
    message = seal_first_hop(original_message)
    queries = []
    callback = lambda do |domain, selector|
      queries << [domain, selector]
      keys.fetch([domain, selector])
    end

    message.verify_arc(callback)

    expect(queries).to include(['hop1.example', 'arc'])
  end

  it 'accepts a callback that returns a public key or PEM string' do
    message = seal_first_hop(original_message)
    public_key_finder = lambda do |domain, _selector|
      domain == 'hop1.example' ? hop1_key.public_key : nil
    end
    pem_finder = lambda do |domain, _selector|
      domain == 'hop1.example' ? hop1_key.public_key.to_pem : nil
    end

    expect(message.verify_arc(public_key_finder)).to be_valid
    expect(message.verify_arc(pem_finder)).to be_valid
  end

  it 'reports a message without ARC sets as none rather than failure' do
    result = original_message.verify_arc(->(_domain, _selector) { nil })

    expect(result.status).to eq(:none)
    expect(result).not_to be_valid
    expect(result.instances).to be_empty
    expect(result.to_h).to include(status: :none, valid: false, break: nil)
  end

  it 'reports every missing component for an incomplete instance' do
    message = Mail.new(
      "ARC-Authentication-Results: i=1; hop1.example; spf=pass\r\n" \
      "\r\nbody\r\n"
    )

    result = message.verify_arc(->(_domain, _selector) { nil })

    expect(result.status).to eq(:fail)
    expect(result.instances.first.aar_status).to eq(:valid)
    expect(result.instances.first.ams_status).to eq(:missing)
    expect(result.instances.first.as_status).to eq(:missing)
    expect(result.break.fetch(:field)).to eq('ARC-Message-Signature')
  end
end
