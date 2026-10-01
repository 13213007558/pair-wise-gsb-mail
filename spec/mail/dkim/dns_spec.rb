# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require_relative 'dkim_spec_helper'

RSpec.describe Mail::DKIM::DNS do
  include DKIMSpecHelpers

  describe '.record_name' do
    it 'builds selector._domainkey.domain' do
      expect(described_class.record_name('sel', 'example.com'))
        .to eq('sel._domainkey.example.com')
    end
  end

  describe '.fetch' do
    it 'calls a callable resolver with the record name' do
      seen = nil
      resolver = ->(name) { seen = name; 'v=DKIM1' }
      described_class.fetch('sel', 'example.com', resolver)
      expect(seen).to eq('sel._domainkey.example.com')
    end

    it 'calls #txt on an object resolver' do
      resolver = Object.new
      resolver.define_singleton_method(:txt) { |_| 'v=DKIM1' }
      expect(described_class.fetch('s', 'd', resolver)).to eq('v=DKIM1')
    end

    it 'rejects an object that is neither callable nor responds to #txt' do
      expect { described_class.fetch('s', 'd', Object.new) }
        .to raise_error(ArgumentError)
    end

    it 'concatenates array TXT character-strings without separators' do
      resolver = ->(_) { ['abc', 'def'] }
      expect(described_class.fetch('s', 'd', resolver)).to eq('abcdef'.b)
    end

    it 'passes nil through' do
      expect(described_class.fetch('s', 'd', ->(_) { nil })).to be_nil
    end
  end

  describe '.public_key' do
    it 'decodes the SubjectPublicKeyInfo p= value' do
      record = Base64.strict_encode64(rsa_key.public_to_der)
      key = described_class.public_key(record)
      expect(key).to be_a(OpenSSL::PKey::RSA)
      expect(key.n).to eq(rsa_key.n)
    end

    it 'decodes a PKCS#1 RSAPublicKey p= value as well' do
      record = Base64.strict_encode64(rsa_key.public_key.to_der)
      expect(described_class.public_key(record).n).to eq(rsa_key.n)
    end

    it 'raises on garbage' do
      expect { described_class.public_key('!!!notbase64') }.to raise_error(StandardError)
    end
  end
end

RSpec.describe Mail::DKIM::TagList do
  T = described_class

  it 'parses tag=value pairs' do
    expect(T.parse('v=1; a=rsa-sha256')).to eq(
      'v' => '1', 'a' => 'rsa-sha256'
    )
  end

  it 'trims whitespace around names and values' do
    expect(T.parse(" v = 1 ;\r\n\ta = x ")).to eq('v' => '1', 'a' => 'x')
  end

  it 'downcases names but preserves values' do
    expect(T.parse('D=Example.COM')).to eq('d' => 'Example.COM')
  end

  it 'keeps an empty value' do
    expect(T.parse('b=')).to eq('b' => '')
  end

  it 'raises on duplicate tags by default' do
    expect { T.parse('a=1; a=2') }.to raise_error(T::DuplicateTag)
  end

  it 'can keep the first duplicate occurrence' do
    expect(T.parse('a=1; a=2', on_duplicate: :keep_first)['a']).to eq('1')
  end

  it 'encodes pairs canonically' do
    expect(T.encode([['v', '1'], ['a', 'x']])).to eq('v=1; a=x')
  end
end
