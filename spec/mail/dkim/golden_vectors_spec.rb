# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require 'yaml'

# Regression tests against frozen, fixed-key golden vectors. The vectors and
# the RSA private key used to generate them are committed in
# spec/fixtures/dkim so no network or randomness is needed.
RSpec.describe 'Mail::DKIM golden vectors' do
  FIXTURE = File.expand_path('../../../fixtures/dkim/golden_vectors.yml', __FILE__)
  VECTORS = YAML.safe_load(File.binread(FIXTURE))

  def resolver
    ->(name) { name == 'sel._domainkey.example.com' ? VECTORS['txt_record'] : nil }
  end

  def verify(raw)
    Mail::DKIM.verify(raw, resolver: resolver)
  end

  it 'fixture file exists and carries the expected vectors' do
    expect(VECTORS.keys).to include(
      'relaxed_relaxed', 'simple_simple', 'length_limited'
    )
  end

  it 'verifies the frozen relaxed/relaxed vector' do
    expect(verify(VECTORS['relaxed_relaxed']).first.status).to eq(:pass)
  end

  it 'verifies the frozen simple/simple vector' do
    expect(verify(VECTORS['simple_simple']).first.status).to eq(:pass)
  end

  describe 'trailing empty lines' do
    it 'does NOT break the signature when blank lines are appended' do
      altered = VECTORS['simple_simple'].sub(/\z/, "\r\n\r\n")
      expect(verify(altered).first.status).to eq(:pass)
    end

    it 'DOES break the signature when body content changes' do
      altered = VECTORS['simple_simple'].sub('trailing', 'TRAILING')
      expect(verify(altered).first.status).to eq(:permerror)
    end
  end

  describe 'content appended beyond l=' do
    let(:limited) { VECTORS['length_limited'] }

    it 'verifies the original limited vector' do
      expect(verify(limited).first.status).to eq(:pass)
    end

    it 'does NOT break when bytes are appended past the signed l=' do
      altered = limited.sub(/\z/, "appended\r\n")
      expect(verify(altered).first.status).to eq(:pass)
    end

    it 'DOES break when the signed portion itself is modified' do
      altered = limited.sub('signed body bytes', 'SIGNED BODY BYTES')
      expect(verify(altered).first.status).to eq(:permerror)
    end
  end

  describe 'header mutation' do
    it 'DOES break when From is rewritten' do
      altered = VECTORS['relaxed_relaxed'].sub('jane@example.com', 'mallory@example.com')
      expect(verify(altered).first.status).to eq(:permerror)
    end

    it 'DOES break when Subject is rewritten' do
      altered = VECTORS['relaxed_relaxed'].sub('Golden vector', 'Golden victim')
      expect(verify(altered).first.status).to eq(:permerror)
    end

    it 'does NOT break when an unsigned header is appended at the top' do
      altered = "X-Untracked: yes\r\n" + VECTORS['relaxed_relaxed']
      expect(verify(altered).first.status).to eq(:pass)
    end
  end
end
