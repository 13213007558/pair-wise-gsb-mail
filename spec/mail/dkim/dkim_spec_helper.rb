# frozen_string_literal: true

require 'openssl'
require 'base64'

module DKIMSpecHelpers
  KEY_PATH = File.expand_path('../../../fixtures/dkim/test_rsa2048.pem', __FILE__)

  def private_pem
    @private_pem ||= File.binread(KEY_PATH)
  end

  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.new(private_pem)
  end

  # The DNS TXT record publishing the public key matching the fixed fixture
  # key. Injected into verifiers so verification never touches the network.
  def dns_txt(key = rsa_key)
    "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(key.public_to_der)}"
  end

  def dns_resolver(records = { 'example.com' => { 'sel' => dns_txt } })
    lambda do |name|
      records.each do |domain, selectors|
        selectors.each do |selector, record|
          return record if name == "#{selector}._domainkey.#{domain}"
        end
      end
      nil
    end
  end

  # Sign +mail+ with the fixed key and return the encoded raw bytes.
  def dkim_signed(mail_or_body = nil, **opts)
    mail =
      case mail_or_body
      when Mail::Message then mail_or_body
      when String then Mail.new { from 'jane@example.com'; to 'joe@example.org'; subject 'Hi'; body mail_or_body }
      else Mail.new { from 'jane@example.com'; to 'joe@example.org'; subject 'Hi'; body 'Hello' }
      end
    defaults = {
      domain: 'example.com', selector: 'sel', private_key: private_pem,
      time: 1_700_000_000
    }
    mail.dkim_sign!(**defaults.merge(opts))
    mail.encoded
  end

  def verify(raw, resolver: nil)
    Mail::DKIM.verify(raw, resolver: resolver || dns_resolver)
  end
end
