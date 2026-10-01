# frozen_string_literal: true

require 'mail/dkim/canonicalization'
require 'mail/dkim/tag_list'
require 'mail/dkim/key_record'
require 'mail/dkim/result'
require 'mail/dkim/signer'
require 'mail/dkim/resolver'
require 'mail/dkim/verifier'

module Mail
  # DomainKeys Identified Mail (RFC 6376).
  #
  # This module provides in-process RSA-SHA256 signing and verification
  # of messages.  Keys and DNS TXT answers are injected by the caller
  # rather than fetched from disk or network implicitly:
  #
  #   private_key = File.read('dkim.pem')
  #   signed = Mail::DKIM.sign(message.encoded,
  #                            domain: 'example.com',
  #                            selector: 'sel',
  #                            private_key: private_key)
  #
  #   results = Mail::DKIM.verify(signed, resolver: {
  #     'sel._domainkey.example.com' => "v=DKIM1; p=MIGfMA0..."
  #   })
  #   results.pass? # => true
  module DKIM
    module_function

    # Sign +message+ (raw String or Mail::Message) with RSA-SHA256.
    # Returns the signed message bytes.
    def sign(message, domain:, selector:, private_key:, **options)
      Signer.new(domain: domain, selector: selector,
                 private_key: private_key, **options).sign(message)
    end

    # Verify every DKIM-Signature on +message+ against the raw received
    # bytes.  Returns a VerificationResult (one independent Result per
    # signature).
    def verify(message, resolver:, **options)
      Verifier.new(resolver: resolver, **options).verify(message)
    end
  end
end
