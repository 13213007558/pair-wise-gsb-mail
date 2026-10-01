# frozen_string_literal: true

# DomainKeys Identified Mail (DKIM), RFC 6376.
#
# This is a pure-Ruby (OpenSSL-backed) implementation of the RSA-SHA256
# signing and verification mechanisms defined by RFC 6376. No external
# commands are invoked.
#
# == Signing
#
#   mail = Mail.new do
#     from    'jane@example.com'
#     to      'joe@example.org'
#     subject 'Signed mail'
#     body    'Hello'
#   end
#
#   mail.dkim_sign!(
#     domain:    'example.com',
#     selector:  'sel',
#     private_key: File.read('private.pem')
#   )
#   mail.deliver
#
# The DKIM-Signature field is added to the message itself, so the bytes that
# were signed are exactly those produced by Mail::Message#encoded and handed
# to the delivery method (SMTP, sendmail, file, test, ...).
#
# == Verification
#
# Verification always operates on the raw bytes as received:
#
#   results = Mail::DKIM.verify(raw_mail, resolver: ->(name) { txt_record })
#   results.each { |r| puts "#{r.status}: #{r.reason}" }
#
# Each DKIM-Signature field is evaluated independently: a failure on one
# signature never erases the result of another.
module Mail
  class DKIM
    autoload :Canonicalization, 'mail/dkim/canonicalization'
    autoload :DNS, 'mail/dkim/dns'
    autoload :Result, 'mail/dkim/result'
    autoload :Signer, 'mail/dkim/signer'
    autoload :TagList, 'mail/dkim/tag_list'
    autoload :Verifier, 'mail/dkim/verifier'

    # Sign a Mail::Message in place. Accepts the same keyword arguments as
    # Mail::DKIM::Signer.new. Returns the message.
    def self.sign(message, **options)
      Signer.new(**options).sign!(message)
    end

    # Sign raw RFC 5322 message bytes without round-tripping them through the
    # Mail parser, preserving repeated headers exactly as received. Returns
    # the signed binary message.
    def self.sign_bytes(raw, **options)
      Signer.new(**options).sign_bytes(raw)
    end

    # Verify all signatures on a raw message string or Mail::Message.
    def self.verify(message, resolver: nil)
      Verifier.new(resolver: resolver).verify(message)
    end
  end
end
