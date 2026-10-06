# frozen_string_literal: true
require 'base64'
require 'openssl'

module Mail
  module ARC
    ALGORITHM = 'rsa-sha256'
    DIGEST = 'sha256'
    FIELD_NAMES = [
      'ARC-Authentication-Results',
      'ARC-Message-Signature',
      'ARC-Seal'
    ].freeze

    autoload :Chain, 'mail/arc/chain'
    autoload :Canonicalization, 'mail/arc/canonicalization'
    autoload :InstanceResult, 'mail/arc/instance_result'
    autoload :Result, 'mail/arc/result'
    autoload :Sealer, 'mail/arc/sealer'
    autoload :Tags, 'mail/arc/tags'
    autoload :Verifier, 'mail/arc/verifier'

    def self.append(message, options = {}, &block)
      Sealer.new(message, options).append(&block)
    end

    def self.verify(message, key_finder, allow_modified_body: false)
      Verifier.new(message, key_finder, allow_modified_body: allow_modified_body).verify
    end
  end

  class Message
    def verify_arc(key_finder = nil, &block)
      key_finder ||= block
      Mail::ARC.verify(self, key_finder)
    end
    alias_method :arc_verify, :verify_arc

    def append_arc(options = {}, &block)
      Mail::ARC.append(self, options, &block)
    end
    alias_method :arc_seal, :append_arc
    alias_method :arc_forward, :append_arc
  end
end
