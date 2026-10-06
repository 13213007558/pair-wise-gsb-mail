# frozen_string_literal: true

require 'mail/arc/chain'

module Mail
  module ARC
    def self.verify(message, key_fetcher = nil)
      Chain.verify(message, key_fetcher)
    end

    def self.seal(message, authentication_results:, domain:, selector:, key_fetcher: nil, private_key: nil, cv: nil)
      Chain.seal(
        message,
        authentication_results: authentication_results,
        domain: domain,
        selector: selector,
        key_fetcher: key_fetcher,
        private_key: private_key,
        cv: cv
      )
    end

    class << self
      alias_method :append_hop, :seal
    end
  end

  class Message
    def arc_verify(key_fetcher = nil)
      Mail::ARC.verify(self, key_fetcher)
    end

    def arc_seal(authentication_results:, domain:, selector:, key_fetcher: nil, private_key: nil, cv: nil)
      Mail::ARC.seal(
        self,
        authentication_results: authentication_results,
        domain: domain,
        selector: selector,
        key_fetcher: key_fetcher,
        private_key: private_key,
        cv: cv
      )
    end

    alias_method :arc_append_hop, :arc_seal
  end
end
