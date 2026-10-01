# encoding: utf-8
# frozen_string_literal: true

module Mail
  #
  # resent-msg-id   =       "Resent-Message-ID:" msg-id CRLF
  class ResentMessageIdField < CommonMessageIdField #:nodoc:
    NAME = 'Resent-Message-ID'

    # RFC 5322 3.6.6: one Resent-Message-ID per resent block; multiple
    # blocks may be present, so the field is not singular across a header.
    def self.singular?
      false
    end
  end
end
