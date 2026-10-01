# encoding: utf-8
# frozen_string_literal: true

module Mail
  #
  # resent-date     =       "Resent-Date:" date-time CRLF
  class ResentDateField < CommonDateField #:nodoc:
    NAME = 'Resent-Date'

    # RFC 5322 3.6.6: a resent-date field is unique within a single resent
    # block, but a message may carry one resent-date per resending event.
    def self.singular?
      false
    end
  end
end
