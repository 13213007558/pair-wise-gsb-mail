# encoding: utf-8
# frozen_string_literal: true

module Mail
  # RFC 6376 DKIM-Signature header field.
  #
  # The tag list is emitted verbatim on one unfolded line. DKIM verification
  # unfolds the field before canonicalization (RFC 6376 3.7), and an unfolded
  # value is unambiguous for both the simple and relaxed header algorithms so
  # that the bytes signed are exactly the bytes that get delivered.
  class DkimSignatureField < OptionalField #:nodoc:
    NAME = 'DKIM-Signature'

    def self.parse(value, charset = 'utf-8')
      new(NAME, value, charset).parse
    end

    private

      def do_encode
        if value && !value.empty?
          "#{NAME}: #{value}\r\n"
        else
          "#{NAME}: \r\n"
        end
      end
  end
end
