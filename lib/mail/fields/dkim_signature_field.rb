# encoding: utf-8
# frozen_string_literal: true

module Mail
  # RFC 6376 DKIM-Signature header field.
  #
  # Unlike a generic unstructured field this field never rewraps or
  # encoded-word encodes its value: the b= signature tag is raw base64
  # and its folding is part of the signed data, so the bytes must be
  # preserved exactly once a message has been signed.
  class DkimSignatureField < CommonField
    NAME = 'DKIM-Signature'

    def self.singular?
      true
    end

    def initialize(value = nil, charset = nil)
      super(self.class::NAME, value, charset)
    end

    def parse
      self
    end

    private

    def do_encode
      if value && !value.empty?
        separator = value.start_with?(' ') ? '' : ' '
        "#{NAME}:#{separator}#{value}\r\n"
      else
        ''
      end
    end

    def do_decode
      value
    end
  end
end
