# encoding: utf-8
# frozen_string_literal: true
#
# Thanks to Nicolas Fouché for this wrapper
#
require 'singleton'

module Mail

  # The Configuration class is a Singleton used to hold the default
  # configuration for all Mail objects.
  #
  # Each new mail object gets a copy of these values at initialization
  # which can be overwritten on a per mail object basis.
  class Configuration
    include Singleton

    def initialize
      @delivery_method  = nil
      @retriever_method = nil
      super
    end

    # When true (the default), unstructured header fields containing
    # non-US-ASCII content use the historical single-Q-encoded-word folding
    # algorithm. When false, a compact encoder chooses for each encoded word
    # the cheaper of quoted-printable (Q) and Base64 (B), jointly minimizing
    # the wire byte count (field-name prefix, encoded-word wrappers, folding
    # whitespace and CRLFs) while keeping every encoded word at <= 75
    # characters and every physical line within
    # +unstructured_header_line_length+.
    def compact_header_encoding(value = nil)
      if value.nil?
        defined?(@compact_header_encoding) ? @compact_header_encoding : false
      else
        @compact_header_encoding = value
      end
    end

    # Maximum physical line length emitted for unstructured headers.
    def unstructured_header_line_length(value = nil)
      if value.nil?
        defined?(@unstructured_header_line_length) ?
          @unstructured_header_line_length : 78
      else
        @unstructured_header_line_length = value
      end
    end

    def delivery_method(method = nil, settings = {})
      return @delivery_method if @delivery_method && method.nil?
      @delivery_method = lookup_delivery_method(method).new(settings)
    end

    def lookup_delivery_method(method)
      case method.is_a?(String) ? method.to_sym : method
      when nil
        Mail::SMTP
      when :smtp
        Mail::SMTP
      when :sendmail
        Mail::Sendmail
      when :exim
        Mail::Exim
      when :file
        Mail::FileDelivery
      when :smtp_connection
        Mail::SMTPConnection
      when :test
        Mail::TestMailer
      when :logger
        Mail::LoggerDelivery
      else
        method
      end
    end

    def retriever_method(method = nil, settings = {})
      return @retriever_method if @retriever_method && method.nil?
      @retriever_method = lookup_retriever_method(method).new(settings)
    end

    def lookup_retriever_method(method)
      case method
      when nil
        Mail::POP3
      when :pop3
        Mail::POP3
      when :imap
        Mail::IMAP
      when :test
        Mail::TestRetriever
      else
        method
      end
    end

    def param_encode_language(value = nil)
      value ? @encode_language = value : @encode_language ||= 'en'
    end

  end

end
