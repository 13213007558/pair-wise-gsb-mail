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

    # When true, non US-ASCII unstructured header fields are encoded using a
    # byte-minimal mix of Q and B encoded-words (see
    # Mail::CompactHeaderEncoder). Defaults to false to preserve the
    # historical all-Q behavior.
    def compact_header_encoding(value = nil)
      if value.nil?
        defined?(@compact_header_encoding) ? @compact_header_encoding : false
      else
        @compact_header_encoding = value
      end
    end

    # Maximum physical line length (in characters/bytes) when folding header
    # fields. 78 per RFC 2822 section 2.1.1.
    def header_line_length(value = nil)
      if value.nil?
        defined?(@header_line_length) ? @header_line_length : 78
      else
        @header_line_length = Integer(value)
      end
    end

  end

end
