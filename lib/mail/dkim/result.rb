# frozen_string_literal: true

module Mail
  class DKIM
    # Outcome of verifying a single DKIM-Signature header field.
    #
    # Each signature is evaluated independently; a failure on one signature
    # never removes or mutates the result recorded for another signature on
    # the same message.
    class Result
      STATUSES = [:none, :pass, :fail, :neutral, :permerror, :temperror].freeze

      attr_accessor :status, :reason, :domain, :selector, :identity,
                    :header_algorithm, :body_algorithm, :tags, :raw_field,
                    :body_length

      def initialize(status: :none, reason: nil, domain: nil, selector: nil,
                     identity: nil, header_algorithm: nil, body_algorithm: nil,
                     tags: nil, raw_field: nil, body_length: nil)
        @status = status
        @reason = reason
        @domain = domain
        @selector = selector
        @identity = identity
        @header_algorithm = header_algorithm
        @body_algorithm = body_algorithm
        @tags = tags
        @raw_field = raw_field
        @body_length = body_length
      end

      def pass?
        status == :pass
      end

      def fail?
        status == :fail
      end

      # Permanent protocol/key problem (RFC 6376 2.5.5).
      def permerror?
        status == :permerror
      end

      # Transient DNS/resource problem (RFC 6376 2.5.6).
      def temperror?
        status == :temperror
      end

      # Signature could not be evaluated (e.g. unsupported algorithm).
      def neutral?
        status == :neutral
      end

      def to_s
        detail = [status, reason].compact.join(': ')
        d = domain ? " d=#{domain}" : ''
        s = selector ? " s=#{selector}" : ''
        "#{detail}#{d}#{s}"
      end
    end
  end
end
