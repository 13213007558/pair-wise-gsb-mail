# frozen_string_literal: true

module Mail
  module DKIM
    # Outcome of verifying a single DKIM-Signature header field.
    class Result
      STATUSES = [:none, :pass, :fail].freeze

      attr_accessor :identity, :domain, :selector, :algorithm,
                    :header_canonicalization, :body_canonicalization,
                    :signed_headers, :body_length, :reason, :error,
                    :key_record, :timestamp, :expiration, :warnings

      def initialize
        @warnings = []
        @reason = nil
        @error = nil
      end

      def status
        @status || :none
      end

      def pass!
        @status = :pass
      end

      def fail!(reason, error = nil)
        @status = :fail
        @reason = reason
        @error = error
      end

      def pass?
        status == :pass
      end

      def fail?
        status == :fail
      end

      def verified?
        pass?
      end

      def to_s
        case status
        when :pass
          "pass (d=#{domain} s=#{selector})"
        when :fail
          "fail (d=#{domain} s=#{selector}: #{reason}#{error ? " (#{error.message})" : ''})"
        else
          "none"
        end
      end

      def inspect
        "#<#{self.class} #{self}>"
      end
    end

    # Verification outcome for a whole message: one Result per
    # DKIM-Signature found.  Each signature is evaluated independently;
    # a failing signature never removes the results of the others.
    class VerificationResult < Array
      def pass?
        any?(&:pass?)
      end

      def verified?
        pass?
      end

      def failed
        select(&:fail?)
      end

      def valid_signatures
        select(&:pass?)
      end

      def identities
        map(&:identity)
      end
    end
  end
end
