# frozen_string_literal: true

module Mail
  module ARC
    class HopResult
      attr_reader :instance, :domain, :selector, :authentication_results, :claimed_status
      attr_reader :seal_status, :seal_error, :message_signature_status, :message_signature_error
      attr_reader :header_status, :body_status, :authentication_results_status, :status, :error

      def initialize(instance, fields, status:, authentication_results: nil, domain: nil, selector: nil,
                     claimed_status: nil, seal_status: nil, seal_error: nil,
                     message_signature_status: nil, message_signature_error: nil,
                     header_status: nil, body_status: nil,
                     authentication_results_status: :present, error: nil)
        @instance = instance
        @fields = fields
        @status = status
        @authentication_results = authentication_results
        @domain = domain
        @selector = selector
        @claimed_status = claimed_status
        @seal_status = seal_status
        @seal_error = seal_error
        @message_signature_status = message_signature_status
        @message_signature_error = message_signature_error
        @header_status = header_status
        @body_status = body_status
        @authentication_results_status = authentication_results_status
        @error = error
      end

      def pass?
        status == :pass
      end

      def fail?
        status == :fail
      end

      def active?
        @fields == :latest
      end

      def chain_break?
        seal_status == :fail || (active? && fail?)
      end

      def to_h
        {
          instance: instance,
          status: status,
          active: active?,
          domain: domain,
          selector: selector,
          claimed_status: claimed_status,
          authentication_results: authentication_results,
          authentication_results_status: authentication_results_status,
          seal: { status: seal_status, error: seal_error },
          message_signature: {
            status: message_signature_status,
            header_status: header_status,
            body_status: body_status,
            error: message_signature_error
          },
          error: error
        }
      end
    end

    class VerificationResult
      include Enumerable

      attr_reader :instances, :status, :failure_instance, :error

      def initialize(instances, status:, failure_instance: nil, error: nil)
        @instances = instances
        @status = status
        @failure_instance = failure_instance
        @error = error
      end

      def pass?
        status == :pass
      end

      def valid?
        pass?
      end

      def fail?
        status == :fail
      end

      def none?
        status == :none
      end

      def each(&block)
        instances.each(&block)
      end

      def [](instance)
        instances.detect { |hop| hop.instance == instance }
      end

      def chain
        instances.map(&:to_h)
      end

      def to_h
        {
          status: status,
          valid: pass?,
          failure_instance: failure_instance,
          error: error,
          instances: chain
        }
      end
    end
  end
end
