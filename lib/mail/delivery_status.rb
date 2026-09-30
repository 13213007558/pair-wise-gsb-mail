# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/header'

module Mail
  # Parses the body of a message/delivery-status part (RFC 3464) while
  # preserving its structure: one block of report-level (per-message)
  # fields, followed by one block of fields per recipient.
  #
  # Report-level fields are read directly off the DeliveryStatus:
  #
  #   status['reporting-mta']      #=> "dns; mail.example.com"
  #   status['x-postfix-queue-id'] # unknown extension fields work too
  #
  # Per-recipient fields are read off each recipient record, so values
  # stay paired even when a recipient omits an optional field such as
  # Diagnostic-Code:
  #
  #   status.recipients.each do |recipient|
  #     recipient.final_recipient  #=> "rfc822; someone@example.com"
  #     recipient.status           #=> "5.1.1"
  #     recipient.diagnostic_code  #=> nil when absent for this recipient
  #     recipient.bounced?         #=> true when Action is "failed"
  #     recipient.retryable?       #=> false when Status starts with 5
  #   end
  #
  # Whole-report aggregation rules:
  #
  # * +bounced?+   is true when at least one recipient's Action is "failed".
  # * +retryable?+ is true when at least one recipient did not permanently
  #   fail (Status does not start with 5); it is false only when every
  #   recipient failed permanently.
  class DeliveryStatus
    # One per-recipient block of a delivery status report. Field values
    # are unfolded, and unknown extension fields remain readable through
    # #[]. Optional fields that a recipient omits read as nil.
    class RecipientRecord
      def initialize(block)
        @header = Header.new(block.to_s)
      end

      # Value of any per-recipient field, e.g. record['original-recipient'].
      # Returns nil when this recipient's block omits the field.
      def [](field_name)
        field = @header[field_name]
        field.value if field
      end

      def action
        self['action']
      end

      def final_recipient
        self['final-recipient']
      end

      def status
        self['status']
      end

      def diagnostic_code
        self['diagnostic-code']
      end

      def remote_mta
        self['remote-mta']
      end

      def bounced?
        !!(action =~ /failed/i)
      end

      def retryable?
        !(status =~ /^5/)
      end
    end

    # One RecipientRecord per recipient block, in the order the blocks
    # appear in the report.
    attr_reader :recipients

    def initialize(body)
      blocks = body.to_s.split(/#{Constants::LAX_CRLF}#{Constants::WSP}*#{Constants::LAX_CRLF}/)
      @message_fields = Header.new(blocks.shift.to_s)
      @recipients = blocks.reject { |block| block.strip.empty? }.map { |block| RecipientRecord.new(block) }
    end

    # Value of a report-level (per-message) field, e.g. status['reporting-mta'].
    # Returns nil when the report does not contain the field.
    def [](field_name)
      field = @message_fields[field_name]
      field.value if field
    end

    # True when at least one recipient's Action is "failed".
    def bounced?
      recipients.any?(&:bounced?)
    end

    # True when at least one recipient did not permanently fail (Status
    # does not start with 5); false when every recipient failed
    # permanently.
    def retryable?
      recipients.any?(&:retryable?)
    end
  end
end
