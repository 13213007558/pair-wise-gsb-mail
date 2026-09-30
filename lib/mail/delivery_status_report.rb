# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Parses the body of a message/delivery-status part (RFC 3464).
  #
  # A delivery status notification (DSN) is a series of field groups separated
  # by blank lines:
  #
  # 1. A single per-message (report level) group, containing fields such as
  #    Reporting-MTA and Arrival-Date.
  # 2. Zero or more per-recipient groups, each containing fields such as
  #    Final-Recipient, Action and Status for exactly one recipient.
  #
  # Keeping the groups intact means optional fields may differ between
  # recipients without the field arrays getting out of alignment.
  class DeliveryStatusReport
    attr_reader :message_fields, :recipient_reports

    def initialize(body)
      groups = split_groups(Mail::Utilities.to_crlf(body.to_s))
      message_group = groups.shift
      @message_fields = message_group || Mail::Header.new
      @recipient_reports = groups.map { |group| RecipientReport.new(group) }
    end

    # Fields that belong to the whole report rather than to a recipient,
    # for example <tt>report['reporting-mta']</tt>.
    def [](name)
      field = @message_fields[Mail::Utilities.dasherize(name)]
      field && field.value
    end

    # Values collected from each per-recipient group. Returns a single String
    # when there is only one recipient and an Array when there are several,
    # preserving the order of the recipient groups. Missing fields are nil in
    # the array so that values stay aligned across recipients.
    def values(name)
      values = recipient_reports.map { |report| report[name] }
      values.size <= 1 ? values.first : values
    end

    # True when at least one recipient report is a permanent failure (an
    # "failed" action or a 5.x status). A mixed notification with a delayed
    # recipient can therefore still be bounced for another recipient; use the
    # per-recipient reports to distinguish them.
    def bounced?
      !recipient_reports.empty? && recipient_reports.any?(&:bounced?)
    end

    # True when delivery may still succeed for any recipient (a transient 4.x
    # status), and false when every known recipient status is non retryable
    # (a permanent 5.x status). Returns nil when there is no usable status.
    def retryable?
      statuses = recipient_reports.map(&:retryable?).compact
      return nil if statuses.empty?

      statuses.any?
    end

    private

    def split_groups(raw_source)
      # Groups are separated by one or more empty (possibly whitespace only)
      # lines. Folded continuation lines (CRLF followed by whitespace and
      # then more content) are not separators and stay within their group.
      raw_source
        .split(/\r?\n[ \t]*(?:\r?\n[ \t]*)+/)
        .reject { |group| group.strip.empty? }
        .map { |group| Mail::Header.new(group) }
    end

    # Holds the fields of a single per-recipient group of a DSN.
    class RecipientReport
      attr_reader :fields

      def initialize(fields)
        @fields = fields
      end

      # Reads any field from the recipient group, including folded fields and
      # unknown extension fields. Returns nil when the field is absent.
      def [](name)
        field = fields[Mail::Utilities.dasherize(name)]
        field && field.value
      end

      def final_recipient
        self['final-recipient']
      end

      def action
        self['action']
      end

      def status
        self['status']
      end

      alias_method :error_status, :status

      def diagnostic_code
        self['diagnostic-code']
      end

      def remote_mta
        self['remote-mta']
      end

      # A permanent failure, identified by a "failed" action or a 5.x status.
      def bounced?
        !!(action =~ /failed/i) || !!(status =~ /\A5\./)
      end

      # Retryable per RFC 3464: a transient 4.x status. Returns nil when no
      # status is present.
      def retryable?
        return nil unless status

        status =~ /\A4\./ ? true : false
      end
    end
  end
end
