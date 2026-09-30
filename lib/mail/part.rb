# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/utilities'

module Mail
  class Part < Message
    # Creates a new empty Content-ID field and inserts it in the correct order
    # into the Header.  The ContentIdField object will automatically generate
    # a unique content ID if you try and encode it or output it to_s without
    # specifying a content id.
    #
    # It will preserve the content ID you specify if you do.
    def add_content_id(content_id_val = '')
      header['content-id'] = content_id_val
    end

    # Returns true if the part has a content ID field, the field may or may
    # not have a value, but the field exists or not.
    def has_content_id?
      header.has_content_id?
    end

    def cid
      add_content_id unless has_content_id?
      Utilities.uri_escape(Utilities.unbracket(content_id))
    end

    def url
      "cid:#{cid}"
    end

    def inline?
      header[:content_disposition].disposition_type == 'inline' if header[:content_disposition].respond_to?(:disposition_type)
    end

    def add_required_fields
      super
      add_content_id if !has_content_id? && inline?
    end

    def add_required_message_fields
      # Override so we don't add Date, MIME-Version, or Message-ID.
    end

    def delivery_status_report_part?
      (main_type =~ /message/i && sub_type =~ /delivery-status/i) && body =~ /Status:/
    end

    # Returns a Mail::DeliveryStatus exposing the report-level fields and
    # one record per recipient for a message/delivery-status part.
    # Returns an empty hash for other parts.
    def delivery_status_data
      delivery_status_report_part? ? parse_delivery_status_report : {}
    end

    # True when at least one recipient's Action is "failed".
    def bounced?
      !!(delivery_status && delivery_status.bounced?)
    end

    # True when at least one recipient did not permanently fail (Status
    # does not start with 5); false when every recipient failed
    # permanently.
    def retryable?
      !!(delivery_status && delivery_status.retryable?)
    end

    # Either returns the action if the message has just a single report, or an
    # array of all the actions, one for each report
    def action
      get_return_values('action')
    end

    def final_recipient
      get_return_values('final-recipient')
    end

    def error_status
      get_return_values('status')
    end

    def diagnostic_code
      get_return_values('diagnostic-code')
    end

    def remote_mta
      get_return_values('remote-mta')
    end

    private

    def delivery_status
      parse_delivery_status_report if delivery_status_report_part?
    end

    def get_return_values(key)
      return nil unless delivery_status
      values = delivery_status.recipients.map { |recipient| recipient[key] }
      values.length <= 1 ? values.first : values
    end

    # A part may not have a header.... so, just init a body if no header
    def parse_message
      header_part, body_part = raw_source.split(/#{Constants::LAX_CRLF}#{Constants::WSP}*#{Constants::LAX_CRLF}/m, 2)
      if header_part =~ Constants::HEADER_LINE
        self.header = header_part
        self.body   = body_part
      else
        self.header = "Content-Type: text/plain\r\n"
        self.body   = raw_source
      end
    end

    def parse_delivery_status_report
      @delivery_status_data ||= DeliveryStatus.new(body.to_s)
    end

  end

end
