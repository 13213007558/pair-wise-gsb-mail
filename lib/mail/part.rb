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

    # Returns the structured Mail::DeliveryStatus representation of this
    # message/delivery-status part, distinguishing the per-message block from
    # the per-recipient blocks.  Returns nil for other part types.
    def delivery_status
      @delivery_status ||= Mail::DeliveryStatus.new(body.to_s) if delivery_status_report_part?
    end

    # Deprecated: use #delivery_status.  Retained for backwards compatibility.
    def delivery_status_data
      delivery_status
    end

    def bounced?
      delivery_status ? delivery_status.bounced? : false
    end

    # Returns the Action of a single-recipient report, or an array of the
    # actions of every recipient block.
    def action
      delivery_status && delivery_status.action
    end

    def final_recipient
      delivery_status && delivery_status.final_recipient
    end

    def error_status
      delivery_status && delivery_status.status
    end

    def diagnostic_code
      delivery_status && delivery_status.diagnostic_code
    end

    def remote_mta
      delivery_status && delivery_status.remote_mta
    end

    def retryable?
      delivery_status ? delivery_status.retryable? : false
    end

    private

    # A part may not have a header.... so, just init a body if no header
    def parse_message
      header_part, body_part = raw_source.split(/#{Constants::LAX_CRLF}#{Constants::WSP}*#{Constants::LAX_CRLF}/m, 2)
      if header_part =~ Constants::HEADER_LINE
        self.header = header_part
        self.body   = body_part
      else
        self.header = "Content-Type: text/plain\r\n"
        self.body = raw_source
      end
    end

  end

end
