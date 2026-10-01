# frozen_string_literal: true

module Mail
  class SmtpEnvelope #:nodoc:
    # Reasonable cap on address length to avoid SMTP line length
    # overflow on old SMTP servers.
    MAX_ADDRESS_BYTESIZE = 2000

    attr_reader :from, :to, :message

    # Build the SMTP envelope for delivering a resent message from one
    # complete resent batch (RFC 5322 3.6.6).  The envelope sender is the
    # batch Resent-Sender, or the first Resent-From address; recipients are
    # Resent-To + Resent-Cc + Resent-Bcc.  The delivered message is a copy
    # with the batch's own Resent-Bcc stripped.
    def self.for_resent_block(mail, block)
      from = block.sender_address || block.from.first
      new.tap do |envelope|
        envelope.from = from
        envelope.to = block.recipients
        envelope.message = mail.resent_delivery_copy(block).encoded
      end
    end

    def initialize(mail = nil)
      if mail
        self.from = mail.smtp_envelope_from
        self.to = mail.smtp_envelope_to
        self.message = mail.encoded
      end
    end

    def from=(addr)
      if Utilities.blank? addr
        raise ArgumentError, "SMTP From address may not be blank: #{addr.inspect}"
      end

      @from = validate_addr 'From', addr
    end

    def to=(addr)
      if Utilities.blank?(addr)
        raise ArgumentError, "SMTP To address may not be blank: #{addr.inspect}"
      end

      @to = Array(addr).map do |addr|
        validate_addr 'To', addr
      end
    end

    def message=(message)
      if Utilities.blank?(message)
        raise ArgumentError, 'SMTP message may not be blank'
      end

      @message = message
    end


    private
      def validate_addr(addr_name, addr)
        if addr.bytesize > MAX_ADDRESS_BYTESIZE
          raise ArgumentError, "SMTP #{addr_name} address may not exceed #{MAX_ADDRESS_BYTESIZE} bytes: #{addr.inspect}"
        end

        if /[\r\n]/.match?(addr)
          raise ArgumentError, "SMTP #{addr_name} address may not contain CR or LF line breaks: #{addr.inspect}"
        end

        addr
      end
  end
end
