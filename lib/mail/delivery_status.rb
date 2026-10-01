# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = DeliveryStatus
  #
  # Structured reader and writer for the machine readable
  # +message/delivery-status+ MIME entity carried inside
  # +multipart/report; report-type=delivery-status+ bounce messages
  # (RFC 3464).
  #
  # A delivery status body is made of a per-message field block
  # (+Reporting-MTA+, +Arrival-Date+, ...) followed by one field block
  # per recipient (+Final-Recipient+, +Action+, +Status+,
  # +Diagnostic-Code+, ...).  Unknown extension fields are preserved
  # verbatim when parsing and re-emitting a report.
  #
  # == Reading a report
  #
  #   status = Mail::DeliveryStatus.parse(part.body.decoded)
  #   status.message_fields['Reporting-MTA'].value # => "mail.example.com"
  #   status.recipients.each do |rcpt|
  #     rcpt.action          # => "failed"
  #     rcpt.status          # => "5.1.1"
  #     rcpt.diagnostic_code # => "550 5.1.1 User unknown"
  #   end
  #
  # == Writing a report
  #
  #   status = Mail::DeliveryStatus.new
  #   status.message_fields['Reporting-MTA'] = 'dns; mail.example.com'
  #   rcpt = status.add_recipient
  #   rcpt['Final-Recipient'] = 'rfc822; user@example.com'
  #   rcpt['Action']          = 'failed'
  #   rcpt['Status']          = '5.1.1'
  #   rcpt['Diagnostic-Code'] = 'smtp; 550 5.1.1 User unknown'
  #
  #   part = Mail::Part.new(:content_type => 'message/delivery-status',
  #                         :body => status.to_s)
  class DeliveryStatus
    CRLF = "\r\n".freeze

    # Lines longer than this are folded with a CRLF followed by a space.
    MAX_LINE_LENGTH = 78

    # A field line is a printable-ASCII (excluding ':') name, a colon and
    # a value.
    FIELD_LINE = /\A([!-9;-~]+):[ \t]*(.*)\z/.freeze

    # Field values may carry a type prefix, e.g. "rfc822; user@example.com"
    # or "smtp; 550 5.1.1 User unknown".
    TYPE_PREFIX = /\A([A-Za-z0-9][A-Za-z0-9._-]*);[ \t]*(.*)\z/.freeze

    # Raised when a delivery status body cannot be parsed.  Carries the
    # index of the block (0 is the per-message block, 1..n the per-recipient
    # blocks) and the offending line so the problem can be located.
    class ParseError < StandardError
      attr_reader :block_index, :line

      def initialize(message, block_index = nil, line = nil)
        @block_index = block_index
        @line = line
        super(message)
      end
    end

    # A single field of a delivery status block.  The value's type prefix
    # ("rfc822;" in "rfc822; user@example.com") is split out into #type.
    class Field
      attr_reader :name
      attr_accessor :type, :value

      def initialize(name, value, type = nil)
        @name  = name.to_s
        @type  = type
        @value = value.to_s
      end

      # The value including its type prefix, e.g. "dns; mail.example.com".
      def full_value
        type ? "#{type}; #{value}" : value.to_s
      end

      # The folded header-style line, e.g. "Remote-MTA: dns; mail.example.com".
      def to_s
        DeliveryStatus.fold("#{name}: #{full_value}")
      end
    end

    # An ordered, name-addressable collection of fields.  Field names are
    # matched case-insensitively; unknown (extension) fields are kept in
    # order alongside the well known ones.
    class Block
      include Enumerable

      attr_reader :fields

      def initialize(fields = [])
        @fields = fields.dup
      end

      def each(&block)
        @fields.each(&block)
      end

      # Returns the first Field with the given (case-insensitive) name.
      def [](name)
        name = name.to_s
        @fields.find { |field| field.name.casecmp(name).zero? }
      end

      # Sets the first field with this name, or appends a new field.
      # The value may be a String (a type prefix, if any, is parsed out)
      # or a DeliveryStatus::Field.
      def []=(name, value)
        field = self[name]
        if field && !value.is_a?(Field)
          field.type, field.value = DeliveryStatus.split_type_prefix(value.to_s)
          field
        elsif field
          @fields[@fields.index(field)] = value
        else
          @fields << DeliveryStatus.build_field(name, value)
        end
      end

      # Always appends a new field, even if one with the same name exists.
      def add(name, value)
        @fields << DeliveryStatus.build_field(name, value)
      end

      def key?(name)
        !self[name].nil?
      end

      def delete(name)
        name = name.to_s
        @fields.delete_if { |field| field.name.casecmp(name).zero? }
      end

      def empty?
        @fields.empty?
      end

      def to_s
        @fields.map(&:to_s).join(CRLF)
      end
    end

    # A per-recipient block with convenience accessors for the standard
    # RFC 3464 recipient fields.  Accessors return the field value without
    # its type prefix; use block['Field-Name'] to get the whole Field.
    class RecipientBlock < Block
      def original_recipient
        field_value('Original-Recipient')
      end

      def final_recipient
        field_value('Final-Recipient')
      end

      def action
        field_value('Action')
      end

      def status
        field_value('Status')
      end

      def remote_mta
        field_value('Remote-MTA')
      end

      def diagnostic_code
        field_value('Diagnostic-Code')
      end

      def last_attempt_date
        field_value('Last-Attempt-Date')
      end

      def final_log_id
        field_value('Final-Log-ID')
      end

      def will_retry_until
        field_value('Will-Retry-Until')
      end

      # True when the Action of this recipient is "failed".
      def bounced?
        action.to_s.downcase == 'failed'
      end

      # True when the Status is not a 5.x.y permanent failure.
      def retryable?
        status !~ /\A5/
      end

      private

      def field_value(name)
        field = self[name]
        field && field.value
      end
    end

    # The per-message fields of the report (a Block).
    attr_reader :message_fields

    # The per-recipient blocks of the report (an Array of RecipientBlock).
    attr_reader :recipient_blocks
    alias recipients recipient_blocks

    # Parses a message/delivery-status body.  Raises ParseError, located
    # to the offending block, if a line is not a valid field line.
    def self.parse(string)
      new.parse(string)
    end

    # Splits a "type; value" string into [type, value].  Returns
    # [nil, string] when there is no type prefix.
    def self.split_type_prefix(string)
      if (match = TYPE_PREFIX.match(string.to_s))
        [match[1], match[2]]
      else
        [nil, string.to_s]
      end
    end

    # Builds a Field from a name and a String or Field value.
    def self.build_field(name, value)
      if value.is_a?(Field)
        value
      else
        type, val = split_type_prefix(value.to_s)
        Field.new(name, val, type)
      end
    end

    # Folds a field line to MAX_LINE_LENGTH characters, breaking at
    # whitespace and continuing the line with a single space.
    def self.fold(line)
      return line if line.length <= MAX_LINE_LENGTH

      folded = +''
      rest = line
      while rest.length > MAX_LINE_LENGTH
        break_at = rest.rindex(/[ \t]/, MAX_LINE_LENGTH - 1)
        break unless break_at && break_at > 0

        folded << rest[0...break_at] << CRLF << ' '
        rest = rest[(break_at + 1)..-1]
      end
      folded << rest
    end

    def initialize
      @message_fields   = Block.new
      @recipient_blocks = []
    end

    # Parses a delivery status body into this object, replacing any
    # existing content.  Returns self.
    def parse(string)
      @message_fields   = Block.new
      @recipient_blocks = []

      split_blocks(unfold(string.to_s)).each_with_index do |lines, index|
        block = index.zero? ? @message_fields : add_recipient
        lines.each do |line|
          match = FIELD_LINE.match(line)
          unless match
            raise ParseError.new(
              "Invalid field line in #{block_label(index)} of delivery-status: #{line.inspect}",
              index, line)
          end
          block.add(match[1], match[2])
        end
      end
      self
    end

    # Appends a new empty per-recipient block and returns it.
    def add_recipient
      RecipientBlock.new.tap { |block| @recipient_blocks << block }
    end

    def empty?
      @message_fields.empty? && @recipient_blocks.all?(&:empty?)
    end

    # Renders the report as a valid message/delivery-status body: the
    # per-message block, then each per-recipient block, separated by blank
    # lines, with CRLF line endings and folded long lines.
    def to_s
      blocks = [message_fields, *recipient_blocks].reject(&:empty?)
      return '' if blocks.empty?

      blocks.map(&:to_s).join(CRLF * 2) + CRLF
    end

    private

    def block_label(index)
      index.zero? ? 'the per-message block' : "recipient block #{index}"
    end

    # Removes RFC 5322 folding: continuation lines (starting with WSP) are
    # joined to the previous line with a single space.
    def unfold(string)
      string.split(/\r\n|\n/).each_with_object([]) do |line, lines|
        if line =~ /\A[ \t]/ && !lines.empty?
          lines[-1] << ' ' << line.strip
        else
          lines << line
        end
      end
    end

    # Splits unfolded lines into field blocks separated by blank lines.
    # Empty blocks (e.g. from a trailing blank line) are dropped.
    def split_blocks(lines)
      lines.each_with_object([[]]) do |line, blocks|
        if line.strip.empty?
          blocks << [] unless blocks.last.empty?
        else
          blocks.last << line
        end
      end.reject(&:empty?)
    end
  end
end
