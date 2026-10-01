# frozen_string_literal: true

module Mail
  # Represents one complete resent block (RFC 5322 3.6.6).
  #
  # A message may be resent more than once; each resending event adds its
  # own set of Resent-* header fields.  ResentBlock groups the fields of a
  # single event together so that reading, appending or removing one batch
  # never touches the fields belonging to another batch.
  #
  # Blocks are built from header fields with ::from_fields and turned back
  # into header fields with #to_fields.  New blocks are created with ::new
  # using keyword arguments.
  class ResentBlock
    # Raised when a resent block is missing fields required by RFC 5322,
    # or carries multiple Resent-From addresses without a Resent-Sender.
    class ValidationError < StandardError
    end

    NAMES = %w[
      Resent-Date
      Resent-From
      Resent-Sender
      Resent-To
      Resent-Cc
      Resent-Bcc
      Resent-Message-ID
    ].freeze

    # Order in which a newly created block's fields are emitted.
    CANONICAL_ORDER = NAMES

    attr_reader :date, :from, :sender, :to, :cc, :bcc, :message_id, :fields

    # Build a new block.  +from+ and at least one recipient (+to+, +cc+ or
    # +bcc+) are required; +date+ defaults to the current time.  If more
    # than one +from+ address is given, +sender+ is required.
    #
    # Address values accept anything the corresponding header field accepts
    # (strings, arrays, formatted addresses).
    def initialize(date: nil, from: nil, sender: nil, to: nil, cc: nil, bcc: nil,
                   message_id: nil)
      @date = normalize_date(date)
      @from = Array(from)
      @sender = sender ? Array(sender) : nil
      @to = Array(to)
      @cc = Array(cc)
      @bcc = Array(bcc)
      @message_id = message_id
      @fields = nil

      validate!
    end

    # Group the Resent-* fields of a header (in header order) into blocks.
    #
    # A new block starts whenever a Resent-Date field is encountered, or
    # when a field that already exists in the current block is
    # encountered.  The field order within each block is preserved.
    def self.from_fields(fields)
      blocks = []
      current = []

      fields.each do |field|
        if current.any? { |f| f.responsible_for?(field.name) }
          blocks << new_from_fields(current)
          current = []
        end
        current << field
      end
      blocks << new_from_fields(current) if current.any?

      blocks
    end

    def self.new_from_fields(fields) #:nodoc:
      allocate.tap do |block|
        block.instance_variable_set(:@fields, fields.dup)

        values = Hash[NAMES.map { |name| [name, nil] }]
        fields.each do |field|
          name = field.name
          next unless values.key?(name)

          case name
          when 'Resent-Date'
            values[name] = field.date_time rescue field.value.to_s
          when 'Resent-Message-ID'
            values[name] = field.default
          else
            values[name] = field.addresses
          end
        end

        block.instance_variable_set(:@date, values['Resent-Date'])
        block.instance_variable_set(:@from, Array(values['Resent-From']))
        block.instance_variable_set(:@sender, values['Resent-Sender'])
        block.instance_variable_set(:@to, Array(values['Resent-To']))
        block.instance_variable_set(:@cc, Array(values['Resent-Cc']))
        block.instance_variable_set(:@bcc, Array(values['Resent-Bcc']))
        block.instance_variable_set(:@message_id, values['Resent-Message-ID'])
      end
    end

    # Header Field objects for this block, in canonical order.
    def to_fields(charset = nil)
      NAMES.flat_map do |name|
        value = value_for(name)
        next [] if value.nil? || (value.respond_to?(:empty?) && value.empty?)

        [Mail::Field.new(name, value, charset)]
      end
    end

    # Raises ValidationError unless the block satisfies RFC 5322 3.6.6:
    # Resent-Date, Resent-From and a recipient are mandatory, and
    # Resent-Sender is required when Resent-From lists multiple authors.
    def validate!
      missing = []
      missing << 'Resent-Date' if date.nil? || date.to_s.empty?
      missing << 'Resent-From' if from.empty?
      if to.empty? && cc.empty? && bcc.empty?
        missing << 'Resent-To/Resent-Cc/Resent-Bcc'
      end

      unless missing.empty?
        raise ValidationError,
              "resent block is missing required field(s): #{missing.join(', ')}"
      end

      if from.length > 1 && (sender.nil? || sender.empty?)
        raise ValidationError,
              'Resent-Sender is required when Resent-From contains more than one address'
      end

      true
    end

    # True when the block conforms to RFC 5322 3.6.6.
    def valid?
      validate!
    rescue ValidationError
      false
    end

    # All recipient addresses of the block (Resent-To, Resent-Cc and
    # Resent-Bcc, in that order).
    def recipients
      to + cc + bcc
    end

    # The single Resent-Sender address, or nil.
    def sender_address
      sender && sender.first
    end

    def ==(other)
      other.is_a?(self.class) &&
        date == other.date && from == other.from && sender == other.sender &&
        to == other.to && cc == other.cc && bcc == other.bcc &&
        message_id == other.message_id
    end
    alias_method :eql?, :==

    def hash
      [date, from, sender, to, cc, bcc, message_id].hash
    end

    def inspect
      "#<#{self.class.name} date=#{date.inspect} from=#{from.inspect} " \
        "sender=#{sender.inspect} to=#{to.inspect} cc=#{cc.inspect} " \
        "bcc=#{bcc.inspect} message_id=#{message_id.inspect}>"
    end

    private

    def normalize_date(value)
      normalized = Mail::ResentDateField.normalize_datetime(value)
      return nil if normalized.nil?

      ::DateTime.parse(normalized) rescue normalized
    end

    def value_for(name)
      case name
      when 'Resent-Date' then date
      when 'Resent-From' then from
      when 'Resent-Sender' then sender
      when 'Resent-To' then to
      when 'Resent-Cc' then cc
      when 'Resent-Bcc' then bcc
      when 'Resent-Message-ID' then message_id
      end
    end
  end
end
