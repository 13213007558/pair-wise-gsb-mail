# encoding: utf-8
# frozen_string: true
require 'mail/constants'

module Mail
  # Structured reader and writer for the body of a +message/delivery-status+
  # part as defined by RFC 3464.
  #
  # A delivery status notification (DSN) consists of one or more blocks of
  # "field: value" lines separated by blank lines.  The first block carries
  # per-message fields and each subsequent block describes the delivery
  # attempt for a single recipient:
  #
  #   status = Mail::DeliveryStatus.new(part.body.to_s)
  #   status.reporting_mta        #=> "mail.example.com"
  #   status.recipients.length    #=> 3
  #   status.recipients.first.action #=> "delivered"
  #   status.action               #=> ["delivered", "delayed", "failed"]
  #
  # Type prefixes ("rfc822; user@example.com") and folded header lines are
  # parsed, and every field (including unknown extensions) is retained.  The
  # object can be built programmatically and serialized back into a legal
  # +message/delivery-status+ body which Mail can read again.
  class DeliveryStatus
    include Enumerable

    # Matches the printable "atom" characters allowed in a type prefix token.
    ATOM = /\A[!#$%&'*+\-.\/0-9=?A-Z^_`a-z{|}~]+\z/

    # Fields defined by RFC 3464 as carrying a type prefix ("type; value").
    TYPED_FIELDS = %w[ original-recipient final-recipient remote-mta
                       diagnostic-code received-from-mta reporting-mta ].freeze

    # A single field line inside a delivery status block.
    #
    # Many DSN fields carry a type prefix separated from the value by a
    # semicolon (+Final-Recipient: rfc822; user@example.com+): +type+ is
    # +"rfc822"+ and +value+ is +"user@example.com"+.  The complete, unfolded
    # field body is always available from #body so formatting survives a
    # parse/serialize round trip.
    class Field
      attr_reader :name, :type

      def initialize(name, value = nil, type = nil, typed = nil)
        @name = name.to_s
        if value.nil? && @name.include?(':')
          @name, value = @name.split(':', 2)
        end
        if value.nil?
          @raw_body = +''
          @type = nil
        elsif type
          @type = type.to_s
          @raw_body = "#{@type}; #{value}"
        else
          @raw_body = unfold(value.to_s)
          typed = TYPED_FIELDS.include?(@name.downcase) if typed.nil?
          parse_body(@raw_body, typed)
        end
      end

      # Builds a Field from a complete, possibly folded "Name: body" line.
      def self.parse(line)
        name, body = line.to_s.split(':', 2)
        raise ArgumentError, "not a field line: #{line.inspect}" if body.nil?
        new(name, body)
      end

      # The field value with any type prefix removed.
      def value
        if @type
          match = @raw_body.match(/\A[^;]*;[\x20\x09]*(.*)\z/m)
          match ? match[1] : @raw_body
        else
          @raw_body
        end
      end

      # The full unfolded field body, including any type prefix.
      def body
        @raw_body
      end

      alias to_s body

      def inspect
        "#<#{self.class} #{name}: #{body}>"
      end

      def encoded
        "#{name}: #{fold(@raw_body, 78 - name.length - 2)}"
      end

      def ==(other)
        other.is_a?(Field) &&
          name.casecmp?(other.name) &&
          body == other.body
      end
      alias eql? ==

      def hash
        [name.downcase, body].hash
      end

      private

      # Splits the field body into an optional type prefix and a value.  Only
      # the first semicolon is considered, so values like the SMTP transcript
      # in Diagnostic-Code ("smtp; 550 ...; try again") stay intact.
      def parse_body(field_body, typed)
        index = field_body.index(';')
        if typed && index
          candidate = field_body[0, index]
          if candidate.strip =~ ATOM
            @type = candidate.strip
          else
            @type = nil
          end
        else
          @type = nil
        end
      end

      # Unfolds a folded field body (RFC 5322): a line break followed by
      # folding whitespace is replaced by a single space.
      def unfold(text)
        text = text.gsub("\r\n", "\n").gsub(/\n[\x20\x09]+/, ' ')
        text.strip
      end

      # RFC 5322 style folding so emitted lines stay within the recommended
      # +limit+ for the body (excluding the "Name: " prefix).  Breaks happen at
      # whitespace where possible; a token longer than the limit is hard split.
      def fold(text, limit = 78)
        return text if text.length <= limit
        # Find a fold point: the rightmost whitespace within the limit.
        window = text[0, limit]
        break_index = window.rindex(/[\x20\x09]/)
        if break_index.nil? || break_index.zero?
          break_index = limit
          head = text[0, break_index]
          tail = text[break_index..-1].to_s.sub(/\A[\x20\x09]+/, '')
        else
          head = text[0, break_index]
          tail = text[(break_index + 1)..-1].to_s
        end
        if tail.empty?
          head
        else
          "#{head}#{Constants::CRLF} #{fold(tail, limit - 1)}"
        end
      end
    end

    # One per-message or per-recipient block of fields.
    class Block
      attr_reader :fields

      def initialize(fields = [])
        @fields = []
        Array(fields).each { |field| self << field }
      end

      # Accepts a Field or a [name, value] / [name, value, type] tuple.
      def <<(field)
        unless field.is_a?(Field)
          name, value, type = field
          field = Field.new(name, value, type)
        end
        @fields << field
        field
      end
      alias add <<

      def field(name)
        @fields.find { |f| f.name.casecmp?(name.to_s) }
      end
      alias [] field

      def fields_named(name)
        @fields.select { |f| f.name.casecmp?(name.to_s) }
      end

      def value(name)
        f = field(name)
        f && f.value
      end

      def body(name)
        f = field(name)
        f && f.body
      end

      %w[ action status diagnostic-code remote-mta final-recipient
          original-recipient reporting-mta received-from-mta
          arrival-date last-attempt-date will-retry-until ].each do |method_name|
        define_method(method_name.gsub(/-/, '_')) { value(method_name) }
      end

      def each(&block)
        @fields.each(&block)
      end

      def encoded
        @fields.map(&:encoded).join(Constants::CRLF)
      end

      alias to_s encoded

      def inspect
        "#<#{self.class} #{@fields.map(&:inspect).join(', ')}>"
      end
    end

    # Raised when the body of a message/delivery-status part cannot be parsed.
    # #block_index identifies the offending block (0 is the per-message block,
    # 1 onwards the recipient blocks) and #line_number the line within it.
    class ParseError < StandardError
      attr_reader :block_index, :line_number, :line

      def initialize(message, block_index: nil, line_number: nil, line: nil)
        @block_index = block_index
        @line_number = line_number
        @line = line
        location = []
        location << case block_index
                    when 0 then 'per-message block'
                    when nil then nil
                    else "recipient block ##{block_index}"
                    end
        location << "line #{line_number}" if line_number
        suffix = location.empty? ? '' : " (#{location.compact.join(', ')})"
        detail = line ? " |#{line}|" : ''
        super("malformed delivery status report#{suffix}: #{message}#{detail}")
      end
    end

    attr_reader :per_message, :recipients

    # Builds a structured representation.  Pass the raw message/delivery-status
    # body to parse it, or a block to construct one programmatically:
    #
    #   dsn = Mail::DeliveryStatus.new do |s|
    #     s.message_field 'Reporting-MTA', 'mx.example.com', 'dns'
    #     s.add_recipient('Final-Recipient' => ['rfc822', 'a@example.com'],
    #                     'Action' => 'delivered', 'Status' => '2.0.0')
    #   end
    def initialize(source = nil, &block)
      @per_message = Block.new
      @recipients = []
      if source
        parse(source)
      elsif block
        block.call(self)
      end
    end

    # Adds a field to the per-message block.
    def message_field(name, value = nil, type = nil)
      @per_message << Field.new(name, value, type)
    end

    # Adds and returns a new recipient block.  Accepts a Hash of field name to
    # value (use a [type, value] pair for typed fields), a list of Field/tuple
    # objects, or nothing (populate the returned block afterwards).
    def add_recipient(fields = nil)
      block = Block.new
      case fields
      when Hash
        fields.each do |name, spec|
          spec.is_a?(Array) ? block << [name, spec[1], spec[0]] : block << [name, spec]
        end
      when nil
        # populated by caller
      else
        Array(fields).each { |field| block << field }
      end
      @recipients << block
      block
    end

    def blocks
      [@per_message, *@recipients]
    end

    def each(&block)
      blocks.each(&block)
    end

    %w[ reporting-mta received-from-mta arrival-date ].each do |method_name|
      define_method(method_name.gsub(/-/, '_')) do
        @per_message.value(method_name)
      end
    end

    # Returns one value for a single-recipient report, otherwise an array in
    # recipient order.  Values keep their type prefix (e.g. "RFC822; a@b.c").
    %w[ action status diagnostic-code remote-mta
        final-recipient original-recipient ].each do |method_name|
      define_method(method_name.gsub(/-/, '_')) do
        values = @recipients.map { |r| r.body(method_name) }
        values.length > 1 ? values : values.first
      end
    end

    # True when any recipient block reports a permanent failure.
    def bounced?
      @recipients.any? { |r| r.action && r.action =~ /failed/i }
    end

    # True when no recipient reports a permanent 5.x.x failure.
    def retryable?
      !@recipients.any? { |r| r.status && r.status =~ /\A5\./ }
    end

    def encoded
      blocks.map(&:encoded).join(Constants::CRLF + Constants::CRLF) + Constants::CRLF
    end

    alias to_s encoded

    def inspect
      "#<#{self.class} per_message=#{@per_message.inspect} recipients=#{@recipients.inspect}>"
    end

    private

    FIELD_NAME = /[A-Za-z0-9!#$%&'*+\-.\/=?^_`{|}~]+/

    def parse(source)
      text = source.to_s.gsub("\r\n", "\n")
      chunks = text.split(/\n{2,}/).reject { |chunk| chunk.strip.empty? }
      raise ParseError.new('no field blocks found') if chunks.empty?

      chunks.each_with_index do |chunk, block_index|
        block = block_index.zero? ? @per_message : Block.new
        parse_block(chunk, block, block_index)
        @recipients << block if block_index > 0
      end
    end

    def parse_block(chunk, block, block_index)
      logical_lines(chunk, block_index).each do |line, raw_line_number|
        unless line =~ /\A(#{FIELD_NAME}):[\x20\x09]*(.*)\z/m
          raise ParseError.new('could not parse field line',
                               block_index: block_index,
                               line_number: raw_line_number,
                               line: line)
        end
        block << Field.new($1, $2)
      end
      raise ParseError.new('empty field block', block_index: block_index) if block.fields.empty?
    end

    # Joins folded continuation lines, pairing each logical line with the
    # number of its first physical line for error reporting.
    def logical_lines(chunk, block_index)
      lines = []
      current = nil
      chunk.each_line("\n").with_index(1) do |raw, index|
        line = raw.chomp("\n")
        if line =~ /\A[\x20\x09]/
          raise ParseError.new('folded continuation without a preceding field',
                               block_index: block_index,
                               line_number: index, line: line) unless current
          current[0] << line.sub(/\A[\x20\x09]+/, ' ')
        else
          lines << current if current
          current = [line, index]
        end
      end
      lines << current if current
      lines.map { |text, number| [text.strip, number] }.reject { |text, _| text.empty? }
    end
  end
end
