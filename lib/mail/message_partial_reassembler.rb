# encoding: utf-8
# frozen_string_literal: true

module Mail
  class MessagePartialReassembler
    UNKNOWN_TOTAL_STATUS = :unknown_total
    INCOMPLETE_STATUS = :incomplete
    COMPLETE_STATUS = :complete

    class ConflictError < ArgumentError
    end

    Fragment = Struct.new(:number, :total, :id, :message, :body, keyword_init: true)

    attr_reader :id, :status, :numbers, :total

    def self.reassemble(*messages)
      reassembler = new
      Array(messages).flatten.each { |message| reassembler.add(message) }
      reassembler.message
    end

    def initialize(id = nil)
      @id = id
      @fragments = {}
      @total = nil
      @numbers = []
      @status = UNKNOWN_TOTAL_STATUS
      @message = nil
    end

    def add(message_or_source)
      fragment = parse_fragment(message_or_source)
      ensure_matching_id(fragment.id)

      if existing = @fragments[fragment.number]
        unless existing.body == fragment.body
          raise ConflictError,
                "conflicting message/partial fragments with id #{fragment.id.inspect} and number #{fragment.number}"
        end

        set_total(fragment.total)
        ensure_number_within_total(fragment.number)
        fragment.message = existing.message
      else
        set_total(fragment.total)
        ensure_number_within_total(fragment.number)
        @fragments[fragment.number] = fragment
        @numbers = @fragments.keys.sort
      end

      update_status
      @message = complete? ? reassemble : nil
      self
    end
    alias_method :<<, :add

    def message
      @message ||= reassemble if complete?
    end

    def complete?
      status == COMPLETE_STATUS
    end

    def incomplete?
      !complete?
    end

    def unknown_total?
      status == UNKNOWN_TOTAL_STATUS
    end

    def missing_numbers
      return numbers unless total

      (1..total).to_a - numbers
    end

    private

      def parse_fragment(message_or_source)
        message = message_or_source.is_a?(Message) ? message_or_source : Mail.new(message_or_source.to_s)
        unless message.mime_type&.downcase == 'message/partial'
          raise ArgumentError, 'message must have Content-Type message/partial'
        end

        parameters = message[:content_type].parameters
        fragment_id = parameters[:id].to_s
        number = parse_positive_integer(parameters[:number], :number)
        fragment_total = parse_optional_positive_integer(parameters[:total])
        body = Utilities.to_crlf(message.body.raw_source.to_s)

        Fragment.new(number: number, total: fragment_total, id: fragment_id,
                     message: message, body: body)
      end

      def parse_positive_integer(value, name)
        integer = parse_optional_positive_integer(value)
        return integer if integer

        raise ArgumentError, "message/partial #{name} must be a positive integer"
      end

      def parse_optional_positive_integer(value)
        return nil if value.nil? || value.to_s.empty?

        value = value.to_s.strip
        unless value.match?(/\A[1-9]\d*\z/)
          raise ArgumentError, 'message/partial number and total must be positive integers'
        end

        value.to_i
      end

      def ensure_matching_id(fragment_id)
        if fragment_id.empty?
          raise ArgumentError, 'message/partial id is required'
        elsif @id.nil?
          @id = fragment_id
        elsif @id != fragment_id
          raise ArgumentError,
                "expected message/partial id #{@id.inspect}, got #{fragment_id.inspect}"
        end
      end

      def set_total(fragment_total)
        return unless fragment_total
        return if @total && @total == fragment_total

        raise ConflictError,
              "conflicting message/partial totals for id #{@id.inspect}: #{@total} and #{fragment_total}" if @total

        @total = fragment_total
      end

      def ensure_number_within_total(number)
        return unless @total && number > @total

        raise ConflictError,
              "message/partial number #{number} is greater than total #{@total} for id #{@id.inspect}"
      end

      def update_status
        @status =
          if @total.nil?
            UNKNOWN_TOTAL_STATUS
          elsif @fragments.size == @total && numbers == (1..@total).to_a
            COMPLETE_STATUS
          else
            INCOMPLETE_STATUS
          end
      end

      def reassemble
        return nil unless complete?

        first_fragment = @fragments.fetch(1)
        raw = (1..@total).map { |number| @fragments.fetch(number).body }.join
        inner_header_source, inner_body = split_message(raw)

        outer_fields = selected_fields(first_fragment.message, :outer)
        inner_fields = selected_fields(Header.new(inner_header_source.to_s), :inner)
        header_source = (outer_fields + inner_fields).map { |field| field + Constants::CRLF }.join

        Mail.new(header_source + Constants::CRLF + inner_body.to_s)
      end

      def selected_fields(header_or_message, location)
        header = header_or_message.is_a?(Header) ? header_or_message : header_or_message.header
        header.raw_source.to_s.split(Constants::HEADER_SPLIT).select do |field|
          include_field?(field_name(field), location)
        end
      end

      def include_field?(name, location)
        inner_field = name.downcase.start_with?('content-') ||
          %w[subject message-id encrypted mime-version].include?(name.downcase)

        location == :inner ? inner_field : !inner_field
      end

      def field_name(field)
        field.split(Constants::COLON, 2).first.to_s
      end

      def split_message(source)
        source.split(/#{Constants::LAX_CRLF}#{Constants::WSP}*#{Constants::LAX_CRLF}/, 2)
      end
  end

  PartialMessageReassembler = MessagePartialReassembler
end
