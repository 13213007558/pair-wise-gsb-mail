# encoding: utf-8
# frozen_string_literal: true

module Mail
  class MessagePartial
    class Error < StandardError
    end

    class ConflictError < Error
    end

    class << self
      def collect(*messages)
        collector = new
        messages.flatten.each { |message| collector.add(message) }
        collector
      end

      def reassemble(*messages)
        collector = new
        messages.flatten.each { |message| collector.add(message) }
        collector.reassemble
      end

      def reassemble!(*messages)
        collector = new
        messages.flatten.each { |message| collector.add(message) }
        collector.reassemble!
      end
    end

    UNKNOWN_TOTAL = :unknown_total
    INCOMPLETE = :incomplete
    COMPLETE = :complete
    CONFLICT = :conflict

    attr_reader :ids

    def initialize
      @fragments = Hash.new { |hash, id| hash[id] = {} }
      @totals = {}
      @encodings = {}
      @conflicts = Hash.new { |hash, id| hash[id] = [] }
      @ids = []
    end

    def add(message)
      fragment = Fragment.new(message)
      record_id(fragment.id)
      check_conflict(fragment)
      check_encoding(fragment)
      check_range(fragment)
      store(fragment)
      result(fragment.id)
    end
    alias_method :<<, :add

    def status(id = nil)
      if id
        fragment_status(id)
      else
        @ids.to_h { |message_id| [message_id, fragment_status(message_id)] }
      end
    end

    def ids_with_status(status)
      @ids.select { |message_id| fragment_status(message_id) == status }
    end

    def complete?(id = nil)
      if id
        fragment_status(id) == COMPLETE
      else
        !@ids.empty? && @ids.all? { |message_id| complete?(message_id) }
      end
    end

    def missing_numbers(id)
      return nil unless @totals[id]

      (1..@totals[id]).reject { |number| @fragments[id].key?(number) }
    end

    def numbers(id)
      @fragments[id].keys.sort
    end

    def total(id)
      @totals[id]
    end

    def result(id)
      Result.new(
        id,
        fragment_status(id),
        @totals[id],
        numbers(id),
        missing_numbers(id),
        complete?(id) ? build_message(id) : nil
      )
    end

    def results
      @ids.map { |id| result(id) }
    end

    def reassemble(id = nil)
      if id
        result(id).message
      else
        complete_results = results.select(&:complete?)
        complete_results.map(&:message)
      end
    end

    def reassemble!(id = nil)
      if id
        message = reassemble(id)
        message or raise Error, "Message partial #{id.inspect} is #{fragment_status(id)}"
      else
        incomplete = @ids.reject { |message_id| complete?(message_id) }
        unless incomplete.empty?
          statuses = incomplete.map { |message_id| "#{message_id.inspect}: #{fragment_status(message_id)}" }
          raise Error, "Incomplete message partials: #{statuses.join(', ')}"
        end

        reassemble
      end
    end

    private

    def record_id(id)
      @ids << id unless @ids.include?(id)
    end

    def check_conflict(fragment)
      id = fragment.id

      if (existing = @fragments[id][fragment.number])
        if existing.raw_body != fragment.raw_body
          add_conflict(id, fragment.number)
          raise ConflictError,
                "Conflicting message/partial fragments for #{id.inspect} number #{fragment.number}"
        end
      end

      if fragment.total && @totals[id] && fragment.total != @totals[id]
        add_conflict(id, :total)
        raise ConflictError,
              "Conflicting message/partial totals for #{id.inspect}: #{@totals[id]} and #{fragment.total}"
      end
    end

    def check_encoding(fragment)
      id = fragment.id
      return unless fragment.encoding && @encodings[id] &&
                    !encodings_match?(@encodings[id], fragment.encoding)

      add_conflict(id, :encoding)
      raise ConflictError,
            "Conflicting message/partial encodings for #{id.inspect}: #{@encodings[id].inspect} and #{fragment.encoding.inspect}"
    end

    def check_range(fragment)
      id = fragment.id
      total = fragment.total || @totals[id]
      out_of_range_number = fragment.number > total if total
      out_of_range_number ||= fragment.total && @fragments[id].keys.any? { |number| number > fragment.total }
      return unless out_of_range_number

      add_conflict(id, fragment.number)
      raise ConflictError,
            "message/partial number is outside the declared total"
    end

    def add_conflict(id, conflict)
      @conflicts[id] << conflict
      @conflicts[id].uniq!
    end

    def store(fragment)
      @fragments[fragment.id][fragment.number] = fragment
      @totals[fragment.id] ||= fragment.total
      @encodings[fragment.id] ||= fragment.encoding
    end

    def fragment_status(id)
      return CONFLICT unless @conflicts[id].empty?
      return UNKNOWN_TOTAL unless @totals[id]

      expected = 1..@totals[id]
      expected.all? { |number| @fragments[id].key?(number) } ? COMPLETE : INCOMPLETE
    end

    def encodings_match?(left, right)
      left.to_s.downcase.tr('-', '') == right.to_s.downcase.tr('-', '')
    end

    def build_message(id)
      encoded_body = (1..@totals[id]).map { |number| @fragments[id][number].raw_body }.join
      raw_body = decode_body(id, encoded_body)
      message = Mail.new(raw_body)
      message.header['mime-version'] ||= '1.0'
      message
    end

    def decode_body(id, encoded_body)
      encoding = @encodings[id]
      return encoded_body unless encoding

      decoder = Mail::Encodings.get_encoding(encoding)
      raise Error, "Unknown Content-Transfer-Encoding #{encoding.inspect}" unless decoder

      Mail::Utilities.to_crlf(decoder.decode(encoded_body))
    end

    class Fragment
      attr_reader :message, :id, :number, :total, :raw_body, :encoding

      def initialize(message)
        @message = message.is_a?(Mail::Message) ? message : Mail.new(message.to_s)

        unless @message.main_type.to_s.downcase == 'message' &&
               @message.sub_type.to_s.downcase == 'partial'
          raise Error, 'Expected a message/partial MIME part'
        end

        parameters = @message.content_type_parameters || {}
        @id = parameters['id']
        @number = parse_positive_integer(parameters['number'], 'number')
        @total = parse_optional_positive_integer(parameters['total'])
        @raw_body = @message.body.raw_source.dup.force_encoding(Encoding::BINARY)
        @encoding = @message.content_transfer_encoding || '7bit'

        raise Error, 'message/partial requires an id parameter' if @id.nil? || @id.to_s.empty?
      end

      private

      def parse_positive_integer(value, name)
        integer = parse_optional_positive_integer(value)
        return integer if integer && integer.positive?

        raise Error, "message/partial requires a positive integer #{name} parameter"
      end

      def parse_optional_positive_integer(value)
        return nil if value.nil? || value.to_s.empty?
        raise Error, "Invalid message/partial integer: #{value.inspect}" unless /\A[0-9]+\z/.match?(value.to_s)

        integer = value.to_i
        raise Error, "message/partial integer must be positive: #{value.inspect}" unless integer.positive?

        integer
      end
    end

    class Result
      attr_reader :id, :status, :total, :numbers, :missing_numbers, :message

      def initialize(id, status, total, numbers, missing_numbers, message)
        @id = id
        @status = status
        @total = total
        @numbers = numbers
        @missing_numbers = missing_numbers
        @message = message
      end

      def complete?
        status == COMPLETE
      end
    end

    private_constant :Fragment, :Result
  end
end
