# encoding: binary
# frozen_string_literal: true

require 'stringio'

module Mail
  module Mboxrd
    ENVELOPE_PREFIX = "From ".b
    QUOTED_PREFIX = ">From ".b
    DEFAULT_CHUNK_SIZE = 16 * 1024

    class FormatError < StandardError; end

    class MalformedSeparatorError < FormatError
      attr_reader :line, :offset

      def initialize(message, line, offset)
        @line = line
        @offset = offset
        super(message)
      end
    end

    class Record
      attr_reader :envelope_from, :envelope_date, :raw_envelope,
                  :start_offset, :envelope_end_offset, :end_offset,
                  :malformed_separator

      def initialize(events, start_offset, envelope_end_offset, raw_envelope,
                     envelope_from, envelope_date, malformed_separator = nil)
        @events = events
        @start_offset = start_offset
        @envelope_end_offset = envelope_end_offset
        @end_offset = nil
        @raw_envelope = raw_envelope
        @envelope_from = envelope_from
        @envelope_date = envelope_date
        @malformed_separator = malformed_separator
        @consumed = false
      end

      def each_chunk
        return enum_for(:each_chunk) unless block_given?
        return if @consumed

        loop do
          event, payload, offset = @events.next
          case event
          when :body
            yield payload
          when :end_record
            @end_offset = offset
            @consumed = true
            break
          else
            raise Mboxrd::FormatError, "unexpected mboxrd parser event: #{event.inspect}"
          end
        end
      end

      def read(length = nil, &block)
        if block
          each_chunk(&block)
          nil
        else
          bytes = +"".b
          each_chunk { |chunk| bytes << chunk }
          if length
            bytes.byteslice(0, length)
          else
            bytes
          end
        end
      end

      def to_s
        read
      end

      def to_mail
        mail = Mail.new(read)
        mail.set_envelope(raw_envelope) if raw_envelope && malformed_separator.nil?
        mail
      end

      def byte_range
        end_offset or raise Mboxrd::FormatError, "record has not been consumed yet"
        start_offset...end_offset
      end

      def body_byte_range
        end_offset or raise Mboxrd::FormatError, "record has not been consumed yet"
        envelope_end_offset...end_offset
      end

      def bytesize
        byte_range.size
      end

      def consumed?
        @consumed
      end

      def close
        each_chunk { |_| } unless consumed?
        nil
      end
    end

    class Reader
      include Enumerable

      def initialize(source, malformed_separator: :raise, leading_content: :raise,
                     chunk_size: DEFAULT_CHUNK_SIZE, &on_malformed_separator)
        @source = source
        @malformed_separator = malformed_separator
        @leading_content = leading_content
        @chunk_size = chunk_size
        @on_malformed_separator = on_malformed_separator
      end

      def each
        return enum_for(:each) unless block_given?

        events = Enumerator.new do |yielder|
          scanner = Scanner.new(
            yielder,
            malformed_separator: @malformed_separator,
            leading_content: @leading_content,
            on_malformed_separator: @on_malformed_separator
          )
          read_chunks { |chunk| scanner.push(chunk) }
          scanner.finish
        end

        loop do
          event, *args = events.next
          next unless event == :start

          record = Record.new(events, *args)
          yield record
          record.close unless record.consumed?
        end
      end

      private

      def read_chunks
        if @source.respond_to?(:read)
          loop do
            chunk = @source.read(@chunk_size)
            break if chunk.nil? || chunk.empty?
            yield chunk
          end
        elsif @source.respond_to?(:each)
          @source.each { |chunk| yield chunk }
        else
          raise ArgumentError, "mboxrd reader needs an IO or chunk enumerator"
        end
      end
    end

    class Writer
      def self.open(output, mode = "wb")
        io = output.is_a?(::String) ? File.open(output, mode) : output
        writer = new(io)
        return writer unless block_given?

        begin
          yield writer
        ensure
          writer.close
          io.close if output.is_a?(::String)
        end
      end

      def initialize(output)
        @output = output
        @first_message = true
        @quoter = nil
      end

      def write_message(message = nil, from: nil, date: nil)
        flush_previous_message

        envelope_from = from
        envelope_date = date
        if message
          envelope_from ||= message.envelope_from if message.respond_to?(:envelope_from)
          envelope_date ||= message.envelope_date if message.respond_to?(:envelope_date)
          envelope_date ||= message.date if message.respond_to?(:date)
          envelope_from ||= message.smtp_envelope_from if message.respond_to?(:smtp_envelope_from)
        end

        raw_envelope = build_raw_envelope(envelope_from, envelope_date)
        @output.write("From #{raw_envelope}\n".b)

        @quoter = BodyQuoter.new(@output)
        @ended_with_newline = false
        @first_message = false

        if block_given?
          yield self
        elsif message
          write_object(message)
        end

        self
      end

      def write_body(chunk)
        raise Mboxrd::FormatError, "call write_message before writing message body" unless @quoter
        @ended_with_newline = @quoter.write(chunk)
      end

      def close
        @quoter&.flush
        nil
      end

      private

      def flush_previous_message
        return if @first_message
        @quoter&.flush
        @output.write("\n".b) unless @ended_with_newline
      end

      def write_object(object)
        if object.respond_to?(:encoded)
          write_body(object.encoded)
        elsif object.respond_to?(:read)
          while (chunk = object.read(DEFAULT_CHUNK_SIZE))
            write_body(chunk)
          end
        elsif object.respond_to?(:each)
          object.each { |chunk| write_body(chunk) }
        else
          write_body(object.to_s)
        end
      end

      def build_raw_envelope(from, date)
        raise ArgumentError, "mboxrd envelope sender is required" if from.nil?
        sender = from.to_s
        raise ArgumentError, "envelope sender must not contain a line break" if /[\r\n]/.match?(sender)

        if date.nil?
          raw = sender
        else
          formatted = date.respond_to?(:ctime) ? date.ctime : date.to_s
          raise ArgumentError, "envelope date must not contain a line break" if /[\r\n]/.match?(formatted)
          raw = "#{sender} #{formatted}"
        end

        Mail::EnvelopeFromElement.new(raw).to_s
      end
    end

    class BodyQuoter
      def initialize(output)
        @output = output
        @at_line_start = true
        @pending = +"".b
      end

      def write(chunk)
        data = @pending + chunk.to_s.dup.force_encoding(Encoding::BINARY)
        @pending = +"".b
        position = 0

        while position < data.bytesize
          unless @at_line_start
            newline = data.index("\n".b, position)
            if newline
              @output.write(data.byteslice(position..newline))
              position = newline + 1
              @at_line_start = true
            else
              @output.write(data.byteslice(position..-1))
              position = data.bytesize
            end
            next
          end

          newline = data.index("\n".b, position)
          if newline
            line = data.byteslice(position..newline)
            @output.write(">".b) if quote_line?(line)
            @output.write(line)
            position = newline + 1
          else
            prefix = data.byteslice(position, QUOTED_PREFIX.bytesize)
            if data.bytesize - position >= ENVELOPE_PREFIX.bytesize
              exact = data.byteslice(position, ENVELOPE_PREFIX.bytesize)
              if exact == ENVELOPE_PREFIX
                @output.write(">".b)
                @output.write(exact)
                position += ENVELOPE_PREFIX.bytesize
                @at_line_start = false
                next
              end
            end

            if data.bytesize - position >= QUOTED_PREFIX.bytesize
              exact = data.byteslice(position, QUOTED_PREFIX.bytesize)
              if exact.match?(/\A>+From /)
                @output.write(">".b)
                @output.write(exact)
                position += QUOTED_PREFIX.bytesize
                @at_line_start = false
                next
              end
            end

            if separator_prefix?(prefix) || quoted_prefix?(prefix)
              @pending = data.byteslice(position..-1)
              return false
            end

            if data.bytesize >= ENVELOPE_PREFIX.bytesize
              @output.write(data.byteslice(position..-1))
              @at_line_start = false
              position = data.bytesize
            else
              candidate = data.byteslice(position..-1)
              if candidate_prefix?(candidate)
                @pending = candidate
                return false
              end

              @pending = +"".b
              @output.write(candidate)
              @at_line_start = false
              position = data.bytesize
            end
          end
        end

        @at_line_start
      end

      def flush
        return if @pending.empty?
        @output.write(">".b) if quote_line?(@pending + "\n".b)
        @output.write(@pending)
        @pending = +"".b
      end

      private

      def separator_prefix?(prefix)
        ENVELOPE_PREFIX.start_with?(prefix)
      end

      def quoted_prefix?(prefix)
        prefix =~ /\A>+(?:F|Fr|Fro|From|From )?\z/
      end

      def candidate_prefix?(candidate)
        ENVELOPE_PREFIX.start_with?(candidate) || quoted_prefix?(candidate)
      end

      def quote_line?(line)
        line.start_with?(ENVELOPE_PREFIX) || line =~ /\A>+From /
      end
    end

    class Scanner
      def initialize(yielder, malformed_separator:, leading_content:, on_malformed_separator:)
        @yielder = yielder
        @malformed_separator = malformed_separator
        @leading_content = leading_content
        @on_malformed_separator = on_malformed_separator
        @line_offset = 0
        @source_offset = 0
        @at_line_start = true
        @separator_candidate = false
        @quoted_candidate = false
        @pending = +"".b
        @in_message = false
      end

      def push(chunk)
        chunk = chunk.to_s.dup.force_encoding(Encoding::BINARY)
        source_end_offset = @source_offset + chunk.bytesize
        data = @pending + chunk
        data_base_offset = @line_offset
        @separator_candidate = @pending.start_with?(ENVELOPE_PREFIX)
        @quoted_candidate = @pending.match?(/\A>+From /)
        @pending = +"".b
        position = 0

        while position < data.bytesize
          unless @at_line_start
            newline = data.index("\n".b, position)
            if newline
              emit_body(data.byteslice(position..newline), data_base_offset + position)
              position = newline + 1
              @at_line_start = true
              @separator_candidate = false
            else
              emit_body(data.byteslice(position..-1), data_base_offset + position)
              position = data.bytesize
            end
            next
          end

          newline = data.index("\n".b, position)
          line_offset = data_base_offset + position

          unless newline
            line_start = data.byteslice(position, QUOTED_PREFIX.bytesize)
            exact_separator_start = data.byteslice(position, ENVELOPE_PREFIX.bytesize) == ENVELOPE_PREFIX
            if @separator_candidate || @quoted_candidate || exact_separator_start ||
               separator_prefix?(line_start) || quoted_prefix?(line_start)
              @pending = data.byteslice(position..-1)
              @line_offset = line_offset
              @source_offset = source_end_offset
              @separator_candidate = @separator_candidate || exact_separator_start
              quoted_match = line_start.match?(/\A>+From /)
              @quoted_candidate = !@separator_candidate && quoted_match
              return
            end

            emit_body(data.byteslice(position..-1), line_offset)
            @line_offset = @source_offset = source_end_offset
            @at_line_start = false
            return
          end

          line = data.byteslice(position..newline)
          if @separator_candidate || line.start_with?(ENVELOPE_PREFIX)
            handle_separator(line, line_offset)
          elsif @quoted_candidate || quoted_from_line?(line)
            emit_body(line.byteslice(1..-1), line_offset)
          else
            emit_body(line, line_offset)
          end

          position = newline + 1
          @at_line_start = true
          @separator_candidate = false
          @quoted_candidate = false
        end

        @line_offset = @source_offset = source_end_offset
      end

      def finish
        unless @pending.empty?
          line_offset = @line_offset
          if @separator_candidate && @pending.start_with?(ENVELOPE_PREFIX)
            handle_separator(@pending, line_offset)
          elsif @quoted_candidate || quoted_from_line?(@pending)
            emit_body(@pending.byteslice(1..-1), line_offset)
          else
            emit_body(@pending, line_offset)
          end
          @line_offset = @source_offset = line_offset + @pending.bytesize
          @pending = +"".b
        end
        @yielder.yield([:end_record, nil, @source_offset]) if @in_message
      end

      private

      def separator_prefix?(prefix)
        ENVELOPE_PREFIX.start_with?(prefix)
      end

      def quoted_prefix?(prefix)
        prefix =~ /\A>+(?:F|Fr|Fro|From|From )?\z/
      end

      def quoted_from_line?(line)
        line =~ /\A>+From /
      end

      def handle_separator(line, offset)
        envelope = parse_envelope(line)
        if envelope
          start_message(line, offset, envelope)
        else
          handle_malformed_separator(line, offset)
        end
      end

      def start_message(line, offset, envelope)
        raw_envelope, envelope_from, envelope_date = envelope
        @yielder.yield([:end_record, nil, offset]) if @in_message
        envelope_end_offset = offset + line.bytesize
        @yielder.yield([
          :start, offset, envelope_end_offset, raw_envelope, envelope_from, envelope_date, nil
        ])
        @in_message = true
      end

      def handle_malformed_separator(line, offset)
        action = @on_malformed_separator&.call(line: line, offset: offset) || @malformed_separator

        case action
        when :raise
          raise MalformedSeparatorError.new(
            "invalid mboxrd separator at byte #{offset}: #{line.inspect}", line, offset
          )
        when :message
          @yielder.yield([:end_record, nil, offset]) if @in_message
          @yielder.yield([
            :start, offset, offset + line.bytesize, separator_payload(line), nil, nil, line
          ])
          @in_message = true
        when :body
          unless @in_message
            raise MalformedSeparatorError.new(
              "invalid mboxrd separator before first message at byte #{offset}: #{line.inspect}",
              line, offset
            )
          end
          emit_body(line)
        when :skip
          # Explicitly requested by the caller.
        else
          raise ArgumentError, "unknown malformed separator action: #{action.inspect}"
        end
      end

      def emit_body(part, offset = @offset)
        unless @in_message
          case @leading_content
          when :raise
            raise FormatError, "content before first mboxrd separator at byte #{offset}"
          when :skip
            return
          else
            raise ArgumentError, "unknown leading content action: #{@leading_content.inspect}"
          end
        end

        @yielder.yield([:body, part, nil])
      end

      def parse_envelope(line)
        payload = separator_payload(line)
        element = Mail::EnvelopeFromElement.new(payload)
        [payload, element.address, element.date_time]
      rescue StandardError
        nil
      end

      def separator_payload(line)
        line.byteslice(ENVELOPE_PREFIX.bytesize..-1).chomp("\n".b).chomp("\r".b)
      end
    end
  end
end
