# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Streaming reader and writer for the "mboxrd" mailbox format.
  #
  # mboxrd stores messages concatenated in a single file. Each message is
  # introduced by a separator line of the form:
  #
  #   From <envelope sender> <envelope date>
  #
  # and any content line beginning with "From " (or one or more ">" followed
  # by "From ") is escaped by prepending a single ">" when written, and has
  # exactly one ">" removed when read. This makes the escaping reversible.
  #
  # The reader streams the source in chunks so mailboxes larger than memory
  # can be imported, yields one Record per message as soon as it is complete,
  # and reports the byte range each message occupied in the original file.
  #
  #   Mail::Mbox::Reader.open('archive.mbox') do |reader|
  #     reader.each do |record|
  #       record.envelope_sender # => "alice@example.com"
  #       record.envelope_date   # => "Thu Jan  2 03:04:05 2020"
  #       record.byte_range      # => 0...4096 (separator line included)
  #       record.content_range   # => 48...4096 (message content only)
  #       record.to_mail         # => Mail::Message
  #     end
  #   end
  #
  #   Mail::Mbox::Writer.new(File.open('out.mbox', 'wb')).tap do |writer|
  #     writer.write(mail.to_s, sender: 'alice@example.com', date: Time.now)
  #   end
  module Mbox
    # Raised when a line that looks like an mbox separator does not carry a
    # parseable envelope sender and date, or when content appears before the
    # first separator. Carries the byte +offset+ and the offending +line+.
    class InvalidSeparatorError < StandardError
      attr_reader :offset, :line

      def initialize(message, offset: nil, line: nil)
        @offset = offset
        @line = line
        super(message)
      end
    end

    # A single message read from an mbox stream.
    class Record
      # Envelope sender taken from the "From " separator line. +nil+ for
      # anonymous records (see Reader's :keep_as_body strategy).
      attr_reader :envelope_sender

      # Raw envelope date string taken from the separator line.
      attr_reader :envelope_date

      # The message content with mboxrd ">" escaping removed. Binary string.
      attr_reader :data

      # Byte range in the original file covering the separator line and the
      # (still escaped) message content.
      attr_reader :byte_range

      # Byte range in the original file covering only the message content
      # (as stored, i.e. still escaped).
      attr_reader :content_range

      def initialize(envelope_sender, envelope_date, data, byte_range, content_range)
        @envelope_sender = envelope_sender
        @envelope_date = envelope_date
        @data = data
        @byte_range = byte_range
        @content_range = content_range
      end

      # The envelope date parsed as a DateTime, or +nil+ if it does not parse.
      def envelope_time
        return @envelope_time if defined?(@envelope_time)
        @envelope_time =
          begin
            DateTime.parse(envelope_date.to_s)
          rescue StandardError
            nil
          end
      end

      # Parse the message content as a Mail::Message.
      def to_mail
        Mail.new(data)
      end
    end

    # Streams an mboxrd source, yielding one Record per message.
    #
    # The source is any object responding to +read(length)+ (e.g. an IO
    # opened in binary mode). Input is consumed in +chunk_size+ byte blocks;
    # chunk boundaries may fall anywhere, including in the middle of a line,
    # and a final message without a trailing newline is still yielded.
    #
    # A line beginning with "From " that does not parse as
    # "From <sender> <date>", or content appearing before the first
    # separator, is handled according to +on_invalid_separator+:
    #
    # [:raise]        (default) raise InvalidSeparatorError
    # [:skip]         drop the offending line
    # [:keep_as_body] append the offending line to the current message; if no
    #                 message is open yet, start an anonymous record whose
    #                 envelope sender and date are +nil+
    class Reader
      include Enumerable

      DEFAULT_CHUNK_SIZE = 64 * 1024

      SEPARATOR = /\AFrom (\S+) (.+)\z/.freeze
      UNESCAPE_FROM = /\A>(?=>*From )/.freeze

      INVALID_SEPARATOR_STRATEGIES = [:raise, :skip, :keep_as_body].freeze

      def self.open(path, **options)
        File.open(path, 'rb') do |file|
          return yield new(file, **options)
        end
      end

      def initialize(source, chunk_size: DEFAULT_CHUNK_SIZE, on_invalid_separator: :raise)
        unless INVALID_SEPARATOR_STRATEGIES.include?(on_invalid_separator)
          raise ArgumentError, "on_invalid_separator must be one of #{INVALID_SEPARATOR_STRATEGIES.inspect}"
        end
        @source = source
        @chunk_size = chunk_size
        @on_invalid_separator = on_invalid_separator
      end

      def each
        return enum_for(:each) unless block_given?

        pending = nil
        each_line_with_offset do |line, offset|
          if line.start_with?('From ')
            separator = parse_separator(line)
            if separator
              yield pending.to_record if pending
              pending = PendingRecord.new(separator[0], separator[1], offset, offset + line.bytesize)
            else
              pending = handle_invalid_line(line, offset, pending)
            end
          elsif pending
            pending.append(line)
          else
            pending = handle_invalid_line(line, offset, nil)
          end
        end
        yield pending.to_record if pending
        self
      end

      private

      # Accumulates the content of one message while tracking byte offsets.
      class PendingRecord
        def initialize(envelope_sender, envelope_date, record_start, content_start)
          @envelope_sender = envelope_sender
          @envelope_date = envelope_date
          @record_start = record_start
          @content_start = content_start
          @content_end = content_start
          @data = +''.b
        end

        # Stores the line with mboxrd escaping removed while accounting the
        # raw (still escaped) bytes against the content range.
        def append(line)
          @data << line.sub(UNESCAPE_FROM, '')
          @content_end += line.bytesize
        end

        def to_record
          Record.new(@envelope_sender, @envelope_date, @data,
                     @record_start...@content_end, @content_start...@content_end)
        end
      end
      private_constant :PendingRecord

      def parse_separator(line)
        match = SEPARATOR.match(strip_line_ending(line))
        match && [match[1], match[2]]
      end

      def strip_line_ending(line)
        line.chomp("\n").chomp("\r")
      end

      def handle_invalid_line(line, offset, pending)
        case @on_invalid_separator
        when :raise
          raise InvalidSeparatorError.new(
            "malformed mbox separator or stray content at byte #{offset}: #{line.inspect}",
            offset: offset, line: line)
        when :skip
          pending
        when :keep_as_body
          pending ||= PendingRecord.new(nil, nil, offset, offset)
          pending.append(line)
          pending
        end
      end

      # Yields each line (including its trailing newline, except possibly for
      # the final line) together with its absolute byte offset in the source.
      def each_line_with_offset
        buffer = +''.b
        offset = 0
        while (chunk = @source.read(@chunk_size))
          buffer << chunk.force_encoding(Encoding::BINARY)
          while (index = buffer.index("\n"))
            line = buffer.slice!(0, index + 1)
            yield line, offset
            offset += line.bytesize
          end
        end
        yield buffer, offset unless buffer.empty?
      end
    end

    # Appends messages to an mboxrd destination.
    #
    # Each call to #write emits a "From <sender> <date>" separator line
    # followed by the message content with mboxrd escaping applied: any
    # content line matching /\A>*From / gets one ">" prepended, so Reader
    # restores the original bytes exactly. A trailing newline is appended
    # when the content does not end with one, so the next separator always
    # starts on its own line.
    class Writer
      ESCAPABLE_FROM = /\A>*From /.freeze

      def initialize(io)
        @io = io
      end

      # Writes +data+ as one mbox message. +sender+ is the envelope sender
      # recorded on the separator line (defaults to "-"); +date+ is a String
      # used verbatim, or a Time/DateTime formatted in ctime style
      # ("Thu Jan  2 03:04:05 2020"). Returns self so calls can be chained.
      def write(data, sender: '-', date: nil)
        sender = sender.to_s
        if sender.empty? || sender =~ /\s/
          raise ArgumentError, 'envelope sender must be a single token without whitespace'
        end
        date = format_date(date)
        if date =~ /[\r\n]/
          raise ArgumentError, 'envelope date must not contain newlines'
        end

        @io.write("From #{sender} #{date}\n")
        data = data.to_s
        unless data.empty?
          data.each_line do |line|
            @io.write(line =~ ESCAPABLE_FROM ? ">#{line}" : line)
          end
          @io.write("\n") unless data.end_with?("\n")
        end
        self
      end

      private

      def format_date(date)
        case date
        when nil
          format_date(Time.now)
        when String
          date
        when ->(value) { value.respond_to?(:strftime) }
          date.strftime('%a %b %e %H:%M:%S %Y')
        else
          date.to_s
        end
      end
    end
  end
end
