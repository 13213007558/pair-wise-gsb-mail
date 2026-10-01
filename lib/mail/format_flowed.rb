# encoding: utf-8
# frozen_string_literal: true

module Mail
  # RFC 3676 ("format=flowed") support for text/plain bodies.
  #
  # +decode+ turns the physical lines of a <tt>text/plain; format=flowed</tt>
  # body back into logical paragraphs, each tagged with its quote depth.
  # +encode+ wraps logical paragraphs into physical lines again at a given
  # width. +rewrap+ combines both to reflow a received body.
  #
  #   paragraphs = Mail::FormatFlowed.decode(body, del_sp: false)
  #   Mail::FormatFlowed.encode(paragraphs, width: 72)
  #   Mail::FormatFlowed.rewrap(body, width: 72)
  module FormatFlowed
    include Mail::Constants

    # RFC 5322 hard limit on physical line length, in octets.
    HARD_LIMIT = 998

    # RFC 3676 recommends wrapping between columns 66 and 78.
    DEFAULT_WIDTH = 78

    # The signature separator is a fixed line by definition (RFC 3676 4.3).
    SIGNATURE_SEPARATOR = '-- '.freeze

    # A logical paragraph of a format=flowed body: the text left over after
    # flowed physical lines have been stitched back together, plus the quote
    # depth of the lines it was read from. Blank lines and the signature
    # separator are represented as paragraphs of their own so decoding and
    # re-encoding preserve the structure of the message.
    class Paragraph
      attr_accessor :quote_depth, :text

      def initialize(quote_depth, text)
        @quote_depth = quote_depth
        @text = text
      end

      def ==(other)
        other.is_a?(Paragraph) &&
          quote_depth == other.quote_depth &&
          text == other.text
      end
      alias_method :eql?, :==

      def blank?
        text.empty?
      end

      def signature_separator?
        text == SIGNATURE_SEPARATOR
      end
    end

    class << self
      # Decode a format=flowed body into an array of Paragraph.
      #
      # With +del_sp: false+ (the default) the trailing space of a flowed
      # line is kept when lines are joined. With +del_sp: true+ it is
      # deleted, which lets CJK text be broken at any character.
      def decode(text, del_sp: false)
        paragraphs = []
        buffer = nil
        buffer_depth = 0
        flush = lambda do
          paragraphs << Paragraph.new(buffer_depth, buffer) if buffer
          buffer = nil
        end

        physical_lines(text).each do |raw|
          depth, content = split_quote(raw)
          content = content[1..-1].to_s if content.start_with?(' ')

          if content == SIGNATURE_SEPARATOR || content.empty?
            # The signature separator and blank lines are fixed lines and
            # terminate any paragraph in progress.
            flush.call
            paragraphs << Paragraph.new(depth, content)
            next
          end

          flowed = content.end_with?(' ')
          # Never join across quote depths: a depth change ends the
          # paragraph even if the previous line was flowed.
          flush.call if buffer && buffer_depth != depth

          piece = flowed && del_sp ? content[0...-1] : content
          if buffer
            buffer << piece
          else
            buffer = piece.dup
            buffer_depth = depth
          end
          flush.call unless flowed
        end
        flush.call
        paragraphs
      end

      # Encode paragraphs into a format=flowed body wrapped at +width+
      # bytes, measured on the encoded output including quote prefixes and
      # the trailing space of flowed lines. UTF-8 characters are never
      # split. Content that cannot be folded within the soft width (a word
      # longer than +width+) is kept intact on its own fixed line, but no
      # physical line ever exceeds the RFC 5322 hard limit of 998 octets.
      #
      # Accepts an array of Paragraph, or a String of logical paragraphs
      # (one per line, with optional ">" quote prefixes).
      def encode(paragraphs, width: DEFAULT_WIDTH, del_sp: false)
        paragraphs = parse(paragraphs) if paragraphs.is_a?(String)
        width = [width, HARD_LIMIT].min

        lines = []
        paragraphs.each do |paragraph|
          prefix = paragraph.quote_depth > 0 ? ('>' * paragraph.quote_depth) + ' ' : +''
          if paragraph.blank?
            lines << prefix.rstrip
          elsif paragraph.signature_separator?
            lines << prefix + SIGNATURE_SEPARATOR
          else
            wrap(paragraph.text, prefix, width, del_sp, lines)
          end
        end
        lines.join(Constants::CRLF) << Constants::CRLF
      end

      # Decode a format=flowed body and re-encode it at +width+ bytes.
      def rewrap(text, width: DEFAULT_WIDTH, del_sp: false)
        encode(decode(text, del_sp: del_sp), width: width, del_sp: del_sp)
      end

      private

      def physical_lines(text)
        text.to_s.split(/\r\n|\r|\n/)
      end

      # Strip the quote indicators: each ">" plus one optional following
      # space. Returns [quote_depth, content].
      def split_quote(line)
        depth = 0
        while line.start_with?('>')
          depth += 1
          line = line[1..-1].to_s
          line = line[1..-1].to_s if line.start_with?(' ')
        end
        [depth, line]
      end

      # Parse a plain string into paragraphs, one per line.
      def parse(text)
        physical_lines(text).map do |line|
          depth, content = split_quote(line)
          Paragraph.new(depth, content)
        end
      end

      def wrap(text, prefix, width, del_sp, lines)
        text = text.rstrip
        current = nil

        text.split(/ /, -1).each do |word|
          if !line_fits?(word, prefix, width)
            # A word that cannot fit within the soft width on its own.
            emit_line(lines, prefix, current, true) if current && !current.empty?
            if del_sp
              # DelSp=yes lets us break anywhere; split on UTF-8 character
              # boundaries and let the decoder delete the flow spaces.
              pieces = byte_chunks(word, chunk_budget(prefix, width))
              pieces[0...-1].each { |piece| emit_line(lines, prefix, piece, true) }
              current = pieces[-1]
            elsif word.bytesize > chunk_budget(prefix, HARD_LIMIT)
              # Obey the hard limit even though it costs the word its
              # integrity; each piece is flowed on to the next.
              pieces = byte_chunks(word, chunk_budget(prefix, HARD_LIMIT))
              pieces[0...-1].each { |piece| emit_line(lines, prefix, piece, true) }
              current = pieces[-1]
            else
              # Keep the word intact on its own line, preserving its
              # semantics even though the line exceeds the soft width.
              current = word
            end
          elsif current.nil?
            current = word
          elsif line_fits?(current + ' ' + word, prefix, width)
            current = current + ' ' + word
          else
            emit_line(lines, prefix, current, true)
            current = word
          end
        end
        emit_line(lines, prefix, current || +'', false)
      end

      # Reserve one byte for the trailing space of a flowed line and one
      # for possible space-stuffing.
      def chunk_budget(prefix, limit)
        [limit - prefix.bytesize - 2, 1].max
      end

      def line_fits?(content, prefix, width)
        prefix.bytesize + stuffed(content).bytesize + 1 <= width
      end

      def emit_line(lines, prefix, content, flowed)
        line = prefix + stuffed(content)
        line += ' ' if flowed
        lines << line
      end

      # Space-stuff lines that would otherwise be misparsed on receipt:
      # lines starting with "From ", ">" or a space (RFC 3676 4.4).
      def stuffed(content)
        if content.start_with?(' ', '>', 'From ')
          ' ' + content
        else
          content
        end
      end

      # Split into chunks of at most +max_bytes+ without cutting a UTF-8
      # character in half.
      def byte_chunks(str, max_bytes)
        str = str.dup.force_encoding(Encoding::UTF_8) if str.encoding == Encoding::BINARY
        chunks = []
        current = +''
        str.each_char do |char|
          if !current.empty? && current.bytesize + char.bytesize > max_bytes
            chunks << current
            current = +''
          end
          current << char
        end
        chunks << current unless current.empty?
        chunks
      end
    end
  end
end
