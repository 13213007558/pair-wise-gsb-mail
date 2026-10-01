# encoding: utf-8
# frozen_string_literal: true

module Mail
  # RFC 3676 format=flowed text/plain encoding and decoding.
  module RFC3676
    DEFAULT_WIDTH = 78
    HARD_WIDTH = 998

    class Paragraph < String
      attr_reader :quote_depth
      attr_accessor :fixed, :open

      def initialize(text = "", quote_depth: 0, fixed: false)
        super(text)
        @quote_depth = quote_depth
        @fixed = fixed
        @open = false
      end

      def signature?
        @signature
      end

      def signature
        @signature
      end

      def signature=(value)
        @signature = value
        @fixed = true if value
      end

      def signature!
        self.signature = true
      end

      def fixed?
        @fixed
      end

      def open?
        @open
      end
    end

    class LogicalText < String
      attr_reader :paragraphs

      def initialize(paragraphs)
        @paragraphs = paragraphs
        super(paragraphs.map { |paragraph| RFC3676.send(:render_paragraph, paragraph) }.join("\n"))
      end
    end

    class << self
      def decode(input, del_sp: false, delsp: nil)
        del_sp = delsp unless delsp.nil?
        paragraphs = []
        current = nil

        physical_lines(input).each do |line|
          depth, text = quote_prefix(line)
          text = text.slice(1..-1).to_s if text.start_with?(" ")

          if text.empty?
            current = Paragraph.new("", quote_depth: depth, fixed: true)
            paragraphs << current
            next
          end

          signature = text == "-- "
          soft = !signature && text.end_with?(" ")
          text = text.chomp(" ") if soft
          current.open = false if signature && current && current.open?

          current = nil if current && !current.open?

          if !signature && current && current.quote_depth == depth && !current.signature?
            current << (del_sp ? text : " #{text}")
            current.fixed = false
          else
            current = Paragraph.new(text, quote_depth: depth, fixed: !soft)
            paragraphs << current
          end

          current.signature! if signature
          current.open = soft
        end

        append_final_space(current, del_sp)
        LogicalText.new(paragraphs)
      end

      def encode(input, del_sp: false, delsp: nil, width: DEFAULT_WIDTH, hard_width: HARD_WIDTH)
        del_sp = delsp unless delsp.nil?
        width, hard_width = validate_widths(width, hard_width)
        if input.is_a?(LogicalText)
          paragraphs = input.paragraphs
        elsif input.is_a?(Paragraph)
          paragraphs = [input]
        elsif input.respond_to?(:paragraphs)
          paragraphs = Array(input.paragraphs)
        else
          paragraphs = logical_paragraphs(input.to_s)
        end

        lines = paragraphs.flat_map do |paragraph|
          encode_paragraph(paragraph, del_sp, width, hard_width)
        end

        result = lines.join("\r\n")
        result.force_encoding(Encoding::BINARY) if input.to_s.encoding == Encoding::BINARY
        result
      end

      private

      def physical_lines(input)
        return [] if input.nil? || input.to_s.empty?

        text = input.to_s.gsub(/\r\n|\r/, "\n")
        text = text[0...-1] if text.end_with?("\n")
        text.split("\n", -1)
      end

      def quote_prefix(line)
        position = 0
        depth = 0

        while position < line.length && line[position] == ">"
          run = 0
          while position < line.length && line[position] == ">"
            run += 1
            position += 1
          end

          depth += run

          if position < line.length
            return [0, line] unless line[position] == " "

            position += 1
          end
        end

        [depth, line[position..-1].to_s]
      end

      def append_final_space(paragraph, del_sp)
        return unless paragraph && paragraph.open?

        paragraph << " " unless del_sp || paragraph.end_with?(" ")
        paragraph.open = false
      end

      def logical_paragraphs(text)
        return [] if text.empty?

        text.split("\n", -1).map do |line|
          paragraph = Paragraph.new(line, quote_depth: 0)
          paragraph.signature! if line == "-- "
          paragraph
        end
      end

      def validate_widths(width, hard_width)
        [width, hard_width].each do |value|
          unless value.is_a?(Integer) && value > 0
            raise ArgumentError, "width must be a positive integer"
          end
        end

        [[width, hard_width].min, hard_width]
      end

      def encode_paragraph(paragraph, del_sp, width, hard_width)
        prefix = quote_prefix_for_output(paragraph.quote_depth, paragraph)
        return [prefix] if paragraph.empty?
        return [physical_line(prefix, paragraph.to_s, false)] if paragraph.signature?

        if paragraph.fixed?
          return hard_split(prefix, paragraph, hard_width).map { |chunk| physical_line(prefix, chunk, false) }
        end

        segments =
          if del_sp
            del_sp_segments(prefix, paragraph, width, hard_width)
          else
            fixed_width_segments(prefix, paragraph, width, hard_width)
          end

        segments.map { |content, soft| physical_line(prefix, content, soft) }
      end

      def quote_prefix_for_output(depth, paragraph)
        if paragraph.empty?
          ">" * depth
        else
          ("> " * depth)
        end
      end

      def render_paragraph(paragraph)
        "#{quote_prefix_for_output(paragraph.quote_depth, paragraph)}#{paragraph}"
      end

      def physical_line(prefix, content, soft)
        content = " #{content}" if needs_space_stuffing?(content)
        "#{prefix}#{content}#{soft ? " " : ""}"
      end

      def needs_space_stuffing?(content)
        content.start_with?(" ", ">", "From ")
      end

      def del_sp_segments(prefix, content, width, hard_width)
        segments = []
        line = String.new

        each_codepoint(content) do |codepoint|
          candidate = line + codepoint
          if fits?(prefix, candidate, width, candidate.end_with?(" ") ? 2 : 1)
            line = candidate
          elsif line.empty?
            line = candidate
          else
            segments << [line, true]
            line = codepoint
          end
        end

        segments << final_segment(prefix, line, hard_width)
        segments
      end

      def fixed_width_segments(prefix, content, width, hard_width)
        segments = []
        line = String.new
        pending_spaces = 0

        content.scan(/ +|[^ ]+/).each do |token|
          if token.start_with?(" ")
            pending_spaces = token.length
            next
          end

          candidate = line + (" " * pending_spaces) + token
          if line.empty?
            if fits?(prefix, candidate, hard_width, 0)
              line = +candidate
            else
              append_unbreakable(prefix, segments, candidate, hard_width)
              line = String.new
            end
          elsif fits?(prefix, candidate, width, 1)
            line = +candidate
          elsif pending_spaces > 1 && fits?(prefix, line + (" " * pending_spaces) + token, width, 0)
            segments << [line, true]
            append_unbreakable(prefix, segments, (" " * pending_spaces) + token, hard_width)
            line = String.new
          elsif fits?(prefix, line + token, width, 0)
            segments << [line, true]
            line = +token
          else
            segments << [line, true]
            append_unbreakable(prefix, segments, (" " * (pending_spaces - 1)) + token, hard_width)
            line = String.new
          end
          pending_spaces = 0
        end

        if line.empty? && pending_spaces > 0
          append_unbreakable(prefix, segments, " " * pending_spaces, hard_width)
        elsif !line.empty?
          line << " " * pending_spaces
          segments << [line, line.end_with?(" ")]
        end
        segments
      end

      def append_unbreakable(prefix, segments, content, hard_width)
        remainder = content
        until remainder.empty?
          chunk, remainder = hard_chunk(prefix, remainder, hard_width)
          segments << [chunk, false]
        end
      end

      def final_segment(prefix, line, hard_width)
        return ["", false] if line.empty?

        [line, line.end_with?(" ")]
      end

      def hard_split(prefix, content, hard_width)
        chunks = []
        remainder = content

        until remainder.empty?
          chunk, remainder = hard_chunk(prefix, remainder, hard_width)
          chunks << chunk
        end

        chunks
      end

      def hard_chunk(prefix, content, hard_width)
        working = with_utf8(content)
        chunk = String.new

        each_codepoint(working) do |codepoint|
          candidate = chunk + codepoint
          if chunk.empty? || fits?(prefix, candidate, hard_width, 0)
            chunk << codepoint
          else
            remainder = content.byteslice(chunk.bytesize..-1).to_s
            chunk.force_encoding(content.encoding) if content.encoding == Encoding::BINARY
            return [chunk, remainder]
          end
        end

        [chunk.force_encoding(content.encoding), ""]
      end

      def fits?(prefix, content, limit, soft_bytes = 0)
        size = prefix.bytesize + content.bytesize
        size += 1 if needs_space_stuffing?(content)
        size += soft_bytes
        size <= limit
      end

      def each_codepoint(content, &block)
        working = with_utf8(content)
        return enum_for(:each_codepoint, content) unless block

        if working.equal?(content)
          content.each_char(&block)
        else
          working.each_char { |codepoint| yield codepoint.force_encoding(content.encoding) }
        end
      end

      def with_utf8(content)
        if content.encoding == Encoding::BINARY && content.valid_encoding?
          content.dup.force_encoding(Encoding::UTF_8)
        else
          content
        end
      end
    end
  end
end
