# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Implements RFC 3676 ("The Text/Plain Format and DelSp Parameters",
  # a.k.a. format=flowed) as an explicit, opt-in encoder and decoder.
  #
  # Plain text mail is sometimes sent with "soft" line breaks so the
  # receiving client can rewrap paragraphs to its display width. Reading
  # such a body verbatim shows the sender's physical line breaks. This
  # module converts between the wire format and logical text:
  #
  #   Mail::Flowed.decode("foo \r\nbar\r\n")               # => "foo bar"
  #   Mail::Flowed.encode("foo bar", :width => 10)            # => "foo bar\r\n"
  #   Mail::Flowed.decode(wire, :del_sp => true)              # DelSp handling
  #
  # Decoding rules (RFC 3676 sections 4.1-4.6):
  #
  # * Lines are split on CRLF (a lone CR or LF is also accepted).
  # * The quote depth of a line is the number of ">" characters at the
  #   start of the raw line. Only lines at the same quote depth are
  #   merged.
  # * Space-stuffing is removed: after stripping the quote characters,
  #   one leading space (if present) is deleted. This also removes the
  #   conventional space after the quote characters.
  # * A line whose content ends with a space is "flowed" and is merged
  #   with the following line, unless it is the last line, the signature
  #   separator ("-- "), an empty line, or followed by a line with a
  #   different quote depth, an empty line, or the signature separator.
  # * With DelSp, the single trailing space of a flowed line is deleted
  #   before merging; without DelSp it is kept as content.
  # * Decoded output is joined with "\n".
  #
  # Encoding rules:
  #
  # * Logical lines (paragraphs) are wrapped so that every physical line
  #   fits the configured display width, measured in characters
  #   (grapheme clusters), never bytes, so multibyte characters are
  #   never split. The soft-break marker (and the real space preserved
  #   with DelSp) counts towards the width.
  # * A word longer than the width is never split; it is kept intact on
  #   its own line and allowed to exceed the width.
  # * Lines starting with a space, "From", or ">" are space-stuffed.
  #   Stuffing is applied after wrapping, so a stuffed line may exceed
  #   the width by one character.
  # * Empty logical lines are emitted as empty lines and always
  #   terminate a paragraph. The signature separator "-- " is emitted
  #   verbatim. Trailing whitespace of a logical line is dropped, as it
  #   would be indistinguishable from a soft break on the wire.
  # * Encoded output is joined with CRLF.
  module Flowed
    # Default display width used by .encode (78 columns, leaving room
    # for the trailing soft-break space within the traditional 79).
    DEFAULT_WIDTH = 78

    # The Usenet signature separator is always a fixed line (RFC 3676
    # section 4.6), even though it ends with a space.
    SIGNATURE_SEPARATOR = '-- '

    LINE_BREAK = /\r\n|\r|\n/.freeze

    module_function

    # Decodes RFC 3676 format=flowed text into logical text.
    #
    #   Mail::Flowed.decode("foo \r\nbar\r\n") # => "foo bar"
    #
    # Options:
    # [:del_sp] Decode using the DelSp convention: the trailing space of
    #           a flowed line is deleted before merging. Defaults to
    #           false. When reading a message, pass the value of the
    #           DelSp content-type parameter (see Message#decode_flowed).
    def decode(text, del_sp: false)
      lines = text.to_s.split(LINE_BREAK)

      output = []
      pending = nil
      pending_depth = 0
      flow_into_next = false
      last_index = lines.length - 1

      lines.each_with_index do |raw, index|
        depth, content = split_line(raw)
        signature = (content == SIGNATURE_SEPARATOR)

        if flow_into_next && depth == pending_depth && !signature && !content.empty?
          pending << content
        else
          output << pending unless pending.nil?
          pending = +content
          pending_depth = depth
        end

        flowed = index != last_index && !signature && content.end_with?(' ')
        pending = pending.chop if flowed && del_sp
        flow_into_next = flowed
      end

      output << pending unless pending.nil?
      output.join("\n")
    end

    # Encodes logical text into RFC 3676 format=flowed wire format.
    #
    #   Mail::Flowed.encode("foo bar", :width => 4) # => "foo \r\nbar"
    #
    # Options:
    # [:width]  Display width to wrap at, in characters (grapheme
    #           clusters), including the soft-break marker. Defaults to
    #           DEFAULT_WIDTH. Words longer than the width are kept
    #           intact on their own line and may exceed it.
    # [:del_sp] Encode using the DelSp convention: the space at a break
    #           point is emitted as content followed by a separate
    #           soft-break marker, so decoding with DelSp preserves it.
    #           Defaults to false.
    def encode(text, width: DEFAULT_WIDTH, del_sp: false)
      width = width.to_i
      raise ArgumentError, 'width must be at least 1' if width < 1

      logical_lines = text.to_s.split(LINE_BREAK, -1)
      logical_lines.pop if logical_lines.length > 1 && logical_lines.last.empty?

      physical = logical_lines.flat_map { |line| wrap_line(line, width, del_sp) }
      physical.map { |line| space_stuff(line) }.join("\r\n")
    end

    # Splits a raw line into its quote depth and its content with
    # space-stuffing removed.
    def split_line(line) # :nodoc:
      depth = 0
      depth += 1 while line[depth] == '>'
      content = line[depth..-1] || +''
      content = content[1..-1] || +'' if content.start_with?(' ')
      [depth, content]
    end

    # Wraps one logical line into physical lines that fit the width.
    def wrap_line(line, width, del_sp) # :nodoc:
      return [line] if line.empty? || line == SIGNATURE_SEPARATOR

      leading = line[/\A +/].to_s
      words = line[leading.length..-1].to_s.split(/ +/).reject(&:empty?)
      return [leading] if words.empty?

      # Room reserved on flowed lines for the soft-break marker (and,
      # with DelSp, the real space preserved at the break point).
      reserve = del_sp ? 2 : 1

      groups = []
      current = leading.empty? ? nil : leading.dup

      words.each do |word|
        if current.nil? || current !~ /[^ ]/
          # Never break before the first word of a line; a word longer
          # than the width is kept intact and allowed to exceed it.
          current = current ? current << word : word.dup
        elsif display_width(current) + 1 + display_width(word) + reserve <= width
          current << ' ' << word
        else
          groups << current
          current = word.dup
        end
      end
      groups << current

      groups.each_with_index.map do |group, index|
        if index < groups.length - 1
          del_sp ? group + '  ' : group + ' '
        else
          group
        end
      end
    end

    # Prefixes a space to lines that would otherwise be misparsed:
    # lines starting with a space, "From" (mbox separator protection),
    # or ">" (would look quoted).
    def space_stuff(line) # :nodoc:
      if line.start_with?(' ', '>', 'From')
        ' ' + line
      else
        line
      end
    end

    # Width of a string in characters (grapheme clusters), never bytes,
    # so multibyte characters are never split when wrapping.
    def display_width(string) # :nodoc:
      string.each_grapheme_cluster.size
    end
  end
end
