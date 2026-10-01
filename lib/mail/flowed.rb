# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Explicit RFC 3676 "format=flowed" decoding and encoding for plain text.
  #
  # Some plain text mails write display line breaks as soft breaks
  # (Content-Type: text/plain; format=flowed), so reading the decoded body
  # directly shows extra line breaks. This module joins soft breaks back
  # into paragraphs, and can also generate flowed text. It handles the
  # DelSp parameter, RFC 3676 quote levels and space-stuffing.
  #
  # The interface is strictly opt-in: Mail never applies it to text/plain
  # bodies by itself. Call it only when you know the body is format=flowed:
  #
  #   Mail::Flowed.decode(mail.body.decoded, del_sp: true)
  #   Mail::Flowed.encode(text, width: 72, del_sp: true)
  #
  module Flowed
    include Mail::Constants

    # Fallback display width for .encode, used when no width is given and
    # none is configured with Mail.defaults { flowed_display_width 78 }.
    DEFAULT_WIDTH = 78

    # The signature separator is always a fixed line, never a soft break,
    # even though it ends in a space.
    SIGNATURE_SEPARATOR = '-- '

    # Decodes format=flowed text, joining soft line breaks back into
    # paragraphs.
    #
    # Lines only merge within the same quote level: a quote-depth change,
    # an empty line or the signature separator always ends a paragraph.
    # The quote prefix and one space-stuffed leading space are removed
    # from every line; quote prefixes are normalized to one "> " per
    # level in the output.
    #
    # With del_sp: true (from the DelSp parameter of the Content-Type) the
    # trailing space that marks a soft break is deleted when lines join,
    # otherwise it is kept as content.
    #
    # Returns the decoded text with lines separated by "\n".
    def self.decode(text, del_sp: false)
      lines = text.to_s.split(LAX_CRLF, -1)
      lines.pop if lines.last == ''

      output = []
      paragraph = nil
      paragraph_depth = 0
      paragraph_flowed = false

      flush = lambda do
        if paragraph
          paragraph.chomp!(' ') if paragraph_flowed && del_sp
          output << ('> ' * paragraph_depth) + paragraph
          paragraph = nil
        end
      end

      lines.each do |raw|
        depth, content = analyze_line(raw)
        flowed = content.end_with?(' ') && content != SIGNATURE_SEPARATOR

        if paragraph && paragraph_flowed && depth == paragraph_depth &&
           !content.empty? && content != SIGNATURE_SEPARATOR
          paragraph.chomp!(' ') if del_sp
          paragraph << content
        else
          flush.call
          paragraph = content
          paragraph_depth = depth
        end

        paragraph_flowed = flowed
        flush.call unless flowed
      end
      flush.call

      output.join("\n")
    end

    # Encodes plain text as format=flowed.
    #
    # Paragraphs are wrapped at the configured display width
    # (Mail.defaults { flowed_display_width 78 }, overridable with the
    # width: option) counting characters, so multibyte characters are
    # never split. A word longer than the width is kept whole on its own
    # line, which may then exceed the width.
    #
    # Lines starting with a space, "From " or ">" are space-stuffed.
    # With del_sp: true the space marking a soft break is synthetic and
    # deleted on decode, while real content spaces are kept at the start
    # of the continuation line (protected by space-stuffing). The
    # signature separator is emitted as a fixed line.
    #
    # Returns CRLF-separated lines ready for a text/plain body.
    def self.encode(text, width: nil, del_sp: false)
      width = (width || Mail::Configuration.instance.flowed_display_width).to_i
      if width < 1
        raise ArgumentError, 'display width must be a positive number of characters'
      end

      lines = text.to_s.split(LAX_CRLF, -1)
      lines.pop if lines.last == ''

      output = []
      lines.each do |line|
        if line.empty? || line == SIGNATURE_SEPARATOR
          output << line
        else
          wrap_line(line, width, del_sp).each { |segment| output << space_stuff(segment) }
        end
      end
      output.join(CRLF)
    end

    # Splits one logical line into physical lines of at most +width+
    # characters, breaking at spaces. All segments but the last end with
    # the soft-break space. Words longer than +width+ stay whole.
    def self.wrap_line(line, width, del_sp) # :nodoc:
      segments = []
      rest = line
      while rest.length > width
        idx = rest.rindex(' ', width - 1)
        idx = nil if idx && idx.zero?
        idx ||= rest.index(' ', width)
        break unless idx

        if del_sp
          # Break before the space: the trailing space is synthetic and
          # deleted on decode, the real space starts the next line.
          segments << rest[0...idx] + ' '
          rest = rest[idx..-1]
        else
          segments << rest[0..idx]
          rest = rest[(idx + 1)..-1]
        end
      end
      segments << rest unless rest.empty?
      segments
    end
    private_class_method :wrap_line

    # RFC 3676 space-stuffing: lines starting with a space, ">" or
    # "From " get one extra leading space.
    def self.space_stuff(line) # :nodoc:
      if line.start_with?(' ', '>') || line.start_with?('From ')
        " #{line}"
      else
        line
      end
    end
    private_class_method :space_stuff

    # Returns [quote_depth, content] for a raw line: strips the quote
    # prefix (each ">" plus one optional following space) and undoes
    # one space-stuffed leading space.
    def self.analyze_line(line) # :nodoc:
      depth = 0
      while line.start_with?('>')
        depth += 1
        line = line[1..-1] || ''
        line = line[1..-1] || '' if line.start_with?(' ')
      end
      line = line[1..-1] || '' if line.start_with?(' ')
      [depth, line]
    end
    private_class_method :analyze_line
  end
end
