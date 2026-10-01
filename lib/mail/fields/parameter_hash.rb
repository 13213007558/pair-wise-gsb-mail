# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/indifferent_hash'
require 'mail/encodings'

module Mail
  # ParameterHash is an intelligent Hash that allows you to add
  # parameter values including the MIME extension paramaters that
  # have the name*0="blah", name*1="bleh" keys, and will just return
  # a single key called name="blahbleh" and do any required un-encoding
  # to make that happen
  #
  # Parameters are defined in RFC2045. Split keys are in RFC2231.
  class ParameterHash < IndifferentHash #:nodoc:
    def [](key_name)
      key_pattern = Regexp.escape(key_name.to_s)
      sections = Hash.new { |h, idx| h[idx] = [] }
      encoded_only = nil
      exact = nil

      each do |k, v|
        case k
        when /\A#{key_pattern}\*(?<section>\d+)(?<encoded>\*)?\z/i
          sections[Regexp.last_match[:section].to_i] <<
            [k, v, !Regexp.last_match[:encoded].nil?]
        when /\A#{key_pattern}\*\z/i
          encoded_only = [k, v]
        when /\A#{key_pattern}\z/i
          exact = k
        end
      end

      if encoded_only
        string, encoding = split_charset_language(encoded_only.last.to_s)
        return Mail::Encodings.param_decode(string, encoding)
      end

      # Malformed continuation sections (e.g. no section 0): fall back to
      # the plain "name=" value, if any.
      decoded_sections = decode_sections(sections) unless sections.empty?
      return decoded_sections if decoded_sections

      # Just dealing with a single, unextended value pair
      super(exact || key_name)
    end

    def encoded
      map.sort_by { |a| a.first.to_s }.map! do |key_name, value|
        unless value.ascii_only?
          value = Mail::Encodings.param_encode(value)
          key_name = "#{key_name}*"
        end
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join(";\r\n\s")
    end

    def decoded
      map.sort_by { |a| a.first.to_s }.map! do |key_name, value|
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join("; ")
    end

    private

    # Assemble and decode RFC 2231 continuation sections.
    #
    # +sections+ maps a section number to a list of [key, value, encoded?]
    # triples (a list because malformed messages can repeat a section).
    #
    # The sequence must start at section 0 and be contiguous: sections are
    # joined in numerical order (so 10 sorts after 9 rather than before 2),
    # and assembly stops at the first gap. Sections past the gap, and any
    # value without a section 0, are ignored and +nil+ is returned so the
    # caller can fall back to a plain "name=" value if one exists.
    #
    # If a section number appears more than once, the entries are kept in
    # key order and the first one wins, making the result deterministic.
    def decode_sections(sections)
      chosen = {}
      sections.each do |index, triples|
        chosen[index] = triples.sort_by { |key, _, _| key.to_s }.first
      end

      return nil unless chosen.key?(0)

      raw = +"".b
      encoding = nil
      index = 0
      while chosen.key?(index)
        _key, value, encoded = chosen[index]
        part = value.to_s
        if index.zero? && encoded
          part, encoding = split_charset_language(part)
        end
        raw << (encoded ? percent_decode(part) : part.b)
        index += 1
      end

      charset_decode(raw, encoding)
    end

    # Splits the leading RFC 2231 "charset'language'value" prefix off an
    # encoded value. Charset and language are both optional, so a value
    # without the two apostrophes is returned untouched with no charset.
    def split_charset_language(string)
      if (match = string.match(/\A(?:([^']*)'[^']*')?(.*)\z/m))
        [match[2], match[1]]
      else
        [string, nil]
      end
    end

    # Percent-decodes a section while working in binary so that multibyte
    # sequences (e.g. UTF-8) which straddle a section boundary survive the
    # concatenation done by the caller.
    def percent_decode(string)
      string.b.gsub(/%([0-9A-Fa-f]{2})/) { [$1].pack('H2') }
    end

    def charset_decode(string, encoding)
      if encoding && !encoding.empty?
        string = Utilities.charset_encoder.encode(string, encoding)
      end
      transcode_to_scrubbed_utf8(string)
    end

    def transcode_to_scrubbed_utf8(str)
      decoded = str.encode(Encoding::UTF_8, :undef => :replace,
                           :invalid => :replace, :replace => "�")
      if decoded.valid_encoding?
        decoded
      else
        decoded.encode(Encoding::UTF_16LE, :invalid => :replace,
                       :replace => "�").encode(Encoding::UTF_8)
      end
    end
  end
end
