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

    # name       -> a plain parameter                 (RFC 2045)
    # name*      -> a single extended parameter        (RFC 2231 section 3)
    # name*N     -> the Nth continuation (raw bytes)   (RFC 2231 section 4.1)
    # name*N*    -> the Nth extended continuation      (RFC 2231 section 4.2)
    EXTENDED_KEY = /\A(.+?)\*(?:(\d+)(\*?))?\z/i

    def [](key_name)
      key_pattern = Regexp.escape(key_name.to_s)
      pairs = []
      exact = nil

      each do |k, v|
        if k =~ /\A#{key_pattern}(\*|$)/i
          if $1 == Constants::ASTERISK
            pairs << [k, v]
          else
            exact = k
          end
        end
      end

      if pairs.empty? # Just dealing with a single value pair
        super(exact || key_name)
      else # Dealing with a single extended value or RFC 2231 continuations
        decode_extended_pairs(pairs) || super(exact || key_name)
      end
    end

    def encoded
      map.sort_by { |key_name, _| parameter_sort_key(key_name) }.map! do |key_name, value|
        unless value.ascii_only?
          value = Mail::Encodings.param_encode(value)
          key_name = "#{key_name}*"
        end
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join(";\r\n\s")
    end

    def decoded
      map.sort_by { |key_name, _| parameter_sort_key(key_name) }.map! do |key_name, value|
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join("; ")
    end

    private

    # Sort keys by parameter name (case-insensitive), then by RFC 2231
    # section number so that filename*10 sorts after filename*2. Plain
    # parameters and single extended (name*) parameters sort before any
    # numbered sections of the same name.
    def parameter_sort_key(key_name)
      key_name = key_name.to_s
      md = EXTENDED_KEY.match(key_name)
      base_name = (md ? md[1] : key_name).downcase
      section = md && md[2] ? md[2].to_i : -1
      [base_name, section, key_name.downcase]
    end

    # Assemble and decode the extended (starred) parameters found for a
    # single attribute name.
    #
    # Two shapes are handled (see RFC 2231 sections 3, 4.1 and 4.2):
    #
    #   name*=charset'lang'value            a single extended parameter
    #   name*0*=charset'lang'value ; name*1=value ; name*2*=...
    #                                       a continued parameter
    #
    # Continuation sections are ordered numerically, not lexicographically,
    # so 0,1,...,9,10,11. Sections carrying a trailing '*' are
    # percent-decoded; plain sections contribute their raw bytes. The raw
    # bytes of all sections are joined before any charset conversion, so a
    # multi-byte UTF-8 character split across a section boundary decodes
    # correctly. The charset'language' prefix is only recognised on
    # section 0 of a continuation or on a name* parameter.
    #
    # Malformed input is handled deterministically:
    # * Sections are ordered numerically and any missing section numbers
    #   are skipped (the surviving bytes are still joined in order). This
    #   keeps decoding best-effort and stable regardless of insertion
    #   order.
    # * A duplicated section number (e.g. name*1 and name*1*) resolves
    #   deterministically: the extended (trailing '*') value wins.
    # * A name*= extended parameter is preferred over a plain name=
    #   parameter when both are present, as required by RFC 2231.
    # * Unrelated keys (neither name= nor name*=) are left untouched.
    def decode_extended_pairs(pairs)
      continuations = {}
      single = nil

      pairs.each do |key, value|
        md = EXTENDED_KEY.match(key.to_s)
        next unless md
        if md[2]
          index = md[2].to_i
          extended = md[3] == Constants::ASTERISK
          # Extended (trailing *) occurrences win over plain duplicates.
          continuations[index] = [value, extended] if extended || !continuations.key?(index)
        else
          single = value
        end
      end

      if continuations.empty?
        return nil unless single
        string, charset = split_extended_value(single)
        return decode_assembled(Mail::Utilities.percent_decode(string).b, charset)
      end

      bytes = ''.b
      charset = nil

      continuations.keys.sort.each do |index|
        value, extended = continuations[index]
        if index.zero?
          value, charset = split_extended_value(value)
        end
        # Only extended sections are percent-encoded; plain sections
        # contribute their raw bytes verbatim.
        bytes << (extended ? Mail::Utilities.percent_decode(value) : value).to_s.b
      end

      decode_assembled(bytes, charset)
    end

    # Split an RFC 2231 value into its (data, charset) pair. The language
    # tag is discarded. Values without a charset'language' prefix are
    # returned verbatim with a nil charset.
    def split_extended_value(value)
      if (md = value.match(/\A([\w\-]*)'([^']*)'(.*)\z/m))
        [md[3], md[1].empty? ? nil : md[1]]
      else
        [value, nil]
      end
    end

    def decode_assembled(bytes, charset)
      Mail::Encodings.param_decode_assembled(bytes, charset)
    end
  end
end
