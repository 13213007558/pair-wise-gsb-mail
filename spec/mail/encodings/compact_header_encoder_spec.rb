# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'
require 'mail/encodings/compact_header_encoder'

RSpec.describe Mail::Encodings::CompactHeaderEncoder do
  def encode(value, name = 'Subject', limit = 78)
    described_class.encode(value, name, limit)
  end

  def check(value, limit = 78)
    out = encode(value, 'Subject', limit)
    decoded = Mail::Field.parse(out).decoded
    expect(decoded).to eq(value)
    lines = out.chomp.split("\r\n")
    expect(lines.map(&:length).max).to be <= limit
    expect(lines[1..].to_a.all? { |l| l.start_with?(' ') || l.start_with?("\t") }).to eq(true)
    out.scan(/=\?[^?\r\n]*\?[QB]\?[^?\r\n]*\?=/).each do |word|
      expect(word.length).to be <= 75
    end
    out
  end

  describe "basic encoding" do
    it "leaves plain ASCII unencoded" do
      expect(encode("Hello Frank")).to eq("Subject: Hello Frank")
    end

    it "encodes a single non-ASCII character with B when shorter" do
      out = check("中")
      expect(out).to include("=?UTF-8?B?")
    end

    it "uses Q for a word containing many spaces" do
      # With enough spaces in one encoded word, Q (space -> 1 byte "_") is
      # shorter than Base64 (always 4/3 expansion). Force the spaces into a
      # single word by using a field-start WSP run adjacent to CJK.
      s = (" " * 18 + "中").dup.force_encoding("UTF-8")
      out = check(s)
      expect(out).to include("=?UTF-8?Q?")
    end

    it "uses B when it is shorter than Q for dense CJK" do
      out = check("全部中文")
      expect(out).to include("=?UTF-8?B?")
    end
  end

  describe "space and tab preservation" do
    it "preserves spaces around encoded words" do
      check("a 中 b")
      check("中 a")
      check("a 中")
    end

    it "preserves tabs" do
      check("a\tb 中 c\t\td")
    end

    it "preserves leading and trailing whitespace" do
      check(" 中")
      check("中 ")
      check(" 中 ")
    end

    it "preserves multiple consecutive spaces and tabs" do
      check("a  中")
      check("中  a")
      check("x \t 中  \t  y")
    end

    it "preserves whitespace in a long folded field" do
      check(("a 中 b " * 5) + "z")
    end
  end

  describe "folding and length limits" do
    it "keeps every physical line at or below 78 by default" do
      check("中" * 60)
      check("a " * 30 + "中" * 30 + " z" * 30)
    end

    it "respects a custom line limit" do
      s = "中" * 40
      out = check(s, 40)
      out.chomp.split("\r\n").each { |l| expect(l.length).to be <= 40 }
    end

    it "includes the field name prefix in the line budget" do
      s = "abcdefgh " * 8 + "中"
      out = check(s)
      out.chomp.split("\r\n").each { |l| expect(l.length).to be <= 78 }
    end

    it "does not split a UTF-8 character" do
      s = ("a" * 70) + "中"
      out = check(s)
      expect(Mail::Field.parse(out).decoded).to eq(s)
    end
  end

  describe "encoded-word constraints" do
    it "never emits an encoded word longer than 75 characters" do
      ["中" * 100, "a 中 b " * 20 + "z", "x" * 300].each do |s|
        s.force_encoding("UTF-8")
        check(s)
      end
    end
  end

  describe "Q versus B choice" do
    it "uses B for pure CJK" do
      b_out = check("中" * 10)
      expect(b_out.scan(/\?B\?/).size).to be >= 1
      expect(b_out.scan(/\?Q\?/).size).to eq(0)
    end

    it "mixes Q and B across words when beneficial" do
      check("æøå 中")
    end
  end

  describe "over-long raw tokens" do
    it "word-encodes an ASCII token longer than a physical line" do
      check("x" * 100)
      check("ab " + "y" * 90)
      check("a" * 100 + "中")
      check("中" + "a" * 100)
    end
  end

  describe "emoji (4-byte UTF-8)" do
    it "round-trips a long subject containing emoji" do
      check("emoji 😀 test " + "x" * 100 + " 日本語")
    end
  end

  describe "minimality for short strings" do
    # Independent exhaustive enumeration of raw/encoded-word partitions with
    # fold choices, validated by decoding with the real mail gem.
    def exhaustive_min(value, name = 'Subject')
      require 'base64'
      limit = 78
      chars = value.each_char.to_a
      n = chars.size
      qp = ->(bytes) {
        bytes.map { |b|
          if b == 0x20 then '_'
          elsif (33..126).include?(b) && ![0x3D, 0x3F, 0x5F].include?(b) then b.chr
          else '=%02X' % b end
        }.join
      }
      best = Float::INFINITY
      qb = ->(b) { (b == 0x20 || ((33..126).include?(b) && ![0x3D, 0x3F, 0x5F].include?(b))) ? 1 : 3 }

      evaluate_wire = lambda do |parts|
        # parts: array of [kind,string]; build wire, optionally folding at
        # each raw WSP piece; validate length/decode
        raw_wsp_indexes = []
        atoms = []
        parts.each_with_index do |(kind, str), idx|
          if kind == :raw
            str.scan(/[ \t]+|[^ \t]+/).each do |tok|
              if tok =~ /\A[ \t]+\z/
                raw_wsp_indexes << atoms.size
              end
              atoms << tok
            end
          else
            atoms << str
          end
        end
        # which raw WSP atoms become fold leaders
        count = raw_wsp_indexes.size
        (0..count).each do |nf|
          raw_wsp_indexes.combination(nf).each do |folded|
            folded = folded.to_h { |x| [x, true] }
            wire = +''
            line = +''
            atoms.each_with_index do |a, idx|
              if folded[idx]
                next if line.empty?
                wire << line << "\r\n"
                line = +a
              else
                line << a
              end
            end
            wire << line
            lines = wire.split("\r\n")
            next if lines.any? { |l| l.length > limit }
            next if (lines[1..] || []).any? { |l| !(l.start_with?(' ') || l.start_with?("\t")) }
            next if wire.scan(/=\?[^?\r\n]*\?[QB]\?[^?\r\n]*\?=/).any? { |w| w.length > 75 }
            dec = begin
                    Mail::Field.parse("#{name}: #{wire}\r\n").decoded
                  rescue StandardError
                    nil
                  end
            best = wire.bytesize if dec == value && wire.bytesize < best
          end
        end
      end

      recurse = nil
      recurse = lambda do |pos, parts|
        if pos == n
          evaluate_wire.call(parts)
          return
        end
        c = chars[pos]
        if c.ascii_only? && c != "\r" && c != "\n"
          j = pos + 1
          while j < n && chars[j].ascii_only? && chars[j] != "\r" && chars[j] != "\n"
            j += 1
          end
          # raw segment [pos..k) for every k (so a word can also start inside
          # a raw run via a different partition)
          (pos+1..j).each do |k|
            recurse.call(k, parts + [[:raw, chars[pos...k].join]])
          end
        end
        ((pos + 1)..n).each do |k|
          bytes = chars[pos...k].join.bytes
          next if bytes.size > 45
          next unless (pos...k).any? { |z|
            !(chars[z].ascii_only? && chars[z] != "\r" && chars[z] != "\n") }
          ql = bytes.sum { |b| qb.call(b) }
          bl = 4 * ((bytes.size + 2) / 3)
          [[:Q, ql], [:B, bl]].each do |mode, payload_len|
            wlen = 12 + payload_len
            next if wlen > 75
            payload = mode == :Q ? qp.call(bytes) : ::Base64.strict_encode64(bytes.pack('C*'))
            recurse.call(k, parts + [[:word, "=?UTF-8?#{mode}?#{payload}?="]])
          end
        end
      end
      recurse.call(0, [])
      best
    end

    it "matches the exhaustive optimum for a corpus of short strings" do
      alphabet = ['a', '=', ' ', '中', 'æ']
      srand(4242)
      checked = 0
      80.times do
        len = rand(1..6)
        s = Array.new(len) { alphabet.sample }.join.dup.force_encoding("UTF-8")
        min = exhaustive_min(s)
        next if min == Float::INFINITY
        out = encode(s)
        checked += 1
        expect(out.bytesize - "Subject: ".bytesize).to eq(min),
          "src=#{s.inspect} out=#{out.inspect} min=#{min}"
      end
      expect(checked).to be > 30
    end
  end

  describe "integration with UnstructuredField" do
    after { Mail.defaults { compact_header_encoding false } }

    it "is used when compact_header_encoding is enabled" do
      Mail.defaults { compact_header_encoding true }
      field = Mail::UnstructuredField.new("Subject", "中")
      expect(field.encoded).to include("=?UTF-8?B?")
    end

    it "keeps the legacy behaviour when disabled" do
      Mail.defaults { compact_header_encoding false }
      field = Mail::UnstructuredField.new("Subject", "中")
      expect(field.encoded).to include("=?UTF-8?Q?")
    end

    it "honours the configured physical line limit" do
      Mail.defaults do
        compact_header_encoding true
        unstructured_header_line_length 50
      end
      out = Mail::UnstructuredField.new("Subject", "中" * 40).encoded
      out.chomp.split("\r\n").each { |l| expect(l.length).to be <= 50 }
    end
  end
end
