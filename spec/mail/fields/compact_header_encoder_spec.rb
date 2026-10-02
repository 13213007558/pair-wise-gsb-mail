# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require File.expand_path('../support/short_header_optimal', __FILE__)

RSpec.describe Mail::CompactHeaderEncoder do
  def encode(str, field_name: 'Subject', line_length: 78)
    described_class.encode(str.dup.force_encoding('UTF-8'),
                          first_line_width: "#{field_name}: ".length,
                          line_length: line_length)
  end

  # Decode the produced field body the same way a parsed header does: unfold
  # CRLF+WSP and run the RFC 2047 value decoder.
  def roundtrip(str, field_name: 'Subject', line_length: 78)
    body = encode(str, field_name: field_name, line_length: line_length)
    expect(body).to be_a(String)
    unfolded = body.gsub("\r\n ".b, "\r\n ".b) # folding stays for value_decode
    Mail::Encodings.value_decode(unfolded)
  end

  def encoded_words(body)
    body.scan(/=\?UTF-8\?[QB]\?[^?]*\?=/m)
  end

  describe "plain ASCII" do
    it "leaves short all-ASCII values untouched" do
      expect(encode("Just a plain subject")).to eq "Just a plain subject"
    end

    it "returns an empty string for an empty value" do
      expect(encode("")).to eq ""
    end

    it "does not encode when the value fits the physical line" do
      expect(encode("ascii only, no special chars")).not_to include("=?UTF-8")
    end
  end

  describe "Q versus B selection" do
    it "uses base64 when it is shorter than quoted-printable" do
      # A single non-ASCII char: B "w6k=" is shorter than Q "=C3=A9".
      body = encode("café")
      expect(body).to include("=?UTF-8?B?")
      expect(body).not_to include("=?UTF-8?Q?")
    end

    it "does not encode trailing printable ASCII that can stay literal" do
      # é alone is one encoded-word; adding a trailing printable run only
      # costs bytes if encoded, so a space + ASCII stays outside the word.
      body = encode("café here")
      expect(body).to end_with(" here")
      expect(encoded_words(body).length).to eq 1
    end

    it "encodes dense Chinese with base64" do
      body = encode("中文测试主题")
      expect(body).to include("=?UTF-8?B?")
      expect(roundtrip("中文测试主题")).to eq "中文测试主题"
    end
  end

  describe "byte minimality (exhaustive on short strings)" do
    it "is byte-minimal on an exhaustive set of random short headers" do
      rng = Random.new(20260930)
      alphabet = ["a", " ", "\t", "é", "中", "😀", "\n", "=", "?"]
      checked = 0
      500.times do
        n = rng.rand(1..8)
        str = Array.new(n) { alphabet.sample(random: rng) }.join.dup.force_encoding("UTF-8")
        optimum = ShortHeaderOptimal.optimal(str)
        got = encode(str)
        if optimum
          expect(got).not_to be_nil
          expect(got.bytesize).to eq(optimum.bytesize)
          expect(Mail::Header.new("Subject: #{got}")["Subject"].decoded).to eq str
          checked += 1
        end
      end
      expect(checked).to be > 100
    end
  end


  describe "RFC 2047 limits" do
    it "keeps every encoded-word at most 75 characters" do
      s = ("中" * 60).dup.force_encoding('UTF-8')
      encoded_words(encode(s)).each do |ew|
        expect(ew.bytesize).to be <= 75
      end
    end

    it "keeps every physical line at most the configured length" do
      s = ("word word 中 " * 20).dup.force_encoding('UTF-8')
      encode(s).lines.each do |line|
        expect(line.chomp.bytesize).to be <= 78
      end
    end

    it "counts the field-name prefix on the first line" do
      s = ("word " * 30).dup.force_encoding('UTF-8') + "中"
      body = encode(s, field_name: 'X-Long-Field-Name')
      ("X-Long-Field-Name: " + body).lines.each do |line|
        expect(line.chomp.bytesize).to be <= 78
      end
    end

    it "never splits a multibyte UTF-8 character" do
      s = ("é中😀" * 20).dup.force_encoding('UTF-8')
      expect(roundtrip(s)).to eq s
    end
  end

  describe "line folding" do
    it "folds a long subject across several physical lines" do
      s = ("word " * 30).dup.force_encoding('UTF-8') + "中"
      body = encode(s)
      expect(body.lines.length).to be > 1
      body.lines.each { |l| expect(l.chomp.bytesize).to be <= 78 }
      expect(Mail::Encodings.value_decode(body)).to include("中")
    end

    it "folds before an encoded-word using the continuation WSP as separator" do
      s = ("abcdef " * 20).dup.force_encoding('UTF-8') + "中"
      body = encode(s)
      expect(body).to include("\r\n =?UTF-8?")
    end
  end

  describe "whitespace preservation" do
    it "preserves a run of spaces and tabs after decoding" do
      s = "a 中b and   multiple spaces\tkeep".dup.force_encoding('UTF-8')
      expect(roundtrip(s)).to eq s
    end

    it "absorbs leading whitespace into the first encoded-word so it survives" do
      s = "  lead café".dup.force_encoding('UTF-8')
      body = encode(s)
      # The leading spaces must be inside the encoded-word, not bare.
      expect(body).to start_with("=?UTF-8?")
      header = Mail::Header.new("Subject: #{body}")
      expect(header["Subject"].decoded).to eq s
    end

    it "preserves interior whitespace between plain text and an encoded-word" do
      s = "café  and more text here".dup.force_encoding('UTF-8')
      expect(roundtrip(s)).to eq s
    end
  end

  describe "configuration" do
    after { Mail.defaults { header_line_length 78 } }

    it "honors a custom header line length" do
      s = ("word word 中 "*10).dup.force_encoding('UTF-8')
      body = encode(s, line_length: 40)
      body.lines.each { |l| expect(l.chomp.bytesize).to be <= 40 }
      expect(Mail::Encodings.value_decode(body)).to include("中")
    end

    it "falls back when the value cannot fit (returns nil)" do
      # A single encoded-word cannot fit a first line shorter than its width.
      s = "中".dup.force_encoding('UTF-8')
      expect(encode(s, field_name: 'X'*70, line_length: 72)).to be_nil
    end
  end
end

RSpec.describe "compact header encoding integration" do
  after { Mail.defaults { compact_header_encoding false } }

  it "is disabled by default and keeps the historical Q encoding" do
    Mail.defaults { compact_header_encoding false }
    field = Mail::UnstructuredField.new("Subject", "café".dup.force_encoding("UTF-8"))
    expect(field.encoded).to eq "Subject: =?UTF-8?Q?caf=C3=A9?=\r\n"
  end

  it "uses the compact encoder when enabled through configuration" do
    Mail.defaults { compact_header_encoding true }
    field = Mail::UnstructuredField.new("Subject", "café".dup.force_encoding("UTF-8"))
    expect(field.encoded).to include("=?UTF-8?B?")
    expect(field.decoded).to eq "café"
  end

  it "does not change all-ASCII fields when enabled" do
    Mail.defaults { compact_header_encoding true }
    field = Mail::UnstructuredField.new("Subject", "just plain ascii")
    expect(field.encoded).to eq "Subject: just plain ascii\r\n"
  end

  it "can be set per Mail.defaults block without leaking" do
    Mail.defaults { compact_header_encoding true }
    expect(Mail::Configuration.instance.compact_header_encoding).to eq true
    Mail.defaults { compact_header_encoding false }
    expect(Mail::Configuration.instance.compact_header_encoding).to eq false
  end
end
