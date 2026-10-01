# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::FormatFlowed do
  def paragraph(depth, text)
    Mail::FormatFlowed::Paragraph.new(depth, text)
  end

  def texts(paragraphs)
    paragraphs.map { |p| [p.quote_depth, p.text] }
  end

  describe "decode" do
    it "joins flowed lines into a logical paragraph (DelSp=no)" do
      body = "The quick brown fox \r\njumps over"
      expect(texts(described_class.decode(body))).to eq [[0, "The quick brown fox jumps over"]]
    end

    it "deletes the trailing space of flowed lines with DelSp=yes" do
      body = "中文长句 \r\n子继续"
      expect(texts(described_class.decode(body, del_sp: true))).to eq [[0, "中文长句子继续"]]
    end

    it "keeps the trailing space of flowed lines with DelSp=no" do
      body = "word one \r\ntwo"
      expect(texts(described_class.decode(body, del_sp: false))).to eq [[0, "word one two"]]
    end

    it "does not join fixed lines" do
      expect(texts(described_class.decode("one\r\ntwo"))).to eq [[0, "one"], [0, "two"]]
    end

    it "tracks quote depth and never joins across depths" do
      body = "> outer \r\n>> inner\r\n> back"
      expect(texts(described_class.decode(body))).to eq [[1, "outer "], [2, "inner"], [1, "back"]]
    end

    it "joins flowed lines within the same quote depth" do
      body = "> quoted \r\n> text"
      expect(texts(described_class.decode(body))).to eq [[1, "quoted text"]]
    end

    it "removes space-stuffing from lines starting with a space, From or >" do
      body = " From the start\r\n >not a quote\r\n  indented"
      expect(texts(described_class.decode(body))).to eq [[0, "From the start"], [0, ">not a quote"], [0, " indented"]]
    end

    it "treats '-- ' as a fixed signature separator that is never joined" do
      body = "intro \r\n-- \r\nsignature"
      # DelSp=no keeps the trailing space of the unjoinable flowed line.
      expect(texts(described_class.decode(body))).to eq [[0, "intro "], [0, "-- "], [0, "signature"]]
    end

    it "does not join a flowed line onto the signature separator with DelSp=yes either" do
      body = "intro \r\n-- \r\nsignature"
      expect(texts(described_class.decode(body, del_sp: true))).to eq [[0, "intro"], [0, "-- "], [0, "signature"]]
    end

    it "keeps blank lines as paragraph separators" do
      body = "first \r\npara\r\n\r\nsecond"
      expect(texts(described_class.decode(body))).to eq [[0, "first para"], [0, ""], [0, "second"]]
    end

    it "keeps blank quoted lines with their quote depth" do
      body = "> quoted\r\n>\r\n> more"
      expect(texts(described_class.decode(body))).to eq [[1, "quoted"], [1, ""], [1, "more"]]
    end

    it "accepts LF-only line endings" do
      expect(texts(described_class.decode("a \nb"))).to eq [[0, "a b"]]
    end
  end

  describe "encode" do
    it "wraps flowed paragraphs at the given width in encoded bytes" do
      encoded = described_class.encode([paragraph(0, "The quick brown fox jumps over the lazy dog")], width: 40)
      expect(encoded).to eq "The quick brown fox jumps over the lazy \r\ndog\r\n"
    end

    it "counts the quote prefix towards the width" do
      encoded = described_class.encode([paragraph(2, "aa bb cc dd ee ff gg hh ii jj")], width: 20)
      encoded.split("\r\n").each do |line|
        expect(line.bytesize).to be <= 20
        expect(line).to start_with(">> ")
      end
    end

    it "space-stuffs lines starting with From, > or a space" do
      encoded = described_class.encode([
        paragraph(0, "From the start"),
        paragraph(0, ">looks quoted"),
        paragraph(0, " indented"),
      ], width: 40)
      expect(encoded).to eq " From the start\r\n >looks quoted\r\n  indented\r\n"
    end

    it "emits the signature separator as a fixed line" do
      encoded = described_class.encode([paragraph(0, "hi"), paragraph(0, "-- "), paragraph(0, "sig")], width: 40)
      expect(encoded).to eq "hi\r\n-- \r\nsig\r\n"
    end

    it "emits blank paragraphs as blank lines and quoted blank lines as bare quote marks" do
      encoded = described_class.encode([paragraph(0, "a"), paragraph(0, ""), paragraph(1, ""), paragraph(1, "b")], width: 40)
      expect(encoded).to eq "a\r\n\r\n>\r\n> b\r\n"
    end

    it "keeps an unbreakable word intact on its own fixed line (DelSp=no)" do
      word = "x" * 60
      encoded = described_class.encode([paragraph(0, word)], width: 40)
      expect(encoded).to eq word + "\r\n"
    end

    it "flows an unbreakable word mid-paragraph without altering it (DelSp=no)" do
      word = "x" * 60
      paragraphs = described_class.decode(described_class.encode([paragraph(0, "before #{word} after")], width: 40))
      expect(paragraphs).to eq [paragraph(0, "before #{word} after")]
    end

    it "never exceeds the 998 octet hard limit, even for huge words" do
      word = "x" * 3000
      encoded = described_class.encode([paragraph(0, word)], width: 78)
      encoded.split("\r\n").each { |line| expect(line.bytesize).to be <= 998 }
    end

    it "breaks long words on UTF-8 character boundaries with DelSp=yes" do
      word = "中" * 400
      encoded = described_class.encode([paragraph(0, word)], width: 78, del_sp: true)
      lines = encoded.split("\r\n")
      lines.each do |line|
        expect(line.bytesize).to be <= 78
        expect(line.valid_encoding?).to be true
      end
      expect(described_class.decode(encoded, del_sp: true)).to eq [paragraph(0, word)]
    end

    it "accepts a plain string of logical paragraphs" do
      encoded = described_class.encode("> quoted\nplain", width: 40)
      expect(encoded).to eq "> quoted\r\nplain\r\n"
    end
  end

  describe "round trip" do
    let(:paragraphs) do
      [
        paragraph(0, "The quick brown fox jumps over the lazy dog"),
        paragraph(0, ""),
        paragraph(1, "quoted text here"),
        paragraph(2, "deep quote"),
        paragraph(1, "-- "),
        paragraph(1, "back to outer quote"),
        paragraph(0, "这是一段很长的中文段落没有空格"),
      ]
    end

    let(:fixture) do
      "The quick brown fox jumps over the lazy \r\n" \
      "dog\r\n" \
      "\r\n" \
      "> quoted text here\r\n" \
      ">> deep quote\r\n" \
      "> -- \r\n" \
      "> back to outer quote\r\n" \
      "这是一段很长的中文段落没有空格\r\n"
    end

    it "decodes a two-level quoted body with signature and Chinese paragraph" do
      expect(described_class.decode(fixture)).to eq paragraphs
    end

    it "re-encodes to the identical body" do
      expect(described_class.encode(described_class.decode(fixture), width: 40)).to eq fixture
    end

    it "round-trips paragraphs through encode and decode" do
      expect(described_class.decode(described_class.encode(paragraphs, width: 40))).to eq paragraphs
    end

    it "round-trips a long Chinese paragraph with DelSp=yes" do
      chinese = paragraph(1, "没有空格的中文长段落需要按指定的宽度折行而且不能截断任何一个字符")
      encoded = described_class.encode([chinese], width: 40, del_sp: true)
      encoded.split("\r\n").each { |line| expect(line.bytesize).to be <= 40 }
      expect(described_class.decode(encoded, del_sp: true)).to eq [chinese]
    end

    it "rewraps a received body at a new width" do
      rewrapped = described_class.rewrap(fixture, width: 30)
      rewrapped.split("\r\n").each { |line| expect(line.bytesize).to be <= 45 } # fixed CJK line may exceed the soft width
      expect(described_class.decode(rewrapped)).to eq paragraphs
    end
  end
end
