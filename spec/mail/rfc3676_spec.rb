# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::RFC3676 do
  describe '.decode' do
    it 'joins soft line breaks without removing a DelSp=no space' do
      decoded = described_class.decode("first \nsecond")

      expect(decoded).to eq("first second")
      expect(decoded.paragraphs.length).to eq(1)
      expect(decoded.paragraphs.first.quote_depth).to eq(0)
      expect(decoded.paragraphs.first).not_to be_fixed
    end

    it 'removes soft line break spaces with DelSp=yes' do
      decoded = described_class.decode("first \nsecond", del_sp: true)

      expect(decoded).to eq("firstsecond")
    end

    it 'restores space-stuffed body text' do
      decoded = described_class.decode(" From a mbox file\n > quoted-looking text")

      expect(decoded).to eq("From a mbox file\n> quoted-looking text")
    end

    it 'keeps fixed lines and signature separators as separate paragraphs' do
      source = "normal \nparagraph\nfixed line\n-- \nsignature\n"
      decoded = described_class.decode(source)

      expect(decoded).to eq("normal paragraph\nfixed line\n-- \nsignature")
      expect(decoded.paragraphs.map(&:to_s)).to eq(["normal paragraph", "fixed line", "-- ", "signature"])
      expect(decoded.paragraphs.map(&:fixed?)).to eq([false, true, true, true])
      expect(decoded.paragraphs.map(&:signature?)).to eq([nil, nil, true, nil])
    end

    it 'does not join across quote levels or paragraph separators' do
      source = "> first \n> line\n\n>> second \n>> line\n> middle"
      decoded = described_class.decode(source)

      expect(decoded).to eq("> first line\n\n> > second line\n> middle")
      expect(decoded.paragraphs.map(&:quote_depth)).to eq([1, 0, 2, 1])
    end

    it 'does not join a soft line into a signature separator' do
      decoded = described_class.decode("abc \n-- \nsignature")

      expect(decoded).to eq("abc\n-- \nsignature")
      expect(decoded.paragraphs.map(&:signature?)).to eq([nil, true, nil])
    end

    it 'preserves the real trailing space at the end of a flowed paragraph' do
      expect(described_class.decode("trailing  ")).to eq("trailing ")
      expect(described_class.decode("trailing  ", del_sp: true)).to eq("trailing ")
    end
  end

  describe '.encode' do
    it 'adds DelSp=no soft breaks and space-stuffing' do
      encoded = described_class.encode("a b " * 7, width: 20)

      expect(encoded).to eq("a b a b a b a b a b \r\na b a b  ")
      encoded.each_line("\r\n") do |line|
        expect(line.chomp("\r\n").bytesize).to be <= 20
      end
    end

    it 'does not insert spaces when DelSp=yes wraps between words' do
      encoded = described_class.encode("a b " * 7, del_sp: true, width: 20)

      expect(encoded).to eq("a b a b a b a b a b \r\n  a b a b  ")
      expect(described_class.decode(encoded, del_sp: true)).to eq("a b " * 7)
    end

    it 'uses byte width without splitting a multibyte character' do
      encoded = described_class.encode("中文字符内容", del_sp: true, width: 4)

      expect(encoded).to eq("中 \r\n文 \r\n字 \r\n符 \r\n内 \r\n容")
      expect(encoded.lines.map { |line| line.chomp("\r\n").bytesize }).to all(be <= 4)
      expect(described_class.decode(encoded, del_sp: true)).to eq("中文字符内容")
    end

    it 'preserves fixed content at the soft width but hard wraps at the hard limit' do
      fixed = described_class::Paragraph.new("abcdefghij", fixed: true)

      expect(described_class.encode(fixed, width: 4, hard_width: 8)).to eq("abcdefgh\r\nij")

      long = described_class::Paragraph.new("中中中", fixed: true)
      encoded = described_class.encode(long, width: 1, hard_width: 5)

      expect(encoded).to eq("中\r\n中\r\n中")
      expect(encoded.bytes).not_to include(0xE4.chr.b)
    end

    it 'keeps hard wraps under the SMTP limit for long reflowable DelSp=yes content' do
      encoded = described_class.encode("中" * 400, del_sp: true, width: 1000)

      expect(encoded.lines.map { |line| line.chomp("\r\n").bytesize }.max).to eq(997)
      expect(described_class.decode(encoded, del_sp: true)).to eq("中" * 400)
    end

    it 'hard splits unbreakable DelSp=no content and preserves the hard paragraph break' do
      encoded = described_class.encode("a" * 1000, width: 1000)

      expect(encoded.lines.map { |line| line.chomp("\r\n").bytesize }).to eq([998, 2])
      expect(described_class.decode(encoded)).to eq("#{'a' * 998}\naa")
    end

    it 'protects lines beginning with space, greater-than, or From' do
      encoded = described_class.encode(" leading\n> literal\nFrom sender", width: 78)

      expect(encoded).to eq("  leading\r\n > literal\r\n From sender")
    end

    it 'encodes quote levels and quoted signature separators' do
      decoded = described_class.decode("> -- \n> name")
      encoded = described_class.encode(decoded, width: 78)

      expect(encoded).to eq("> -- \r\n> name")
    end

    it 'round trips two quote levels around a signature and a long Chinese paragraph' do
      source = "outer \nline\n\n> > 中文长段落内容中文长段落内容 \n> > 继续中文长段落内容\n\n> -- \n> 签名\n\n> quoted \n> reply\n"
      decoded = described_class.decode(source)
      physical = described_class.encode(decoded, del_sp: true, width: 18)

      physical.each_line("\r\n") do |line|
        expect(line.chomp("\r\n").bytesize).to be <= 18
      end
      expect(described_class.decode(physical, del_sp: true)).to eq(decoded)
      expect(physical).to include("> > 中文长段")
      expect(physical).to include("> -- \r\n")
      expect(decoded.paragraphs.map(&:quote_depth)).to eq([0, 0, 2, 0, 1, 1, 0, 1])
    end
  end

  describe 'Mail integration' do
    it 'decodes flowed text and re-encodes it at the configured width' do
      mail = Mail.new(
        "Content-Type: text/plain; charset=UTF-8; format=flowed\r\n" \
        "Content-Transfer-Encoding: 8bit\r\n" \
        "\r\n" \
        "first \nsecond\n"
      )

      expect(mail.decoded).to eq("first second")
      mail.body.flowed_width = 12
      encoded = Mail.new(mail.encoded)

      expect(encoded.content_type_parameters['format']).to eq('flowed')
      expect(encoded.body.decoded).to eq("first second")
      expect(encoded.decoded).to eq("first second")
    end

    it 'preserves DelSp=yes semantics through quoted-printable transport' do
      body = "first second中文长段落"
      mail = Mail.new do |message|
        message.content_type 'text/plain; charset=UTF-8; format=flowed; delsp=yes'
        message.body body
        message.body.flowed_width = 9
      end
      reparsed = Mail.new(mail.encoded)

      expect(reparsed.content_type_parameters).to include('format' => 'flowed', 'delsp' => 'yes')
      expect(['quoted-printable', 'base64']).to include(reparsed.content_transfer_encoding)
      expect(reparsed.decoded).to eq(body)
    end
  end

end
