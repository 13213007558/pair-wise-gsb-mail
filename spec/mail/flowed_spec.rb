# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Flowed do
  describe '.decode' do
    it 'joins soft line breaks into logical lines' do
      expect(Mail::Flowed.decode("foo \r\nbar\r\n")).to eq "foo bar"
    end

    it 'keeps hard line breaks' do
      expect(Mail::Flowed.decode("foo\r\nbar\r\n")).to eq "foo\nbar"
    end

    it 'accepts lone LF line breaks' do
      expect(Mail::Flowed.decode("foo \nbar\n")).to eq "foo bar"
    end

    it 'returns an empty string for empty input' do
      expect(Mail::Flowed.decode('')).to eq ''
    end

    it 'does not flow the last line' do
      expect(Mail::Flowed.decode("foo \r\n")).to eq "foo "
    end

    describe 'DelSp' do
      it 'deletes the trailing space of flowed lines' do
        expect(Mail::Flowed.decode("foo \r\nbar\r\n", del_sp: true)).to eq "foobar"
      end

      it 'preserves a real space encoded before the soft break marker' do
        expect(Mail::Flowed.decode("foo  \r\nbar\r\n", del_sp: true)).to eq "foo bar"
      end
    end

    describe 'quote depth' do
      it 'merges lines at the same quote depth' do
        expect(Mail::Flowed.decode("> foo \r\n> bar\r\n")).to eq "foo bar"
      end

      it 'merges nested quotes at the same depth' do
        expect(Mail::Flowed.decode(">> foo \r\n>> bar\r\n")).to eq "foo bar"
      end

      it 'does not merge lines at different quote depths' do
        expect(Mail::Flowed.decode("> foo \r\nbar\r\n")).to eq "foo \nbar"
        expect(Mail::Flowed.decode("> foo \r\n>> bar\r\n")).to eq "foo \nbar"
      end

      it 'removes the conventional space after the quote characters' do
        expect(Mail::Flowed.decode("> foo\r\n")).to eq "foo"
      end

      it 'handles quoted lines without a space after the quote characters' do
        expect(Mail::Flowed.decode(">foo \r\n>bar\r\n")).to eq "foo bar"
      end
    end

    describe 'space-stuffing' do
      it 'removes stuffing from lines starting with a space' do
        expect(Mail::Flowed.decode(" foo\r\n")).to eq "foo"
      end

      it 'keeps one leading space of a doubly stuffed line' do
        expect(Mail::Flowed.decode("  foo\r\n")).to eq " foo"
      end

      it 'removes stuffing from lines starting with From' do
        expect(Mail::Flowed.decode(" From foo\r\n")).to eq "From foo"
      end

      it 'removes stuffing from lines starting with > without quoting them' do
        expect(Mail::Flowed.decode(" >foo\r\n")).to eq ">foo"
      end
    end

    describe 'signature separator' do
      it 'does not treat the signature separator as a flowed line' do
        expect(Mail::Flowed.decode("foo\r\n-- \r\nbar\r\n")).to eq "foo\n-- \nbar"
      end

      it 'does not merge a flowed line into the signature separator' do
        expect(Mail::Flowed.decode("foo \r\n-- \r\n")).to eq "foo \n-- "
      end

      it 'recognizes a quoted signature separator' do
        expect(Mail::Flowed.decode("> foo\r\n> -- \r\n> bar\r\n")).to eq "foo\n-- \nbar"
      end
    end

    describe 'empty lines' do
      it 'does not merge a flowed line with an empty line' do
        expect(Mail::Flowed.decode("foo \r\n\r\nbar\r\n")).to eq "foo \n\nbar"
      end

      it 'preserves an empty line before flowed lines' do
        expect(Mail::Flowed.decode("\r\nfoo \r\nbar\r\n")).to eq "\nfoo bar"
      end

      it 'preserves empty lines between paragraphs' do
        expect(Mail::Flowed.decode("foo\r\n\r\nbar\r\n")).to eq "foo\n\nbar"
      end
    end
  end

  describe '.encode' do
    it 'wraps paragraphs at the given display width' do
      encoded = Mail::Flowed.encode("foo bar baz qux quux", width: 10)
      expect(encoded).to eq "foo bar \r\nbaz qux \r\nquux"
    end

    it 'emits CRLF line breaks' do
      expect(Mail::Flowed.encode("foo bar", width: 4)).to eq "foo \r\nbar"
    end

    it 'defaults to a 78 column display width' do
      encoded = Mail::Flowed.encode('a' + ' b' * 50)
      expect(encoded.split("\r\n").first.length).to eq 78
    end

    it 'raises for an invalid width' do
      expect { Mail::Flowed.encode('foo', width: 0) }.to raise_error(ArgumentError)
    end

    it 'never splits a word longer than the width' do
      encoded = Mail::Flowed.encode("supercalifragilisticexpialidocious ok", width: 10)
      expect(encoded).to eq "supercalifragilisticexpialidocious \r\nok"
    end

    it 'does not break multibyte characters when wrapping' do
      encoded = Mail::Flowed.encode("你好 世界 你好 世界", width: 5)
      expect(encoded).to eq "你好 \r\n世界 \r\n你好 \r\n世界"
    end

    it 'space-stuffs lines starting with a space' do
      expect(Mail::Flowed.encode(" indented")).to eq "  indented"
    end

    it 'space-stuffs lines starting with From' do
      expect(Mail::Flowed.encode("From foo")).to eq " From foo"
    end

    it 'space-stuffs lines starting with >' do
      expect(Mail::Flowed.encode("> quoted")).to eq " > quoted"
    end

    it 'emits the signature separator verbatim' do
      expect(Mail::Flowed.encode("foo\n-- \nbar")).to eq "foo\r\n-- \r\nbar"
    end

    it 'keeps empty lines between paragraphs' do
      expect(Mail::Flowed.encode("foo\n\nbar")).to eq "foo\r\n\r\nbar"
    end

    it 'encodes breaks with a real space and a marker when DelSp is on' do
      encoded = Mail::Flowed.encode("foo bar baz", width: 5, del_sp: true)
      expect(encoded).to eq "foo  \r\nbar  \r\nbaz"
    end

    it 'round-trips through decode' do
      source = "The quick brown fox jumps over the lazy dog. " * 3
      expect(Mail::Flowed.decode(Mail::Flowed.encode(source, width: 20))).to eq source.strip
    end

    it 'round-trips through decode with DelSp' do
      source = "The quick brown fox jumps over the lazy dog. " * 3
      encoded = Mail::Flowed.encode(source, width: 20, del_sp: true)
      expect(Mail::Flowed.decode(encoded, del_sp: true)).to eq source.strip
    end

    it 'round-trips lines that need space-stuffing' do
      source = "From here\n> there\n indented"
      expect(Mail::Flowed.decode(Mail::Flowed.encode(source))).to eq source
    end
  end

  describe Mail::Message do
    it 'detects format=flowed from the content type' do
      mail = Mail.new("Content-Type: text/plain; format=flowed\r\n\r\nfoo \r\nbar\r\n")
      expect(mail.format_flowed?).to be true
      expect(mail.flowed_del_sp?).to be false
    end

    it 'detects the DelSp parameter from the content type' do
      mail = Mail.new("Content-Type: text/plain; format=flowed; delsp=yes\r\n\r\nfoo\r\n")
      expect(mail.flowed_del_sp?).to be true
    end

    it 'decodes a raw CRLF format=flowed message on demand' do
      raw = "Content-Type: text/plain; format=flowed\r\n" \
            "\r\n" \
            "The quick brown fox \r\n" \
            "jumps over the lazy \r\n" \
            "dog.\r\n"
      mail = Mail.new(raw)
      expect(mail.decode_flowed).to eq "The quick brown fox jumps over the lazy dog."
    end

    it 'honours DelSp when decoding a message' do
      raw = "Content-Type: text/plain; format=flowed; delsp=yes\r\n" \
            "\r\n" \
            "foo  \r\n" \
            "bar\r\n"
      expect(Mail.new(raw).decode_flowed).to eq "foo bar"
    end

    it 'decodes flowed parts of a multipart message' do
      raw = "Content-Type: multipart/mixed; boundary=abc\r\n" \
            "\r\n" \
            "--abc\r\n" \
            "Content-Type: text/plain; format=flowed\r\n" \
            "\r\n" \
            "foo \r\nbar\r\n" \
            "--abc--\r\n"
      mail = Mail.new(raw)
      expect(mail.parts.first.format_flowed?).to be true
      expect(mail.parts.first.decode_flowed).to eq "foo bar"
    end

    it 'leaves the default #decoded output untouched' do
      raw = "Content-Type: text/plain; format=flowed\r\n\r\nfoo \r\nbar\r\n"
      mail = Mail.new(raw)
      expect(mail.decoded).to eq "foo \nbar\n"
    end

    it 'does not treat plain text as flowed' do
      mail = Mail.new("Content-Type: text/plain\r\n\r\nfoo \r\nbar\r\n")
      expect(mail.format_flowed?).to be false
      expect(mail.decoded).to eq "foo \nbar\n"
    end
  end
end
