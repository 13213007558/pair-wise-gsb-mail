# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Flowed do
  def flowed_mail(body, del_sp: false)
    params = del_sp ? 'format=flowed; delsp=yes' : 'format=flowed'
    Mail.new("To: someone@example.com\r\n" \
             "Content-Type: text/plain; charset=utf-8; #{params}\r\n" \
             "\r\n" +
             body)
  end

  describe '.decode' do
    it 'joins soft line breaks of a raw CRLF format=flowed message' do
      mail = flowed_mail("This is a long paragraph that was \r\n" \
                         "wrapped by the sender and should \r\n" \
                         "be joined again.\r\n")
      expect(mail.content_type_parameters['format']).to eq 'flowed'
     expect(described_class.decode(mail.body.decoded)).to eq \
        'This is a long paragraph that was wrapped by the sender and should be joined again.'
    end

    it 'keeps the soft break space as content without DelSp' do
      mail = flowed_mail("foo \r\nbar\r\n")
      expect(described_class.decode(mail.body.decoded)).to eq 'foo bar'
    end

   it 'deletes the soft break space with DelSp' do
      # With DelSp the trailing space is synthetic; the real space is
      # kept at the start of the continuation line (space-stuffed).
      mail = flowed_mail("foo \r\n  bar\r\n", del_sp: true)
      expect(mail.content_type_parameters['delsp']).to eq 'yes'
      expect(described_class.decode(mail.body.decoded, del_sp: true)).to eq 'foo bar'
    end

    it 'only joins lines at the same quote level' do
      mail = flowed_mail("> first \r\n" \
                         "> second\r\n" \
                         ">> nested \r\n" \
                         ">> quote\r\n" \
                         "> outer again\r\n")
      expect(described_class.decode(mail.body.decoded)).to eq \
        "> first second\n> > nested quote\n> outer again"
    end

    it 'does not join a flowed line with a different quote level' do
      mail = flowed_mail("> quoted \r\nplain\r\n", del_sp: true)
      expect(described_class.decode(mail.body.decoded, del_sp: true)).to eq "> quoted\nplain"
    end

    it 'does not treat the signature separator as a soft break' do
      mail = flowed_mail("Some text \r\n-- \r\nSignature\r\n", del_sp: true)
      expect(described_class.decode(mail.body.decoded, del_sp: true)).to eq \
        "Some text\n-- \nSignature"
    end

    it 'removes space-stuffing from lines starting with a space, From or >' do
      mail = flowed_mail("  leading space\r\n" \
                         " From the start\r\n" \
                         " > not a quote\r\n")
      expect(described_class.decode(mail.body.decoded)).to eq \
        " leading space\nFrom the start\n> not a quote"
    end

    it 'removes space-stuffing inside quoted lines' do
      mail = flowed_mail(">  stuffed\r\n")
      expect(described_class.decode(mail.body.decoded)).to eq '> stuffed'
    end

    it 'does not join a soft break with an empty line' do
      mail = flowed_mail("foo \r\n\r\nbar\r\n", del_sp: true)
      expect(described_class.decode(mail.body.decoded, del_sp: true)).to eq "foo\n\nbar"
    end

    it 'keeps empty lines as paragraph separators' do
      mail = flowed_mail("first paragraph \r\nends here.\r\n\r\nsecond paragraph\r\n")
      expect(described_class.decode(mail.body.decoded)).to eq \
        "first paragraph ends here.\n\nsecond paragraph"
    end

    it 'handles a trailing flowed line at the end of the body' do
      mail = flowed_mail("dangling \r\n", del_sp: true)
      expect(described_class.decode(mail.body.decoded, del_sp: true)).to eq 'dangling'
    end
  end

  describe '.encode' do
    it 'wraps at the configured display width' do
      Mail.defaults { flowed_display_width 10 }
      begin
        expect(described_class.encode('aaaa bbbb cccc dddd eeee')).to eq \
          "aaaa bbbb \r\ncccc dddd \r\neeee"
      ensure
        Mail.defaults { flowed_display_width 78 }
      end
    end

    it 'wraps at an explicitly given width' do
      expect(described_class.encode('aaaa bbbb cccc dddd eeee', width: 15)).to eq \
        "aaaa bbbb cccc \r\ndddd eeee"
    end

    it 'never splits multibyte characters' do
      encoded = described_class.encode('你好世界 你好世界 你好世界 你好', width: 8)
      expect(encoded).to eq "你好世界 \r\n你好世界 \r\n你好世界 你好"
      expect(encoded.valid_encoding?).to be true
      encoded.split("\r\n").each do |line|
        expect(line.length).to be <= 8
      end
      expect(described_class.decode(encoded)).to eq '你好世界 你好世界 你好世界 你好'
    end

    it 'keeps a word longer than the width whole on its own line' do
      encoded = described_class.encode('averyverylongwordthatexceeds ok', width: 10)
      expect(encoded).to eq "averyverylongwordthatexceeds \r\nok"
      expect(described_class.decode(encoded)).to eq 'averyverylongwordthatexceeds ok'
    end

    it 'space-stuffs lines starting with a space, From or >' do
      encoded = described_class.encode(" leading\nFrom here\n> quoted\nplain")
      expect(encoded).to eq "  leading\r\n From here\r\n > quoted\r\nplain"
      expect(described_class.decode(encoded)).to eq " leading\nFrom here\n> quoted\nplain"
    end

    it 'emits the signature separator as a fixed line' do
      encoded = described_class.encode("Some text\n-- \nSignature")
      expect(encoded).to eq "Some text\r\n-- \r\nSignature"
      expect(described_class.decode(encoded)).to eq "Some text\n-- \nSignature"
    end

    it 'encodes DelSp soft breaks with a synthetic trailing space' do
      encoded = described_class.encode('aaaa bbbb cccc dddd eeee', width: 10, del_sp: true)
      expect(encoded).to eq "aaaa bbbb \r\n  cccc \r\n  dddd eeee"
      expect(described_class.decode(encoded, del_sp: true)).to eq 'aaaa bbbb cccc dddd eeee'
    end

    it 'keeps empty lines and paragraphs intact' do
      encoded = described_class.encode("one\r\n\r\ntwo")
      expect(encoded).to eq "one\r\n\r\ntwo"
      expect(described_class.decode(encoded)).to eq "one\n\ntwo"
    end

    it 'round-trips mixed content through decode' do
      text = "Hello world this is a longer paragraph that will be wrapped somewhere.\n\n" \
             "> quoted reply\n-- \nsignature"
      encoded = described_class.encode(text, width: 20)
      expect(described_class.decode(encoded)).to eq text
    end

    it 'round-trips multibyte text with DelSp' do
      text = '你好世界 你好世界 这是一个更长的段落 需要折行处理'
      encoded = described_class.encode(text, width: 12, del_sp: true)
      expect(described_class.decode(encoded, del_sp: true)).to eq text
    end

    it 'raises for an invalid display width' do
      expect { described_class.encode('text', width: 0) }.to raise_error(ArgumentError)
    end
  end

  describe 'opt-in behavior' do
   it 'does not change the default decoding of text/plain bodies' do
     mail = Mail.new("Content-Type: text/plain; format=flowed\r\n\r\nfoo \r\nbar\r\n")
      expect(mail.body.decoded).to eq "foo \nbar\n"
      expect(Mail::Flowed.decode(mail.body.decoded)).to eq 'foo bar'
   end
  end
end
