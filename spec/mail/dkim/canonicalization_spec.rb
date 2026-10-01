# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'

RSpec.describe Mail::DKIM::Canonicalization do
  C = described_class

  def canon_header(name, value, alg)
    C.canonical_header(name, value, alg)
  end

  describe 'to_crlf' do
    it 'normalizes bare LF' do
      expect(C.to_crlf("a\nb")).to eq("a\r\nb".b)
    end

    it 'normalizes bare CR' do
      expect(C.to_crlf("a\rb")).to eq("a\r\nb".b)
    end

    it 'leaves CRLF untouched' do
      expect(C.to_crlf("a\r\nb")).to eq("a\r\nb".b)
    end

    it 'returns binary encoded strings' do
      expect(C.to_crlf('x').encoding).to eq(Encoding::BINARY)
    end
  end

  describe 'simple header' do
    it 'keeps name and value verbatim apart from line folding' do
      expect(canon_header('From', ' a@x.com', :simple)).to eq("From: a@x.com".b)
    end
  end

  describe 'relaxed header' do
    it 'lowercases the name' do
      expect(canon_header('From', 'a@x.com', :relaxed)).to eq('from:a@x.com'.b)
    end

    it 'unfolds and compacts whitespace runs' do
      expect(canon_header('Subject', "Hey \t there", :relaxed))
        .to eq('subject:Hey there'.b)
    end

    it 'strips leading and trailing whitespace from the value' do
      expect(canon_header('X', '  padded  ', :relaxed)).to eq('x:padded'.b)
    end
  end

  describe 'simple body (RFC 6376 3.4.3)' do
    it 'strips all but one trailing CRLF' do
      expect(C.canonical_body("a\r\n\r\n\r\n", :simple)).to eq("a\r\n".b)
    end

    it 'adds a terminating CRLF to a body without one' do
      expect(C.canonical_body('a', :simple)).to eq("a\r\n".b)
    end

    it 'reduces an empty body to a single CRLF' do
      expect(C.canonical_body('', :simple)).to eq("\r\n".b)
      expect(C.canonical_body("\r\n\r\n", :simple)).to eq("\r\n".b)
    end

    it 'keeps interior whitespace and lines intact' do
      body = "a \r\nb \r\n"
      expect(C.canonical_body(body, :simple)).to eq(body.b)
    end
  end

  describe 'relaxed body (RFC 6376 3.4.4)' do
    it 'reduces whitespace runs and strips leading/trailing line whitespace' do
      expect(C.canonical_body("a   b\t c \r\n  d  \r\n", :relaxed))
        .to eq("a b c\r\nd\r\n".b)
    end

    it 'removes all trailing empty lines' do
      expect(C.canonical_body("a\r\n\r\n\r\n", :relaxed)).to eq("a\r\n".b)
    end

    it 'canonicalizes an empty body to a single CRLF' do
      expect(C.canonical_body('', :relaxed)).to eq("\r\n".b)
    end
  end

  describe 'canonical_headers with repeated headers' do
    let(:fields) do
      [['Received', 'a'], ['Subject', 'one'], ['Received', 'b'], ['Subject', 'two']]
    end

    it 'selects the bottom-most occurrence first and walks upward' do
      out = C.canonical_headers(fields, %w[subject subject received received], :relaxed)
      expect(out).to eq(
        "subject:two\r\nsubject:one\r\nreceived:b\r\nreceived:a\r\n".b
      )
    end

    it 'emits an empty header for a signed name that is absent' do
      out = C.canonical_headers(fields, %w[subject missing], :relaxed)
      expect(out).to eq("subject:two\r\nmissing:\r\n".b)
    end

    it 'appends the DKIM-Signature with its lowercased name' do
      out = C.canonical_headers(fields, ['subject'], :relaxed, 'v=1; b=')
      expect(out).to eq("subject:two\r\ndkim-signature:v=1; b=\r\n".b)
    end
  end

  describe 'parse_headers' do
    it 'unfolds continuation lines retaining the separator WSP' do
      raw = "Subject: a\r\n\tb\r\nX: y\r\n"
      fields = C.parse_headers(raw)
      expect(fields).to eq([['Subject', " a\tb"], ['X', ' y']])
    end

    it 'unfolds multi-line base64 signature values' do
      raw = "DKIM-Signature: v=1;\r\n b=AAAA\r\n\tBBBB\r\n"
      fields = C.parse_headers(raw)
      expect(fields).to eq([['DKIM-Signature', "v=1; b=AAAA\tBBBB"]])
    end
  end

  describe 'body length limit (l=)' do
    it 'canonicalizes only the first l octets' do
      expect(C.canonical_body("abc\r\ndef\r\n", :relaxed, 3)).to eq("abc\r\n".b)
    end
  end

  describe '.algorithms' do
    it 'parses c= header/body pairs' do
      expect(C.algorithms('relaxed/simple')).to eq([:relaxed, :simple])
    end

    it 'rejects unknown algorithms' do
      expect { C.algorithms('nope/simple') }.to raise_error(ArgumentError)
    end
  end
end
