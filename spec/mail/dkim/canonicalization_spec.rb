# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DKIM::Canonicalization do
  C = described_class

  def b(str)
    str.b
  end

  describe '.to_crlf' do
    it 'leaves CRLF separated input untouched' do
      expect(C.to_crlf("a\r\nb")).to eq(b("a\r\nb"))
    end

    it 'converts lone LF to CRLF' do
      expect(C.to_crlf("a\nb")).to eq(b("a\r\nb"))
    end

    it 'converts lone CR to CRLF' do
      expect(C.to_crlf("a\rb")).to eq(b("a\r\nb"))
    end

    it 'does not double convert CRLF' do
      expect(C.to_crlf("a\r\nb\nc")).to eq(b("a\r\nb\r\nc"))
    end

    it 'returns binary encoded strings' do
      expect(C.to_crlf('a').encoding).to eq(Encoding::BINARY)
    end
  end

  describe '.split_message' do
    it 'splits header and body at the empty separator line' do
      headers, body = C.split_message("A: 1\r\nB: 2\r\n\r\nbody\r\n")
      expect(headers).to eq(b("A: 1\r\nB: 2"))
      expect(body).to eq(b("body\r\n"))
    end

    it 'treats a missing separator as headers only and an empty body' do
      headers, body = C.split_message("A: 1\r\n")
      expect(headers).to eq(b("A: 1"))
      expect(body).to eq(b(''))
    end

    it 'splits at the first empty line only' do
      _, body = C.split_message("A: 1\r\n\r\none\r\n\r\ntwo\r\n")
      expect(body).to eq(b("one\r\n\r\ntwo\r\n"))
    end
  end

  describe '.parse_headers' do
    it 'returns ordered name/value pairs keeping the folded value bytes' do
      raw = "Subject: hello\r\nX-Long: one\r\n\ttwo\r\nFrom: a@b\r\n"
      headers = C.parse_headers(raw)
      expect(headers.map(&:first)).to eq(%w[Subject X-Long From])
      expect(headers[1].last).to eq(b(" one\r\n\ttwo"))
      expect(headers[0].last).to eq(b(' hello'))
    end

    it 'handles a header block without a trailing CRLF' do
      headers = C.parse_headers('Subject: x')
      expect(headers).to eq([['Subject', b(' x')]])
    end
  end

  describe 'header canonicalization' do
    it 'does not change simple headers at all' do
      expect(C.simple_header('Subject', ' Hello')).to eq(b("Subject: Hello\r\n"))
      expect(C.simple_header('Subject', " one\r\n\ttwo")).to eq(b("Subject: one\r\n\ttwo\r\n"))
    end

    it 'lowercases the relaxed header name, preserves value case and reduces WSP' do
      expect(C.relaxed_header('Subject', ' Hello   World ')).to eq(b("subject:Hello World\r\n"))
    end

    it 'unfolds and collapses WSP in relaxed headers' do
      expect(C.relaxed_header('X', " one\r\n\ttwo  ")).to eq(b("x:one two\r\n"))
    end

    it 'uses the lower cased h= name with relaxed but keeps simple name case' do
      headers = [['Subject', ' X']]
      expect(C.canonical_headers(:relaxed, headers, %w[SUBJECT])).to eq(b("subject:X\r\n"))
      expect(C.canonical_headers(:simple, headers, %w[Subject])).to eq(b("Subject: X\r\n"))
    end
  end

  describe 'duplicate header selection' do
    let(:headers) do
      C.parse_headers("Subject: one\r\nSubject: two\r\nSubject: three\r\n")
    end

    it 'selects unused instances from the bottom upwards' do
      out = C.canonical_headers(:relaxed, headers, %w[subject subject])
      expect(out).to eq(b("subject:three\r\nsubject:two\r\n"))
    end

    it 'selects topmost last when every instance is referenced' do
      out = C.canonical_headers(:relaxed, headers,
                                %w[subject subject subject])
      expect(out).to eq(b("subject:three\r\nsubject:two\r\nsubject:one\r\n"))
    end

    it 'emits a bare CRLF for a header with no remaining instance' do
      out = C.canonical_headers(:relaxed, headers,
                                %w[subject subject subject subject])
      expect(out).to eq(b("subject:three\r\nsubject:two\r\nsubject:one\r\n\r\n"))
    end

    it 'emits a bare CRLF for a missing header under simple too' do
      out = C.canonical_headers(:simple, [['From', ' a']], %w[from received])
      expect(out).to eq(b("From: a\r\n\r\n"))
    end
  end

  describe 'body canonicalization' do
    describe 'simple' do
      it 'ignores trailing empty lines and adds exactly one CRLF' do
        expect(C.simple_body("a\r\n\r\n\r\n")).to eq(b("a\r\n"))
      end

      it 'canonicalizes an empty body to a single CRLF' do
        expect(C.simple_body('')).to eq(b("\r\n"))
        expect(C.simple_body("\r\n\r\n")).to eq(b("\r\n"))
      end

      it 'keeps interior empty lines' do
        expect(C.simple_body("a\r\n\r\nb\r\n")).to eq(b("a\r\n\r\nb\r\n"))
      end
    end

    describe 'relaxed' do
      it 'reduces WSP runs, trims each line, and removes trailing blanks' do
        expect(C.relaxed_body("a \tb \r\n\r\n\r\n")).to eq(b("a b\r\n"))
      end

      it 'canonicalizes an empty body to a single CRLF (RFC 6376 3.4.4 note)' do
        expect(C.relaxed_body('')).to eq(b("\r\n"))
        expect(C.relaxed_body("\r\n\r\n")).to eq(b("\r\n"))
      end

      it 'adds a CRLF to a non empty body missing its final newline' do
        expect(C.relaxed_body('a')).to eq(b("a\r\n"))
      end

      it 'keeps interior empty lines' do
        expect(C.relaxed_body("a\r\n\r\nb\r\n")).to eq(b("a\r\n\r\nb\r\n"))
      end
    end

    describe 'l= length truncation' do
      it 'hashes only the first l canonical body bytes' do
        expect(C.relaxed_body("hello\r\nworld\r\n", 7)).to eq(b("hello\r\n"))
      end

      it 'never reads past the canonical body even if l is larger' do
        expect(C.simple_body("a\r\n", 99)).to eq(b("a\r\n"))
      end
    end
  end

  describe '.signature_header' do
    it 'empties the b tag value while keeping all other tags (relaxed)' do
      value = "v=DKIM1; d=example.com; b=ABCD\r\n EF==; bh=ZGF0YQ=="
      canonical = C.signature_header(:relaxed, value)
      expect(canonical).to eq(
        b("dkim-signature:v=DKIM1; d=example.com; b=; bh=ZGF0YQ==\r\n")
      )
    end

    it 'removes the folded b value bytes under simple as well' do
      value = "v=DKIM1;\r\n b=ABCD\r\n EF=="
      canonical = C.signature_header(:simple, value)
      expect(canonical).to eq(b("dkim-signature:v=DKIM1;\r\n b=\r\n"))
    end

    it 'does not mistake bh for b' do
      value = 'bh=Zm9v; b=AAA'
      canonical = C.signature_header(:relaxed, value)
      expect(canonical).to eq(b("dkim-signature:bh=Zm9v; b=\r\n"))
    end
  end
end
