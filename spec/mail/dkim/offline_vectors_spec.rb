# frozen_string_literal: true

require 'spec_helper'
require 'mail/dkim'
require_relative 'dkim_spec_helper'

# Fixed-key offline vectors. These exercise the exact scenarios called for:
# trailing empty lines, repeated Subject headers and body content appended
# beyond l=. Each vector states explicitly which modifications must break
# the signature and which must not.
RSpec.describe 'Mail::DKIM fixed-key offline vectors' do
  include DKIMSpecHelpers

  %w[simple relaxed].each do |header_alg|
    %w[simple relaxed].each do |body_alg|
      context "#{header_alg}/#{body_alg}" do
        let(:signed) do
          mail = Mail.new do
            from 'jane@example.com'
            to   'joe@example.org'
            subject 'Trailing blanks'
            body "line one\r\nline two\r\n\r\n"
          end
          dkim_signed(mail,
                      header_canonicalization: header_alg,
                      body_canonicalization: body_alg)
        end

        it 'verifies as signed' do
          expect(verify(signed)).to contain_exactly(have_attributes(status: :pass))
        end

        it 'survives additional trailing empty lines (must NOT break)' do
          altered = signed.sub(/\z/, "\r\n\r\n\r\n")
          expect(verify(altered).first.status).to eq(:pass)
        end

        it 'is broken by a body content change' do
          altered = signed.sub('line one', 'LINE ONE')
          expect(verify(altered).first.status).to eq(:permerror)
        end

        it 'is broken by a signed header change' do
          altered = signed.sub('Trailing blanks', 'Changed subject')
          expect(verify(altered).first).to have_attributes(
            status: :permerror, reason: /signature did not verify/
          )
        end
      end
    end
  end

  describe 'repeated header (RFC 6376 5.4.2 bottom-up selection)' do
    # Received is a legitimately repeatable trace header; both occurrences
    # are listed in h= and the verifier must consume the bottom-most first.
    def mail_with_two_received
      mail = Mail.new do
        from 'jane@example.com'
        to   'joe@example.org'
        subject 'Routed'
        body 'body'
      end
      mail.header.fields.push(Mail::Field.new('Received', 'from first by relay-a'))
      mail.header.fields.push(Mail::Field.new('Received', 'from second by relay-b'))
      mail
    end

    let(:signed) do
      mail = mail_with_two_received
      dkim_signed(mail,
                  headers: %w[Received Received From To Subject],
                  header_canonicalization: 'relaxed',
                  body_canonicalization: 'relaxed')
    end

    it 'verifies the message as signed' do
      expect(verify(signed).first.status).to eq(:pass)
    end

    it 'lists the header twice in h=' do
      expect(signed[/h=([^;\r]+)/, 1].scan(/received/).size).to eq(2)
    end

    it 'is broken when the lower (bottom-most, consumed first) Received changes' do
      altered = signed.sub('from second by relay-b', 'from EVIL by relay-b')
      expect(verify(altered).first.status).to eq(:permerror)
    end

    it 'is broken when the upper Received changes (both instances are signed)' do
      altered = signed.sub('from first by relay-a', 'from EVIL by relay-a')
      expect(verify(altered).first.status).to eq(:permerror)
    end

    it 'is NOT broken by a new Received prepended after signing (not in h=)' do
      altered = signed.sub(/\ADate:/, "Received: from later by relay-c\r\nDate:")
      expect(verify(altered).first.status).to eq(:pass)
    end
  end

  describe 'repeated Subject header in received bytes' do
    # RFC 5322 permits multiple Subject fields even though they are unusual;
    # DKIM signing/verification operate on raw bytes, so we build a raw
    # message containing both and sign that.
    let(:raw_message) do
      [
        'From: jane@example.com',
        'To: joe@example.org',
        'Subject: first subject',
        'Subject: second subject',
        '',
        'body'
      ].join("\r\n")
    end
    let(:signed) do
      Mail::DKIM.sign_bytes(
        raw_message,
        domain: 'example.com', selector: 'sel', private_key: private_pem,
        headers: %w[Subject Subject From To],
        header_canonicalization: 'relaxed', body_canonicalization: 'relaxed',
        time: 1_700_000_000
      )
    end

    it 'retains both Subject fields and a valid signature' do
      expect(signed.scan(/Subject:/).size).to eq(2)
      expect(verify(signed).first.status).to eq(:pass)
    end

    it 'is broken by changing the lower Subject' do
      altered = signed.sub('Subject: second subject', 'Subject: tampered')
      expect(verify(altered).first.status).to eq(:permerror)
    end

    it 'is broken by changing the upper Subject' do
      altered = signed.sub('Subject: first subject', 'Subject: tampered')
      expect(verify(altered).first.status).to eq(:permerror)
    end
  end

  describe 'l= body length tag' do
    let(:base) do
      Mail.new do
        from 'jane@example.com'
        to   'joe@example.org'
        subject 'Limited body'
        body 'signed portion'
      end
    end
    let(:body_len) { 'signed portion'.bytesize }
    let(:signed) do
      dkim_signed(base,
                  header_canonicalization: 'relaxed',
                  body_canonicalization: 'relaxed',
                  length: body_len)
    end

    it 'includes the l= tag' do
      expect(signed).to include("l=#{body_len}")
    end

    it 'verifies as signed' do
      expect(verify(signed).first.status).to eq(:pass)
    end

    it 'does NOT break when content is appended beyond l=' do
      altered = signed.sub(/\z/, "\r\nappended by mailing list")
      expect(verify(altered).first.status).to eq(:pass)
    end

    it 'is broken by a change inside the signed portion' do
      altered = signed.sub('signed portion', 'SIGNED PORTION')
      expect(verify(altered).first).to have_attributes(
        status: :permerror, reason: /body hash did not verify/
      )
    end
  end

  describe 'trailing empty lines with no l=' do
    it 'relaxed: a body ending without blank lines canonically gains one CRLF' do
      signed = dkim_signed('no trailing newline',
                           header_canonicalization: 'relaxed',
                           body_canonicalization: 'relaxed')
      expect(verify(signed).first.status).to eq(:pass)
    end
  end
end
