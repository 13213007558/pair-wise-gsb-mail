# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Message, '#prepare_for_transport' do
  def prepare(mail, capabilities = {})
    mail.prepare_for_transport(capabilities: capabilities)
  end

  def parse(source)
    Mail.new(source)
  end

  it 'returns a distinct transport copy' do
    mail = Mail.new(from: 'a@example.test', to: 'b@example.test', subject: 'Test', body: 'hello')

    result = prepare(mail)

    expect(result).to be_success
    expect(result.message).not_to equal(mail)
    expect(result.message.encoded).to include('Content-Transfer-Encoding: 7bit')
    expect(mail.encoded).to include('Message-ID')
  end

  it 'does not share mutable body or header state with the transport copy' do
    mail = Mail.new(from: 'a@example.test', to: 'b@example.test', subject: 'Test', body: 'hello')
    prepared = prepare(mail).message

    prepared.subject = 'Changed'
    prepared.body = 'changed body'

    expect(mail.subject).to eq('Test')
    expect(mail.body.decoded).to eq('hello')
  end

  it 'reports the SMTP extension required by an internationalized transport copy' do
    mail = Mail.new(from: 'sender@example.test', to: '用户@例子.test', body: 'hello')

    result = prepare(mail, 'SMTPUTF8' => true)

    expect(result.required_extensions).to eq(%w[SMTPUTF8])
  end

  it 'downgrades 8-bit text without SMTP extensions' do
    mail = Mail.new(from: 'a@example.test', to: 'b@example.test',
                    content_type: 'text/plain; charset=UTF-8',
                    content_transfer_encoding: '8bit', body: 'héllo')

    result = prepare(mail)

    expect(result).to be_success
    expect(result.message.encoded).to include('Content-Transfer-Encoding: base64')
    expect(parse(result.message.encoded).body.decoded.force_encoding('UTF-8')).to eq('héllo')
  end

  it 'preserves 8-bit text with 8BITMIME' do
    mail = Mail.new(from: 'a@example.test', to: 'b@example.test',
                    content_type: 'text/plain; charset=UTF-8',
                    content_transfer_encoding: '8bit', body: 'héllo')

    result = prepare(mail, '8BITMIME' => true)

    expect(result).to be_success
    expect(result.message.encoded).to include('Content-Transfer-Encoding: 8bit')
    expect(result.message.encoded).to include('héllo')
  end

  it 'downgrades binary attachment bytes without BINARYMIME' do
    bytes = "\x00\xff\x80\n".dup.force_encoding(Encoding::BINARY)
    mail = Mail.new
    mail.add_file(filename: 'data.bin', content: bytes)

    result = prepare(mail)

    expect(result).to be_success
    expect(result.message.encoded).to include('Content-Transfer-Encoding: base64')
    expect(parse(result.message.encoded).attachments.first.body.decoded.b).to eq(bytes.b)
  end

  it 'preserves binary attachment bytes with BINARYMIME' do
    bytes = "\x00\xff\x80\n".dup.force_encoding(Encoding::BINARY)
    mail = Mail.new
    mail.add_file(filename: 'data.bin', content: bytes)

    result = prepare(mail, 'BINARYMIME' => true)

    expect(result).to be_success
    expect(result.message.encoded).to include('Content-Transfer-Encoding: binary')
    expect(result.message.encoded.b).to include("\x00\xff\x80".b)
    expect(parse(result.message.encoded).attachments.first.body.decoded.b).to eq(bytes.b)
  end

  it 'blocks internationalized envelope addresses without SMTPUTF8 and never transliterates them' do
    mail = Mail.new(from: 'sender@example.test', to: '用户@例子.test',
                    subject: '主题', body: 'hello')

    result = prepare(mail)

    expect(result).to be_blocked
    expect(result.reasons.first.code).to eq(:smtputf8_required)
    expect(result.reasons.first.message).to include('用户@例子.test')
    expect(result.reasons.first.message).to include('no transliteration')
    expect(result.message).to be_nil
  end

  it 'allows internationalized envelope addresses with SMTPUTF8' do
    mail = Mail.new(from: 'sender@example.test', to: '用户@例子.test',
                    subject: '主题', body: 'héllo')

    result = prepare(mail, 'SMTPUTF8' => true, '8BITMIME' => true)

    expect(result).to be_success
    expect(result.message.encoded).to include('To: 用户@例子.test')
    expect(result.message.smtp_envelope_to).to eq(['用户@例子.test'])
  end

  it 'checks nested MIME boundaries and preserves nested attachment bytes' do
    attachment = "\xff\x00\n".dup.force_encoding(Encoding::BINARY)
    mail = Mail.new
    html_part = Mail::Part.new(content_type: 'text/html; charset=UTF-8', body: '<p>héllo</p>')
    nested = Mail::Part.new(content_type: 'multipart/alternative')
    nested.add_part(Mail::Part.new(content_type: 'text/plain; charset=UTF-8', body: 'héllo'))
    nested.add_part(html_part)
    mail.add_file(filename: 'outer.bin', content: attachment)
    mail.add_part(nested)

    result = prepare(mail)
    prepared = parse(result.message.encoded)

    expect(result).to be_success
    expect(prepared.boundary.ascii_only?).to eq(true)
    expect(prepared.parts.detect { |part| part.mime_type == 'multipart/alternative' }.boundary).not_to eq(prepared.boundary)
    expect(prepared.attachments.first.body.decoded.b).to eq(attachment.b)
  end

  it 'requires resignation when conversion changes a multipart/signed payload' do
    source = <<~MESSAGE.gsub("\n", "\r\n")
Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="sig-boundary"
MIME-Version: 1.0

--sig-boundary
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

héllo
--sig-boundary
Content-Type: application/pgp-signature
Content-Disposition: attachment; filename="signature.asc"

SIGNATURE
--sig-boundary--
MESSAGE

    result = prepare(parse(source))

    expect(result).to be_blocked
    expect(result.reasons.map(&:code)).to eq([:signature_requires_resign])
  end

  it 'preserves a multipart/signed payload when no covered bytes change' do
    source = <<~MESSAGE.gsub("\n", "\r\n")
Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="sig-boundary"
MIME-Version: 1.0

--sig-boundary
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

hello
--sig-boundary
Content-Type: application/pgp-signature
Content-Disposition: attachment; filename="signature.asc"

SIGNATURE
--sig-boundary--
MESSAGE

    result = prepare(parse(source))

    expect(result).to be_success
    expect(result.message.encoded).to include('hello')
    expect(result.message.encoded).to include('SIGNATURE')
  end

  it 'requires resignation when downgrading a DKIM-signed body' do
    mail = Mail.new(from: 'a@example.test', to: 'b@example.test',
                    subject: 'Signed', content_type: 'text/plain; charset=UTF-8',
                    content_transfer_encoding: '8bit', body: 'héllo')
    mail.header['DKIM-Signature'] = 'v=1; a=rsa-sha256; h=from:to:subject:content-type; b=abc='

    result = prepare(mail)

    expect(result).to be_blocked
    expect(result.reasons.map(&:code)).to eq([:signature_requires_resign])
  end

  it 'blocks an unrecognized transfer encoding instead of relabeling bytes' do
    mail = Mail.new("Content-Transfer-Encoding: weird\r\n\r\nhello")

    result = prepare(mail)

    expect(result).to be_blocked
    expect(result.reasons.map(&:code)).to eq([:unsupported_transfer_encoding])
  end

  it 'blocks a non-7-bit nested message/rfc822 body that cannot be downgraded' do
    inner = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nhéllo\r\n"
    part = Mail::Part.new(content_type: 'message/rfc822', content_disposition: 'attachment; filename="inner.eml"')
    part.body = inner
    mail = Mail.new
    mail.add_part(part)

    result = prepare(mail)

    expect(result).to be_blocked
    expect(result.reasons.map(&:code)).to include(:eightbitmime_required)
  end
end
