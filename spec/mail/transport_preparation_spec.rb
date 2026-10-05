# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::TransportPreparation do
  def utf8_text
    "Max \u{fc}\n"
  end

  it 'returns an independent copy for a 7-bit capable transport' do
    body_text = utf8_text
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject "Hell\u00f6"
      content_type 'text/plain; charset=UTF-8'
      content_transfer_encoding '8bit'
      body body_text
    end

    result = mail.prepare_for_transport(capabilities: [])
    expect(result).not_to be_blocked
    expect(result.message).not_to equal(mail)
    expect(result.message.parts).to be_empty
    expect(result.message.content_transfer_encoding).to eq('base64')
    expect(result.message.encoded).to be_ascii_only
    expect(Mail.new(result.message.encoded).body.decoded.b).to eq(utf8_text.b)
    expect(mail.content_transfer_encoding).to eq('8bit')
  end

  it 'keeps 8bit content with 8BITMIME and supports binary attachments without it' do
    bytes = (0..255).map(&:chr).join.b
    body_text = utf8_text
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject 'Ready'
    end
    mail.text_part = Mail::Part.new(
      content_type: 'text/plain; charset=UTF-8',
      content_transfer_encoding: '8bit',
      body: body_text
    )
    mail.attachments['data.bin'] = {
      mime_type: 'application/octet-stream',
      content: bytes
    }

    eight_bit = mail.prepare_for_transport(capabilities: ['8BITMIME'])
    seven_bit = mail.prepare_for_transport(capabilities: [])
    binary = mail.prepare_for_transport(capabilities: ['BINARYMIME'])

    expect(eight_bit.message.parts.first.content_transfer_encoding).to eq('8bit')
    expect(eight_bit.message.attachments.first.content_transfer_encoding).to eq('base64')
    expect(seven_bit.message.parts.first.content_transfer_encoding).to eq('base64')
    expect(seven_bit.message.attachments.first.content_transfer_encoding).to eq('base64')
    expect(binary.message.parts.first.content_transfer_encoding).to eq('8bit')
    expect(binary.message.attachments.first.content_transfer_encoding).to eq('binary')
    expect(Mail.new(seven_bit.message.encoded).attachments.first.decoded.b).to eq(bytes)
  end

  it 'recursively prepares nested MIME parts while preserving boundaries' do
    mail = Mail.new
    mail.from = 'sender@example.com'
    mail.to = 'recipient@example.com'
    mail.part content_type: 'multipart/alternative' do |alternative|
      alternative.part content_type: 'text/plain; charset=UTF-8',
                         content_transfer_encoding: '8bit',
                         body: utf8_text
      alternative.part content_type: 'text/html; charset=UTF-8',
                         content_transfer_encoding: '8bit',
                         body: "<p>\u00fc</p>"
    end

    original_boundary = mail.parts.first.boundary
    result = mail.prepare_for_transport(capabilities: [])

    expect(result).not_to be_blocked
    expect(result.message.parts.first.boundary).to eq(original_boundary)
    expect(result.message.parts.first.parts.map(&:content_transfer_encoding).to_a)
      .to contain_exactly('base64', 'base64')
  end

  it 'recursively downgrades message/rfc822 attachments' do
    body_text = utf8_text
    nested = Mail.new do
      from 'nested-sender@example.com'
      to 'nested-recipient@example.com'
      content_type 'text/plain; charset=UTF-8'
      content_transfer_encoding '8bit'
      body body_text
    end
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject 'Nested message'
    end
    mail.add_part(Mail::Part.new(
      content_type: 'message/rfc822; filename=nested.eml',
      content_disposition: 'attachment; filename=nested.eml',
      content_transfer_encoding: '8bit',
      body: nested.encoded
    ))

    result = mail.prepare_for_transport(capabilities: [])

    expect(result).not_to be_blocked
    expect(result.message.encoded).to be_ascii_only
    expect(result.message.parts.first.content_transfer_encoding).to eq('7bit')
    nested_part = Mail.new(result.message.parts.first.body.raw_source)
    expect(nested_part.encoded).to be_ascii_only
  end

  it 'blocks non-ASCII envelope addresses without SMTPUTF8 and never transliterates them' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject 'Ready'
      body 'Ready'
    end
    mail.smtp_envelope_to = ["recipient@\u00fc.example"]

    result = mail.prepare_for_transport(capabilities: [])

    expect(result).to be_blocked
    expect(result.reasons.first).to include('SMTPUTF8')
    expect(result.reasons.first).to include("recipient@\u00fc.example")
    expect(result.to_message).to be_nil
    expect(mail.smtp_envelope_to).to eq(["recipient@\u00fc.example"])
  end

  it 'allows non-ASCII envelope addresses with SMTPUTF8' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject 'Ready'
      body 'Ready'
    end
    mail.smtp_envelope_to = ["recipient@\u00fc.example"]

    result = mail.prepare_for_transport(capabilities: ['SMTPUTF8'])

    expect(result).not_to be_blocked
    expect(result.message.smtp_envelope_to).to eq(["recipient@\u00fc.example"])
  end

  it 'protects a multipart/signed payload and permits conversion when the caller accepts resigning' do
    payload = "x\u00fc\n".b
    signature = "SIG\u00ff\n".b
    mail = Mail.new
    mail.from = 'sender@example.com'
    mail.to = 'recipient@example.com'
    mail.header['Content-Type'] = 'multipart/signed; protocol=application/pgp-signature'
    mail.add_part(Mail::Part.new(
      content_type: 'text/plain; charset=UTF-8',
      content_transfer_encoding: '8bit',
      body: payload
    ))
    mail.add_part(Mail::Part.new(
      content_type: 'application/pgp-signature; name=signature.asc',
      content_disposition: 'attachment; filename=signature.asc',
      content_transfer_encoding: '8bit',
      body: signature
    ))

    blocked = mail.prepare_for_transport(capabilities: [])
    allowed = mail.prepare_for_transport(capabilities: [], allow_resign: true)

    expect(blocked).to be_blocked
    expect(blocked).to be_signed
    expect(blocked.resign_required?).to eq(true)
    expect(blocked.signature_preserved?).to eq(false)
    expect(allowed.resign_required?).to eq(true)
    expect(allowed.message.parts.first.content_transfer_encoding).to eq('base64')
    expect(allowed.message.parts.last.content_transfer_encoding).to eq('base64')
  end

  it 'protects a body covered by a DKIM signature and reports resigning as required' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      subject 'Ready'
      content_type 'text/plain; charset=UTF-8'
      content_transfer_encoding '8bit'
      body "x\u{fc}\n"
    end
    mail.header['DKIM-Signature'] = 'v=1; h=from:to:subject; b=ZmFrZQ=='

    blocked = mail.prepare_for_transport(capabilities: [])
    allowed = mail.prepare_for_transport(capabilities: [], allow_resign: true)

    expect(blocked).to be_blocked
    expect(blocked.resign_required?).to eq(true)
    expect(allowed.resign_required?).to eq(true)
    expect(allowed.message.encoded).to be_ascii_only
  end

  it 'reports a malformed multipart structure instead of inventing a boundary' do
    mail = Mail.new
    mail.header['Content-Type'] = 'multipart/mixed'
    mail.body = 'plain body'

    result = mail.prepare_for_transport(capabilities: [])

    expect(result).to be_blocked
    expect(result.reasons.first).to include('boundary')
  end

  it 'checks boundary delimiters against leaf MIME bytes' do
    boundary = 'BOUNDARY'
    mail = Mail.new
    mail.header['Content-Type'] = "multipart/mixed; boundary=#{boundary}"
    mail.body = "\r\n--#{boundary}\r\nContent-Type: text/plain\r\n\r\nsafe\r\n--#{boundary}\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=2D=2D#{boundary}\r\n--#{boundary}--\r\n"
    mail.body.split!(boundary)

    result = mail.prepare_for_transport(capabilities: [])

    expect(result).to be_blocked
    expect(result.reasons.first).to include('BOUNDARY')
  end

  it 'accepts capability names as strings, symbols, arrays, and a hash' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'recipient@example.com'
      body 'Ready'
    end

    symbol_result = mail.prepare_for_transport(capabilities: :smtputf8)
    string_result = mail.prepare_for_transport(capabilities: 'SMTPUTF8')
    hash_result = mail.prepare_for_transport(capabilities: { 'SMTPUTF8' => true })

    expect(symbol_result).not_to be_blocked
    expect(string_result).not_to be_blocked
    expect(hash_result).not_to be_blocked
  end
end
