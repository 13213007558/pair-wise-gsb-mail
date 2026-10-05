# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::MessagePartial do
  def fragment_headers(id, number, total)
    headers = [
      "Date: Mon, 1 Jan 2024 00:00:00 +0000",
      "From: outer-from@example.com",
      "To: outer-to@example.com",
      "Message-ID: <outer-message@example.com>",
      "Subject: Outer subject",
      "Content-Type: message/partial; id=#{id}; number=#{number}"
    ]
    headers.last << "; total=#{total}" if total
    headers.join("\r\n")
  end

  def fragment_with_x_header(source, number)
    source.sub(
      "Content-Type: message/partial",
      "X-Fragment: #{number}\r\nContent-Type: message/partial"
    )
  end

  def split_partial(message, id:, total:, outer_encoding: 'base64')
    encoded = Mail::Encodings.get_encoding(outer_encoding).encode(message).sub(/\r\n\z/, '')
    positions = (0..total).map { |index| (encoded.bytesize * index) / total }

    positions.each_cons(2).with_index(1).map do |(start_position, end_position), number|
      headers = fragment_headers(id, number, number == total ? total : nil)
      "#{headers}\r\nContent-Transfer-Encoding: #{outer_encoding}\r\n\r\n" \
        "#{encoded.byteslice(start_position...end_position)}"
    end
  end

  let(:original) do
    Mail.new do
      from    'inner-from@example.com'
      to      'inner-to@example.com'
      subject 'Inner subject'
      content_type 'multipart/mixed; boundary="outer-boundary"'
      body "--outer-boundary\r\n" \
        "Content-Type: multipart/alternative; boundary=\"inner-boundary\"\r\n" \
        "\r\n" \
        "--inner-boundary\r\n" \
        "Content-Type: text/plain\r\n" \
        "\r\n" \
        "plain\r\n" \
        "--inner-boundary\r\n" \
        "Content-Type: text/html\r\n" \
        "\r\n" \
        "<p>html</p>\r\n" \
        "--inner-boundary--\r\n" \
        "--outer-boundary\r\n" \
        "Content-Type: application/octet-stream; name=attachment.bin\r\n" \
        "Content-Transfer-Encoding: base64\r\n" \
        "Content-Disposition: attachment\r\n" \
        "\r\n" \
        "AAECAwQF\r\n" \
        "--outer-boundary--\r\n"
    end.encoded
  end

  it 'reassembles out-of-order nested multipart fragments without decoding each body' do
    fragments = split_partial(original, id: 'message@example.com', total: 3)
    parsed_fragments = fragments.map { |fragment| Mail.new(fragment) }
    incorrectly_joined = parsed_fragments.map { |fragment| fragment.body.decoded }.join
    reassembler = described_class.new
    fragments.rotate(2).each { |fragment| reassembler.add(fragment) }

    expect(reassembler.status('message@example.com')).to eq(:complete)
    message = reassembler.reassemble('message@example.com')

    expect(message).to be_multipart
    expect(message.content_type_parameters['boundary']).to eq('outer-boundary')
    expect(message.from).to eq(['inner-from@example.com'])
    expect(message.to).to eq(['inner-to@example.com'])
    expect(message.subject).to eq('Inner subject')

    nested = message.parts.first
    expect(nested).to be_multipart
    expect(nested.content_type_parameters['boundary']).to eq('inner-boundary')
    expect(nested.text_part.body.decoded).to eq('plain')
    expect(nested.html_part.body.decoded).to eq('<p>html</p>')

    attachment = message.parts.last
    expect(attachment).to be_attachment
    expect(attachment.body.decoded).to eq("\x00\x01\x02\x03\x04\x05".b)
    expect(incorrectly_joined).not_to eq(message.raw_source.b)
  end

  it 'accepts an identical duplicate fragment' do
    fragments = split_partial(original, id: 'duplicate@example.com', total: 2)
    reassembler = described_class.new

    [fragments.last, fragments.first, fragments.last].shuffle.each do |fragment|
      reassembler.add(fragment)
    end

    expect(reassembler.status('duplicate@example.com')).to eq(:complete)
    expect(reassembler.reassemble('duplicate@example.com')).to be_a(Mail::Message)
  end

  it 'rejects an identical fragment body with a different total' do
    reassembler = described_class.new
    first, = split_partial(original, id: 'total-conflict@example.com', total: 2)
    first_with_total = first.sub('number=1', 'number=1; total=2')
    conflicting_total = first_with_total.sub('total=2', 'total=3')

    reassembler.add(first_with_total)

    expect do
      reassembler.add(conflicting_total)
    end.to raise_error(described_class::ConflictError, /Conflicting message\/partial totals/)
    expect(reassembler.status('total-conflict@example.com')).to eq(:conflict)
  end

  it 'distinguishes an unknown total from a known total with missing fragments' do
    reassembler = described_class.new
    first, second = split_partial(original, id: 'status@example.com', total: 3)

    expect(reassembler.add(first).status).to eq(:unknown_total)
    expect(reassembler.add(second).status).to eq(:unknown_total)
    expect(reassembler.missing_numbers('status@example.com')).to be_nil

    reassembler.add(fragment_with_known_total(2))
    expect(reassembler.status('status@example.com')).to eq(:incomplete)
    expect(reassembler.missing_numbers('status@example.com')).to eq([3])
  end

  it 'rejects different content with the same fragment number' do
    fragments = split_partial(original, id: 'conflict@example.com', total: 2)
    conflicting_fragment = "#{fragments.first}x"
    reassembler = described_class.new
    reassembler.add(fragments.first)

    expect do
      reassembler.add(conflicting_fragment)
    end.to raise_error(described_class::ConflictError, /number 1/)
    expect(reassembler.status('conflict@example.com')).to eq(:conflict)
  end

  it 'marks a number outside a known total as conflicting' do
    reassembler = described_class.new
    first, = split_partial(original, id: 'range@example.com', total: 2)
    third = split_partial(original, id: 'range@example.com', total: 3).last.sub('total=3', 'total=2')

    reassembler.add(first)

    expect do
      reassembler.add(third)
    end.to raise_error(described_class::ConflictError, /outside the declared total/)
    expect(reassembler.status('range@example.com')).to eq(:conflict)
  end

  it 'uses inner headers and does not retain fragment envelope headers' do
    fragments = split_partial(original, id: 'headers@example.com', total: 2)
    fragments = fragments.map.with_index do |fragment, number|
      fragment_with_x_header(fragment, number + 1)
    end
    message = described_class.reassemble(fragments).first

    expect(message.from).to eq(['inner-from@example.com'])
    expect(message.subject).to eq('Inner subject')
    expect(message.message_id).not_to eq('outer-message@example.com')
    expect(message.header['x-fragment']).to be_nil
    expect(message.mime_type).to eq('multipart/mixed')
    expect(message.header['content-transfer-encoding'].value).to eq('7bit')
  end

  it 'provides a one-shot reassembler' do
    fragments = split_partial(original, id: 'one-shot@example.com', total: 3)
    messages = Mail.reassemble_partials(fragments)

    expect(messages.map(&:class)).to eq([Mail::Message])
    expect(messages.first.subject).to eq('Inner subject')
  end

  def fragment_with_known_total(number)
    _, second = split_partial(original, id: 'status@example.com', total: 3)
    second.sub('number=2', 'number=2; total=3')
  end
end
