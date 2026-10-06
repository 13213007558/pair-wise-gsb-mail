# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::Mboxrd do
  let(:time) { Time.utc(2020, 1, 2, 3, 4, 5) }

  def read_mbox(raw, chunk_size: raw.bytesize, **options, &block)
    described_class::Reader.new(StringIO.new(raw), chunk_size: chunk_size, **options, &block).map do |record|
      [record, record.read]
    end
  end

  def write_mbox(messages)
    io = StringIO.new
    writer = described_class::Writer.new(io)
    messages.each { |message, options| writer.write_message(message, **options) }
    writer.close
    io.string
  end

  it 'round-trips mboxrd quoting and envelopes across every input split' do
    first = "From: first@example.com\r\n\r\nFrom bare\n>From one\n>>From two\r\n"
    second = "From: second@example.com\r\n\r\nlast"
    raw = write_mbox(
      [
        [first, { from: 'first@example.com', date: time }],
        [second, { from: 'second@example.com' }]
      ]
    )

    expect(raw).to eq(
      "From first@example.com Thu Jan  2 03:04:05 2020\n" +
      "From: first@example.com\r\n\r\n" +
      ">From bare\n>>From one\n>>>From two\r\n" +
      "From second@example.com\n" +
      "From: second@example.com\r\n\r\nlast"
    )

    (1..raw.bytesize).each do |chunk_size|
      records = read_mbox(raw, chunk_size: chunk_size)
      expect(records.map(&:last)).to eq([first, second])
      expect(records.map { |record, _| record.envelope_from }).to eq(%w[
        first@example.com second@example.com
      ])
      expect(records[0][0].envelope_date).to eq(time.to_datetime)
      expect(records[1][0].envelope_date).to be_nil
    second_offset = raw.bytesize - second.bytesize - "From second@example.com\n".bytesize
    expect(records[0][0].byte_range).to eq(0...second_offset)
    expect(records[1][0].byte_range).to eq(second_offset...raw.bytesize)
    end
  end

  it 'quotes writer input split at every byte boundary' do
    message = "From bare\n>From one\n>>From two\r\nlast"
    expected = ">From bare\n>>From one\n>>>From two\r\nlast"

    (1..message.bytesize).each do |chunk_size|
      io = StringIO.new
      writer = described_class::Writer.new(io)
      writer.write_message(from: 'sender@example.com') do |mbox|
        message.bytes.each_slice(chunk_size) { |bytes| mbox.write_body(bytes.pack('C*')) }
      end
      writer.close

      expect(io.string).to eq("From sender@example.com\n#{expected}")
    end
  end

  it 'lets callers choose malformed separator recovery without merging messages' do
    raw = "From first@example.com\none\nFrom broken line\ntwo\n"

    expect do
      read_mbox(raw)
    end.to raise_error(described_class::MalformedSeparatorError) do |error|
      expect(error.offset).to eq(raw.index("From broken"))
      expect(error.line).to eq("From broken line\n")
    end

    records = read_mbox(raw, malformed_separator: :body)
    expect(records.length).to eq(1)
    record, body = records.first
    expect(body).to eq("one\nFrom broken line\ntwo\n")
    expect(record.byte_range).to eq(0...raw.bytesize)

    records = read_mbox(raw, malformed_separator: :message)
    expect(records.length).to eq(2)
    expect(records.first.last).to eq("one\n")
    expect(records.last.last).to eq("two\n")
    expect(records.last.first.malformed_separator).to eq("From broken line\n")
  end

  it 'supports CRLF envelopes, callback recovery, and leading content handling' do
    raw = "leading\nFrom first@example.com\r\nbody\r\nFrom broken line\ntail\r\n"

    expect do
      read_mbox(raw)
    end.to raise_error(described_class::FormatError, /content before first mboxrd separator/)

    decisions = []
    records = read_mbox(
      raw,
      leading_content: :skip,
      malformed_separator: :raise
    ) do |line:, offset:|
      decisions << [line, offset]
      :body
    end

    expect(decisions).to eq([["From broken line\n", raw.index("From broken")]])
    expect(records.map(&:last)).to eq(["body\r\nFrom broken line\ntail\r\n"])
    expect do
      read_mbox(raw, leading_content: :skip)
    end.to raise_error(described_class::MalformedSeparatorError)
  end

  it 'round-trips a binary attachment containing From lines' do
    attachment = "\x00before\r\nFrom binary line\r\n>From quoted\xff".b
    message = Mail.new do
      from 'sender@example.com'
      subject 'Binary mboxrd'
      body 'text'
    end
    message.attachments['data.bin'] = { content: attachment, encoding: 'binary' }
    message.transport_encoding = 'binary'

    raw = write_mbox([[message, { from: 'sender@example.com', date: time }]])
    raw.force_encoding(Encoding::BINARY)
    parsed_record, parsed_body = read_mbox(raw, chunk_size: 7).first
    parsed = Mail.new(parsed_body)

    expect(parsed_record.envelope_from).to eq('sender@example.com')
    expect(parsed_record.envelope_date).to eq(time.to_datetime)
    expect(raw).to include("\x00before\r\n>From binary line\r\n>>From quoted\xff".b)
    expect(parsed.attachments.first.decoded).to eq(attachment)
  end
end
