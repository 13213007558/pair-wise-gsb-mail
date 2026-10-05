# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::MessagePartialReassembler do
  def fragment(number, total, id, body, subject: "Fragment #{number}")
    parameters = %(id="#{id}"; number=#{number})
    parameters << "; total=#{total}" if total

    "X-Partial-Hop: preserved\r\n" \
      "From: outer From <outer-from@example.test>\r\n" \
      "To: outer To <outer-to@example.test>\r\n" \
      "Subject: #{subject}\r\n" \
      "Message-ID: <outer-#{number}@example.test>\r\n" \
      "MIME-Version: 1.0\r\n" \
      "Content-Transfer-Encoding: 7bit\r\n" \
      "Content-Type: message/partial; #{parameters}\r\n" \
      "\r\n" \
      "#{body}"
  end

  def fragments_for(raw, count: 3)
    lines = raw.split(/(?<=\r\n)/)
    first = (lines.length * 0.35).ceil
    second = (lines.length * 0.70).ceil
    positions = [0, first, second, lines.length]

    count.times.map do |index|
      number = index + 1
      body = lines[positions[index]...positions[index + 1]].join
      fragment(number, count, 'nested@example.test', body)
    end
  end

  let(:nested_message) do
    "From: inner-from@example.test\r\n" \
      "To: inner-to@example.test\r\n" \
      "Subject: Reassembled nested message\r\n" \
      "Message-ID: <inner@example.test>\r\n" \
      "MIME-Version: 1.0\r\n" \
      "X-Inner-Dropped: dropped\r\n" \
      "Content-Description: nested message\r\n" \
      "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n" \
      "\r\n" \
      "--OUTER\r\n" \
      "Content-Type: multipart/alternative; boundary=\"INNER\"\r\n" \
      "\r\n" \
      "--INNER\r\n" \
      "Content-Type: text/plain\r\n" \
      "\r\n" \
      "Plain body\r\n" \
      "--INNER\r\n" \
      "Content-Type: text/html\r\n" \
      "\r\n" \
      "<p>HTML body</p>\r\n" \
      "--INNER--\r\n" \
      "--OUTER\r\n" \
      "Content-Type: text/plain\r\n" \
      "Content-Disposition: attachment; filename=\"notes.txt\"\r\n" \
      "Content-Transfer-Encoding: base64\r\n" \
      "\r\n" \
      "SGVsbG8sIG5lc3RlZCBtYWls\r\n" \
      "--OUTER--\r\n"
  end

  it 'reassembles fragments arriving out of order and parses nested multiparts after raw concatenation' do
    fragments = fragments_for(nested_message)
    reassembler = described_class.new

    reassembler.add(fragments[2])
    expect(reassembler.status).to eq(:incomplete)
    expect(reassembler).to be_incomplete
    expect(reassembler.missing_numbers).to eq([1, 2])
    expect(reassembler.message).to be_nil

    reassembler.add(fragments[0])
    reassembler << fragments[1]

    expect(reassembler.status).to eq(:complete)
    expect(reassembler).to be_complete
    expect(reassembler.missing_numbers).to eq([])

    message = reassembler.message
    expect(message).to be_a(Mail::Message)
    expect(message.mime_type).to eq('multipart/mixed')
    expect(message.parts.size).to eq(2)
    expect(message.parts.first.mime_type).to eq('multipart/alternative')
    expect(message.parts.first.parts.map(&:mime_type)).to eq(%w[text/plain text/html])
    expect(message.parts.first.parts.first.body.to_s).to eq('Plain body')
    expect(message.attachments.first.filename).to eq('notes.txt')
    expect(message.attachments.first.decoded).to eq('Hello, nested mail')

    expect(message.subject.to_s).to eq('Reassembled nested message')
    expect(message.message_id).to eq('inner@example.test')
    expect(message.mime_version).to eq('1.0')
    expect(message.content_description.to_s).to eq('nested message')
    expect(message.from).to contain_exactly('outer-from@example.test')
    expect(message.to).to contain_exactly('outer-to@example.test')
    expect(message['X-Partial-Hop'].to_s).to eq('preserved')
    expect(message.header['X-Inner-Dropped']).to be_nil
  end

  it 'distinguishes an unknown total from a known total with missing fragments' do
    unknown = described_class.new
    unknown.add(fragment(1, nil, 'unknown@example.test', 'Subject: Unknown total\r\n\r\nbody'))
    expect(unknown.status).to eq(:unknown_total)
    expect(unknown).to be_unknown_total
    expect(unknown.missing_numbers).to eq([1])
    expect(unknown.message).to be_nil

    known = described_class.new
    known.add(fragment(1, 2, 'known@example.test', 'Subject: Known total\r\n\r\nfirst'))
    expect(known.status).to eq(:incomplete)
    expect(known).not_to be_unknown_total
    expect(known.missing_numbers).to eq([2])
    expect(known.message).to be_nil
  end

  it 'accepts a repeated identical payload and rejects the same number with different payloads' do
    reassembler = described_class.new
    first = fragment(2, 2, 'duplicate@example.test', 'second', subject: 'Original subject')
    duplicate = fragment(2, 2, 'duplicate@example.test', 'second', subject: 'Retransmitted subject')

    reassembler.add(first)
    reassembler.add(duplicate)

    expect(reassembler.numbers).to eq([2])
    expect(reassembler.status).to eq(:incomplete)

    conflicting = fragment(2, 2, 'duplicate@example.test', 'changed')
    expect { reassembler.add(conflicting) }.
      to raise_error(described_class::ConflictError, /conflicting.*number 2/)
  end

  it 'rejects conflicting totals, mismatched ids, and non-partial messages' do
    reassembler = described_class.new
    reassembler.add(fragment(1, 2, 'id@example.test', 'first'))

    expect { reassembler.add(fragment(2, 3, 'id@example.test', 'second')) }.
      to raise_error(described_class::ConflictError, /conflicting.*totals/)
    expect { reassembler.add(fragment(3, 2, 'id@example.test', 'third')) }.
      to raise_error(described_class::ConflictError, /greater than total/)
    expect { reassembler.add(fragment(2, 2, 'other@example.test', 'second')) }.
      to raise_error(ArgumentError, /expected message\/partial id/)
    expect { reassembler.add(Mail.new('Content-Type: text/plain\r\n\r\nbody')) }.
      to raise_error(ArgumentError, /message\/partial/)
  end

  it 'supports one-shot reassembly and the reversed class name alias' do
    fragments = fragments_for(nested_message)
    message = described_class.reassemble(*fragments.shuffle)

    expect(message).to be_a(Mail::Message)
    expect(message.attachments.first.decoded).to eq('Hello, nested mail')
    expect(Mail::PartialMessageReassembler).to equal(described_class)
  end
end
