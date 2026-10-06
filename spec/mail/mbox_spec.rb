# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Mbox do
  let(:message_one) do
    "From: alice@example.com\r\n" \
    "To: bob@example.com\r\n" \
    "Subject: one\r\n" \
    "\r\n" \
    "first body\n"
  end

  let(:message_two) do
    "From: carol@example.com\r\n" \
    "\r\n" \
    ">From a line that must be escaped\n" \
    ">>From an already escaped line\n" \
    ">>>From a doubly escaped line\n" \
    "last line\n"
  end

  let(:message_two_unescaped) do
    "From: carol@example.com\r\n" \
    "\r\n" \
    "From a line that must be escaped\n" \
    ">From an already escaped line\n" \
    ">>From a doubly escaped line\n" \
    "last line\n"
  end

  let(:separator_one) { "From alice@example.com Thu Jan  2 03:04:05 2020\n" }
  let(:separator_two) { "From carol@example.com Fri Jan  3 04:05:06 2020\n" }
  let(:source) { separator_one + message_one + separator_two + message_two }

  def read_records(string, **options)
    Mail::Mbox::Reader.new(StringIO.new(string), **options).to_a
  end

  describe Mail::Mbox::Reader do
    it "yields one record per message with envelope sender and date" do
      records = read_records(source)
      expect(records.size).to eq 2
      expect(records[0].envelope_sender).to eq 'alice@example.com'
      expect(records[0].envelope_date).to eq 'Thu Jan  2 03:04:05 2020'
      expect(records[1].envelope_sender).to eq 'carol@example.com'
      expect(records[1].envelope_date).to eq 'Fri Jan  3 04:05:06 2020'
    end

    it "parses the envelope date as a DateTime" do
      record = read_records(source).first
      expect(record.envelope_time).to eq DateTime.new(2020, 1, 2, 3, 4, 5)
    end

    it "unescapes mboxrd >From lines by removing exactly one >" do
      records = read_records(source)
      expect(records[1].data).to eq message_two_unescaped
    end

    it "reports the byte range of each message in the original file" do
      records = read_records(source)
      expect(records[0].byte_range).to eq 0...(separator_one.bytesize + message_one.bytesize)
      expect(records[1].byte_range).to eq records[0].byte_range.end...source.bytesize
      expect(source.byteslice(records[0].byte_range)).to eq separator_one + message_one
      expect(source.byteslice(records[1].byte_range)).to eq separator_two + message_two
    end

    it "reports the content byte range separately from the separator" do
      records = read_records(source)
      expect(records[0].content_range).to eq separator_one.bytesize...(separator_one.bytesize + message_one.bytesize)
      expect(source.byteslice(records[0].content_range)).to eq message_one
    end

    it "yields the final message even without a trailing newline" do
      records = read_records(separator_one + "Subject: no newline")
      expect(records.size).to eq 1
      expect(records[0].data).to eq "Subject: no newline"
      expect(records[0].byte_range).to eq 0...(separator_one.bytesize + "Subject: no newline".bytesize)
    end

    it "parses identically when chunks split lines and newlines" do
      expected = read_records(source)
      [1, 3, 7, 64].each do |chunk_size|
        records = read_records(source, chunk_size: chunk_size)
        expect(records.map(&:data)).to eq expected.map(&:data)
        expect(records.map(&:byte_range)).to eq expected.map(&:byte_range)
        expect(records.map(&:content_range)).to eq expected.map(&:content_range)
      end
    end

    it "handles an empty source" do
      expect(read_records("")).to eq []
    end

    it "returns an enumerator when no block is given" do
      reader = Mail::Mbox::Reader.new(StringIO.new(source))
      expect(reader.each).to be_a Enumerator
      expect(reader.each.count).to eq 2
    end

    it "reads from a file path with Reader.open" do
      path = File.join(SPEC_ROOT, 'tmp', 'reader_open.mbox')
      File.open(path, 'wb') { |f| f.write(source) }
      records = Mail::Mbox::Reader.open(path) { |reader| reader.to_a }
      expect(records.map(&:envelope_sender)).to eq %w[alice@example.com carol@example.com]
    end

    describe "invalid separator handling" do
      let(:bad_source) { separator_one + "Subject: ok\n" + "From \n" + "more body\n" }

      it "raises by default instead of silently merging into the next message" do
        expect { read_records(bad_source) }.to raise_error(Mail::Mbox::InvalidSeparatorError) do |error|
          expect(error.offset).to eq(separator_one.bytesize + "Subject: ok\n".bytesize)
          expect(error.line).to eq "From \n"
        end
      end

      it "raises on content before the first separator" do
        expect { read_records("stray\n" + separator_one) }.to raise_error(Mail::Mbox::InvalidSeparatorError)
      end

      it "rejects an unknown strategy" do
        expect { Mail::Mbox::Reader.new(StringIO.new(''), on_invalid_separator: :bogus) }.
          to raise_error(ArgumentError)
      end

      it "drops the bad line with :skip" do
        records = read_records(bad_source, on_invalid_separator: :skip)
        expect(records.size).to eq 1
        expect(records[0].data).to eq "Subject: ok\nmore body\n"
      end

      it "keeps the bad line as body with :keep_as_body" do
        records = read_records(bad_source, on_invalid_separator: :keep_as_body)
        expect(records.size).to eq 1
        expect(records[0].data).to eq "Subject: ok\nFrom \nmore body\n"
      end

      it "starts an anonymous record for stray content with :keep_as_body" do
        records = read_records("stray\n" + separator_one + "body\n", on_invalid_separator: :keep_as_body)
        expect(records.size).to eq 2
        expect(records[0].envelope_sender).to be_nil
        expect(records[0].envelope_date).to be_nil
        expect(records[0].data).to eq "stray\n"
        expect(records[0].byte_range).to eq 0...("stray\n".bytesize)
        expect(records[1].data).to eq "body\n"
      end
    end
  end

  describe Mail::Mbox::Writer do
    def write_to_string
      io = StringIO.new(+''.b)
      yield Mail::Mbox::Writer.new(io)
      io.string
    end

    it "writes the separator line with envelope sender and ctime date" do
      output = write_to_string do |writer|
        writer.write("body\n", sender: 'alice@example.com', date: Time.utc(2020, 1, 2, 3, 4, 5))
      end
      expect(output).to eq "From alice@example.com Thu Jan  2 03:04:05 2020\nbody\n"
    end

    it "accepts a raw date string" do
      output = write_to_string do |writer|
        writer.write("body\n", sender: '-', date: 'Thu Jan  2 03:04:05 2020')
      end
      expect(output).to start_with "From - Thu Jan  2 03:04:05 2020\n"
    end

    it "escapes From and >From lines with one extra >" do
      output = write_to_string do |writer|
        writer.write("From one\n>From two\n>>From three\nFromage four\nplain\n", sender: 'a@b', date: 'd')
      end
      expect(output).to eq(
        "From a@b d\n" \
        ">From one\n" \
        ">>From two\n" \
        ">>>From three\n" \
        "Fromage four\n" \
        "plain\n")
    end

    it "appends a trailing newline when the content lacks one" do
      output = write_to_string do |writer|
        writer.write("no newline", sender: 'a@b', date: 'd')
        writer.write("next\n", sender: 'a@b', date: 'd')
      end
      expect(output).to eq "From a@b d\nno newline\nFrom a@b d\nnext\n"
    end

    it "rejects senders with whitespace and dates with newlines" do
      expect { write_to_string { |w| w.write("x", sender: 'a b', date: 'd') } }.to raise_error(ArgumentError)
      expect { write_to_string { |w| w.write("x", sender: 'a', date: "d\nevil") } }.to raise_error(ArgumentError)
    end

    it "round-trips messages through the reader byte for byte" do
      bodies = [
        "Subject: plain\n\nbody\n",
        "From starts the body\n>From quoted\n>>From double\n",
        "no trailing newline",
        ""
      ]
      output = write_to_string do |writer|
        bodies.each_with_index do |body, index|
          writer.write(body, sender: "sender#{index}@example.com", date: "Thu Jan  2 03:04:0#{index} 2020")
        end
      end
      records = read_records(output)
      normalized = bodies.map { |b| b.empty? || b.end_with?("\n") ? b : "#{b}\n" }
      expect(records.map(&:data)).to eq normalized
      expect(records.map(&:envelope_sender)).to eq (0..3).map { |i| "sender#{i}@example.com" }
      expect(records.map(&:envelope_date)).to eq (0..3).map { |i| "Thu Jan  2 03:04:0#{i} 2020" }
    end
  end

  describe "read/write round trip with a binary attachment" do
    it "preserves an encoded body containing From lines" do
      binary = (0..255).map(&:chr).join.b
      binary << "\nFrom a line inside the attachment\n"
      binary << ">From an escaped line inside the attachment\n"
      binary << (255..0).step(-1).map(&:chr).join.b

      encoded = Mail::Encodings::QuotedPrintable.encode(binary)
      expect(encoded).to include "From a line inside the attachment"

      raw = +"From: alice@example.com\r\n" \
            "To: bob@example.com\r\n" \
            "Subject: binary payload\r\n" \
            "Content-Type: multipart/mixed; boundary=mbox-test-boundary\r\n" \
            "\r\n" \
            "--mbox-test-boundary\r\n" \
            "Content-Type: text/plain\r\n" \
            "\r\n" \
            "see attachment\r\n" \
            "--mbox-test-boundary\r\n" \
            "Content-Type: application/octet-stream; name=payload.bin\r\n" \
            "Content-Transfer-Encoding: quoted-printable\r\n" \
            "Content-Disposition: attachment; filename=payload.bin\r\n" \
            "\r\n"
      raw << encoded
      raw << "\r\n"
      raw << "--mbox-test-boundary--\r\n"

      io = StringIO.new(+''.b)
      writer = Mail::Mbox::Writer.new(io)
      writer.write(raw, sender: 'alice@example.com', date: Time.utc(2020, 1, 2, 3, 4, 5))
      writer.write(raw, sender: 'carol@example.com', date: 'Fri Jan  3 04:05:06 2020')

      records = Mail::Mbox::Reader.new(StringIO.new(io.string), chunk_size: 17).to_a
      expect(records.size).to eq 2
      expect(records.map(&:envelope_sender)).to eq %w[alice@example.com carol@example.com]
      records.each do |record|
        expect(record.data).to eq raw
        decoded = record.to_mail.attachments.first.decoded
        expect(decoded.b).to eq Mail::Encodings::QuotedPrintable.decode(encoded).b
        expect(decoded).to include "From a line inside the attachment"
        expect(decoded).to include ">From an escaped line inside the attachment"
      end

      # The escaped archive must not contain an unescaped "From " body line.
      io.string.each_line do |line|
        next if line =~ /\AFrom \S+ .+\n?\z/
        expect(line).not_to start_with 'From '
      end
    end
  end
end
