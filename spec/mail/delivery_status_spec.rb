# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DeliveryStatus do
  let(:crlf_body) do
    Mail::Utilities.to_crlf(<<-DSN)
Reporting-MTA: dns; mx.example.com
X-Greylist-Node: gv1; delayed=300

Final-Recipient: rfc822; ok@example.com
Action: delivered
Status: 2.0.0
Remote-MTA: dns; dest.example.com
Diagnostic-Code: smtp; 250 2.0.0 Message accepted
X-Queue-Id: Q1

Final-Recipient: rfc822; slow@example.com
Action: delayed
Status: 4.4.1
Diagnostic-Code: smtp; 451 4.4.1 Temporary failure;
    please stand by
X-Queue-Id: Q2

Final-Recipient: rfc822; gone@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; reject.example.com
Diagnostic-Code: smtp; 550 5.1.1 User unknown
X-Queue-Id: Q3
    DSN
  end

  describe "parsing" do
    subject(:dsn) { Mail::DeliveryStatus.new(crlf_body) }

    it "separates the per-message block from the recipient blocks" do
      expect(dsn.per_message.fields.map(&:name)).to eq %w[Reporting-MTA X-Greylist-Node]
      expect(dsn.recipients.size).to eq 3
    end

    it "parses per-message fields" do
      expect(dsn.reporting_mta).to eq 'mx.example.com'
      f = dsn.per_message.field('reporting-mta')
      expect(f.type).to eq 'dns'
      expect(f.value).to eq 'mx.example.com'
    end

    it "returns the actions one per recipient" do
      expect(dsn.recipients.map(&:action)).to eq %w[delivered delayed failed]
      expect(dsn.action).to eq %w[delivered delayed failed]
      expect(dsn.status).to eq %w[2.0.0 4.4.1 5.1.1]
    end

    it "splits type prefixes on the first semicolon only" do
      diag = dsn.recipients[1].field('diagnostic-code')
      expect(diag.type).to eq 'smtp'
      expect(diag.value).to eq '451 4.4.1 Temporary failure; please stand by'
    end

    it "keeps the complete field body available" do
      expect(dsn.recipients[0].body('remote-mta')).to eq 'dns; dest.example.com'
    end

    it "unfolds continued lines" do
      expect(dsn.recipients[1].diagnostic_code).to include('please stand by')
      expect(dsn.recipients[1].diagnostic_code).not_to include("\n")
    end

    it "keeps unknown extension fields" do
      expect(dsn.per_message.body('x-greylist-node')).to eq 'gv1; delayed=300'
      expect(dsn.recipients.map { |r| r.body('x-queue-id') }).to eq %w[Q1 Q2 Q3]
    end

    it "exposes blocks through Enumerable" do
      expect(dsn.map { |block| block.fields.size }).to eq [2, 6, 5, 6]
    end

    it "does not treat a semicolon in an untyped field as a prefix" do
      f = dsn.per_message.field('x-greylist-node')
      expect(f.type).to be_nil
      expect(f.value).to eq 'gv1; delayed=300'
    end
  end

  describe "single recipient reports" do
    it "returns scalar values instead of one element arrays" do
      body = "Reporting-MTA: dns; mx.example.com\r\n\r\n" \
             "Final-Recipient: rfc822; a@example.com\r\n" \
             "Action: failed\r\nStatus: 5.3.0\r\n"
      dsn = Mail::DeliveryStatus.new(body)
      expect(dsn.action).to eq 'failed'
      expect(dsn.status).to eq '5.3.0'
    end
  end

  describe "#bounced? and #retryable?" do
    it "is bounced and not retryable when any recipient failed with a 5 code" do
      dsn = Mail::DeliveryStatus.new(crlf_body)
      expect(dsn).to be_bounced
      expect(dsn).not_to be_retryable
    end

    it "is retryable with only 2.x and 4.x results" do
      body = "Reporting-MTA: dns; mx\r\n\r\n" \
             "Action: delayed\r\nStatus: 4.2.2\r\n\r\n" \
             "Action: delivered\r\nStatus: 2.0.0\r\n"
      dsn = Mail::DeliveryStatus.new(body)
      expect(dsn).not_to be_bounced
      expect(dsn).to be_retryable
    end
  end

  describe "error localization" do
    it "points at the recipient block and physical line" do
      body = "Reporting-MTA: dns; mx\r\n\r\n" \
             "Action: failed\r\nStatus: 5.1.1\r\n\r\n" \
             "Action: failed\r\nbroken line\r\nStatus: 5.1.1\r\n"
      expect { Mail::DeliveryStatus.new(body) }.to raise_error(
        Mail::DeliveryStatus::ParseError) { |error|
        expect(error.block_index).to eq 2
        expect(error.line_number).to eq 2
        expect(error.message).to include('recipient block #2')
        expect(error.message).to include('broken line')
      }
    end

    it "identifies the per-message block as block 0" do
      body = "Reporting-MTA: dns; mx\r\nbroken\r\n"
      expect { Mail::DeliveryStatus.new(body) }.to raise_error(
        Mail::DeliveryStatus::ParseError, /per-message block/)
    end

    it "reports the first physical line of a folded logical line" do
      body = "Reporting-MTA: dns; mx\r\n\r\n" \
             "Action:\r\n failed\r\nnot a field\r\n"
      expect { Mail::DeliveryStatus.new(body) }.to raise_error(
        Mail::DeliveryStatus::ParseError) { |error|
        expect(error.block_index).to eq 1
        expect(error.line_number).to eq 3
      }
    end

    it "rejects a folded continuation with no preceding field" do
      body = "Reporting-MTA: dns; mx\r\n\r\n orphan\r\n"
      expect { Mail::DeliveryStatus.new(body) }.to raise_error(
        Mail::DeliveryStatus::ParseError, /continuation/)
    end

    it "raises on a body with no blocks" do
      expect { Mail::DeliveryStatus.new("\r\n\r\n") }.to raise_error(
        Mail::DeliveryStatus::ParseError, /no field blocks/)
    end
  end

  describe "generation and round trips" do
    it "builds a report with a block" do
      dsn = Mail::DeliveryStatus.new do |s|
        s.message_field 'Reporting-MTA', 'mx.example.com', 'dns'
        s.message_field 'X-Generated', 'generator'
        s.add_recipient(
          'Final-Recipient' => ['rfc822', 'a@example.com'],
          'Action' => 'delivered',
          'Status' => '2.0.0'
        )
        block = s.add_recipient
        block << ['Final-Recipient', 'b@example.com', 'rfc822']
        block << ['Action', 'failed']
        block << ['Status', '5.1.1']
      end

      expect(dsn.recipients.size).to eq 2
      expect(dsn.encoded).to include("Reporting-MTA: dns; mx.example.com\r\n")
      expect(dsn.encoded).to include("X-Generated: generator\r\n")
      expect(dsn.encoded).to include("Action: failed\r\n")
    end

    it "survives being parsed again" do
      original = Mail::DeliveryStatus.new(crlf_body)
      reparsed = Mail::DeliveryStatus.new(original.encoded)

      expect(reparsed.per_message.fields.map { |f| [f.name, f.body] })
        .to eq original.per_message.fields.map { |f| [f.name, f.body] }
      expect(reparsed.recipients.size).to eq original.recipients.size
      reparsed.recipients.each_with_index do |block, i|
        expect(block.fields.map { |f| [f.name.downcase, f.body] })
          .to eq original.recipients[i].fields.map { |f| [f.name.downcase, f.body] }
      end
    end

    it "does not lose unknown extension fields on a round trip" do
      reparsed = Mail::DeliveryStatus.new(Mail::DeliveryStatus.new(crlf_body).encoded)
      expect(reparsed.per_message.body('x-greylist-node')).to eq 'gv1; delayed=300'
      expect(reparsed.recipients.map { |r| r.body('x-queue-id') }).to eq %w[Q1 Q2 Q3]
    end

    it "folds long values and parses them back" do
      long_text = 'word ' * 30
      field = Mail::DeliveryStatus::Field.new('Diagnostic-Code', long_text.strip, 'smtp')
      encoded_line = field.encoded
      expect(encoded_line).to include("\r\n ")
      encoded_line.lines.each do |line|
        expect(line.chomp.length).to be <= 78
      end
      rebuilt = Mail::DeliveryStatus::Field.parse(encoded_line)
      expect(rebuilt.type).to eq 'smtp'
      expect(rebuilt.value).to eq long_text.strip
    end
  end
end
