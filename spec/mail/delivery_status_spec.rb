# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DeliveryStatus do
  let(:mail) { read_fixture('emails', 'multipart_report_emails', 'mixed_status_report.eml') }
  let(:status) { mail.delivery_status }

  describe "parsing a report with delivered, delayed and failed recipients" do
    it "is found through the message" do
      expect(mail).to be_delivery_status_report
      expect(status).to be_a(Mail::DeliveryStatus)
    end

    it "separates per-message fields from per-recipient blocks" do
      expect(status.message_fields['Reporting-MTA'].value).to eq 'mx.example.com'
      expect(status.message_fields['Reporting-MTA'].type).to eq 'dns'
      expect(status.message_fields['Arrival-Date'].value).to eq 'Wed, 30 Sep 2026 11:59:58 +0000'
      expect(status.recipients.size).to eq 3
    end

    it "takes the results out recipient by recipient" do
      delivered, delayed, failed = status.recipients

      expect(delivered.action).to eq 'delivered'
      expect(delivered.status).to eq '2.0.0'
      expect(delivered.final_recipient).to eq 'alice@example.com'
      expect(delivered).not_to be_bounced

      expect(delayed.action).to eq 'delayed'
      expect(delayed.status).to eq '4.2.2'
      expect(delayed).to be_retryable
      expect(delayed).not_to be_bounced

      expect(failed.action).to eq 'failed'
      expect(failed.status).to eq '5.1.1'
      expect(failed).to be_bounced
      expect(failed).not_to be_retryable
    end

    it "splits type prefixes off field values" do
      failed = status.recipients.last
      expect(failed['Final-Recipient'].type).to eq 'rfc822'
      expect(failed['Final-Recipient'].value).to eq 'carol@example.org'
      expect(failed.remote_mta).to eq 'mx.example.org'
      expect(failed.diagnostic_code).to eq '550 5.1.1 <carol@example.org>... User unknown'
      expect(failed['Diagnostic-Code'].type).to eq 'smtp'
    end

    it "unfolds folded field values" do
      delayed = status.recipients[1]
      expect(delayed.diagnostic_code).to eq '452 4.2.2 <bob@example.net>... Mailbox full, retry later'
    end

    it "keeps unknown extension fields" do
      expect(status.message_fields['X-Original-Queue-ID'].value).to eq '4XkTm12h3Lz9wPq'
      expect(status.recipients[0]['X-Remote-Queue-ID'].value).to eq '12345'
      expect(status.recipients[1]['X-Next-Retry'].value).to eq 'Wed, 30 Sep 2026 12:30:00 +0000'
      expect(status.recipients[2]['X-Failure-Reason'].value).to eq 'mailbox-unavailable'
    end
  end

  describe "error reporting" do
    it "locates a malformed line to its recipient block" do
      body = "Reporting-MTA: dns; mx.example.com\r\n" \
             "\r\n" \
             "Final-Recipient: rfc822; a@example.com\r\n" \
             "Action: failed\r\n" \
             "\r\n" \
             "Final-Recipient: rfc822; b@example.com\r\n" \
             "this is not a field\r\n"

      error = nil
      begin
        Mail::DeliveryStatus.parse(body)
      rescue Mail::DeliveryStatus::ParseError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.block_index).to eq 2
      expect(error.line).to eq 'this is not a field'
      expect(error.message).to include('recipient block 2')
    end

    it "locates a malformed line in the per-message block" do
      expect {
        Mail::DeliveryStatus.parse("not a field at all\r\n\r\nAction: failed\r\n")
      }.to raise_error(Mail::DeliveryStatus::ParseError, /per-message block/)
    end
  end

  describe "generating a report" do
    let(:generated) do
      report = Mail::DeliveryStatus.new
      report.message_fields['Reporting-MTA'] = 'dns; mx.example.com'
      report.message_fields['Arrival-Date'] = 'Wed, 30 Sep 2026 11:59:58 +0000'
      report.message_fields['X-Custom-Message-Extension'] = 'queue-id-123'

      ok = report.add_recipient
      ok['Final-Recipient'] = 'rfc822; alice@example.com'
      ok['Action'] = 'delivered'
      ok['Status'] = '2.0.0'

      bad = report.add_recipient
      bad['Final-Recipient'] = 'rfc822; carol@example.org'
      bad['Action'] = 'failed'
      bad['Status'] = '5.1.1'
      bad['Remote-MTA'] = 'dns; mx.example.org'
      bad['Diagnostic-Code'] = 'smtp; 550 5.1.1 <carol@example.org>... User unknown, this is a ' \
                               'rather long diagnostic line that must be folded when emitted'
      bad['X-Vendor-Extension'] = 'vendor; some-opaque-value'
      report
    end

    it "emits a parseable body that round-trips every field" do
      reparsed = Mail::DeliveryStatus.parse(generated.to_s)

      expect(reparsed.message_fields['Reporting-MTA'].full_value).to eq 'dns; mx.example.com'
      expect(reparsed.message_fields['X-Custom-Message-Extension'].value).to eq 'queue-id-123'
      expect(reparsed.recipients.map(&:action)).to eq %w(delivered failed)
      expect(reparsed.recipients[1].diagnostic_code).to eq(
        '550 5.1.1 <carol@example.org>... User unknown, this is a rather long ' \
        'diagnostic line that must be folded when emitted')
      expect(reparsed.recipients[1]['X-Vendor-Extension'].type).to eq 'vendor'
      expect(reparsed.recipients[1]['X-Vendor-Extension'].value).to eq 'some-opaque-value'
    end

    it "folds long lines" do
      expect(generated.to_s.lines.map(&:chomp).reject { |l| l.start_with?(' ') }.all? { |l| l.length <= 78 }).to be true
    end

    it "round-trips unknown fields without loss" do
      original = Mail::DeliveryStatus.parse(mail.delivery_status_part.body.decoded)
      reparsed = Mail::DeliveryStatus.parse(original.to_s)

      expect(reparsed.message_fields.fields.map(&:name)).to eq original.message_fields.fields.map(&:name)
      expect(reparsed.recipients.size).to eq 3
      reparsed.recipients.each_with_index do |rcpt, i|
        expect(rcpt.fields.map { |f| [f.name, f.type, f.value] }).
          to eq original.recipients[i].fields.map { |f| [f.name, f.type, f.value] }
      end
    end

    it "builds a full multipart/report message that Mail reads back" do
      body = generated.to_s
      report = Mail.new do
        from    'MAILER-DAEMON@example.com'
        to      'sender@example.org'
        subject 'Delivery Status Notification'
        content_type 'multipart/report; report-type=delivery-status'

        text_part do
          body 'Your message could not be delivered to all recipients.'
        end

        add_part Mail::Part.new(:content_type => 'message/delivery-status',
                                :body => body)
      end

      bounced = Mail.new(report.to_s)
      expect(bounced).to be_delivery_status_report

      status = bounced.delivery_status
      expect(status.message_fields['Reporting-MTA'].value).to eq 'mx.example.com'
      expect(status.recipients.map(&:action)).to eq %w(delivered failed)
      expect(status.recipients[0].final_recipient).to eq 'alice@example.com'
      expect(status.recipients[1].status).to eq '5.1.1'
      expect(status.recipients[1].remote_mta).to eq 'mx.example.org'
      expect(status.recipients[1]['X-Vendor-Extension'].value).to eq 'some-opaque-value'
      expect(status.message_fields['X-Custom-Message-Extension'].value).to eq 'queue-id-123'
    end
  end

  describe Mail::Part do
    it "exposes the structured delivery status of a part" do
      part = mail.delivery_status_part
      expect(part).to be_delivery_status_report_part
      expect(part.delivery_status).to be_a(Mail::DeliveryStatus)
      expect(part.delivery_status.recipients.size).to eq 3
    end

    it "returns nil for a human readable message/delivery-status part" do
      human = Mail::Part.new(:content_type => 'message/delivery-status',
                             :body => "This message was undeliverable.\r\n")
      expect(human.delivery_status).to be_nil
      expect(human).not_to be_delivery_status_report_part
    end
  end
end
