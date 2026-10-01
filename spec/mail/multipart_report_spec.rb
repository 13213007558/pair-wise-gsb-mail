# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe "multipart/report emails" do
  
  it "should know if it is a multipart report type" do
    mail = read_fixture('emails', 'multipart_report_emails', 'report_422.eml')
    expect(mail).to be_multipart_report
  end

  describe "delivery-status reports" do

    it "should know if it is a deliver-status report" do
      mail = read_fixture('emails', 'multipart_report_emails', 'report_422.eml')
      expect(mail).to be_delivery_status_report
    end

    it "should find its message/delivery-status part" do
      mail = read_fixture('emails', 'multipart_report_emails', 'report_422.eml')
      expect(mail.delivery_status_part).not_to be_nil
    end

    it "should handle a report that has a human readable message/delivery-status" do
      mail = read_fixture('emails', 'multipart_report_emails', 'multipart_report_multiple_status.eml')
      expect(mail).to be_bounced
    end

    describe "delivery-status part in a non report email" do
      let(:mail){
        string = read_raw_fixture('emails', 'multipart_report_emails', 'report_422.eml')
        Mail.read_from_string(string.sub("multipart/report; report-type=delivery-status;", "multipart/mixed;"))
      }

      it "does not return a delivery_status_part" do
        expect(mail.delivery_status_part).to be_nil
      end
    end

    describe "multipart reports with more than one address" do
      it "should not crash" do
        mail1 = read_fixture('emails', 'multipart_report_emails', 'multi_address_bounce1.eml')
        mail2 = read_fixture('emails', 'multipart_report_emails', 'multi_address_bounce2.eml')
        expect { mail1.bounced? }.not_to raise_error
        expect { mail2.bounced? }.not_to raise_error
      end

      it "should not know that a multi address email was bounced" do
        mail1 = read_fixture('emails', 'multipart_report_emails', 'multi_address_bounce1.eml')
        mail2 = read_fixture('emails', 'multipart_report_emails', 'multi_address_bounce2.eml')
        expect(mail1).to be_bounced
        expect(mail2).to be_bounced
      end
    end

    describe "temporary failure" do

      before(:each) do
        @mail = read_fixture('emails', 'multipart_report_emails', 'report_422.eml')
      end

      it "should be bounced" do
        expect(@mail).not_to be_bounced
      end

      it "should say action 'delayed'" do
        expect(@mail.action).to eq 'delayed'
      end

      it "should give a final recipient" do
        expect(@mail.final_recipient).to eq 'RFC822; fraser@oooooooo.com.au'
      end

      it "should give an error code" do
        expect(@mail.error_status).to eq '4.2.2'
      end

      it "should give a diagostic code" do
        expect(@mail.diagnostic_code).to eq 'SMTP; 452 4.2.2 <fraser@oooooooo.com.au>... Mailbox full'
      end

      it "should give a remote-mta" do
        expect(@mail.remote_mta).to eq 'DNS; mail.oooooooo.com.au'
      end

      it "should be retryable" do
        expect(@mail).to be_retryable
      end
    end

    describe "permanent failure" do

      before(:each) do
        @mail = read_fixture('emails', 'multipart_report_emails', 'report_530.eml')
      end

      it "should be bounced" do
        expect(@mail).to be_bounced
      end

      it "should say action 'failed'" do
        expect(@mail.action).to eq 'failed'
      end

      it "should give a final recipient" do
        expect(@mail.final_recipient).to eq 'RFC822; edwin@zzzzzzz.com'
      end

      it "should give an error code" do
        expect(@mail.error_status).to eq '5.3.0'
      end

      it "should give a diagostic code" do
        expect(@mail.diagnostic_code).to eq 'SMTP; 553 5.3.0 <edwin@zzzzzzz.com>... Unknown E-Mail Address'
      end

      it "should give a remote-mta" do
        expect(@mail.remote_mta).to eq 'DNS; mail.zzzzzz.com'
      end

      it "should be retryable" do
        expect(@mail).not_to be_retryable
      end
    end

  end

  describe "structured delivery status" do
    let(:mail) { read_fixture('emails', 'multipart_report_emails', 'report_mixed_actions.eml') }

    it "exposes a structured delivery status object" do
      expect(mail.delivery_status).to be_a(Mail::DeliveryStatus)
      expect(mail.delivery_status.recipients.size).to eq 3
    end

    it "separates per-message fields from recipient blocks" do
      expect(mail.delivery_status.reporting_mta).to eq 'mx.example.com'
      expect(mail.delivery_status.per_message.fields.map(&:name))
        .to include('Reporting-MTA', 'X-Example-Account', 'Arrival-Date')
    end

    it "returns one result per recipient, in order" do
      dsn = mail.delivery_status
      expect(dsn.recipients.map(&:action)).to eq %w[delivered delayed failed]
      expect(dsn.recipients.map(&:status)).to eq %w[2.0.0 4.4.1 5.1.1]
    end

    it "splits the type prefix from the value" do
      recipient = mail.delivery_status.recipients.first
      field = recipient.field('final-recipient')
      expect(field.type).to eq 'rfc822'
      expect(field.value).to eq 'delivered-user@example.com'
    end

    it "keeps Action, Status, Diagnostic-Code and Remote-MTA" do
      failed = mail.delivery_status.recipients.last
      expect(failed.action).to eq 'failed'
      expect(failed.status).to eq '5.1.1'
      expect(failed.remote_mta).to eq 'reject-mta.example.com'
      expect(failed.diagnostic_code).to eq '550 5.1.1 User unknown'
      expect(failed.body('diagnostic-code')).to eq 'smtp; 550 5.1.1 User unknown'
    end

    it "unfolds folded Diagnostic-Code values" do
      delayed = mail.delivery_status.recipients[1]
      expect(delayed.diagnostic_code).to eq '451 4.4.1 Temporary network failure; will retry shortly'
    end

    it "returns arrays from the message level accessors for multi-recipient reports" do
      expect(mail.action).to eq %w[delivered delayed failed]
      expect(mail.error_status).to eq %w[2.0.0 4.4.1 5.1.1]
    end

    it "is bounced because one recipient failed, and not retryable" do
      expect(mail).to be_bounced
      expect(mail).not_to be_retryable
    end

    it "preserves unknown extension fields on a parse/serialize/read round trip" do
      dsn = mail.delivery_status

      rebuilt_part = Mail::Part.new do
        content_type 'message/delivery-status'
        body dsn.encoded
      end
      rebuilt = rebuilt_part.delivery_status

      expect(rebuilt.recipients.size).to eq 3
      expect(rebuilt.per_message.body('x-example-account')).to eq '12345; alpha'
      expect(rebuilt.recipients.map { |r| r.body('x-example-ticket') })
        .to eq %w[INC-1 INC-2 INC-3]

      original_blocks = dsn.blocks.map { |b| b.fields.map { |f| [f.name.downcase, f.body] } }
      rebuilt_blocks = rebuilt.blocks.map { |b| b.fields.map { |f| [f.name.downcase, f.body] } }
      expect(rebuilt_blocks).to eq original_blocks
    end

    it "generates a legal report that Mail reads back" do
      dsn = Mail::DeliveryStatus.new do |status|
        status.message_field 'Reporting-MTA', 'mx.generated.example.com', 'dns'
        status.message_field 'X-Generated-By', 'mail gem'
        status.add_recipient(
          'Final-Recipient' => ['rfc822', 'ok@example.com'],
          'Action' => 'delivered',
          'Status' => '2.0.0',
          'X-Recipient-Tag' => 'green'
        )
        status.add_recipient(
          'Final-Recipient' => ['rfc822', 'gone@example.com'],
          'Action' => 'failed',
          'Status' => '5.1.1',
          'Diagnostic-Code' => ['smtp', '550 5.1.1 unknown user'],
          'X-Recipient-Tag' => 'red'
        )
      end

      generated = Mail.new do
        from 'MAILER-DAEMON@mx.generated.example.com'
        to 'sender@example.com'
        subject 'Generated delivery report'
        content_type 'multipart/report; report-type=delivery-status'
      end
      generated.add_part(Mail::Part.new { content_type 'text/plain'; body 'see report' })
      generated.add_part(Mail::Part.new { content_type 'message/delivery-status'; body dsn.encoded })

      read_back = Mail.read_from_string(generated.to_s)
      expect(read_back).to be_delivery_status_report
      expect(read_back).to be_bounced
      expect(read_back.delivery_status.recipients.map(&:action)).to eq %w[delivered failed]
      expect(read_back.delivery_status.recipients.map { |r| r.body('x-recipient-tag') })
        .to eq %w[green red]
      expect(read_back.delivery_status.per_message.body('x-generated-by')).to eq 'mail gem'
      expect(read_back.delivery_status.recipients.last.diagnostic_code).to eq '550 5.1.1 unknown user'
    end
  end

end

