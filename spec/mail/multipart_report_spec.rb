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

    describe "multiple recipients with different optional fields" do
      let(:alice_block) do
        <<ENDPART
Final-Recipient: RFC822; alice@example.com
Action: delayed
Status: 4.2.2
Remote-MTA: DNS; mx.example.com
ENDPART
      end

      let(:bob_block) do
        <<ENDPART
Final-Recipient: RFC822; bob@example.com
Action: failed
Status: 5.1.1
Remote-MTA: DNS; mx.example.com
Diagnostic-Code: SMTP; 550 5.1.1 mailbox does not exist
ENDPART
      end

      let(:report_block) do
        <<ENDPART
Reporting-MTA: dns; mail.example.com
Arrival-Date: Mon, 24 Dec 2007 10:03:47 +1100
ENDPART
      end

      def build_mail(recipient_blocks)
        status_body = report_block + "\n" + recipient_blocks.join("\n")
        Mail.new(Mail::Utilities.to_crlf(<<ENDCONTENT))
Content-Type: multipart/report; report-type=delivery-status;
 boundary="boundary"

--boundary
Content-Type: text/plain

delivery status notification
--boundary
Content-Type: message/delivery-status

#{status_body}--boundary--
ENDCONTENT
      end

      it "pairs optional fields per recipient and aggregates the mail" do
        mail = build_mail([alice_block, bob_block])

        expect(mail).to be_delivery_status_report
        expect(mail.final_recipient)
          .to eq ['RFC822; alice@example.com', 'RFC822; bob@example.com']
        expect(mail.error_status).to eq ['4.2.2', '5.1.1']
        expect(mail.diagnostic_code)
          .to eq [nil, 'SMTP; 550 5.1.1 mailbox does not exist']
        expect(mail).to be_retryable
        expect(mail).to be_bounced

        alice, bob = mail.recipient_reports
        expect([alice.retryable?, alice.bounced?]).to eq [true, false]
        expect([bob.retryable?, bob.bounced?]).to eq [false, true]
      end

      it "keeps the same per-recipient results when the blocks are swapped" do
        mail = build_mail([alice_block, bob_block])
        swapped = build_mail([bob_block, alice_block])

        conclusions = lambda do |m|
          m.recipient_reports.map do |record|
            [record.final_recipient, record.status,
             record.diagnostic_code, record.retryable?, record.bounced?]
          end.sort_by(&:first)
        end

        expect(conclusions.call(swapped)).to eq conclusions.call(mail)
      end
    end

  end

end
