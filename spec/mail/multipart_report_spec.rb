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

    describe "multipart report with mixed per-recipient results" do

      let(:mail) { read_fixture('emails', 'multipart_report_emails', 'multi_address_mixed_results.eml') }
      let(:delivery_status) { mail.delivery_status_part.delivery_status_data }

      def recipient_conclusions(message)
        message.delivery_status_part.delivery_status_data.recipients.map do |recipient|
          [recipient.final_recipient, recipient.action, recipient.status,
           recipient.diagnostic_code, recipient.retryable?, recipient.bounced?]
        end.sort_by(&:first)
      end

      it "keeps report-level fields separate from the recipient records" do
        expect(delivery_status['reporting-mta']).to eq 'dns; mail.example.com'
        expect(delivery_status['x-postfix-queue-id']).to eq 'MIXED001'
        expect(delivery_status.recipients.length).to eq 2
      end

      it "keeps per-recipient fields paired when an optional field is missing" do
        delayed, failed = delivery_status.recipients
        expect(delayed.final_recipient).to eq 'rfc822; delayed@example.com'
        expect(delayed.status).to eq '4.4.1'
        expect(delayed.diagnostic_code).to be_nil
        expect(failed.final_recipient).to eq 'rfc822; failed@example.com'
        expect(failed.status).to eq '5.1.1'
        expect(failed.diagnostic_code).to eq "smtp; 550 5.1.1 <failed@example.com>... User unknown,\tmailbox does not exist"
      end

      it "gives per-recipient retry and failure results" do
        delayed, failed = delivery_status.recipients
        expect(delayed).to be_retryable
        expect(delayed).not_to be_bounced
        expect(failed).not_to be_retryable
        expect(failed).to be_bounced
      end

      it "aggregates the whole message across recipients" do
        expect(mail).to be_bounced
        expect(mail).to be_retryable
      end

      it "keeps the legacy array accessors aligned by recipient" do
        expect(mail.action).to eq ['delayed', 'failed']
        expect(mail.error_status).to eq ['4.4.1', '5.1.1']
        expect(mail.final_recipient).to eq ['rfc822; delayed@example.com', 'rfc822; failed@example.com']
        expect(mail.diagnostic_code).to eq [nil, "smtp; 550 5.1.1 <failed@example.com>... User unknown,\tmailbox does not exist"]
      end

      it "does not change per-recipient conclusions when the blocks are swapped" do
        raw = read_raw_fixture('emails', 'multipart_report_emails', 'multi_address_mixed_results.eml')
        swapped = raw.sub(/(Final-Recipient: rfc822; delayed@example\.com.*?)\n\n(Final-Recipient: rfc822; failed@example\.com.*?)(\n\n--)/m) do
          "#{$2}\n\n#{$1}#{$3}"
        end
        swapped_mail = Mail.read_from_string(swapped)
        expect(recipient_conclusions(swapped_mail)).to eq recipient_conclusions(mail)
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

end
