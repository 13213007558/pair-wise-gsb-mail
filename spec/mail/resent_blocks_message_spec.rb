# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Message, 'resent blocks' do
  let(:raw_message) do
    <<~RAW
      Resent-Date: Mon, 01 Jan 2024 10:00:00 +0000
      Resent-From: Alice <alice@example.com>
      Resent-Sender: Sender One <sender1@example.com>
      Resent-To: Bob <bob@example.com>
      Resent-Cc: Bob CC <bobcc@example.com>
      Resent-Bcc: Secret One <secret1@example.com>
      Resent-Message-ID: <batch1@example.com>
      Resent-Date: Tue, 02 Jan 2024 11:00:00 +0000
      Resent-From: Carol <carol@example.com>
      Resent-To: Dave <dave@example.com>
      Resent-Bcc: Secret Two <secret2@example.com>
      From: Original Author <orig@example.com>
      To: First Recipient <first@example.com>
      Subject: Saying Hello
      Date: Fri, 21 Nov 1997 09:55:06 -0600

      Original body.
    RAW
  end

  let(:mail) { Mail.new(raw_message) }

  describe "parsing independent batches" do
    it "keeps every Resent-* occurrence in source order" do
      expect(mail.header.fields.map(&:name)).to eq %w[
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        Resent-Bcc Resent-Message-ID
        Resent-Date Resent-From Resent-To Resent-Bcc
        Date From To Subject
      ]
    end

    it "splits the fields into separate blocks" do
      expect(mail.resent_blocks.size).to eq 2
      expect(mail.resent_blocks[0].from).to eq ['alice@example.com']
      expect(mail.resent_blocks[0].sender_address).to eq 'sender1@example.com'
      expect(mail.resent_blocks[0].to).to eq ['bob@example.com']
      expect(mail.resent_blocks[0].cc).to eq ['bobcc@example.com']
      expect(mail.resent_blocks[0].bcc).to eq ['secret1@example.com']
      expect(mail.resent_blocks[0].message_id).to eq 'batch1@example.com'

      expect(mail.resent_blocks[1].from).to eq ['carol@example.com']
      expect(mail.resent_blocks[1].to).to eq ['dave@example.com']
      expect(mail.resent_blocks[1].bcc).to eq ['secret2@example.com']
    end

    it "reads convenience accessors from the latest block" do
      expect(mail.resent_from).to eq ['carol@example.com']
      expect(mail.resent_to).to eq ['dave@example.com']
      expect(mail.resent_bcc).to eq ['secret2@example.com']
      expect(mail.resent_date).to eq DateTime.parse('Tue, 02 Jan 2024 11:00:00 +0000')
      expect(mail.resent_sender).to be_nil
      expect(mail.resent_cc).to be_nil
      expect(mail.resent_message_id).to be_nil
    end

    it "never confuses the original author with the latest resender" do
      expect(mail.from).to eq ['orig@example.com']
      expect(mail.resent_from).to eq ['carol@example.com']
    end
  end

  describe "appending a batch" do
    before do
      mail.append_resent_block(from: 'Erin <erin@example.com>',
                               to: 'Faye <faye@example.com>',
                               cc: 'Greg <greg@example.com>',
                               bcc: 'Secret Three <secret3@example.com>')
    end

    it "adds a third independent block without reordering earlier fields" do
      expect(mail.header.fields.map(&:name)).to eq %w[
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        Resent-Bcc Resent-Message-ID
        Resent-Date Resent-From Resent-To Resent-Bcc
        Resent-Date Resent-From Resent-To Resent-Cc Resent-Bcc
        Date From To Subject
      ]
      expect(mail.resent_blocks.size).to eq 3
      expect(mail.resent_blocks.map(&:from)).to eq [
        ['alice@example.com'], ['carol@example.com'], ['erin@example.com']
      ]
    end

    it "round-trips all three same-named batches through re-parsing" do
      reparsed = Mail.new(mail.encoded)

      expect(reparsed.resent_blocks.size).to eq 3
      expect(reparsed.resent_blocks.map(&:from)).to eq [
        ['alice@example.com'], ['carol@example.com'], ['erin@example.com']
      ]
      expect(reparsed.resent_blocks.map { |b| b.to }).to eq [
        ['bob@example.com'], ['dave@example.com'], ['faye@example.com']
      ]
      expect(reparsed.resent_blocks.map { |b| b.bcc }).to eq [
        ['secret1@example.com'], ['secret2@example.com'], ['secret3@example.com']
      ]

      # The original author must not be rewritten to the last resender.
      expect(reparsed.from).to eq ['orig@example.com']
      expect(reparsed.resent_from).to eq ['erin@example.com']
    end

    it "rejects an invalid block before modifying the message" do
      expect {
        mail.append_resent_block(to: 'nobody@example.com')
      }.to raise_error(Mail::ResentBlock::ValidationError)
      expect(mail.resent_blocks.size).to eq 3
    end
  end

  describe "removing a batch" do
    it "removes only the selected block and keeps other field order" do
      mail.remove_resent_block(1)

      expect(mail.header.fields.map(&:name)).to eq %w[
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        Resent-Bcc Resent-Message-ID
        Date From To Subject
      ]
      expect(mail.resent_blocks.size).to eq 1
      expect(mail.resent_blocks.first.from).to eq ['alice@example.com']
      expect(mail.encoded).to include('secret1@example.com')
      expect(mail.encoded).not_to include('secret2@example.com')
    end

    it "removes a block found by a matcher" do
      mail.remove_resent_block { |b| b.from.include?('carol@example.com') }
      expect(mail.resent_blocks.map(&:from)).to eq [['alice@example.com']]
    end

    it "returns nil when nothing matches" do
      expect(mail.remove_resent_block(9)).to be_nil
      expect(mail.resent_blocks.size).to eq 2
    end
  end

  describe "validation across blocks" do
    it "validates every batch" do
      expect(mail.validate_resent_blocks!).to eq true
    end

    it "passes when a multi-author batch supplies a sender" do
      block = Mail::ResentBlock.new(from: ['x@example.com', 'y@example.com'],
                                    sender: 's@example.com',
                                    to: 'z@example.com')
      mail.append_resent_block(block)
      expect(mail.validate_resent_blocks!).to eq true
    end
  end

  describe '#resent_envelope' do
    it "builds the envelope from the latest complete batch" do
      envelope = mail.resent_envelope

      expect(envelope).to be_a(Mail::SmtpEnvelope)
      expect(envelope.from).to eq 'carol@example.com'
      expect(envelope.to).to eq ['dave@example.com', 'secret2@example.com']
    end

    it "prefers Resent-Sender as envelope sender when present" do
      mail.append_resent_block(from: ['a@example.com', 'b@example.com'],
                               sender: 's@example.com',
                               to: 'c@example.com')
      expect(mail.resent_envelope.from).to eq 's@example.com'
    end

    it "raises when there is no resent block" do
      plain = Mail.new { from 'orig@example.com'; to 'dest@example.com' }
      expect { plain.resent_envelope }.to raise_error(
        Mail::ResentBlock::ValidationError, /no resent block/
      )
    end
  end

  describe '#resent_delivery_copy' do
    it "strips the latest batch's Resent-Bcc from the copy only" do
      copy = mail.resent_delivery_copy

      expect(copy.encoded).not_to include('secret2@example.com')
      # Other batches' fields stay untouched in the copy...
      expect(copy.encoded).to include('secret1@example.com')
      # ...and the original message remains complete for auditing.
      expect(mail.encoded).to include('secret2@example.com')
      expect(mail.resent_blocks.last.bcc).to eq ['secret2@example.com']
    end

    it "can strip a specific batch's Bcc by index" do
      copy = mail.resent_delivery_copy(0)
      expect(copy.encoded).not_to include('secret1@example.com')
      expect(copy.encoded).to include('secret2@example.com')
    end

    it "is used by the resent envelope message" do
      expect(mail.resent_envelope.message).not_to include('secret2@example.com')
      expect(mail.resent_envelope.message).to include('secret1@example.com')
    end

    it "keeps the original From unchanged" do
      expect(mail.resent_delivery_copy.from).to eq ['orig@example.com']
    end
  end

  describe "coexisting with trace fields" do
    let(:raw_message) do
      <<~RAW
        Return-Path: <bounce@example.com>
        Received: from a by b; Mon, 01 Jan 2024 09:00:00 +0000
        Resent-Date: Mon, 01 Jan 2024 10:00:00 +0000
        Resent-From: alice@example.com
        Resent-To: bob@example.com
        Received: from c by d; Mon, 01 Jan 2024 10:30:00 +0000
        Resent-Date: Tue, 02 Jan 2024 11:00:00 +0000
        Resent-From: carol@example.com
        Resent-To: dave@example.com
        From: orig@example.com
        To: first@example.com

        body
      RAW
    end

    it "keeps both resent blocks intact alongside trace fields" do
      expect(mail.header.fields.map(&:name)).to eq %w[
        Return-Path Received Received
        Resent-Date Resent-From Resent-To
        Resent-Date Resent-From Resent-To
        From To
      ]
      expect(mail.resent_blocks.map(&:from)).to eq [
        ['alice@example.com'], ['carol@example.com']
      ]
    end

    it "appends a new batch as one block without disturbing earlier fields" do
      mail.append_resent_block(from: 'erin@example.com', to: 'faye@example.com')
      expect(mail.header.fields.map(&:name)).to eq %w[
        Return-Path Received Received
        Resent-Date Resent-From Resent-To
        Resent-Date Resent-From Resent-To
        Resent-Date Resent-From Resent-To
        From To
      ]
    end
  end
end
