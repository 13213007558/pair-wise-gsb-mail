# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ResentBlock do
  describe '#initialize' do
    it "defaults Resent-Date to the current time" do
      block = Mail::ResentBlock.new(from: 'alice@example.com', to: 'bob@example.com')
      expect(block.date).to be_a(DateTime)
    end

    it "accepts an explicit date" do
      block = Mail::ResentBlock.new(date: 'Mon, 01 Jan 2024 10:00:00 +0000',
                                    from: 'alice@example.com',
                                    to: 'bob@example.com')
      expect(block.date).to eq(DateTime.parse('Mon, 01 Jan 2024 10:00:00 +0000'))
    end

    it "collects recipients from to, cc and bcc" do
      block = Mail::ResentBlock.new(from: 'alice@example.com',
                                    to: ['bob@example.com', 'carol@example.com'],
                                    cc: 'dave@example.com',
                                    bcc: 'hidden@example.com')
      expect(block.recipients).to eq %w[
        bob@example.com carol@example.com dave@example.com hidden@example.com
      ]
    end

    it "exposes the single sender address" do
      block = Mail::ResentBlock.new(from: ['a@example.com', 'b@example.com'],
                                    sender: 's@example.com',
                                    to: 'c@example.com')
      expect(block.sender_address).to eq 's@example.com'
    end
  end

  describe '#validate!' do
    it "passes for a complete block" do
      block = Mail::ResentBlock.new(from: 'alice@example.com', to: 'bob@example.com')
      expect(block.validate!).to eq true
      expect(block).to be_valid
    end

    it "requires Resent-From" do
      expect {
        Mail::ResentBlock.allocate.tap do |b|
          b.instance_variable_set(:@date, DateTime.now)
          b.instance_variable_set(:@from, [])
          b.instance_variable_set(:@sender, nil)
          b.instance_variable_set(:@to, ['bob@example.com'])
          b.instance_variable_set(:@cc, [])
          b.instance_variable_set(:@bcc, [])
          b.validate!
        end
      }.to raise_error(Mail::ResentBlock::ValidationError, /Resent-From/)
    end

    it "requires a recipient" do
      expect {
        described_class.new(from: 'alice@example.com', to: nil)
      }.to raise_error(Mail::ResentBlock::ValidationError, /Resent-To\/Resent-Cc\/Resent-Bcc/)
    end

    it "accepts a bcc-only recipient" do
      block = described_class.new(from: 'alice@example.com', bcc: 'hidden@example.com')
      expect(block).to be_valid
    end

    it "requires Resent-Sender when Resent-From lists multiple authors" do
      expect {
        described_class.new(from: ['a@example.com', 'b@example.com'],
                            to: 'c@example.com')
      }.to raise_error(Mail::ResentBlock::ValidationError, /Resent-Sender/)
    end

    it "passes with multiple authors when a sender is given" do
      block = described_class.new(from: ['a@example.com', 'b@example.com'],
                                  sender: 's@example.com',
                                  to: 'c@example.com')
      expect(block).to be_valid
    end
  end

  describe '#to_fields' do
    it "emits fields in canonical order" do
      block = described_class.new(date: 'Mon, 01 Jan 2024 10:00:00 +0000',
                                  from: 'alice@example.com',
                                  sender: 's@example.com',
                                  to: 'bob@example.com',
                                  cc: 'carol@example.com',
                                  bcc: 'hidden@example.com',
                                  message_id: '<1234@example.com>')
      expect(block.to_fields.map(&:name)).to eq %w[
        Resent-Date Resent-From Resent-Sender Resent-To Resent-Cc
        Resent-Bcc Resent-Message-ID
      ]
    end

    it "omits empty optional fields" do
      block = described_class.new(date: 'Mon, 01 Jan 2024 10:00:00 +0000',
                                  from: 'alice@example.com',
                                  to: 'bob@example.com')
      expect(block.to_fields.map(&:name)).to eq %w[Resent-Date Resent-From Resent-To]
    end
  end

  describe '.from_fields' do
    def field(name, value)
      Mail::Field.new(name, value)
    end

    it "groups fields into independent batches by field recurrence" do
      fields = [
        field('Resent-Date', 'Mon, 01 Jan 2024 10:00:00 +0000'),
        field('Resent-From', 'alice@example.com'),
        field('Resent-To', 'bob@example.com'),
        field('Resent-Date', 'Tue, 02 Jan 2024 11:00:00 +0000'),
        field('Resent-From', 'carol@example.com'),
        field('Resent-To', 'dave@example.com'),
        field('Resent-Date', 'Wed, 03 Jan 2024 12:00:00 +0000'),
        field('Resent-From', 'erin@example.com'),
        field('Resent-To', 'faye@example.com')
      ]

      blocks = described_class.from_fields(fields)
      expect(blocks.size).to eq 3
      expect(blocks.map(&:from)).to eq [
        ['alice@example.com'], ['carol@example.com'], ['erin@example.com']
      ]
      expect(blocks.first.fields.map(&:name)).to eq %w[Resent-Date Resent-From Resent-To]
    end

    it "starts a new batch even when a Resent-Date is missing" do
      fields = [
        field('Resent-From', 'alice@example.com'),
        field('Resent-To', 'bob@example.com'),
        field('Resent-From', 'carol@example.com'),
        field('Resent-To', 'dave@example.com')
      ]

      blocks = described_class.from_fields(fields)
      expect(blocks.size).to eq 2
      expect(blocks[0].to).to eq ['bob@example.com']
      expect(blocks[1].to).to eq ['dave@example.com']
    end
  end

  describe '#==' do
    it "compares blocks by content" do
      a = described_class.new(date: 'Mon, 01 Jan 2024 10:00:00 +0000',
                              from: 'alice@example.com', to: 'bob@example.com')
      b = described_class.new(date: 'Mon, 01 Jan 2024 10:00:00 +0000',
                              from: 'alice@example.com', to: 'bob@example.com')
      expect(a).to eq b
    end
  end
end
