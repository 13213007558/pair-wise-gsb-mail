# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe "Resent field groups" do
  # A message that has been resent three times. Each resending prepended
  # its own block of Resent-* fields, so the header carries three groups
  # of same-named fields, most recent first.
  def three_group_message
    Mail.new(<<~MAIL.gsub(/\n/, "\r\n"))
      Resent-Date: Thu, 01 Oct 2026 12:00:00 +0000
      Resent-From: third@resender.example.com
      Resent-To: list-c@example.com
      Resent-Bcc: hidden-c@example.com
      Resent-Date: Wed, 30 Sep 2026 12:00:00 +0000
      Resent-From: second@resender.example.com
      Resent-To: list-b@example.com
      Resent-Bcc: hidden-b@example.com
      Resent-Date: Tue, 29 Sep 2026 12:00:00 +0000
      Resent-From: first@resender.example.com
      Resent-To: list-a@example.com
      Resent-Bcc: hidden-a@example.com
      From: author@example.com
      To: original-recipient@example.com
      Subject: resent three times
      Message-ID: <original@example.com>

      The body.
    MAIL
  end

  describe "parsing" do
    it "keeps every group of same-named Resent-* fields instead of collapsing them" do
      mail = three_group_message
      expect(mail.header.fields.select { |f| f.responsible_for?('Resent-From') }.size).to eq 3
      expect(mail.header.fields.select { |f| f.responsible_for?('Resent-Date') }.size).to eq 3
      expect(mail.header.fields.select { |f| f.responsible_for?('Resent-To') }.size).to eq 3
    end

    it "keeps each block contiguous and in its original order" do
      mail = three_group_message
      expect(mail.header.fields.map(&:name)).to eq(
        %w[Resent-Date Resent-From Resent-To Resent-Bcc] * 3 +
        %w[From To Message-ID Subject]
      )
    end

    it "does not change the original author to the last redeliverer" do
      mail = three_group_message
      expect(mail.from).to eq ['author@example.com']
      expect(mail.to).to eq ['original-recipient@example.com']
    end
  end

  describe "#resent_groups" do
    it "returns one group per resending, most recent first" do
      groups = three_group_message.resent_groups
      expect(groups.size).to eq 3
      expect(groups.map { |g| g.resent_from }).to eq [
        ['third@resender.example.com'],
        ['second@resender.example.com'],
        ['first@resender.example.com']
      ]
    end

    it "exposes the fields of each group" do
      group = three_group_message.resent_groups.first
      expect(group.resent_date).to eq DateTime.parse('Thu, 01 Oct 2026 12:00:00 +0000')
      expect(group.resent_from).to eq ['third@resender.example.com']
      expect(group.resent_to).to eq ['list-c@example.com']
      expect(group.resent_bcc).to eq ['hidden-c@example.com']
      expect(group.resent_cc).to eq []
      expect(group.resent_sender).to be_nil
      expect(group.destinations).to eq ['list-c@example.com', 'hidden-c@example.com']
    end

    it "returns an empty array when there are no resent fields" do
      expect(Mail.new.resent_groups).to eq []
    end

    it "survives a round trip through encoded output with the original author intact" do
      mail = Mail.new(three_group_message.encoded)
      expect(mail.resent_groups.size).to eq 3
      expect(mail.resent_groups.map { |g| g.resent_from.first }).to eq(
        %w[third@resender.example.com second@resender.example.com first@resender.example.com]
      )
      expect(mail.from).to eq ['author@example.com']
      expect(mail.encoded).to eq Mail.new(mail.encoded).encoded
    end
  end

  describe "legacy resent accessors" do
    it "reads the most recent group" do
      mail = three_group_message
      expect(mail.resent_from).to eq ['third@resender.example.com']
      expect(mail.resent_to).to eq ['list-c@example.com']
      expect(mail.resent_date).to eq DateTime.parse('Thu, 01 Oct 2026 12:00:00 +0000')
    end
  end

  describe "#add_resent_group" do
    it "prepends a new group without disturbing the order of the other groups" do
      mail = three_group_message
      before = mail.resent_groups.map(&:encoded)

      group = mail.add_resent_group(from: 'fourth@resender.example.com',
                                    to: 'list-d@example.com',
                                    date: Time.utc(2026, 10, 2))

      expect(mail.resent_groups.size).to eq 4
      expect(mail.resent_groups.first.resent_from).to eq ['fourth@resender.example.com']
      expect(mail.resent_groups[1..-1].map(&:encoded)).to eq before
      expect(group.resent_date).to eq DateTime.parse('Fri, 02 Oct 2026 00:00:00 +0000')
      expect(mail.from).to eq ['author@example.com']
    end

    it "defaults the Resent-Date to now" do
      mail = Mail.new
      group = mail.add_resent_group(from: 'resender@example.com', to: 'list@example.com')
      expect(group.resent_date).to be_within(5).of(DateTime.now)
    end

    it "requires a Resent-From" do
      mail = Mail.new
      expect {
        mail.add_resent_group(to: 'list@example.com')
      }.to raise_error(Mail::Field::FieldError, /Resent-From/)
      expect(mail.resent_groups).to eq []
    end

    it "requires a Resent-Sender when Resent-From has multiple authors" do
      mail = Mail.new
      expect {
        mail.add_resent_group(from: 'one@example.com, two@example.com',
                              to: 'list@example.com')
      }.to raise_error(Mail::Field::FieldError, /Resent-Sender/)

      group = mail.add_resent_group(from: 'one@example.com, two@example.com',
                                    sender: 'one@example.com',
                                    to: 'list@example.com')
      expect(group).to be_complete
      expect(group.envelope_from).to eq 'one@example.com'
    end
  end

  describe "#remove_resent_group" do
    it "removes one group and preserves the order of the remaining groups" do
      mail = three_group_message
      removed = mail.remove_resent_group(1)

      expect(removed.resent_from).to eq ['second@resender.example.com']
      expect(mail.resent_groups.map { |g| g.resent_from.first }).to eq(
        %w[third@resender.example.com first@resender.example.com]
      )
      expect(mail.encoded).not_to include('hidden-b@example.com')
      expect(mail.encoded).to include('hidden-c@example.com')
      expect(mail.encoded).to include('hidden-a@example.com')
      expect(mail.from).to eq ['author@example.com']
    end

    it "removes the most recent group by default" do
      mail = three_group_message
      mail.remove_resent_group
      expect(mail.resent_groups.map { |g| g.resent_from.first }).to eq(
        %w[second@resender.example.com first@resender.example.com]
      )
    end

    it "accepts a group object" do
      mail = three_group_message
      group = mail.resent_groups.last
      mail.remove_resent_group(group)
      expect(mail.resent_groups.size).to eq 2
      expect(mail.encoded).not_to include('first@resender.example.com')
    end

    it "returns nil when there is no such group" do
      expect(Mail.new.remove_resent_group).to be_nil
    end
  end

  describe "group validation" do
    it "is incomplete without Resent-Date" do
      mail = Mail.new("Resent-From: a@example.com\r\n\r\n")
      group = mail.resent_groups.first
      expect(group).not_to be_complete
      expect(group.errors).to include('missing Resent-Date')
      expect { group.validate! }.to raise_error(Mail::Field::FieldError, /Resent-Date/)
    end

    it "is incomplete without Resent-From" do
      mail = Mail.new("Resent-Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n\r\n")
      group = mail.resent_groups.first
      expect(group).not_to be_complete
      expect(group.errors).to include('missing Resent-From')
    end

    it "is incomplete with multiple Resent-From authors and no Resent-Sender" do
      mail = Mail.new(<<~MAIL.gsub(/\n/, "\r\n"))
        Resent-Date: Thu, 01 Oct 2026 12:00:00 +0000
        Resent-From: one@example.com, two@example.com
        Resent-To: list@example.com

      MAIL
      group = mail.resent_groups.first
      expect(group).not_to be_complete
      expect(group.errors).to include(/Resent-Sender/)
    end
  end

  describe "#resent_envelope" do
    it "builds an envelope from the most recent complete group" do
      mail = three_group_message
      envelope = mail.resent_envelope

      expect(envelope.from).to eq 'third@resender.example.com'
      expect(envelope.to).to eq ['list-c@example.com', 'hidden-c@example.com']
    end

    it "prefers the group's Resent-Sender as envelope sender" do
      mail = Mail.new(<<~MAIL.gsub(/\n/, "\r\n"))
        Resent-Date: Thu, 01 Oct 2026 12:00:00 +0000
        Resent-From: one@example.com, two@example.com
        Resent-Sender: secretary@example.com
        Resent-To: list@example.com
        From: author@example.com

      MAIL
      expect(mail.resent_envelope.from).to eq 'secretary@example.com'
    end

    it "strips the corresponding Resent-Bcc from the sent copy only" do
      mail = three_group_message
      envelope = mail.resent_envelope

      # The sent copy drops the most recent group's Resent-Bcc...
      expect(envelope.message).not_to include('hidden-c@example.com')
      # ...but keeps the other groups' fields untouched...
      expect(envelope.message).to include('hidden-b@example.com')
      expect(envelope.message).to include('hidden-a@example.com')
      # ...and the original object still has everything for auditing.
      expect(mail.encoded).to include('hidden-c@example.com')
      expect(mail.resent_groups.size).to eq 3
    end

    it "skips an incomplete latest group and uses the latest complete one" do
      mail = Mail.new(<<~MAIL.gsub(/\n/, "\r\n"))
        Resent-From: broken@example.com
        Resent-Date: Wed, 30 Sep 2026 12:00:00 +0000
        Resent-From: complete@example.com
        Resent-To: list@example.com
        From: author@example.com

      MAIL
      envelope = mail.resent_envelope
      expect(envelope.from).to eq 'complete@example.com'
      expect(envelope.to).to eq ['list@example.com']
    end

    it "raises when no complete resent group exists" do
      mail = Mail.new("From: author@example.com\r\n\r\n")
      expect { mail.resent_envelope }.to raise_error(Mail::Field::FieldError, /no complete resent field group/)
    end

    it "raises when the complete group has no recipients" do
      mail = Mail.new(<<~MAIL.gsub(/\n/, "\r\n"))
        Resent-Date: Thu, 01 Oct 2026 12:00:00 +0000
        Resent-From: resender@example.com
        From: author@example.com

      MAIL
      expect { mail.resent_envelope }.to raise_error(ArgumentError, /To address may not be blank/)
    end
  end
end
