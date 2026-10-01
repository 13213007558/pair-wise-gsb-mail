# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::FieldList do
  it "should be able to add new fields" do
    fl = Mail::FieldList.new
    fl << Mail::Field.parse("To: mikel@me.com")
    fl << Mail::Field.parse("From: mikel@me.com")
    expect(fl.map(&:name)).to eq %w[ From To ]
  end

  it "should be able to add new fields in the right order" do
    fl = Mail::FieldList.new
    fl << Mail::Field.parse("To: mikel@me.com")
    fl << Mail::Field.parse("From: mikel@me.com")
    fl << Mail::Field.parse("Received: from xxx.xxxx.xxx by xxx.xxxx.xxx with ESMTP id 6AAEE3B4D23 for <xxx@xxxx.xxx>; Sun, 8 May 2005 12:30:23 -0500")
    fl << Mail::Field.parse("Return-Path: mikel@me.com")
    expect(fl.map(&:name)).to eq %w[ Return-Path Received From To ]
  end

  it "should add new Received items after the existing ones" do
    fl = Mail::FieldList.new
    fl << Mail::Field.parse("To: mikel@me.com")
    fl << Mail::Field.parse("From: mikel@me.com")
    fl << Mail::Field.parse("Received: from xxx.xxxx.xxx by xxx.xxxx.xxx with ESMTP id 6AAEE3B4D23 for <xxx@xxxx.xxx>; Sun, 8 May 2005 12:30:23 -0500")
    fl << Mail::Field.parse("Return-Path: mikel@me.com")
    fl << Mail::Field.parse("Received: from 123.xxxx.xxx by xxx.xxxx.xxx with ESMTP id 6AAEE3B4D23 for <xxx@xxxx.xxx>; Sun, 8 May 2005 12:30:23 -0500")
    expect(fl[2].field.value).to eq 'from 123.xxxx.xxx by xxx.xxxx.xxx with ESMTP id 6AAEE3B4D23 for <xxx@xxxx.xxx>; Sun, 8 May 2005 12:30:23 -0500'
  end
end

RSpec.describe Mail::FieldList, 'resent fields' do
  it "keeps multiple Resent-* occurrences in source order instead of replacing them" do
    fl = Mail::FieldList.new
    [
      "Resent-Date: Mon, 01 Jan 2024 10:00:00 +0000",
      "Resent-From: alice@example.com",
      "Resent-To: bob@example.com",
      "Resent-Date: Tue, 02 Jan 2024 11:00:00 +0000",
      "Resent-From: carol@example.com",
      "Resent-To: dave@example.com"
    ].each { |raw| fl << Mail::Field.parse(raw) }

    expect(fl.map(&:name)).to eq %w[
      Resent-Date Resent-From Resent-To
      Resent-Date Resent-From Resent-To
    ]
    expect(fl.select { |f| f.responsible_for?('Resent-Date') }.size).to eq 2
    expect(fl.select { |f| f.responsible_for?('Resent-From') }.size).to eq 2
  end

  it "prepends the first resent fields and appends later batches as a block" do
    fl = Mail::FieldList.new
    fl << Mail::Field.parse("From: orig@example.com")
    fl << Mail::Field.parse("To: first@example.com")
    fl << Mail::Field.parse("Resent-Date: Mon, 01 Jan 2024 10:00:00 +0000")
    fl << Mail::Field.parse("Resent-From: alice@example.com")
    fl << Mail::Field.parse("Resent-Date: Tue, 02 Jan 2024 11:00:00 +0000")
    fl << Mail::Field.parse("Resent-From: carol@example.com")

    expect(fl.map(&:name)).to eq %w[
      Resent-Date Resent-From Resent-Date Resent-From
      From To
    ]
  end
end
