# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ParameterHash do
  it "should return the values in the hash" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash.keys).to include("value1")
    expect(hash.keys).to include("value2")
    expect(hash.values).to include('one')
    expect(hash.values).to include('two')
  end

  it "should return the values in the hash regardless of symbol or string" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash['value1']).to eq 'one'
    expect(hash['value2']).to eq 'two'
    expect(hash[:value1]).to eq 'one'
    expect(hash[:value2]).to eq 'two'
  end

  it "should return the values in the hash using case-insensitive key matching" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'VALUE2' => 'two'})
    expect(hash['VALUE1']).to eq 'one'
    expect(hash['vAlUe2']).to eq 'two'
    expect(hash[:VaLuE1]).to eq 'one'
    expect(hash[:value2]).to eq 'two'
  end

  it "should return the correct value if they are not encoded" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash['value1']).to eq 'one'
    expect(hash['value2']).to eq 'two'
  end

  it "should return a name list concatenated" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*1' => 'one', 'value*2' => 'two'})
    expect(hash['value']).to eq 'onetwo'
  end

  it "should return a name list concatenated and unencoded" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*0*' => "us-ascii'en'This%20is%20even%20more%20",
                 'value*1*' => "%2A%2A%2Afun%2A%2A%2A%20",
                 'value*2'  => "isn't it"})
    expect(hash['value']).to eq "This is even more ***fun*** isn't it"
  end

  it "allows for blank language" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "us-ascii''Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "allows for blank charset" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "'en'Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "allows for blank charset and language" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "''Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "converts from specified encoding to utf-8" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "iso-8859-1'en'H%EBll%F3%20there"})
    expect(hash['value']).to eq "Hëlló there"
  end

  it "should allow us to add a value" do
    hash = Mail::ParameterHash.new
    hash['value'] = 'bob'
    expect(hash['value']).to eq 'bob'
  end

  it "should return an encoded value" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*0*' => "us-ascii'en'This%20is%20even%20more%20",
                 'value*1*' => "%2A%2A%2Afun%2A%2A%2A%20",
                 'value*2'  => "isn't it"})
    expect(hash.encoded).to eq %Q{value*0*=us-ascii'en'This%20is%20even%20more%20;\r\n\svalue*1*=%2A%2A%2Afun%2A%2A%2A%20;\r\n\svalue*2="isn't it"}
  end

  describe "RFC 2231 continuations" do
    it "orders continuation sections numerically rather than lexicographically" do
      hash = Mail::ParameterHash.new
      (0..11).each { |i| hash["filename*#{i}"] = "%02d" % i }
      expect(hash['filename']).to eq (0..11).map { |i| "%02d" % i }.join
    end

    it "orders multi-digit sections through encoded output too" do
      hash = Mail::ParameterHash.new
      hash.merge!({'name*0' => 'a', 'name*1' => 'b', 'name*10' => 'k', 'name*2' => 'c'})
      expect(hash.encoded.split(";\r\n\s").map { |p| p.split('=').first }).
        to eq %w[name*0 name*1 name*2 name*10]
    end

    it "concatenates extended and plain sections (mixed encoding)" do
      hash = Mail::ParameterHash.new
      hash.merge!({'filename*0*' => "utf-8''00",
                   'filename*1'  => '01',
                   'filename*2*' => '02',
                   'filename*3'  => '03'})
      expect(hash['filename']).to eq '00010203'
    end

    it "does not percent-decode plain sections" do
      hash = Mail::ParameterHash.new
      hash.merge!({'f*0*' => "utf-8''", 'f*1' => '%41', 'f*2*' => '%42'})
      expect(hash['f']).to eq '%41B'
    end

    it "decodes a UTF-8 character split across a section boundary" do
      hash = Mail::ParameterHash.new
      hash.merge!({'f*0*' => "utf-8''%E6", 'f*1*' => '%97%A5%E6%9C%AC'})
      expect(hash['f']).to eq '日本'
    end

    it "uses the charset and language from section 0 only" do
      hash = Mail::ParameterHash.new
      hash.merge!({'f*0*' => "iso-8859-1'en'%EB", 'f*1*' => '%F3'})
      expect(hash['f']).to eq 'ëó'
    end

    it "skips missing section numbers but keeps the order stable" do
      hash = Mail::ParameterHash.new
      hash.merge!({'f*0' => 'a', 'f*1' => 'b', 'f*3' => 'd'})
      expect(hash['f']).to eq 'abd'
    end

    it "is stable regardless of insertion order" do
      hash = Mail::ParameterHash.new
      {3 => 'd', 0 => 'a', 10 => 'k', 1 => 'b'}.each { |i, v| hash["f*#{i}"] = v }
      expect(hash['f']).to eq 'abdk'
    end

    it "prefers the extended value when a section is duplicated" do
      hash = Mail::ParameterHash.new
      hash.merge!({'f*0*' => "utf-8''%61", 'f*0' => 'z', 'f*1*' => 'b'})
      expect(hash['f']).to eq 'ab'
    end

    it "prefers a single extended parameter over a plain parameter" do
      hash = Mail::ParameterHash.new
      hash.merge!({'filename' => 'a', 'filename*' => "utf-8''b"})
      expect(hash['filename']).to eq 'b'
    end

    it "leaves a plain parameter untouched when no extended parameter exists" do
      hash = Mail::ParameterHash.new
      hash.merge!({'filename' => 'report.pdf'})
      expect(hash['filename']).to eq 'report.pdf'
    end
  end

end
