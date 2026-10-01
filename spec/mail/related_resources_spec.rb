# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::RelatedResources do
  def related_message(parts)
    boundary = 'test-related-boundary'
    body = parts.map do |part|
      headers = part[:headers].map { |k, v| "#{k}: #{v}" }.join("\r\n")
      "--#{boundary}\r\n#{headers}\r\n\r\n#{part[:body]}\r\n"
    end.join
    Mail.new("Content-Type: multipart/related; boundary=#{boundary}; type=\"text/html\"; start=\"<root@example.com>\"\r\n" \
             "Mime-Version: 1.0\r\n\r\n#{body}--#{boundary}--\r\n")
  end

  def html_part(headers = {})
    { :headers => { 'Content-Type' => 'text/html', 'Content-Id' => '<root@example.com>' }.merge(headers),
      :body => '<html><body><img src="cid:logo"></body></html>' }
  end

  def image_part(cid, headers = {})
    { :headers => { 'Content-Type' => 'image/png', 'Content-Id' => "<#{cid}>" }.merge(headers),
      :body => 'IMAGE-DATA' }
  end

  describe 'resolving cid: references' do
    it 'finds the part whose Content-ID matches the cid' do
      mail = related_message([html_part, image_part('logo@example.com')])
      result = mail.resolve_related_resource('cid:logo@example.com')
      expect(result).to be_found
      expect(result.part.mime_type).to eq 'image/png'
      expect(result.part.decoded).to eq 'IMAGE-DATA'
    end

    it 'accepts the cid: scheme case-insensitively and percent-decodes the cid' do
      mail = related_message([html_part, image_part('logo@example.com')])
      expect(mail.resolve_related_resource('CID:logo%40example.com')).to be_found
    end

    it 'matches the Content-ID regardless of angle brackets in the header' do
      mail = related_message([html_part, image_part('logo@example.com')])
      expect(mail.resolve_related_resource('cid:logo@example.com').part.content_id).to eq '<logo@example.com>'
    end

    it 'returns not_found when no part in scope has the cid' do
      mail = related_message([html_part, image_part('logo@example.com')])
      expect(mail.resolve_related_resource('cid:missing@example.com')).to be_not_found
    end

    it 'returns ambiguous when several parts in scope share the cid and never picks one' do
      mail = related_message([html_part, image_part('logo@example.com'), image_part('logo@example.com')])
      result = mail.resolve_related_resource('cid:logo@example.com')
      expect(result).to be_ambiguous
      expect(result.part).to be_nil
      expect(result.parts.size).to eq 2
    end

    it 'returns not_applicable when the referencing part is not inside a multipart/related container' do
      mail = Mail.new("Content-Type: text/html\r\n\r\n<html><img src=\"cid:logo\"></html>")
      expect(mail.resolve_related_resource('cid:logo')).to be_not_applicable
    end
  end

  describe 'resolving Content-Location references' do
    it 'resolves a relative reference against the root part Content-Location' do
      mail = related_message([
        html_part('Content-Location' => 'http://static.example.com/mail/index.html'),
        image_part('img1', 'Content-Location' => 'http://static.example.com/mail/images/logo.png')
      ])
      result = mail.resolve_related_resource('images/logo.png')
      expect(result).to be_found
      expect(result.part.content_id).to eq '<img1>'
    end

    it 'matches an absolute URL claimed by a part through Content-Location' do
      mail = related_message([
        html_part,
        image_part('img1', 'Content-Location' => 'http://static.example.com/mail/images/logo.png')
      ])
      expect(mail.resolve_related_resource('http://static.example.com/mail/images/logo.png')).to be_found
    end

    it 'returns not_applicable for a remote URL no part in scope claims, without accessing the network' do
      mail = related_message([html_part, image_part('img1')])
      expect(mail.resolve_related_resource('http://example.com/remote.png')).to be_not_applicable
    end

    it 'returns not_found for a relative reference nothing in scope claims' do
      mail = related_message([html_part, image_part('img1')])
      expect(mail.resolve_related_resource('images/missing.png')).to be_not_found
    end

    it 'returns ambiguous when several parts claim the same Content-Location' do
      mail = related_message([
        html_part,
        image_part('img1', 'Content-Location' => 'images/logo.png'),
        image_part('img2', 'Content-Location' => 'images/logo.png')
      ])
      result = mail.resolve_related_resource('images/logo.png')
      expect(result).to be_ambiguous
      expect(result.parts.map(&:content_id)).to eq %w[<img1> <img2>]
    end
  end

  describe 'root part determination' do
    it 'uses the start parameter to find the root by Content-ID' do
      mail = related_message([image_part('logo@example.com'), html_part])
      root = mail.related_resources.root_part
      expect(root.mime_type).to eq 'text/html'
      expect(root.content_id).to eq '<root@example.com>'
    end

    it 'falls back to the type parameter when start is absent' do
      boundary = 'b1'
      mail = Mail.new("Content-Type: multipart/related; boundary=#{boundary}; type=\"text/html\"\r\n\r\n" \
                      "--#{boundary}\r\nContent-Type: image/png\r\n\r\nx\r\n" \
                      "--#{boundary}\r\nContent-Type: text/html\r\n\r\n<html></html>\r\n--#{boundary}--\r\n")
      expect(mail.related_resources.root_part.mime_type).to eq 'text/html'
    end

    it 'falls back to the first part when neither start nor type identify a root' do
      boundary = 'b2'
      mail = Mail.new("Content-Type: multipart/related; boundary=#{boundary}\r\n\r\n" \
                      "--#{boundary}\r\nContent-Type: text/html\r\n\r\n<html></html>\r\n" \
                      "--#{boundary}\r\nContent-Type: image/png\r\n\r\nx\r\n--#{boundary}--\r\n")
      expect(mail.related_resources.root_part.mime_type).to eq 'text/html'
    end
  end

  describe 'scoping' do
    describe 'with a nested message/rfc822 that reuses the same CID' do
      let(:mail) { read_fixture('emails', 'related_emails', 'nested_message_same_cid.eml') }
      let(:inner) { Mail.new(mail.parts[2].body.decoded) }

      it 'resolves the outer HTML cid:logo to the outer image only' do
        result = mail.resolve_related_resource('cid:logo')
        expect(result).to be_found
        expect(result.part.decoded).to eq 'OUTER-LOGO-IMAGE'
      end

      it 'does not descend into the message/rfc822 part, so the duplicate CID is not ambiguous' do
        expect(mail.parts[2].mime_type).to eq 'message/rfc822'
        expect(mail.resolve_related_resource('cid:logo')).not_to be_ambiguous
      end

      it 'resolves cid:logo inside the nested message to the inner image' do
        result = inner.resolve_related_resource('cid:logo')
        expect(result).to be_found
        expect(result.part.decoded).to eq 'INNER-LOGO-IMAGE'
      end

      it 'treats the nested message parts as out of scope for the outer message' do
        result = mail.resolve_related_resource('cid:logo', :from => inner.html_part)
        expect(result).to be_not_applicable
      end
    end

    describe 'with a nested multipart/related that reuses the same CID' do
      let(:mail) { read_fixture('emails', 'related_emails', 'nested_related_same_cid.eml') }
      let(:nested_container) { mail.parts[2] }
      let(:nested_html) { nested_container.parts[0] }

      it 'resolves the outer HTML cid:logo to the outer image only' do
        result = mail.resolve_related_resource('cid:logo')
        expect(result).to be_found
        expect(result.part.decoded).to eq 'OUTER-LOGO-IMAGE'
      end

      it 'resolves cid:logo from the nested HTML to the nested image' do
        result = mail.resolve_related_resource('cid:logo', :from => nested_html)
        expect(result).to be_found
        expect(result.part.decoded).to eq 'NESTED-LOGO-IMAGE'
      end

      it 'scopes the nested HTML to the nested multipart/related container' do
        expect(mail.related_resources.container_for(nested_html)).to eq nested_container
        expect(mail.related_resources.container_for(mail.html_part)).to eq mail
      end
    end
  end

  describe Mail::RelatedResources::Result do
    it 'rejects unknown statuses' do
      expect { Mail::RelatedResources::Result.new(:bogus, 'cid:x') }.to raise_error(ArgumentError)
    end

    it 'exposes the reference and matching parts' do
      result = Mail::RelatedResources::Result.new(:not_found, 'cid:x')
      expect(result.reference).to eq 'cid:x'
      expect(result.parts).to eq []
      expect(result.status).to eq :not_found
    end
  end
end
