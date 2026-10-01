# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::RelatedResource do
  def parse(source)
    Mail.read_from_string(source.gsub(/\n/, "\r\n"))
  end

  def related(source_or_mail, anchor = nil)
    mail = source_or_mail.is_a?(String) ? parse(source_or_mail) : source_or_mail
    described_class.find(mail, anchor)
  end

  # A plain multipart/related message: HTML root plus a logo referenced by CID
  # and by a relative Content-Location.
  let(:simple_mail) do
    parse(<<~MAIL)
      Content-Type: multipart/related; boundary="b"; type="text/html"; start="<root@example.com>"

      --b
      Content-Type: text/html
      Content-ID: <root@example.com>
      Content-Location: https://example.com/site/index.html

      <html><body><img src="cid:logo"><img src="images/logo.png"></body></html>
      --b
      Content-Type: image/png
      Content-ID: <logo>
      Content-Location: https://example.com/site/images/logo.png
      Content-Disposition: inline; filename="logo.png"
      Content-Transfer-Encoding: 7bit

      LOGO-DATA
      --b--
    MAIL
  end

  let(:rfc822_fixture) do
    read_fixture('emails', 'related_emails', 'related_nested_rfc822.eml')
  end

  let(:nested_related_fixture) do
    read_fixture('emails', 'related_emails', 'related_nested_related.eml')
  end

  describe "container discovery" do
    it "finds the related container wrapping the HTML part" do
      resolver = described_class.find(simple_mail)
      expect(resolver).not_to be_nil
      expect(resolver.container.mime_type).to eq 'multipart/related'
    end

    it "returns nil when the message has no multipart/related container" do
      plain = parse("Content-Type: text/plain\r\n\r\nHello\r\n")
      expect(described_class.find(plain)).to be_nil
    end

    it "returns nil when the anchor is not a root of any related container" do
      nested = rfc822_fixture
      forward = nested.parts.detect { |p| p.mime_type == 'message/rfc822' }
      # An HTML part inside the forwarded message is outside the outer scope.
      inner_html = Mail.new(forward.body.decoded).html_part
      expect(described_class.find(nested, inner_html)).to be_nil
    end

    it "treats a message that is itself multipart/related as the container" do
      resolver = described_class.find(nested_related_fixture)
      expect(resolver.container).to eq nested_related_fixture
    end

    it "scopes an HTML part behind a multipart/alternative root (RFC 2387 3.2)" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="r"; type="multipart/alternative"

        --r
        Content-Type: multipart/alternative; boundary="a"

        --a
        Content-Type: text/plain

        hi
        --a
        Content-Type: text/html

        <img src="cid:logo">
        --a--
        --r
        Content-Type: image/png
        Content-ID: <logo>

        PNG
        --r--
      MAIL
      result = mail.resolve_related_resource('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/png'
    end
  end

  describe "root determination" do
    it "uses the part named by the start parameter" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"; start="<root@example.com>"

        --b
        Content-Type: image/png
        Content-ID: <logo>

        X
        --b
        Content-Type: text/html
        Content-ID: <root@example.com>

        <img src="cid:logo">
        --b--
      MAIL
      resolver = described_class.new(mail)
      expect(resolver.root.content_id).to eq '<root@example.com>'
      expect(resolver).to be_valid
    end

    it "falls back to the first body part without a start parameter" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html

        hi
        --b
        Content-Type: image/png
        Content-ID: <logo>

        X
        --b--
      MAIL
      resolver = described_class.new(mail)
      expect(resolver.root.mime_type).to eq 'text/html'
    end

    it "is invalid when start names no body part" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"; start="<missing@example.com>"

        --b
        Content-Type: text/html

        hi
        --b--
      MAIL
      resolver = described_class.new(mail)
      expect(resolver).not_to be_valid
      result = resolver.resolve('cid:logo')
      expect(result).to be_not_found
      expect(result.reason).to eq :start_not_found
    end

    it "is not applicable when the root part does not match the declared type" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/plain"; start="<root@example.com>"

        --b
        Content-Type: text/html
        Content-ID: <root@example.com>

        hi
        --b--
      MAIL
      result = described_class.new(mail).resolve('cid:logo')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :root_type_mismatch
    end

    it "is not applicable for a non-related container" do
      plain = parse("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\nhi\r\n--b--\r\n")
      result = described_class.new(plain).resolve('cid:logo')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :not_related
    end
  end

  describe "CID references" do
    it "resolves cid references to the matching body part" do
      result = described_class.new(simple_mail).resolve('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/png'
      expect(result.part.filename).to eq 'logo.png'
    end

    it "accepts percent-encoded CIDs (RFC 2392)" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html

        x
        --b
        Content-Type: image/png
        Content-ID: <lo go@example.com>

        X
        --b--
      MAIL
      result = described_class.new(mail).resolve('cid:lo%20go@example.com')
      expect(result).to be_resolved
    end

    it "reports not_found when no part carries the CID" do
      result = described_class.new(simple_mail).resolve('cid:absent')
      expect(result).to be_not_found
      expect(result.parts).to be_empty
    end

    it "is ambiguous when two parts carry the same CID and keeps both" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html

        <img src="cid:logo">
        --b
        Content-Type: image/png
        Content-ID: <logo>

        ONE
        --b
        Content-Type: image/gif
        Content-ID: <logo>

        TWO
        --b--
      MAIL
      result = described_class.new(mail).resolve('cid:logo')
      expect(result).to be_ambiguous
      expect(result.parts.map(&:mime_type)).to eq ['image/png', 'image/gif']
      expect(result.part).to be_nil
    end

    it "is not applicable for an empty cid reference" do
      result = described_class.new(simple_mail).resolve('cid:')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :invalid_reference
    end
  end

  describe "Content-Location references" do
    it "resolves relative references against the root Content-Location" do
      result = described_class.new(simple_mail).resolve('images/logo.png')
      expect(result).to be_resolved
      expect(result.part.filename).to eq 'logo.png'
    end

    it "resolves a local part advertised at an absolute http URL" do
      result = described_class.new(simple_mail).
        resolve('https://example.com/site/images/logo.png')
      expect(result).to be_resolved
      expect(result.part.filename).to eq 'logo.png'
    end

    it "does not fetch absolute http URLs without a matching part" do
      result = described_class.new(simple_mail).
        resolve('https://elsewhere.example.com/logo.png')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :external_reference
    end

    it "is not applicable for non-http absolute URIs" do
      %w[data:image/png;base64,AA== mailto:a@b.example ftp://example.com/x].each do |ref|
        result = described_class.new(simple_mail).resolve(ref)
        expect(result).to be_not_applicable
        expect(result.reason).to eq :external_reference
      end
    end

    it "is not applicable for same-document fragment references" do
      result = described_class.new(simple_mail).resolve('#top')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :fragment_reference
    end

    it "resolves a query-only reference to the root part" do
      result = described_class.new(simple_mail).resolve('?v=2')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'text/html'
    end

    it "matches parts that carry relative Content-Location headers" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html
        Content-Location: page.html

        <img src="images/logo.png">
        --b
        Content-Type: image/png
        Content-Location: images/logo.png

        X
        --b--
      MAIL
      result = described_class.new(mail).resolve('images/logo.png')
      expect(result).to be_resolved
    end

    it "reports not_found for a relative reference matching nothing without a base" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html

        <img src="missing.png">
        --b
        Content-Type: image/png
        Content-ID: <x>

        X
        --b--
      MAIL
      expect(described_class.new(mail).resolve('missing.png')).to be_not_found
    end

    it "is ambiguous when two parts advertise the same Content-Location" do
      mail = parse(<<~MAIL)
        Content-Type: multipart/related; boundary="b"; type="text/html"

        --b
        Content-Type: text/html
        Content-Location: https://example.com/a/index.html

        <img src="img/logo.png">
        --b
        Content-Type: image/png
        Content-Location: https://example.com/a/img/logo.png

        ONE
        --b
        Content-Type: image/gif
        Content-Location: https://example.com/a/img/logo.png

        TWO
        --b--
      MAIL
      result = described_class.new(mail).resolve('img/logo.png')
      expect(result).to be_ambiguous
      expect(result.parts.map(&:mime_type)).to eq ['image/png', 'image/gif']
    end

    it "does not treat an empty reference as resolvable" do
      result = described_class.new(simple_mail).resolve('   ')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :invalid_reference
    end
  end

  describe "scope isolation" do
    it "resolves the outer logo from the outer HTML of a message/rfc822 nesting" do
      outer = described_class.find(rfc822_fixture)
      result = outer.resolve('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/png'
      expect(result.part.filename).to eq 'outer-logo.png'
      expect(result.part.decoded).to eq 'OUTER-LOGO-PNG-DATA'
    end

    it "resolves the inner logo only from the forwarded message scope" do
      forward = rfc822_fixture.parts.detect { |p| p.mime_type == 'message/rfc822' }
      inner_mail = Mail.new(forward.body.decoded)
      inner = described_class.find(inner_mail)
      result = inner.resolve('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/gif'
      expect(result.part.filename).to eq 'inner-logo.gif'
    end

    it "resolves the outer logo from a related group nested inside another" do
      outer = described_class.new(nested_related_fixture)
      result = outer.resolve('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/png'
      expect(result.part.filename).to eq 'outer-logo.png'
    end

    it "does not leak into a nested related group" do
      inner_container = nested_related_fixture.parts.
        detect { |p| p.mime_type == 'multipart/related' }
      inner = described_class.new(inner_container)
      result = inner.resolve('cid:logo')
      expect(result).to be_resolved
      expect(result.part.mime_type).to eq 'image/gif'
      expect(result.part.filename).to eq 'inner-logo.gif'
    end

    it "does not leak relative Content-Location resolution across scopes" do
      outer = described_class.find(rfc822_fixture)
      # The inner group uses the same image path prefix under a different host.
      result = outer.resolve('images/logo.png')
      expect(result).to be_resolved
      expect(result.part.filename).to eq 'outer-logo.png'

      forward = rfc822_fixture.parts.detect { |p| p.mime_type == 'message/rfc822' }
      inner = described_class.find(Mail.new(forward.body.decoded))
      expect(inner.resolve('images/logo.gif').part.filename).to eq 'inner-logo.gif'
    end
  end

  describe "Message convenience API" do
    it "resolves a reference from the HTML part's related container" do
      result = simple_mail.resolve_related_resource('cid:logo')
      expect(result).to be_resolved
      expect(result.part.filename).to eq 'logo.png'
    end

    it "returns a reusable resolver via related_resources" do
      resolver = simple_mail.related_resources
      expect(resolver).to be_a described_class
      expect(resolver.resolve('cid:logo')).to be_resolved
      expect(resolver.resolve('images/logo.png')).to be_resolved
    end

    it "binds the inner scope when the inner HTML is the anchor" do
      forward = rfc822_fixture.parts.detect { |p| p.mime_type == 'message/rfc822' }
      inner_mail = Mail.new(forward.body.decoded)
      result = inner_mail.resolve_related_resource('cid:logo')
      expect(result.part.filename).to eq 'inner-logo.gif'
    end

    it "is not applicable without a related container" do
      plain = parse("Content-Type: text/html\r\n\r\n<html><img src=\"cid:logo\"></html>\r\n")
      result = plain.resolve_related_resource('cid:logo')
      expect(result).to be_not_applicable
      expect(result.reason).to eq :no_related_container
      expect(plain.related_resources).to be_nil
    end
  end

  describe "Result" do
    it "exposes the container, root and reference for a resolution" do
      result = described_class.new(simple_mail).resolve('cid:logo')
      expect(result.container).to eq simple_mail
      expect(result.root.mime_type).to eq 'text/html'
      expect(result.reference).to eq 'cid:logo'
      expect(result).to be_success
    end
  end
end
