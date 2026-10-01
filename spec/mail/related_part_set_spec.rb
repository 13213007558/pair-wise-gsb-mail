# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::RelatedPartSet do
  def related_mail(parts, type: 'multipart/related; boundary="RELATED-BOUNDARY"')
    body = parts.map { |part| "--RELATED-BOUNDARY\r\n#{part}\r\n" }.join
    body << "--RELATED-BOUNDARY--\r\n"

    Mail.new("MIME-Version: 1.0\r\nContent-Type: #{type}\r\n\r\n#{body}")
  end

  def html_part(body, content_id: nil)
    headers = ["Content-Type: text/html", "Content-Transfer-Encoding: 7bit"]
    headers << "Content-ID: <#{content_id}>" if content_id
    "#{headers.join("\r\n")}\r\n\r\n#{body}"
  end

  def image_part(content_id)
    "Content-Type: image/png\r\nContent-ID: <#{content_id}>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n"
  end

  def mixed_mail(related_body)
    body = "--MIXED-BOUNDARY\r\n#{related_body}\r\n--MIXED-BOUNDARY--\r\n"
    Mail.new("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"MIXED-BOUNDARY\"\r\n\r\n#{body}")
  end

  def related_part(part, content_type)
    "Content-Type: #{content_type}\r\nContent-Transfer-Encoding: 7bit\r\n\r\n#{part}"
  end

  it 'selects the first part as root and connects its CID references' do
    html = '<img src="cid:logo@example"><img src="https://example.test/x.png"><img src="cid:missing@example">'
    mail = related_mail([html_part(html), image_part('logo@example'), image_part('unused@example')])

    result = mail.related_parts

    expect(result.root).to eq(mail.parts.first)
    expect(result.resources.keys).to contain_exactly('logo@example', 'unused@example')
    expect(result.references.map(&:content_id)).to eq(['logo@example'])
    expect(result.references.map(&:part)).to eq([mail.parts[1]])
    expect(result.external_references.map(&:uri)).to eq(['https://example.test/x.png'])
    expect(result.unresolved_references.map(&:content_id)).to eq(['missing@example'])
    expect(result.unused_resources).to eq([mail.parts[2]])
    expect(result.associated_parts).to eq([mail.parts[1], mail.parts[2]])
    expect(result.errors).to be_empty
  end

  it 'finds the related container inside an outer multipart message' do
    related_body = [html_part('<img src="cid:logo@example">'), image_part('logo@example')]
                   .map { |part| "--RELATED-BOUNDARY\r\n#{part}\r\n" }.join + "--RELATED-BOUNDARY--\r\n"
    related = related_part(related_body, 'multipart/related; boundary="RELATED-BOUNDARY"')
    mail = mixed_mail(related)

    result = mail.related_parts

    expect(result.container).to eq(mail.parts.first)
    expect(result.dependency_parts).to eq([mail.parts.first.parts.last])
  end

  it 'preserves associated parts without a usable CID as unused resources' do
    metadata = "Content-Type: application/octet-stream\r\n\r\nmetadata"
    mail = related_mail([html_part('<p>ok</p>'), metadata])

    result = mail.related_parts

    expect(result.resources).to be_empty
    expect(result.unused_resources).to eq([mail.parts.last])
  end

  it 'selects the start part and reports a mismatching root media type' do
    mail = related_mail(
      [html_part('<img src="cid:html@example">', content_id: 'html@example'), image_part('logo@example')],
      type: 'multipart/related; boundary="RELATED-BOUNDARY"; start="<logo@example>"; type="text/html"'
    )

    result = mail.related_parts

    expect(result.root).to eq(mail.parts.last)
    expect(result.resources.keys).to contain_exactly('html@example')
    expect(result.errors.map(&:type)).to eq([:root_type_mismatch])
    expect(result.errors.first.expected).to eq('text/html')
    expect(result.errors.first.actual).to eq('image/png')
  end

  it 'accepts an unbracketed or cid-prefixed start parameter' do
    mail = related_mail(
      [html_part('<p>html</p>', content_id: 'html@example'), image_part('logo@example')],
      type: 'multipart/related; boundary="RELATED-BOUNDARY"; start="cid:logo@example"'
    )

    result = mail.related_parts

    expect(result.root).to eq(mail.parts.last)
    expect(result.errors).to be_empty
 
    mail = related_mail(
      [html_part('<p>html</p>', content_id: 'html@example'), image_part('logo@example')],
      type: 'multipart/related; boundary="RELATED-BOUNDARY"; start="logo@example"'
    )
 
    expect(mail.related_parts.root).to eq(mail.parts.last)
  end

  it 'ignores media type parameters when checking the root type' do
    mail = related_mail(
      [html_part('<p>ok</p>')],
      type: 'multipart/related; boundary="RELATED-BOUNDARY"; type="text/html; charset=UTF-8"'
    )

    result = mail.related_parts

    expect(result.errors).to be_empty
  end

  it 'reports a start CID that cannot be found' do
    mail = related_mail(
      [html_part('<p>ok</p>')],
      type: 'multipart/related; boundary="RELATED-BOUNDARY"; start="<missing@example>"; type="text/html"'
    )

    result = mail.related_parts

    expect(result.root).to be_nil
    expect(result.errors.map(&:type)).to eq([:start_not_found])
  end

  it 'keeps duplicate same-level CIDs ambiguous instead of overwriting one resource' do
    html = '<img src="cid:logo@example">'
    mail = related_mail([html_part(html), image_part('logo@example'), image_part('logo@example')])

    result = mail.related_parts

    expect(result.resources).to be_empty
    expect(result.ambiguous_resources.keys).to eq(['logo@example'])
    expect(result.ambiguous_resources['logo@example']).to eq([mail.parts[1], mail.parts[2]])
    expect(result.references).to be_empty
    expect(result.unresolved_references.map(&:content_id)).to eq(['logo@example'])
  end

  it 'keeps CID scopes separate in a nested multipart/related part' do
    nested = [
      "--NESTED-BOUNDARY\r\n#{html_part('<img src="cid:shared@example">')}\r\n",
      "--NESTED-BOUNDARY\r\n#{image_part('shared@example')}\r\n",
      "--NESTED-BOUNDARY\r\n#{image_part('inner-only@example')}\r\n",
      "--NESTED-BOUNDARY--\r\n"
    ].join
    nested_part = "Content-Type: multipart/related; boundary=\"NESTED-BOUNDARY\"\r\n\r\n#{nested}"
    alternative = [
      "Content-Type: multipart/alternative; boundary=\"ALTERNATIVE-BOUNDARY\"",
      '',
      "--ALTERNATIVE-BOUNDARY\r\n#{html_part('<img src="cid:shared@example"><img src="cid:inner-only@example">')}\r\n",
      "--ALTERNATIVE-BOUNDARY\r\n#{nested_part}\r\n",
      "--ALTERNATIVE-BOUNDARY--\r\n"
    ].join("\r\n")
    mail = related_mail([alternative, image_part('shared@example')])

    result = mail.related_parts
    nested_result = result.related_parts.first

    expect(result.references.map(&:part)).to eq([mail.parts[1]])
    expect(result.unresolved_references.map(&:content_id)).to eq(['inner-only@example'])
    expect(nested_result.references.map { |reference| reference.part.content_id }).to eq(['<shared@example>'])
    expect(nested_result.unused_resources.map { |part| part.header[:content_id].content_id }).to eq(['inner-only@example'])
  end

  it 'gives an embedded message/rfc822 part its own CID scope' do
    embedded = <<~MESSAGE
      MIME-Version: 1.0
      Content-Type: multipart/related; boundary="EMBEDDED-BOUNDARY"

      --EMBEDDED-BOUNDARY
      Content-Type: text/html

      <img src="cid:shared@example"><img src="cid:embedded-only@example">
      --EMBEDDED-BOUNDARY
      #{image_part('shared@example')}
      --EMBEDDED-BOUNDARY
      #{image_part('embedded-only@example')}
      --EMBEDDED-BOUNDARY--
    MESSAGE
    embedded = embedded.gsub("\r\n", "\n").gsub("\n", "\r\n")
    message_part = "Content-Type: message/rfc822\r\n\r\n#{embedded}"
    outer_html = html_part('<img src="cid:shared@example"><img src="cid:embedded-only@example">')
    mail = related_mail([outer_html, image_part('shared@example'), message_part])

    result = mail.related_parts
    embedded_result = result.related_parts.first

    expect(result.references.map(&:part)).to eq([mail.parts[1]])
    expect(result.unresolved_references.map(&:content_id)).to eq(['embedded-only@example'])
    expect(embedded_result.references.size).to eq(2)
    expect(embedded_result.unresolved_references).to be_empty
  end

  it 'uses the injected resource reference extractor and preserves values it cannot resolve' do
    html = '<div data-resource="selected">relative/path</div>'
    mail = related_mail([html_part(html), image_part('selected@example')])
    extractor = lambda do |part|
      part.mime_type == 'text/html' ? ['cid:selected@example', 'relative/path'] : []
    end

    result = mail.related_parts(extractor)

    expect(result.dependency_parts).to eq([mail.parts.last])
    expect(result.unused_resources).to be_empty
    expect(result.unresolved_references.map(&:uri)).to eq(['relative/path'])
  end

  it 'accepts the resource reference extractor as a keyword argument' do
    mail = related_mail([html_part('<img src="cid:logo@example">'), image_part('logo@example')])
    extractor = lambda { |part| part.mime_type == 'text/html' ? ['cid:logo@example'] : [] }

    result = mail.related_parts(resource_reference_extractor: extractor)

    expect(result.dependency_parts).to eq([mail.parts.last])
  end

  it 'connects transitive references from resolved resources' do
    css = "body { background: url(cid:background@example) }"
    css_part = "Content-Type: text/css\r\nContent-ID: <style@example>\r\n\r\n#{css}"
    html = '<link rel="stylesheet" href="cid:style@example">'
    mail = related_mail([html_part(html), css_part, image_part('background@example')])

    result = mail.related_parts

    expect(result.dependency_parts).to eq([mail.parts[1], mail.parts[2]])
    expect(result.unused_resources).to be_empty
  end
end
