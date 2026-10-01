# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::RelatedParts do
  def related_mail(parts, type: 'text/html', start: '<html>')
    parameters = ['boundary="RELATED"']
    parameters << %(type="#{type}") if type
    parameters << %(start=#{start}) if start

    Mail.new(<<~MESSAGE)
      Content-Type: multipart/related; #{parameters.join('; ')}
      MIME-Version: 1.0

      #{parts}
    MESSAGE
  end

  def part(content_type:, cid: nil, body: '')
    headers = ["Content-Type: #{content_type}", cid && "Content-ID: #{cid}"].compact.join("\r\n")
    [headers, body].join("\r\n\r\n")
  end

  def related_part(*parts)
    parts.map { |part| "--RELATED\r\n#{part}" }.join("\r\n") + "\r\n--RELATED--\r\n"
  end

  it 'uses the start parameter instead of the first part' do
    mail = related_mail(related_part(
      part(content_type: 'application/smil', cid: '<smil>', body: 'SMIL'),
      part(content_type: 'text/html', cid: '<html>', body: '<img src="cid:logo">')
    ))

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['cid:logo'] })

    expect(result.root.content_type).to eq 'text/html'
    expect(result.errors).to eq []
  end

  it 'accepts start positionally and a block as the reference extractor' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>', body: '<img src="cid:logo">'),
      part(content_type: 'image/png', cid: '<logo>', body: 'PNG')
    ))

    result = mail.related_parts('<html>') { |_root| ['cid:logo'] }

    expect(result.root.content_type).to eq 'text/html'
    expect(result.used_resources.keys).to eq ['logo']
  end

  it 'defaults to the first part when start is absent' do
    mail = related_mail(related_part(
      part(content_type: 'application/smil', cid: '<smil>', body: 'SMIL'),
      part(content_type: 'text/html', cid: '<html>')
    ), start: nil)

    result = mail.related_parts

    expect(result.root.content_type).to eq 'application/smil'
  end

  it 'reports a root whose media type does not match the type parameter' do
    mail = related_mail(related_part(
      part(content_type: 'text/plain', body: 'plain')
    ), start: nil)

    result = mail.related_parts

    expect(result.root.content_type).to eq 'text/plain'
    expect(result.errors).to include(a_string_matching(/text\/html/))
  end

  it 'connects referenced resources and retains unused resources and parts' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>', body: '<img src="cid:logo">'),
      part(content_type: 'image/png', cid: '<logo>', body: 'PNG'),
      part(content_type: 'image/gif', cid: '<unused>', body: 'GIF'),
      part(content_type: 'application/octet-stream', body: 'NO CID')
    ))

    extractor = ->(_root) do
      ['cid:logo', 'cid:missing', 'http://example.invalid/image.png']
    end
    result = mail.related_parts(resource_reference_extractor: extractor)

    expect(result.used_resources.keys).to eq ['logo']
    expect(result.unused_resources.keys).to eq ['unused']
    expect(result.unused_parts.map(&:mime_type)).to include('application/octet-stream')
    expect(result.unresolved_references).to eq ['cid:missing']
    expect(result.external_references).to eq ['http://example.invalid/image.png']
    expect(result.references).to include('http://example.invalid/image.png')
  end

  it 'normalizes content IDs and cid URIs' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>'),
      part(content_type: 'image/png', cid: '<logo@example>')
    ))

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['cid:logo%40example'] })

    expect(result.used_resources).to eq('logo@example' => result.resources['logo@example'])
    expect(result.unresolved_references).to eq []
  end

  it 'preserves the original form of unresolvable cid references' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>')
    ))

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['CID:Missing%20Thing'] })

    expect(result.unresolved_references).to eq ['CID:Missing%20Thing']
  end

  it 'keeps duplicate content IDs ambiguous instead of overwriting one' do
    first = part(content_type: 'image/png', cid: '<dup>')
    second = part(content_type: 'image/gif', cid: '<dup>')
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>'),
      first,
      second
    ))

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['cid:dup'] })

    expect(result.resources['dup']).to contain_exactly(
      an_object_having_attributes(mime_type: 'image/png'),
      an_object_having_attributes(mime_type: 'image/gif')
    )
    expect(result.ambiguous_resources.keys).to eq ['dup']
    expect(result.unused_resources).not_to have_key('dup')
    expect(result.used_resources).not_to have_key('dup')
  end

  it 'does not use a resource that duplicates the root content ID' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<shared>'),
      part(content_type: 'image/png', cid: '<shared>')
    ), start: nil)

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['cid:shared'] })

    expect(result.ambiguous_resources.keys).to eq ['shared']
    expect(result.used_resources).to eq({})
    expect(result.unresolved_references).to eq([])
  end

  it 'reports an ambiguous start' do
    mail = related_mail(related_part(
      part(content_type: 'image/png', cid: '<dup>'),
      part(content_type: 'image/gif', cid: '<dup>')
    ), start: '<dup>')

    result = mail.related_parts

    expect(result.root).to be_nil
    expect(result.errors).to include('dup: start is ambiguous')
  end

  it 'reports a missing start' do
    mail = related_mail(related_part(
      part(content_type: 'text/html', cid: '<html>')
    ), start: '<missing>')

    result = mail.related_parts

    expect(result.root).to be_nil
    expect(result.errors).to eq ['missing: start not found']
  end

  it 'isolates nested multipart/related CID scopes' do
    mail = Mail.new(<<~MESSAGE)
      Content-Type: multipart/related; boundary="OUTER"; type="multipart/alternative"
      MIME-Version: 1.0

      --OUTER
      Content-Type: multipart/alternative; boundary="ALT"

      --ALT
      Content-Type: text/plain

      plain
      --ALT
      Content-Type: multipart/related; boundary="INNER"; type="text/html"

      --INNER
      Content-Type: text/html
      Content-ID: <inner-html>

      <img src="cid:shared">
      --INNER
      Content-Type: image/png
      Content-ID: <shared>

      inner image
      --INNER--
      --ALT--
      --OUTER
      Content-Type: image/gif
      Content-ID: <outer>

      outer image
      --OUTER--
    MESSAGE

    result = mail.related_parts(resource_reference_extractor: ->(root) {
      root.mime_type == 'multipart/alternative' ? ['cid:outer'] : ['cid:shared']
    })
    nested = result.nested_parts.first

    expect(result.resources.keys).to eq ['outer']
    expect(nested.resources.keys).to eq ['shared']
    expect(result.unresolved_references).to eq []
    expect(nested.unresolved_references).to eq []
  end

  it 'isolates CIDs inside message/rfc822 entities' do
    embedded = <<~EMBEDDED
      Content-Type: multipart/related; boundary="EMBEDDED"; type="text/html"
      MIME-Version: 1.0

      --EMBEDDED
      Content-Type: text/html
      Content-ID: <embedded-html>

      <img src="cid:shared">
      --EMBEDDED
      Content-Type: image/png
      Content-ID: <shared>

      embedded image
      --EMBEDDED--
    EMBEDDED

    mail = Mail.new(<<~MESSAGE)
      Content-Type: multipart/related; boundary="OUTER"; type="text/html"
      MIME-Version: 1.0

      --OUTER
      Content-Type: text/html
      Content-ID: <html>

      root
      --OUTER
      Content-Type: message/rfc822
      Content-ID: <message>

      #{embedded.gsub("\n", "\r\n")}
      --OUTER--
    MESSAGE

    result = mail.related_parts(resource_reference_extractor: ->(_root) { ['cid:message'] })
    nested = result.nested_parts.first

    expect(result.resources.keys).to contain_exactly('message')
    expect(result.used_resources.keys).to eq ['message']
    expect(nested.resources.keys).to eq ['shared']
    expect(nested.root.content_type).to eq 'text/html'
  end

  it 'finds related scopes nested inside non-related containers' do
    mail = Mail.new(<<~MESSAGE)
      Content-Type: multipart/related; boundary="OUTER"; type="multipart/mixed"
      MIME-Version: 1.0

      --OUTER
      Content-Type: multipart/mixed; boundary="MIXED"

      --MIXED
      Content-Type: multipart/related; boundary="INNER"; type="text/html"

      --INNER
      Content-Type: text/html
      Content-ID: <html>

      <img src="cid:logo">
      --INNER
      Content-Type: image/png
      Content-ID: <logo>

      image
      --INNER--
      --MIXED--
      --OUTER
      Content-Type: text/plain
      Content-ID: <note>

      note
      --OUTER--
    MESSAGE

    result = mail.related_parts(resource_reference_extractor: ->(root) {
      root.mime_type == 'multipart/mixed' ? ['cid:note'] : ['cid:logo']
    })
    nested = result.nested_parts.first

    expect(result.resources.keys).to eq ['note']
    expect(nested.resources.keys).to eq ['logo']
    expect(nested.used_resources.keys).to eq ['logo']
  end

  it 'returns nil for entities that are not multipart/related' do
    mail = Mail.new("Content-Type: multipart/mixed; boundary=X\r\n\r\n--X--\r\n")

    expect(mail.related_parts).to be_nil
    expect(mail).not_to be_multipart_related
  end
end
