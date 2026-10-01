# frozen_string_literal: true

require 'cgi'
require 'set'

module Mail
  class RelatedPartSet
    Reference = Struct.new(:uri, :scheme, :content_id, :source_part, :part, keyword_init: true)
    Error = Struct.new(:type, :message, :expected, :actual, keyword_init: true)

    attr_reader :container, :root, :resources, :ambiguous_resources,
                :references, :unresolved_references, :external_references,
                :unused_resources, :errors, :related_parts

    def self.parse(container, extractor = nil, resource_reference_extractor: nil, &block)
      new(container, resource_reference_extractor || extractor || block).parse
    end

    def initialize(container, extractor = nil)
      @container = container
      @extractor = extractor || method(:extract_references)
      @resources = {}
      @ambiguous_resources = {}
      @references = []
      @unresolved_references = []
      @external_references = []
      @unused_resources = []
      @errors = []
      @related_parts = []
    end

    def parse
      collect_resources
      select_root
      check_root_type
      collect_related_parts
      connect_references if @root
      self
    end

    def dependency_parts
      references.map(&:part).uniq
    end
    alias_method :dependencies, :dependency_parts

    def used_resources
      references.map(&:part).uniq
    end

    def associated_parts
      root ? container.parts.reject { |part| part.equal?(root) } : container.parts
    end

    def unresolved_resource_references
      unresolved_references
    end

    def unresolvable_references
      unresolved_references
    end

    private

    def collect_resources
      container.parts.each do |part|
        content_id = content_id_for(part)
        next unless content_id

        if @resources.key?(content_id) || @ambiguous_resources.key?(content_id)
          @ambiguous_resources[content_id] ||= []
          if @resources.key?(content_id)
            @ambiguous_resources[content_id] << @resources.delete(content_id)
          end
          @ambiguous_resources[content_id] << part
        else
          @resources[content_id] = part
        end
      end
    end

    def select_root
      start = parameter('start')

      if start
        content_id = normalize_content_id(start)
        if @ambiguous_resources.key?(content_id)
          @errors << Error.new(
            type: :ambiguous_start,
            message: "multipart/related start #{start} is ambiguous",
            expected: content_id,
            actual: @ambiguous_resources[content_id]
          )
        elsif @resources.key?(content_id)
          @root = @resources.delete(content_id)
        else
          @errors << Error.new(
            type: :start_not_found,
            message: "multipart/related start #{start} was not found",
            expected: content_id,
            actual: nil
          )
        end
      else
        @root = container.parts.first
        if @root
          content_id = content_id_for(@root)
          @resources.delete(content_id) if content_id
        end
      end
    end

    def check_root_type
      expected_type = parameter('type')
      return unless expected_type && @root

      actual_type = @root.mime_type
      unless media_types_equal?(expected_type, actual_type)
        @errors << Error.new(
          type: :root_type_mismatch,
          message: "multipart/related root has type #{actual_type}, expected #{expected_type}",
          expected: expected_type.downcase,
          actual: actual_type
        )
      end
    end

    def collect_related_parts
      container.parts.each { |part| collect_nested_related(part) }
    end

    def collect_nested_related(part)
      if multipart_related?(part)
        @related_parts << self.class.new(part, @extractor).parse unless part.equal?(container)
      elsif message_rfc822?(part)
        begin
          embedded_message(part) { |message| collect_related_from_message(message) }
        rescue StandardError => error
          @errors << Error.new(
            type: :invalid_message_rfc822,
            message: error.message,
            expected: 'message/rfc822',
            actual: part
          )
        end
      elsif multipart?(part)
        part.parts.each { |child| collect_nested_related(child) }
      end
    end

    def collect_related_from_message(message)
      @related_parts << self.class.new(message, @extractor).parse if multipart_related?(message)
      message.parts.each { |part| collect_nested_related(part) }
    end

    def connect_references
      visited = Set.new
      pending = [@root]

      while (part = pending.shift)
        next unless part
        next if visited.include?(part.object_id)
        visited << part.object_id

        references_from(part).each do |reference|
          classify_reference(reference)
          resolved = reference.part
          if resolved && scope_member?(resolved) && !visited.include?(resolved.object_id)
            pending << resolved
          end
        end

        enqueue_children(part, pending)
      end

      @unused_resources = container.parts.reject do |part|
        part.equal?(@root) ||
          references.any? { |reference| reference.part.equal?(part) } ||
          ambiguous_part?(part)
      end
    end

    def enqueue_children(part, pending)
      return unless multipart?(part) && !multipart_related?(part) && !message_rfc822?(part)

      part.parts.each { |child| pending << child }
    end

    def references_from(part)
      values = Array(call_extractor(part))
      values.flat_map { |value| build_reference(value, part) }
    rescue StandardError
      []
    end

    def call_extractor(part)
      if @extractor.respond_to?(:arity) && @extractor.arity == 2
        @extractor.call(part, container)
      else
        @extractor.call(part)
      end
    end

    def build_reference(value, source)
      return [] if value.nil?

      uri = value.to_s.strip
      return [] if uri.empty?

      cid_match = /\Acid:(.*)\z/i.match(uri)
      if cid_match
        content_id = normalize_content_id(CGI.unescape(cid_match[1]))
        return [Reference.new(uri: uri, scheme: 'cid', content_id: content_id, source_part: source)]
      end

      scheme_match = /\A([a-z][a-z0-9+.-]*):/i.match(uri)
      if scheme_match
        [Reference.new(uri: uri, scheme: scheme_match[1].downcase, content_id: nil, source_part: source)]
      else
        [Reference.new(uri: uri, scheme: nil, content_id: nil, source_part: source)]
      end
    end

    def classify_reference(reference)
      if reference.scheme == 'cid'
        if @ambiguous_resources.key?(reference.content_id)
          add_unresolved_reference(reference)
        elsif (part = @resources[reference.content_id])
          reference.part = part
          add_reference(reference)
        else
          add_unresolved_reference(reference)
        end
      elsif reference.scheme
        add_external_reference(reference)
      else
        add_unresolved_reference(reference)
      end
    end

    def add_reference(reference)
      @references << reference unless reference_exists?(@references, reference)
    end

    def add_external_reference(reference)
      @external_references << reference unless reference_exists?(@external_references, reference)
    end

    def add_unresolved_reference(reference)
      @unresolved_references << reference unless reference_exists?(@unresolved_references, reference)
    end

    def reference_exists?(references, reference)
      references.any? do |existing|
        existing.uri == reference.uri && existing.source_part.equal?(reference.source_part)
      end
    end

    def scope_member?(part)
      container.parts.any? { |candidate| candidate.equal?(part) }
    end

    def ambiguous_part?(part)
      @ambiguous_resources.values.any? { |parts| parts.any? { |candidate| candidate.equal?(part) } }
    end

    def extract_references(part)
      return [] unless part.respond_to?(:main_type) && part.main_type && part.main_type.downcase == 'text'

      part.decoded.scan(/(?<![\w.+-])(?:cid|https?|ftp|file):[^\s"'<>\])]+/i)
    rescue StandardError
      []
    end

    def content_id_for(part)
      return nil unless part.respond_to?(:header) && part.header.respond_to?(:has_content_id?) && part.header.has_content_id?

      normalize_content_id(part.header[:content_id].content_id)
    rescue StandardError
      nil
    end

    def embedded_message(part)
      source = Mail::Utilities.to_lf(part.decoded).sub(/\AFrom [^\n]*(?:\r?\n)/, '')
      yield Mail.new(source)
    end

    def parameter(name)
      return nil unless container.respond_to?(:content_type_parameters) && container.content_type_parameters

      container.content_type_parameters[name] || container.content_type_parameters[name.capitalize]
    end

    def normalize_content_id(value)
      normalized = Mail::Utilities.unquote(value.to_s.strip)
      normalized = normalized.sub(/\Acid:/i, '')
      Mail::Utilities.unbracket(normalized).strip
    end

    def media_types_equal?(expected, actual)
      expected_media_type = expected.to_s[/\A\s*([^;\s]+\/[^;\s]+)/i, 1]
      return false unless expected_media_type && actual

      expected_media_type.downcase == actual.downcase
    end

    def multipart?(part)
      part.respond_to?(:multipart?) && part.multipart?
    end

    def multipart_related?(part)
      multipart?(part) && part.respond_to?(:sub_type) && part.sub_type && part.sub_type.downcase == 'related'
    end

    def message_rfc822?(part)
      part.respond_to?(:mime_type) && part.mime_type && part.mime_type.downcase == 'message/rfc822'
    end
  end
end
