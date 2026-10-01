# encoding: utf-8
# frozen_string_literal: true

require 'uri'

require 'mail/utilities'

module Mail
  class RelatedParts
    attr_reader :container, :root, :parts, :resources, :used_resources,
                :used_parts, :unused_resources, :unused_parts,
                :ambiguous_resources, :references,
                :unresolved_references, :external_references, :nested_errors,
                :errors

    def initialize(container, *args,
                   start: nil,
                   resource_reference_extractor: nil,
                   reference_extractor: nil,
                   &block)
      @container = container
      first_argument = args.first

      if first_argument
        if first_argument.respond_to?(:call)
          resource_reference_extractor ||= first_argument
        else
          start ||= first_argument
        end
      end

      @start = start
      @reference_extractor = block || resource_reference_extractor || reference_extractor
      @parts = container.parts.to_a
      @resources = {}
      @used_resources = {}
      @used_parts = []
      @unused_resources = {}
      @unused_parts = []
      @ambiguous_resources = {}
      @references = []
      @unresolved_references = []
      @external_references = []
      @nested_errors = []
      @errors = []

      parse
    end

    def related_part(start = nil)
      cid = normalize_content_id(start || @start)
      cid ? parts_by_content_id[cid] : nil
    end

    def [](start)
      related_part(start)
    end

    def children
      @parts
    end

    def nested_parts
      @nested_parts ||= []
    end

    alias_method :root_part, :root

    def nested_related_parts
      nested_parts
    end

    def valid?
      errors.empty? && ambiguous_resources.empty? && unresolved_references.empty?
    end

    private

    def parse
      select_root
      index_resources
      validate_root_type
      extract_references if root && @reference_extractor
      build_nested_parts
    end

    def select_root
      start = normalize_content_id(@start || start_parameter)

      if start
        candidates = parts_by_content_id[start]

        case candidates
        when nil
          @root = nil
          @errors << "#{start}: start not found"
        when Array
          @root = nil
          @errors << "#{start}: start is ambiguous"
        else
          @root = candidates
        end
      else
        @root = @parts.first
      end
    end

    def index_resources
      parts_by_content_id.each do |content_id, candidates|
        associated = Array(candidates).reject { |part| part.equal?(root) }
        next if associated.empty?

        if candidates.is_a?(Array)
          @ambiguous_resources[content_id] = Array(candidates)
          @resources[content_id] = Array(candidates)
        else
          @resources[content_id] = associated.first
        end
      end

      @resources.each do |content_id, resource|
        next if resource.is_a?(Array) || @ambiguous_resources.key?(content_id)
        @unused_resources[content_id] = resource
      end

      @unused_parts.replace(@parts.reject { |part| part.equal?(root) })
    end

    def parts_by_content_id
      @parts_by_content_id ||=
        begin
          indexed = {}

          @parts.each do |part|
            content_id = part_content_id(part)
            next unless content_id

            if indexed.key?(content_id)
              indexed[content_id] = Array(indexed[content_id]) << part
            else
              indexed[content_id] = part
            end
          end

          indexed
        end
    end

    def validate_root_type
      return unless root && type_parameter

      unless media_type_matches?(root.mime_type, type_parameter)
        @errors << "#{type_parameter}: root Content-Type #{root.mime_type} does not match type"
      end
    end

    def extract_references
      extracted = @reference_extractor.call(root) || []
      references = extracted.respond_to?(:to_ary) ? extracted.to_ary : [extracted]

      references.flat_map { |reference| Array(reference) }.each do |reference|
        resolve_reference(reference)
      end
    rescue => error
      @errors << error.message
    end

    def resolve_reference(reference)
      reference = reference.to_s
      @references << reference

      uri = URI.parse(reference)
      if uri.scheme && uri.scheme.downcase == 'cid'
        resolve_cid_reference(uri, reference)
      else
        @external_references << reference
      end
    rescue URI::InvalidURIError
      @unresolved_references << reference
    end

    def resolve_cid_reference(uri, reference)
      cid = normalize_content_id(uri.opaque.to_s)
      return @unresolved_references << reference if cid.nil?

      resource = @resources[cid]

      if @ambiguous_resources.key?(cid)
        return
      end

      case resource
      when nil
        @unresolved_references << reference
      when Array
        @ambiguous_resources[cid] ||= resource
      else
        if resource.equal?(root)
          @unresolved_references << reference
        else
          @used_resources[cid] = resource
          @used_parts << resource
          @unused_parts.delete(resource)
          @unused_resources.delete(cid)
        end
      end
    end

    def build_nested_parts
      @nested_parts = []
      seen = {}

      each_related_container(@parts) do |nested_container|
        next if seen[nested_container.object_id]

        seen[nested_container.object_id] = true
        @nested_parts << self.class.new(
          nested_container,
          resource_reference_extractor: @reference_extractor
        )
      end
    end

    def each_related_container(parts, &block)
      parts.each do |part|
        if part.mime_type == 'message/rfc822'
          begin
            collect_related_containers(Mail.new(part.body.to_s), &block)
          rescue StandardError => error
            @nested_errors << error
          end
        else
          collect_related_containers(part, &block)
        end
      end
    end

    def collect_related_containers(container, &block)
      return unless container.multipart?

      if container.mime_type == 'multipart/related'
        yield(container)
      end

      container.parts.each do |part|
        each_related_container([part], &block)
      end
    end

    def start_parameter
      content_type_parameter('start')
    end

    def type_parameter
      value = content_type_parameter('type')
      value && strip_value(value)
    end

    def content_type_parameter(name)
      return unless container.content_type_parameters
      container.content_type_parameters[name]
    end

    def part_content_id(part)
      field = part.header[:content_id]
      return unless field

      value =
        if field.respond_to?(:content_id)
          field.content_id
        else
          field.decoded
        end

      normalize_content_id(value)
    rescue Mail::Field::ParseError
      nil
    end

    def normalize_content_id(value)
      return if value.nil?
      value = strip_value(value.to_s)
      return if value.empty?
      decode_cid(Mail::Utilities.unbracket(value))
    end

    def decode_cid(value)
      URI::DEFAULT_PARSER.unescape(value)
    end

    def strip_value(value)
      value = value.strip
      if value.length >= 2 && value.start_with?('"') && value.end_with?('"')
        value[1..-2]
      else
        value
      end
    end

    def media_type_matches?(actual, expected)
      return false unless actual
      actual.downcase.split(';').first.strip == expected.downcase
    end

  end
end
