# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Resolves resource references found in HTML body parts to the MIME parts
  # they point at, following RFC 2387 (The MIME multipart/related Content-Type)
  # and RFC 2557 (MIME Encapsulation of Aggregate Documents, such as HTML).
  #
  # HTML parts refer to embedded resources in two ways:
  #
  # * +cid:+ URLs, which carry the Content-ID of the target part
  #   (<img src="cid:logo@example">)
  # * relative or absolute URLs, which are matched against the Content-Location
  #   of the parts in the same aggregate (<img src="images/logo.png">)
  #
  # Walking every attachment in the message and comparing file names picks the
  # wrong part as soon as scopes nest: a forwarded message (message/rfc822) or
  # a nested multipart/related may reuse the very same Content-ID. This
  # resolver instead finds the innermost multipart/related container that
  # encloses the referencing part, confirms the container's root part from its
  # +start+/+type+ parameters, and only then resolves the reference against
  # the parts belonging to that container's scope. message/rfc822 parts and
  # nested multipart/related containers are scopes of their own and are never
  # entered while resolving on behalf of an enclosing part.
  #
  # No network access is ever performed: an absolute http(s) URL can only be
  # satisfied by a part that claims it through its Content-Location header.
  #
  # Every resolution returns a Result that is exactly one of:
  #
  # * +found+          - precisely one part in scope matches
  # * +ambiguous+      - several parts in scope match (e.g. a duplicated
  #                      Content-ID); no part is picked arbitrarily
  # * +not_found+      - the reference is resolvable in principle, but no part
  #                      in scope matches it
  # * +not_applicable+ - the reference cannot be resolved against this message
  #                      at all (the referencing part is not inside a
  #                      multipart/related container, or the URL is remote and
  #                      no part in scope claims it)
  #
  # Example:
  #
  #   result = mail.resolve_related_resource('cid:logo@example')
  #   if result.found?
  #     result.part # => Mail::Part
  #   end
  class RelatedResources
    # The outcome of resolving a single reference. Exactly one of #found?,
    # #ambiguous?, #not_found? or #not_applicable? returns true.
    class Result
      STATUSES = [:found, :ambiguous, :not_found, :not_applicable].freeze

      # The reference that was resolved, as passed to the resolver.
      attr_reader :reference

      # The matching parts: exactly one when #found?, two or more when
      # #ambiguous?, otherwise empty.
      attr_reader :parts

      def initialize(status, reference, parts = [])
        unless STATUSES.include?(status)
          raise ArgumentError, "unknown related resource status: #{status.inspect}"
        end
        @status = status
        @reference = reference
        @parts = parts.freeze
      end

      # One of :found, :ambiguous, :not_found or :not_applicable.
      attr_reader :status

      def found?
        @status == :found
      end

      def ambiguous?
        @status == :ambiguous
      end

      def not_found?
        @status == :not_found
      end

      def not_applicable?
        @status == :not_applicable
      end

      # The matching part. Only available when the result is #found?; an
      # ambiguous result never picks one of its parts arbitrarily.
      def part
        parts.first if found?
      end

      def inspect
        "#<#{self.class} status=#{status} reference=#{reference.inspect} parts=#{parts.size}>"
      end
    end

    CID_SCHEME = /\Acid:/i
    ABSOLUTE_URI = /\A[A-Za-z][A-Za-z0-9+.-]*:/

    # The message the resolver works on.
    attr_reader :message

    def initialize(message)
      @message = message
    end

    # Resolve +reference+ (for example "cid:logo@example" or
    # "images/logo.png") against the multipart/related container enclosing
    # +from+. +from+ defaults to the message's html part, or the message
    # itself when it has none. Always returns a Result.
    def resolve(reference, from: nil)
      reference = reference.to_s.strip
      container = container_for(from)
      return Result.new(:not_applicable, reference) unless container

      if CID_SCHEME.match?(reference)
        resolve_cid(container, reference.sub(CID_SCHEME, ''), reference)
      elsif ABSOLUTE_URI.match?(reference)
        # An absolute, non-cid: URL can only be satisfied by a part that
        # claims it via Content-Location; it is never fetched over the
        # network. Without a claiming part the reference does not apply to
        # this message.
        result = resolve_location(container, reference, reference)
        result.not_found? ? Result.new(:not_applicable, reference) : result
      else
        resolve_location(container, reference, reference)
      end
    end

    # The innermost multipart/related container whose subtree includes
    # +part+ (default: the message's html part, or the message itself), or
    # nil when the part is not enclosed by any multipart/related container.
    # message/rfc822 parts are opaque: their content is a scope of its own
    # and is never searched for the enclosing message.
    def container_for(part = nil)
      part ||= default_referencing_part
      return nil unless part
      result = find_container(message, part, NOT_FOUND)
      NOT_FOUND.equal?(result) ? nil : result
    end

    # The root part of a multipart/related container, per RFC 2387:
    #
    # 1. the part whose Content-ID matches the container's +start+ parameter
    # 2. otherwise the only direct child whose media type matches the
    #    container's +type+ parameter
    # 3. otherwise the first part of the container
    #
    # Returns nil when there is no container (or it has no parts).
    def root_part(container = nil)
      container ||= container_for
      return nil unless container

      params = container.content_type_parameters || {}
      parts = container.parts

      if start = params['start']
        wanted = unbracket(start.to_s)
        matches = scope_parts(container).select { |part| content_id_of(part) == wanted }
        return matches.first if matches.size == 1
      end

      if type = params['type']
        wanted = type.to_s.downcase
        matches = parts.select { |part| part.mime_type.to_s.downcase == wanted }
        return matches.first if matches.size == 1
      end

      parts.first
    end

    private

    NOT_FOUND = Object.new

    def default_referencing_part
      message.html_part || message
    end

    # Depth-first search for the innermost multipart/related container that
    # encloses +target+. Returns NOT_FOUND when +target+ is not in +node+'s
    # subtree, so a nil container ("found, but not inside any related part")
    # is distinguishable from "not in this subtree". message/rfc822 parts
    # are not multipart, so their nested message is never entered.
    def find_container(node, target, enclosing)
      return enclosing if node.equal?(target)

      if node.multipart?
        enclosing = node if related?(node)
        node.parts.each do |child|
          found = find_container(child, target, enclosing)
          return found unless NOT_FOUND.equal?(found)
        end
      end

      NOT_FOUND
    end

    def related?(part)
      part.multipart? && part.sub_type.to_s.downcase == 'related'
    end

    # The parts that make up the resolution scope of a multipart/related
    # container: its whole subtree, except that nested multipart/related
    # containers and message/rfc822 parts are scopes of their own and are
    # not entered.
    def scope_parts(container)
      collected = []
      walk = lambda do |part|
        part.parts.each do |child|
          collected << child
          walk.call(child) if child.multipart? && !related?(child)
        end
      end
      walk.call(container)
      collected
    end

    def resolve_cid(container, cid, reference)
      wanted = Utilities.uri_unescape(cid.to_s)
      matches = scope_parts(container).select { |part| content_id_of(part) == wanted }
      result_for(matches, reference)
    end

    def resolve_location(container, location, reference)
      base = base_location(container)
      wanted = absolutize(base, location)
      matches = scope_parts(container).select do |part|
        claimed = content_location_of(part)
        claimed && absolutize(base, claimed) == wanted
      end
      result_for(matches, reference)
    end

    def result_for(matches, reference)
      case matches.size
      when 0 then Result.new(:not_found, reference)
      when 1 then Result.new(:found, reference, matches)
      else Result.new(:ambiguous, reference, matches)
      end
    end

    # The base URL for relative references inside the container: the
    # container's own Content-Location, or failing that the root part's.
    def base_location(container)
      content_location_of(container) || content_location_of(root_part(container))
    end

    def absolutize(base, location)
      location = location.to_s
      return location if location.empty? || ABSOLUTE_URI.match?(location)
      return location if base.to_s.empty?

      URI.join(base, location).to_s
    rescue URI::Error
      location
    end

    def content_id_of(part)
      return nil unless part.header.has_content_id?

      unbracket(part.content_id.to_s)
    rescue StandardError
      nil
    end

    def content_location_of(part)
      return nil unless part && part.header && part.header[:content_location]

      # Use the decoded field value rather than ContentLocationField#location:
      # the strict RFC 2557 parser rejects relative references such as
      # "images/logo.png", in which case the field degrades to an
      # unstructured field whose decoded value is still the raw URL.
      part.content_location.to_s.strip
    rescue StandardError
      nil
    end

    def unbracket(value)
      Utilities.unbracket(value.strip)
    end
  end
end
