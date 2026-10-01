# encoding: utf-8
# frozen_string_literal: true
require 'uri'
require 'mail/utilities'

module Mail
  # Resolves references in an HTML body part to the other MIME parts of a
  # multipart/related container, as defined by RFC 2387 and RFC 2557.
  #
  # HTML bodies reference inline resources in two ways:
  #
  # * with a Content-ID URI, e.g. <tt><img src="cid:logo@example"></tt>
  # * with a relative (or absolute) Content-Location URI, e.g.
  #   <tt><img src="images/logo.png"></tt>
  #
  # Iterating over Mail::Message#attachments and matching filenames is not a
  # reliable way to resolve these: attachments span every scope of the message,
  # the resource may be displayed inline rather than attached, and the HTML may
  # reference it by CID rather than filename.  RelatedResource instead:
  #
  # 1. identifies the multipart/related container that owns the HTML part,
  # 2. determines the root part of that container using the +start+ and +type+
  #    parameters of its Content-Type header (RFC 2387 section 3.1), and
  # 3. matches the reference against the Content-ID and Content-Location
  #    headers of the container's direct body parts only.
  #
  # Scopes never leak across boundaries: body parts nested inside a
  # message/rfc822 entity or a nested multipart/related container are not
  # visible to the outer container, matching RFC 2046 section 5.1.4 and
  # RFC 2557 section 2.1.1.
  #
  # Resolution never accesses the network.  An absolute http/https reference
  # is only resolved if one of the container's own parts carries a matching
  # Content-Location; otherwise it is reported as not applicable.
  #
  # == Result states
  #
  # Every lookup returns a Result with one of four states:
  #
  # * <tt>:resolved</tt>  – exactly one matching part was found
  # * <tt>:ambiguous</tt> – more than one part matches; Result#parts holds
  #   every candidate and no single part is chosen.  This happens when two
  #   parts carry the same Content-ID, which RFC 2392 says is a malformed
  #   message.
  # * <tt>:not_found</tt> – the reference belongs to this container (CID or
  #   resolvable relative URI) but no part matches it, or the container could
  #   not establish a root part
  # * <tt>:not_applicable</tt> – the reference cannot be answered from MIME
  #   parts at all (external http/https/data URL, fragment reference, malformed
  #   reference), or the anchor part is not the root of a related container
  class RelatedResource
    # Outcome of a single reference lookup.
    class Result
      # One of +:resolved+, +:ambiguous+, +:not_found+, +:not_applicable+.
      attr_reader :status

      # The multipart/related container the reference was resolved in.
      attr_reader :container

      # The root body part of the container (RFC 2387).
      attr_reader :root

      # The reference string as passed in.
      attr_reader :reference

      # Why the status was reached (a Symbol).  Mainly used for
      # +:not_applicable+ and +:not_found+, where several distinct situations
      # share a status.
      attr_reader :reason

      # Every part that matched.  Holds one part for +:resolved+, several for
      # +:ambiguous+, and none otherwise.
      attr_reader :parts

      def initialize(status, options = {})
        @status = status
        @container = options[:container]
        @root = options[:root]
        @reference = options[:reference]
        @reason = options[:reason]
        @parts = options[:parts] || []
      end

      def resolved?
        @status == :resolved
      end

      # True when more than one part matched.  The caller must decide what to
      # do with the candidates; RelatedResource never picks one on its own.
      def ambiguous?
        @status == :ambiguous
      end

      def not_found?
        @status == :not_found
      end

      def not_applicable?
        @status == :not_applicable
      end

      # The single resolved part, or nil.
      def part
        @parts.first if resolved?
      end

      def success?
        resolved?
      end
    end

    # Finds the multipart/related container owning +anchor+ (by default the
    # message's HTML part) and returns a bound resolver, or nil if the message
    # contains no related container that the anchor is the root of.
    #
    # The container is the innermost multipart/related part whose direct body
    # parts contain the anchor.  Containers nested inside a message/rfc822
    # attachment or another multipart/related container define their own scope
    # and are never crossed.
    def self.find(message, anchor = nil)
      container = find_container(message, anchor)
      new(container) if container
    end

    # Convenience wrapper: resolves +reference+ against the multipart/related
    # container owning +anchor+ (defaulting to the message's HTML part).
    #
    # Returns a Result in the +:not_applicable+ state when no suitable
    # multipart/related container exists.
    def self.resolve(message, reference, anchor = nil)
      resolver = find(message, anchor)
      if resolver
        resolver.resolve(reference)
      else
        Result.new(:not_applicable,
                   :reference => reference,
                   :reason => :no_related_container)
      end
    end

    attr_reader :container, :root

    # +container+ must be a Mail::Part (or Mail::Message) with media type
    # multipart/related.  The root part is determined up front from its
    # +start+ and +type+ parameters.
    def initialize(container)
      @container = container
      @root, @root_status, @root_reason = determine_root
    end

    # True when the container had a usable root part.  When false, every
    # #resolve call stays in the +:not_found+ or +:not_applicable+ state.
    def valid?
      @root_status == :ok
    end

    # Resolves one URI reference from the HTML body to a MIME part.  Always
    # returns a Result and never performs network I/O.
    def resolve(reference)
      return root_result unless valid?

      ref = reference.to_s.strip
      if ref.empty?
        return failure(:not_applicable, :invalid_reference, reference)
      end

      # RFC 2392: cid: URLs reference parts by Content-ID.
      if cid_ref?(ref)
        return resolve_cid(ref, reference)
      end

      uri = parse_uri(ref)
      return failure(:not_applicable, :invalid_reference, reference) unless uri

      if !uri.scheme.nil? && !uri.scheme.to_s.empty?
        resolve_absolute(uri, reference)
      elsif uri.fragment && !uri.fragment.empty? &&
            uri.path.to_s.empty? && uri.query.nil?
        # A same-document fragment never points at another MIME entity.
        failure(:not_applicable, :fragment_reference, reference)
      else
        resolve_relative(uri, ref, reference)
      end
    end

    private

    # ---- container discovery -------------------------------------------

    def self.find_container(message, anchor)
      if anchor
        container_holding_anchor(message, anchor) ||
          container_itself(message, anchor)
      else
        implicit_anchor = message.respond_to?(:html_part) ? message.html_part : nil
        if implicit_anchor
          # The anchor is normally a direct body part of the related group;
          # if it lives deeper (e.g. the root is multipart/alternative, RFC
          # 2387 section 3.2), fall back to the related group that scopes it.
          container_holding_anchor(message, implicit_anchor) ||
            container_itself(message, implicit_anchor) ||
            scoping_container(message, implicit_anchor,
                              related?(message) ? message : nil)
        else
          first_related_container(message)
        end
      end
    end
    private_class_method :find_container

    # Finds the multipart/related group from which +anchor+ is reachable, even
    # when it is nested behind an intermediate container (most typically
    # multipart/alternative acting as the root body part).  A nested related
    # group or a message/rfc822 entity establishes its own scope.
    def self.scoping_container(node, anchor, current_scope)
      return nil unless node.respond_to?(:parts)
      node.parts.each do |part|
        scope = related?(part) ? part : current_scope
        return scope if part.equal?(anchor)

        next if part.mime_type == 'message/rfc822'
        # Stay inside the outermost related group; do not descend into one
        # nested inside it.
        next if related?(part) && current_scope

        found = scoping_container(part, anchor, scope)
        return found if found
      end
      nil
    end
    private_class_method :scoping_container

    # The message (or part passed in) may itself be the multipart/related
    # container with the anchor among its direct body parts.
    def self.container_itself(message, anchor)
      message if related?(message) && message.parts.include?(anchor)
    end
    private_class_method :container_itself

    # Depth-first search for the innermost multipart/related container that
    # contains +anchor+ among its *direct* body parts.  message/rfc822 parts
    # and nested multipart/related containers are scope boundaries and are not
    # descended into.
    def self.container_holding_anchor(node, anchor)
      node.parts.each do |part|
        next unless part.respond_to?(:mime_type)
        if related?(part)
          return part if part.parts.include?(anchor)
        end
        unless scope_boundary?(part)
          found = container_holding_anchor(part, anchor)
          return found if found
        end
      end
      nil
    end
    private_class_method :container_holding_anchor

    def self.first_related_container(node)
      return node if related?(node)
      node.parts.each do |part|
        return part if part.respond_to?(:mime_type) && related?(part)
        unless part.respond_to?(:parts) && scope_boundary?(part)
          found = first_related_container(part)
          return found if found
        end
      end
      nil
    end
    private_class_method :first_related_container

    # Nested multipart/related groups (RFC 2387) and message/rfc822 entities
    # (RFC 2046 5.2.1) establish their own resolution scope.
    def self.scope_boundary?(part)
      part.respond_to?(:mime_type) &&
        (related?(part) || part.mime_type == 'message/rfc822')
    end
    private_class_method :scope_boundary?

    def self.related?(part)
      part.respond_to?(:mime_type) && part.mime_type == 'multipart/related'
    end
    private_class_method :related?

    # ---- root determination (RFC 2387 section 3.1) ----------------------

    def determine_root
      unless related_container?
        return [nil, :not_applicable, :not_related]
      end

      candidates = body_parts
      return [nil, :not_found, :no_parts] if candidates.empty?

      start = content_type_parameter('start')
      root =
        if start
          matches = candidates.select { |part| cid_of(part) == normalize_cid(start) }
          case matches.size
          when 1 then matches.first
          when 0 then return [nil, :not_found, :start_not_found]
          else return [nil, :ambiguous, :duplicate_start]
          end
        else
          candidates.first
        end

      declared_type = content_type_parameter('type')
      if declared_type && root.respond_to?(:mime_type)
        # RFC 2387: +type+ states the content type of the root part.
        if root.mime_type.to_s.downcase != declared_type.to_s.downcase
          return [nil, :not_applicable, :root_type_mismatch]
        end
      end

      [root, :ok, nil]
    end

    def related_container?
      @container.respond_to?(:mime_type) &&
        @container.mime_type == 'multipart/related'
    end

    def content_type_parameter(name)
      params = @container.respond_to?(:content_type_parameters) ?
                 @container.content_type_parameters : nil
      params && params[name]
    end

    def root_result
      if @root_status == :ambiguous
        return Result.new(:ambiguous,
                          :container => @container, :reference => nil,
                          :reason => @root_reason)
      end
      status = @root_status == :ok ? :not_found : @root_status
      Result.new(status,
                 :container => @container, :root => @root,
                 :reference => nil, :reason => @root_reason)
    end

    # ---- cid: resolution (RFC 2392) -------------------------------------

    def resolve_cid(ref, original)
      token = normalize_cid(ref.sub(/\Acid:/i, ''))
      if token.empty?
        return failure(:not_applicable, :invalid_reference, original)
      end

      matches = body_parts.select { |part| cid_of(part) == token }
      build_result(matches, original)
    end

    def cid_ref?(ref)
      ref.downcase.start_with?('cid:')
    end

    # Unbrackets <id@host>, strips a stray cid: prefix and normalizes percent
    # encoding.  Returns nil when the part carries no Content-ID header.
    def cid_of(part)
      return nil unless part.respond_to?(:has_content_id?) && part.has_content_id?
      normalize_cid(part.content_id)
    end

    def normalize_cid(value)
      token = value.to_s.strip
      token = token.sub(/\Acid:/i, '')
      token = Mail::Utilities.unbracket(token)
      token = Mail::Utilities.uri_unescape(token) rescue token
      token
    end

    # ---- Content-Location resolution (RFC 2557) -------------------------

    # Only http/https references may possibly be satisfied by local parts;
    # every other absolute URI scheme is inherently external.
    def resolve_absolute(uri, original)
      unless %w[http https].include?(uri.scheme.to_s.downcase)
        return failure(:not_applicable, :external_reference, original)
      end

      matches = match_locations { |location| same_uri?(location, uri) }
      if matches.empty?
        # The network is never consulted: an http(s) reference without a
        # matching local part cannot be resolved from the message.
        failure(:not_applicable, :external_reference, original)
      else
        build_result(matches, original)
      end
    end

    def resolve_relative(uri, ref, original)
      # A query-only reference ("?v=1") is resolved against the root part
      # itself (RFC 3986 section 5.3).
      if uri.path.to_s.empty? && uri.query
        return build_result([@root], original)
      end

      candidates = []

      base_location = location_of(@root)
      if base_location
        target = merge_reference(base_location, uri)
        if target
          candidates = match_locations do |location|
            same_uri?(location, target) ||
              # RFC 2557 2.1.1 also allows parts to carry a relative
              # Content-Location, which compares against the resolved string.
              (relative_location?(location) && location == target.to_s)
          end
        end
      else
        # Without a base, RFC 2557 cannot resolve the reference, but many
        # real-world messages use matching relative Content-Location headers;
        # compare the reference against them literally.  This never touches
        # the network.
        candidates = match_locations { |location| location == ref }
      end

      build_result(candidates, original)
    end

    # Resolves +uri+ against the root part's Content-Location.  URI#merge
    # rejects relative bases even though RFC 2557 permits relative
    # Content-Location headers, so handle that case with simple path
    # resolution (RFC 3986 section 5.3 semantics are not needed inside a
    # multipart container).
    def merge_reference(base_location, uri)
      base = parse_uri(base_location)
      return nil unless base

      if base.scheme
        base.merge(uri)
      else
        relative_merge(base, uri)
      end
    rescue URI::Error
      nil
    end

    def relative_merge(base, uri)
      if !uri.path.to_s.empty?
        resolve_path(base_path(base), uri.path)
      else
        base_path(base)
      end
    end

    def base_path(base)
      path = base.path.to_s
      path.include?('/') ? path.sub(%r{/[^/]*\z}, '/') : ''
    end

    # Minimal RFC 3986 5.2.4 remove_dot_sections handling for relative paths.
    def resolve_path(base_dir, path)
      combined = path.start_with?('/') ? path : base_dir + path
      segments = combined.split('/', -1).each_with_object([]) do |seg, out|
        if seg == '..'
          out.pop
        elsif seg != '.'
          out << seg
        end
      end
      result = segments.join('/')
      result = '/' + result if combined.start_with?('/')
      result
    end

    def relative_location?(location)
      parsed = parse_uri(location)
      parsed.nil? || parsed.scheme.nil? || parsed.scheme.to_s.empty?
    end

    def body_parts
      # Direct body parts only: parts nested in an inner multipart/related
      # container or a message/rfc822 entity live in their own scope.
      @body_parts ||= @container.parts.reject { |part| nested_scope?(part) }
    end

    # A body part that is itself a multipart/related group or a
    # message/rfc822 entity establishes its own, smaller resolution scope
    # (RFC 2387 / RFC 2046 5.2.1); its descendants do not belong to this one.
    def nested_scope?(part)
      mime = part.respond_to?(:mime_type) ? part.mime_type : nil
      mime == 'multipart/related' || mime == 'message/rfc822'
    end

    def location_of(part)
      field = part.header[:content_location] rescue nil
      return nil unless field
      # ContentLocationField exposes #location; a value the gem's relative-URI
      # parser cannot handle (e.g. an absolute http URL) is kept as a generic
      # unstructured field whose #value still holds the raw location.
      location =
        if field.respond_to?(:location)
          field.location
        elsif field.respond_to?(:value)
          field.value
        end
      location.nil? || location.to_s.strip.empty? ? nil : location.to_s.strip
    end

    def match_locations
      body_parts.select do |part|
        location = location_of(part)
        location && yield(location)
      end
    end

    def same_uri?(location, target)
      parsed = parse_uri(location)
      return false unless parsed
      # +target+ may be a URI (absolute base) or a String (relative base).
      if target.is_a?(::URI::Generic)
        parsed.scheme.nil? == target.scheme.nil? && parsed == target
      else
        parsed.to_s == target.to_s
      end
    rescue URI::Error
      false
    end

    # ---- result helpers -------------------------------------------------

    def build_result(matches, reference, none_reason = :not_found)
      case matches.size
      when 1
        Result.new(:resolved,
                   :container => @container, :root => @root,
                   :reference => reference, :parts => matches)
      when 0
        failure(:not_found, none_reason, reference)
      else
        # Duplicate CIDs / Content-Locations are malformed; never silently
        # choose the first candidate.
        Result.new(:ambiguous,
                   :container => @container, :root => @root,
                   :reference => reference, :parts => matches,
                   :reason => :duplicate_match)
      end
    end

    def failure(status, reason, reference)
      Result.new(status,
                 :container => @container, :root => @root,
                 :reference => reference, :reason => reason)
    end

    def parse_uri(string)
      return nil if string.nil? || string.to_s.strip.empty?
      URI.parse(string.to_s)
    rescue URI::Error
      nil
    end
  end
end
