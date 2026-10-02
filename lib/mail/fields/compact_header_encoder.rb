# encoding: utf-8
# frozen_string_literal: true

require 'base64'

module Mail
  # CompactHeaderEncoder produces the byte-minimal RFC 2047 encoded-word
  # rendering of an unstructured UTF-8 header field body.
  #
  # Unlike UnstructuredField's historical encoder (which Q-encodes each whole
  # physical line), every encoded-word independently uses quoted-printable
  # (Q) or base64 (B), plain ASCII is kept literal, and folding happens at
  # the cheapest legal point. A dynamic program searches every legal
  # segmentation, Q/B choice, and folding, minimizing total wire bytes.
  #
  # Constraints enforced:
  #   * each encoded-word is at most 75 characters (RFC 2047 §2);
  #   * every physical line is at most the configured length (78 by default),
  #     and the field-name prefix width is counted on the first line;
  #   * multibyte UTF-8 characters are never split across encoded-words;
  #   * whitespace is preserved after decoding (RFC 2047 §6.2): whitespace
  #     that would be stripped by a decoder is either kept away from an
  #     encoded-word, folded, or absorbed into an adjacent encoded-word;
  #   * encoded-word boundaries never fall inside a UTF-8 sequence.
  #
  # Among byte-equal solutions the first deterministically enumerated one is
  # kept (the transition enumeration order is fixed), giving a stable
  # tie-break rule for equal wire lengths.
  class CompactHeaderEncoder

    # RFC 2047 §2 hard limit on an encoded-word including its delimiters.
    ENCODED_WORD_MAX_LENGTH = 75

    # Largest payload for which base64 fits a 75-character encoded-word:
    # "=?UTF-8?B?" (10) + base64 + "?=" (2); max base64 text 63 characters,
    # which decodes to 45 bytes.
    BASE64_MAX_PAYLOAD_BYTES = 45

    ENCODED_WORD_PREFIX = "=?UTF-8?".b
    ENCODED_WORD_SUFFIX = "?=".b
    FOLD = "\r\n ".b

    # Characters RFC 2047 §4.2 permits unencoded inside Q encoded-text:
    # printable US-ASCII except '=', '?' and underscore. Space becomes '_'
    # and every other byte is represented as '=XX'.
    Q_PRINTABLE = ("!".b.."~".b).to_a.join.b
    Q_PRINTABLE.delete!("=?_")
    Q_PRINTABLE_BYTES = Q_PRINTABLE.bytes.to_a.freeze

    # Token kinds in the header value.
    WSP   = :wsp   # a single space (0x20) or tab (0x09)
    WORD  = :word  # a maximal run of literal-safe printable US-ASCII
    FORCE = :force # a unit that must live inside an encoded-word

    # Immutable rendered-prefix chain. A node records one emitted move and a
    # pointer to the prefix before it, so transitions allocate O(1) without
    # copying the (potentially long) rendered body. Nodes are hash-consed per
    # (parent, move); the full body is walked only once for the winning path.
    class Prefix
      attr_reader :parent, :move, :plain_seen, :bytesize

      def initialize(parent, move, plain_seen, bytesize)
        @parent = parent
        @move = move
        @plain_seen = plain_seen
        @bytesize = bytesize
      end

      def to_s
        @str ||= (@parent ? @parent.to_s + @move : @move.dup)
      end
    end

    State = Struct.new(:pos, :gap, :col, :first, :cost, :node,
                       keyword_init: true) do
      def body
        node.to_s
      end

      def plain_seen
        node.plain_seen
      end
    end

    # Encode +str+ (a valid UTF-8 String) and return the folded field body
    # (the characters following "<name>: "). Continuation lines are joined
    # by CRLF plus one WSP; the caller prepends the field-name prefix and
    # appends the terminating CRLF.
    def self.encode(str, first_line_width:, line_length: nil)
      new(str, first_line_width, line_length).encode
    end

    def initialize(str, first_line_width, line_length)
      @line_length = (line_length || Mail::Configuration.instance.header_line_length).to_i
      @first_line_width = first_line_width.to_i
      @string = str.b
      @tokens = tokenize(str)
      # Map each token's raw start position to its index, used by the O(1)
      # token_at/span navigation in the dynamic program.
      @token_index = {}
      @tokens.each_with_index { |t, idx| @token_index[t[1]] = idx }
    end

    # Returns the folded field body, or nil if the value cannot fit the
    # physical line limit.
    def encode
      return ''.b if @tokens.empty?
      best = run_dynamic_program
      best && best.body.dup.force_encoding(Encoding::UTF_8)
    end

    private

    # --- Tokenization -----------------------------------------------------
    #
    # Tokens are [kind, raw_start, raw_length] over raw UTF-8 bytes. A WORD
    # is a run of printable ASCII that never contains "=?"; everything else
    # (UTF-8 characters, control bytes, a literal "=?") is a FORCE unit.
    def tokenize(str)
      tokens = []
      bytes = str.b
      i = 0
      while i < bytes.bytesize
        byte = bytes.getbyte(i)
        if byte == 0x20 || byte == 0x09
          tokens << [WSP, i, 1]
          i += 1
        elsif byte < 0x20 || byte == 0x7F
          start = i
          i += 1
          i += 1 while i < bytes.bytesize && control_byte?(bytes.getbyte(i))
          tokens << [FORCE, start, i - start]
        elsif byte >= 0x80
          size = utf8_char_bytesize(byte)
          start = i
          i += size
          i += 1 while i < bytes.bytesize && control_byte?(bytes.getbyte(i))
          tokens << [FORCE, start, i - start]
        else
          j = i
          loop do
            break if j >= bytes.bytesize
            b = bytes.getbyte(j)
            # A plain word is printable US-ASCII excluding WSP (0x20, 0x09)
            # and a literal "=?".
            break unless b > 0x20 && b < 0x7F
            break if b == 0x3D && j + 1 < bytes.bytesize &&
                      bytes.getbyte(j + 1) == 0x3F
            j += 1
          end
          tokens << [WORD, i, j - i] if j > i
          if j < bytes.bytesize # a non-word byte begins here
            if bytes.getbyte(j) == 0x3D && j + 1 < bytes.bytesize &&
               bytes.getbyte(j + 1) == 0x3F
              # A literal "=?" must be encoded (it would otherwise look like
              # the start of an encoded-word); coalesce trailing controls.
              start = j
              j += 2
              j += 1 while j < bytes.bytesize && control_byte?(bytes.getbyte(j))
              tokens << [FORCE, start, j - start]
            end
            # Otherwise (a UTF-8/control byte) leave j where it is; the outer
            # loop reprocesses that byte as its own FORCE unit.
          end
          i = j
        end
      end
      tokens
    end

    # Tab (0x09) is foldable whitespace, not a control byte; everything else
    # below 0x20 (and DEL) must be encoded.
    def control_byte?(byte)
      (byte < 0x20 && byte != 0x09) || byte == 0x7F
    end

    def utf8_char_bytesize(first_byte)
      if first_byte < 0xE0 then 2
      elsif first_byte < 0xF0 then 3
      elsif first_byte < 0xF8 then 4
      else 1 end
    end

    def q_wire(payload)
      (@q_wire ||= {})[payload] ||= begin
        encoded = ''.b
        payload.each_byte do |byte|
          case byte
          when 0x20 then encoded << '_'
          when *Q_PRINTABLE_BYTES then encoded << byte
          else encoded << '=' << ('%02X' % byte)
          end
        end
        "#{ENCODED_WORD_PREFIX}Q?#{encoded}#{ENCODED_WORD_SUFFIX}".b
      end
    end

    def b_wire(payload)
      (@b_wire ||= {})[payload] ||=
        "#{ENCODED_WORD_PREFIX}B?#{Base64.strict_encode64(payload)}#{ENCODED_WORD_SUFFIX}".b
    end

    # --- Dynamic program --------------------------------------------------
    #
    # A state is keyed by:
    #   pos   - raw UTF-8 byte position consumed,
    #   gap   - what the last emitted atom was (see gap classes),
    #   col   - column reached on the current physical line,
    #   first - whether we are still on the first physical line.
    #
    # gap classes:
    #   :start     - nothing emitted yet
    #   :plain     - last atom was foldable plain text (a WSP or word start)
    #   :text      - last atom was a plain byte inside a word (no fold)
    #   :wsp       - last atom was plain WSP directly after an encoded-word
    #   :wsp_lead  - last atom was leading WSP before the first encoded-word
    #   :ew        - last atom was an encoded-word
    def run_dynamic_program
      first_capacity = @line_length - @first_line_width
      return nil if first_capacity <= 0

      @prefixes = {}
      root = prefix(nil, ''.b, false)
      states = { [0, :start, 0, true] =>
                   State.new(pos: 0, gap: :start, col: 0, first: true,
                             cost: 0, node: root) }

      # Every transition advances the raw position, so processing positions
      # in ascending order settles each layer before it is expanded. Before
      # expanding a layer, Pareto-dominated states (same position, gap and
      # first-line flag, but both more wire bytes used and a column no less
      # far left) are dropped: the dominating state has no less room and can
      # mimic every continuation, including future folds.
      (0...@string.bytesize).each do |pos|
        prune_pareto!(states, pos)
        states_at(states, pos).each_value do |state|
          expand(states, state, first_capacity)
        end
      end

      finals = states.select { |k, _| k[0] == @string.bytesize }.values
      return nil if finals.empty?
      finals.min { |a, b| a.cost <=> b.cost }
    end

    def prefix(parent, move, plain_seen)
      key = [parent, move]
      @prefixes.fetch(key) do
        bytesize = move.bytesize + (parent ? parent.bytesize : 0)
        @prefixes[key] = Prefix.new(parent, move, plain_seen, bytesize)
      end
    end

    def states_at(states, pos)
      states.select { |key, _| key[0] == pos }
    end

    # Drop Pareto-dominated states at one raw position. States are grouped by
    # (gap, first-line flag); within a group a state A dominates B when
    # A.cost <= B.cost and A.col <= B.col with at least one strict, because
    # future feasibility/cost from a given position depends only on (gap,
    # col, first) and the shared remaining string.
    def prune_pareto!(states, pos)
      layer = states.select { |key, _| key[0] == pos }
      groups = Hash.new { |h, k| h[k] = [] }
      layer.each_value { |st| groups[[st.gap, st.first]] << st }
      groups.each_value do |sts|
        sts.each do |b|
          dominated = sts.any? do |a|
            !a.equal?(b) && a.cost <= b.cost && a.col <= b.col &&
              (a.cost < b.cost || a.col < b.col)
          end
          states.delete([pos, b.gap, b.col, b.first]) if dominated
        end
      end
    end

    def capacity_for(state, first_capacity)
      state.first ? first_capacity : @line_length
    end

    def token_at(pos)
      return nil if pos >= @string.bytesize
      @tokens.bsearch do |_, base, len|
        if pos < base then -1
        elsif pos >= base + len then 1
        else 0 end
      end
    end

    def token_index_of(token)
      @token_index[token[1]]
    end

    def expand(states, state, first_capacity)
      token = token_at(state.pos)
      return unless token
      kind, base, len = token
      off = state.pos - base

      case kind
      when WORD
        try_plain_byte(states, state, base, off, len, first_capacity)
        # An encoded-word beginning on a plain byte is only competitive when
        # its span can reach a FORCE unit (an encoded-word must encode
        # something non-ASCII/non-printable). When the nearest FORCE unit is
        # farther than one encoded-word can span, starting here can never beat
        # leaving the plain bytes literal, so the transition is skipped.
        if force_reachable_within_span?(state.pos, ENCODED_WORD_SPAN_SCAN)
          try_encoded_word(states, state, state.pos, first_capacity)
        end
      when WSP
        try_plain_wsp(states, state, token, first_capacity)
        # Absorb the WSP into an encoded-word starting here. This preserves
        # the WSP only when it is the field's leading whitespace or it sits
        # directly between two encoded-words; after plain text the WSP must
        # instead be swallowed by an encoded-word that starts before it (that
        # case is offered from the preceding WORD token).
        if state.gap == :start || state.gap == :wsp_lead || state.gap == :ew
          try_encoded_word(states, state, state.pos, first_capacity)
        end
      when FORCE
        try_encoded_word(states, state, state.pos, first_capacity)
      end
    end

    # Maximum number of raw bytes one encoded-word span scan is allowed to
    # reach (a loose upper bound covering the largest legal encoded word:
    # 45 base64 payload bytes plus surrounding ASCII/whitespace headroom).
    ENCODED_WORD_SPAN_SCAN = 75

    # True when a FORCE unit begins within +limit+ raw bytes of +pos+, i.e.
    # an encoded-word starting at +pos+ could contain forced content and
    # therefore be worth enumerating.
    def force_reachable_within_span?(pos, limit)
      f = next_force_at_or_after(pos)
      !f.nil? && f - pos <= limit
    end

    def try_plain_byte(states, state, base, off, len, first_capacity)
      wire = @string.byteslice(base + off, 1)
      capacity = capacity_for(state, first_capacity)
      next_pos = state.pos + 1

      # The first byte of a plain word starts a foldable boundary (:plain);
      # subsequent bytes are in-word continuation (:text). The word's raw
      # offset tells them apart here regardless of how the preceding content
      # was emitted.
      gap = off.zero? ? :plain : :text
      if state.col + 1 <= capacity
        relax(states, state,
              pos: next_pos, gap: gap, col: state.col + 1,
              first: state.first, cost_add: 1, move: wire,
              plain_seen: true)
      end

      # Fold immediately before the word's first byte: continuation line is
      # CRLF + WSP + byte.
      if off.zero? && state.gap != :start && 2 <= @line_length
        relax(states, state,
              pos: next_pos, gap: :plain, col: 2,
              first: false, cost_add: FOLD.bytesize + 1,
              move: FOLD + wire, plain_seen: true)
      end
    end

    def try_plain_wsp(states, state, token, first_capacity)
      wire = @string.byteslice(token[1], 1)
      capacity = capacity_for(state, first_capacity)

      leading = state.gap == :start || state.gap == :wsp_lead
      next_gap =
        if leading then :wsp_lead
        elsif state.gap == :ew then :wsp
        else :plain
        end

      if leading
        # Leading whitespace kept outside the first encoded-word is stripped
        # by a header parser (on the first line and equally on a folded
        # continuation line, since the continuation WSP itself is folding
        # whitespace). It survives only when the entire remainder is plain
        # text; when any FORCE unit follows it must be absorbed into the
        # first encoded-word (offered from the leading WSP position).
        if any_force_after?(state.pos)
          return
        end
        relax_plain_wsp(states, state, token, wire, capacity, next_gap)
      else
        relax_plain_wsp(states, state, token, wire, capacity, next_gap)
      end

      # Fold at this WSP: CRLF + continuation WSP replace the original byte.
      unless state.gap == :start
        relax(states, state,
              pos: state.pos + 1, gap: next_gap, col: 1,
              first: false, cost_add: FOLD.bytesize, move: FOLD,
              plain_seen: state.plain_seen)
      end
    end

    def relax_plain_wsp(states, state, token, wire, capacity, next_gap)
      if state.col + 1 <= capacity
        relax(states, state,
              pos: state.pos + 1, gap: next_gap, col: state.col + 1,
              first: state.first, cost_add: 1, move: wire,
              plain_seen: state.plain_seen)
      end
    end

    # Raw position of the first FORCE unit at or after +pos+; nil when none.
    # A precomputed per-token array plus a binary search keeps this O(log n)
    # even for positions inside a token.
    def next_force_at_or_after(pos)
      @next_force_after_token ||= begin
        upcoming = nil
        Array.new(@tokens.length).tap do |arr|
          (@tokens.length - 1).downto(0) do |k|
            upcoming = @tokens[k][1] if @tokens[k][0] == FORCE
            arr[k] = upcoming
          end
        end
      end
      idx = @token_index[pos]
      # A position inside a token belongs to that token; otherwise find the
      # first token starting after it.
      if idx.nil?
        containing = @tokens.bsearch_index do |_kind, base, len|
          if pos < base then -1
          elsif pos >= base + len then 1
          else 0 end
        end
        idx = containing || @tokens.bsearch_index { |_k, base, _l| base > pos }
      end
      return nil if idx.nil?
      @next_force_after_token[idx]
    end

    def any_force_after?(pos)
      !next_force_at_or_after(pos).nil?
    end

    # Enumerate every legal encoded-word that can begin at raw +start+. The
    # span shapes (payload end positions) and their Q/B wire strings depend
    # only on +start+, not on the emitting state, so they are built once and
    # cached. State-specific legality (leading/trailing WSP, capacity) is
    # applied when a candidate is relaxed into a state.
    def try_encoded_word(states, state, start, first_capacity)
      # Plain WSP directly between two encoded-words is stripped on decode,
      # so starting a new encoded-word there is never a valid continuation
      # (the WSP must be absorbed or folded instead).
      return if state.gap == :wsp

      # Before the field's first encoded-word, still-leading whitespace with
      # no plain text in between would be stripped on decode. The WSP itself
      # is offered as an encoded-word start via the leading position, which
      # absorbs it.
      leading = state.gap == :start || state.gap == :wsp_lead
      if leading && !state.plain_seen && state.pos > 0
        return
      end

      token = token_at(start)
      return unless token

      span_candidates(start, token).each do |end_pos, payload, qwire, bwire|
        # Trailing WSP is never legal inside an encoded-word.
        next if wsp_byte?(payload.getbyte(-1))
        # A leading WSP is absorbed into the encoded-word and may begin the
        # word:
        #   * at field start (leading whitespace is only preserved this way),
        #   * after plain text or another encoded-word, where the absorbed
        #     WSP itself is the required linear whitespace.
        # It is not a valid continuation from a plain-WSP state that sits
        # directly between two encoded-words (already pruned above).
        relax_ew(states, state, end_pos, qwire, first_capacity) if
          qwire && qwire.bytesize <= ENCODED_WORD_MAX_LENGTH
        relax_ew(states, state, end_pos, bwire, first_capacity) if
          bwire && bwire.bytesize <= ENCODED_WORD_MAX_LENGTH
      end
    end

    # Build/cache the list of encoded-word spans starting at +start+:
    # [end_raw_position, payload, q_wire_or_nil, b_wire_or_nil]. Spans that
    # contain no forced unit, end on WSP, or overflow both transports are
    # omitted.
    def span_candidates(start, token)
      @span_cache ||= {}
      @span_cache[start] ||= build_span_candidates(start, token)
    end

    def build_span_candidates(start, token)
      i = token_index_of(token)
      pos = start
      payload = ''.b
      saw_force = false
      candidates = []
      while i < @tokens.length
        tk, tb, tl = @tokens[i]
        take = pos == tb ? 0 : pos - tb

        if tk == WORD
          available = tl - take
          (1..available).each do |k|
            payload << @string.byteslice(pos + k - 1, 1)
            emit_span(candidates, payload, saw_force, pos + k)
          end
          pos += available
          i += 1
        elsif tk == WSP
          payload << @string.byteslice(pos, 1)
          pos += 1
          i += 1
          # A span cannot end on WSP and may only lead with WSP as the
          # field's first encoded-word; record the wire only if some later
          # non-WSP byte completes it (emitted on subsequent units).
        else # FORCE
          n = tl - take
          payload << @string.byteslice(pos, n)
          saw_force = true
          pos += n
          i += 1
          emit_span(candidates, payload, saw_force, pos)
        end

        break if q_wire(payload).bytesize > ENCODED_WORD_MAX_LENGTH &&
                 payload.bytesize > BASE64_MAX_PAYLOAD_BYTES
      end
      candidates
    end

    def emit_span(candidates, payload, saw_force, end_pos)
      return unless saw_force
      return if wsp_byte?(payload.getbyte(-1))
      q = q_wire(payload)
      q = nil if q.bytesize > ENCODED_WORD_MAX_LENGTH
      b = if payload.bytesize <= BASE64_MAX_PAYLOAD_BYTES
            w = b_wire(payload)
            w.bytesize <= ENCODED_WORD_MAX_LENGTH ? w : nil
          end
      candidates << [end_pos, payload.dup, q, b]
    end

    def wsp_byte?(byte)
      byte == 0x20 || byte == 0x09
    end



    def relax_ew(states, state, end_pos, wire, first_capacity)
      capacity = capacity_for(state, first_capacity)

      if state.gap == :start
        if state.col + wire.bytesize <= capacity
          relax(states, state,
                pos: end_pos, gap: :ew, col: state.col + wire.bytesize,
                first: state.first, cost_add: wire.bytesize, move: wire,
                plain_seen: state.plain_seen)
        end
        return
      end

      if state.gap == :ew
        # Adjacent encoded-words require one separating WSP, which is itself
        # stripped on decoding (so it carries no content byte).
        if state.col + 1 + wire.bytesize <= capacity
          relax(states, state,
                pos: end_pos, gap: :ew, col: state.col + 1 + wire.bytesize,
                first: state.first, cost_add: 1 + wire.bytesize,
                move: ' '.b + wire, plain_seen: state.plain_seen)
        end
        # The continuation line's leading WSP doubles as the separator.
        if 1 + wire.bytesize <= @line_length
          relax(states, state,
                pos: end_pos, gap: :ew, col: 1 + wire.bytesize,
                first: false, cost_add: FOLD.bytesize + wire.bytesize,
                move: FOLD + wire, plain_seen: state.plain_seen)
        end
      else
        # Direct contact with preceding plain text (a WSP boundary, a word
        # boundary, or plain text mid-run) needs no separator.
        if state.col + wire.bytesize <= capacity
          relax(states, state,
                pos: end_pos, gap: :ew, col: state.col + wire.bytesize,
                first: state.first, cost_add: wire.bytesize, move: wire,
                plain_seen: state.plain_seen)
        end
        # Fold before the encoded-word; the continuation WSP is content-free
        # whitespace here.
        if state.gap != :text && 1 + wire.bytesize <= @line_length
          relax(states, state,
                pos: end_pos, gap: :ew, col: 1 + wire.bytesize,
                first: false, cost_add: FOLD.bytesize + wire.bytesize,
                move: FOLD + wire, plain_seen: state.plain_seen)
        end
      end
    end

    def relax(states, parent, attrs)
      cost_add = attrs.delete(:cost_add)
      move = attrs.delete(:move)
      first = attrs.delete(:first)
      plain_seen = attrs.key?(:plain_seen) ?
                     attrs.delete(:plain_seen) : parent.node.plain_seen
      node = attrs.delete(:node) ||
             prefix(parent.node, move, plain_seen)
      key = [attrs[:pos], attrs[:gap], attrs[:col], first]
      new_cost = parent.cost + cost_add

      existing = states[key]
      if existing.nil?
        states[key] = State.new(pos: attrs[:pos], gap: attrs[:gap],
                                col: attrs[:col], first: first,
                                cost: new_cost, node: node)
      elsif new_cost < existing.cost
        states[key] = State.new(pos: attrs[:pos], gap: attrs[:gap],
                                col: attrs[:col], first: first,
                                cost: new_cost, node: node)
      end
      # Equal-cost ties are left with the first enumerated candidate; the
      # transition enumeration order is deterministic, which is the stable
      # tie-break rule for byte-equal solutions.
    end
  end
end
