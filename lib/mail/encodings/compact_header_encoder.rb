# encoding: utf-8
# frozen_string_literal: true
require 'base64'

module Mail
  module Encodings
    # Compact encoder for the body of unstructured header fields.
    #
    # Produces an RFC 2047 / RFC 5322 representation chosen for minimum wire
    # byte count. Every encoded word independently uses quoted-printable (Q)
    # or Base64 (B); the objective counts the field-name prefix, encoded-word
    # wrappers, literal separators, fold whitespace and CRLFs, so the result
    # is the shortest valid representation of the field body.
    #
    # Constraints honoured:
    #   * every encoded word is at most 75 characters
    #     (=?charset?X?...?=, including the wrapper)
    #   * every physical line is within the configured limit (78 by default),
    #     and the field name prefix counts against the first line
    #   * multi-byte UTF-8 sequences are never split in the middle
    #   * folding occurs only before WSP (the fold leader is preserved) or
    #     between adjacent encoded words
    #   * every source space/tab decodes back exactly, including runs adjacent
    #     to encoded words and at field edges
    #
    # Strategy. For ordinary-sized fields a shortest-path dynamic program
    # chooses, position by position, whether to emit raw text, a Q word, or a
    # B word, and where to fold; Q/B is selected per word and whitespace runs
    # are absorbed into words exactly when needed to survive decoding. Fields
    # that cannot be laid out by the DP (over-long raw runs, very large
    # inputs) fall back to a greedy word-chain encoder, and finally to a
    # whole-value word encoder. Every emitted header is verified to decode
    # back to the source within the line limit before it is returned.
    class CompactHeaderEncoder
      CHARSET = 'UTF-8'
      WRAPPER = "=?#{CHARSET}?Q?".bytesize + '?='.bytesize # 12
      MAX_WORD = 75
      MAX_WORD_RAW = 45

      def self.encode(value, name, line_limit)
        new(value, name, line_limit).encode
      end

      def initialize(value, name, line_limit)
        @value     = value.to_s
        @name      = name.to_s
        @limit     = line_limit
        @first_rem = @limit - "#{@name}: ".bytesize
        @cont_rem  = @limit - 1
      end

      # Final always-correct fallback: encode the ENTIRE value as encoded
      # words (Q/B), split on whitespace boundaries so source spaces survive
      # as the underscore/Q-escaped space inside words. Runs are broken into
      # word-sized chunks; every physical line stays within the limit.
      def encode_whole
        lines = []
        cur = +''
        first = true
        emit = lambda do |word|
          room = (first ? @first_rem : @cont_rem - 1)
          if cur.bytesize + (cur.empty? ? 0 : 1) + word.bytesize <= room
            cur << ' ' unless cur.empty?
            cur << word
          else
            lines << cur.dup unless cur.empty? && lines.empty?
            cur = +(' ' + word)
            first = false
          end
        end
        # split into whitespace-delimited pieces, keeping WSP inside words
        pieces = @value.scan(/[ \t]*[^ \t]+[ \t]*/)
        pieces.each do |piece|
          bytes = piece.bytes
          pos = 0
          chars = piece.each_char.to_a
          boff = [0]; chars.each { |c| boff << boff.last + c.bytesize }
          while pos < bytes.size
            room = (first ? @first_rem : @cont_rem - 1) - cur.bytesize - (cur.empty? ? 0 : 1)
            ci = boff.index(pos)
            cj = ci + 1
            cj += 1 while cj < chars.size &&
              (boff[cj+1] - pos) <= MAX_WORD_RAW &&
              word_room_ok?(bytes[pos...boff[cj+1]], room)
            cj = [cj, ci + 1].max
            seg = bytes[pos...boff[cj]]
            mode, payload = choose_qb(seg, room)
            emit.call("=?#{CHARSET}?#{mode}?#{payload}?=")
            pos = boff[cj]
          end
        end
        lines << cur.dup
        "#{@name}: " + lines.first.to_s + lines[1..].map { |l| "\r\n" + l }.join
      end

      # Fields longer than this use the conservative encoder; the full DP is
      # cubic-ish in the worst case and is only needed to shave bytes off
      # reasonably sized headers.
      DP_MAX_BYTES = 250

      def encode
        return "#{@name}: \r\n" if @value.empty?
        if @value.bytesize <= DP_MAX_BYTES && !contains_unsplittable_run?
          out = encode_attempt
          return out if out && valid_output?(out)
        end
        c = encode_conservative
        return c if valid_output?(c)
        encode_whole
      end

      # A raw non-WSP run longer than a continuation line cannot be folded by
      # the DP (no WSP boundary); route it through the conservative encoder.
      def contains_unsplittable_run?
        @value.scan(/[^ \t\r\n]+/).any? { |t| t.bytesize > @cont_rem - 1 }
      end

      def encode_attempt
        @lines = []
        @cur   = +''
        @first = true
        @render_pre = +''
        trace = begin
          plan(@value.each_char.to_a, +'', true)
        rescue RuntimeError
          nil
        end
        return nil unless trace && trace_valid?(trace)
        @lines = []
        @cur   = +''
        @first = true
        apply_trace(trace)
        @lines << @cur.dup
        "#{@name}: " + @lines.first.to_s + @lines[1..].map { |l| "\r\n" + l }.join
      end

      def valid_output?(out)
        lines = out.split("\r\n")
        return false if lines.empty?
        return false if lines.any? { |ln| ln.bytesize > @limit }
        return false if lines[1..].any? { |ln| !(ln.start_with?(' ') || ln.start_with?("\t")) }
        return false if out.scan(/=\?[^?\r\n]*\?[QB]\?[^?\r\n]*\?=/).any? { |w| w.length > MAX_WORD }
        dec = begin
          Mail::Field.parse("#{out}\r\n").decoded
        rescue StandardError
          nil
        end
        dec == @value
      end

      # Always-correct conservative encoder. Folds raw text at WSP; whenever
      # a token must be encoded (non-ASCII or too long to fit a line) it is
      # emitted as a chain of encoded words. A raw WSP adjacent to an encoded
      # word is absorbed into that word (the decoder drops raw WSP next to a
      # word at the field edge or between words), so all spaces/tabs survive.
      def encode_conservative
        @lines = []
        @cur = +''
        @first = true
        @pending_absorb = nil

        tokens = @value.scan(/[ \t]+|[^ \t]+/)
        i = 0
        while i < tokens.size
          tok = tokens[i]
          if tok =~ /\A[ \t]+\z/
            conservative_wsp(tok, tokens, i)
            i += @consumed
          else
            conservative_token(tok)
            i += @consumed
          end
        end
        @lines << @cur.dup
        @lines.delete_if { |l| l.empty? && !(@lines.first == l && @lines.size == 1) }
        "#{@name}: " + @lines.first.to_s + @lines[1..].map { |l| "\r\n" + l }.join
      end

      # Emit a WSP run. If the following non-WSP token is (or becomes) encoded,
      # the run is deferred (conservative_token absorbs it); otherwise fold or
      # append as raw text.
      def conservative_wsp(tok, tokens, i)
        nxt = tokens[i+1]
        if nxt && needs_word?(nxt)
          # The following content is (or becomes) an encoded word. A raw WSP
          # directly before a word is kept when raw text precedes it, but
          # dropped when the preceding atom is also an encoded word.
          prev = tokens[i-1]
          if prev && needs_word?(prev)
            # absorb the WSP into the following word so it survives
            @cur << tok unless @cur.bytesize + tok.bytesize > @limit
            @pending_absorb = tok
          else
            @cur << tok
          end
          @consumed = 1
        elsif tok.bytesize <= rem || @cur.empty?
          @cur << tok
          @consumed = 1
        else
          @lines << @cur.dup
          @cur = +(tok[0] + tok[1..].to_s)
          @first = false
          @consumed = 1
        end
      end

      def needs_word?(tok)
        !(tok.ascii_only? && !tok.include?("\r") && !tok.include?("\n")) ||
          tok.bytesize > @cont_rem - 1
      end

      # Emit a non-WSP token: raw when it fits, otherwise as an encoded-word
      # chain (absorbing any trailing raw WSP already appended to @cur).
      def conservative_token(tok)
        @consumed = 1
        plain = tok.ascii_only? && !tok.include?("\r") && !tok.include?("\n")
        if plain && tok.bytesize <= rem
          @cur << tok
          @pending_absorb = nil
          return
        end
        if plain && (m = @cur.match(/\A(.*\S)([ \t]+)\z/m)) &&
           tok.bytesize <= @cont_rem - 1 - m[2].bytesize
          # Fold at the WSP; the raw token fits on the leader line.
          @lines << m[1]
          @cur = +m[2]
          @first = false
          @cur << tok
          @pending_absorb = nil
          return
        end
        # Encode the token. A pending WSP between two encoded words must be
        # absorbed into this word (the decoder drops a literal/fold WSP
        # between adjacent encoded words).
        absorb = @pending_absorb.to_s
        @pending_absorb = nil
        leader = +''
        if !absorb.empty?
          # A WSP between two encoded words. Preserve it by making it the
          # fold-leading WSP: close the current line (which ends in the
          # previous word) and start the continuation line with one retained
          # space plus this token's word chain.
          @cur = @cur.byteslice(0, @cur.bytesize - absorb.bytesize) if absorb.bytesize <= @cur.bytesize
          @lines << @cur.dup
          @cur = +' '
        elsif (m = @cur.match(/\A(.*\S)([ \t]+)\z/m))
          @lines << m[1]
          leader = m[2]                  # retain the full WSP run as leader
          @cur = +leader
        elsif @cur =~ /\A[ \t]+\z/
          leader = @cur.dup              # field-start / bare WSP run
          @cur = +leader
        end
        emit_words_for(tok, leader)
      end

      # Emit `str` (no leading WSP) as a chain of encoded words packed onto
      # physical lines. `leader` is a single fold-leading WSP character that
      # starts the first continuation line. Words are joined on a line by a
      # literal separator space (discarded between adjacent encoded words);
      # when a line fills, CRLF plus one leading space starts the next line.
      def emit_words_for(str, leader = +'')
        chars = str.each_char.to_a
        boff = [0]; chars.each { |c| boff << boff.last + c.bytesize }
        bytes = str.bytes
        pos = 0
        # The caller has already folded (when needed): @lines holds complete
        # lines and @cur is either empty (start of first line) or the single
        # retained fold-leading character for the first continuation line.
        on_first = @cur.empty? && @lines.empty?
        until pos >= bytes.size
          line_has_word = @cur =~ /\?=\z/
          sep = line_has_word ? 1 : 0
          budget = on_first ? @first_rem : @cont_rem - 1
          room = budget - @cur.bytesize - sep
          # fold if even a single source byte cannot form a word that fits
          must_fold =
            if room < WRAPPER + 1
              true
            elsif line_has_word
              one = bytes[pos]
              ql = one ? q_byte(one) : 3
              (WRAPPER + ql > room) && (WRAPPER + 4 > room)
            else
              false
            end
          if must_fold
            # fold to a new continuation line (one retained leading space)
            @lines << @cur.dup
            @cur = +' '
            on_first = false
            sep = 0
            room = @cont_rem - 1 - 1
          end
          ci = boff.index(pos)
          cj = ci + 1
          cj += 1 while cj < chars.size &&
            (boff[cj+1] - pos) <= MAX_WORD_RAW &&
            word_room_ok?(bytes[pos...boff[cj+1]], room)
          cj = [cj, ci + 1].max
          seg = bytes[pos...boff[cj]]
          mode, payload = choose_qb(seg, room)
          word = "=?#{CHARSET}?#{mode}?#{payload}?="
          @cur = +(@cur.to_s + (sep == 1 ? ' ' : '') + word)
          pos = boff[cj]
        end
      end

      # True when at least one codepoint can form an encoded word within the
      # given room on this line.
      def next_word_fits?(bytes, boff, chars, pos, room)
        return false if room < WRAPPER + 1
        one = bytes[pos]
        return false if one.nil?
        ql = q_byte(one)
        bl = 4 * (3 / 3)
        WRAPPER + ql <= room || WRAPPER + bl <= room
      end

      MIN_WORD_ROOM = 14

      def word_room_ok?(seg, room)
        ql = seg.sum { |b| q_byte(b) }
        bl = 4 * ((seg.size + 2) / 3)
        WRAPPER + ql <= room || WRAPPER + bl <= room
      end


      private

      def wsp?(s)     = s =~ /\A[ \t]+\z/
      def rem
        @limit - (@first ? "#{@name}: ".bytesize : 1) - @cur.bytesize
      end

      def rawable?(c) = c.ascii_only? && c != "\r" && c != "\n"
      def special?(s) = !(s.ascii_only? && !s.include?("\r") && !s.include?("\n"))

      def trace_valid?(trace, _expected_decoded = nil)
        wire = render_trace(trace)
        lines = wire.split("\r\n")
        return false if lines.empty?
        return false if lines.any? { |ln| ln.bytesize > @limit }
        return false if lines[1..].any? { |ln| !(ln.start_with?(' ') || ln.start_with?("\t")) }
        words = wire.scan(/=\?[^?\r\n]*\?[QB]\?[^?\r\n]*\?=/ )
        return false if words.any? { |w| w.length > MAX_WORD }
        return false if wire.include?('?==?')
        true
      end

      def render_trace(trace)
        lines = []
        cur = (@cur || +'').dup
        trace.each do |action, *args|
          case action
          when :pre
            cur = (@render_pre || @cur || +'').dup
          when :text, :word then cur << args[0]
          when :fold_synthetic
            lines << cur.dup
            cur = +(' ' + args[0])
          when :fold_leader
            lines << cur.dup
            cur = +args[0]
          when :fold_absorb
            lines << (cur.byteslice(0, cur.bytesize - args[0]) || +'')
            cur = +(' ' + args[1])
          when :fold_before_word
            removed, leader, word = args
            lines << (cur.byteslice(0, cur.bytesize - removed) || +'')
            cur = +(leader + word)
          when :retract
            cur = cur.byteslice(0, cur.bytesize - args[0]) || +''
          end
        end
        lines << cur.dup
        lines.first.to_s + lines[1..].map { |l| "\r\n" + l }.join
      end

      def choose_qb(seg, room)
        ql = seg.sum { |b| q_byte(b) }
        bl = 4 * ((seg.size + 2) / 3)
        if WRAPPER + ql <= room && WRAPPER + ql <= MAX_WORD &&
           (WRAPPER + bl > room || WRAPPER + ql <= WRAPPER + bl)
          [:Q, q_payload(seg)]
        else
          [:B, b_payload(seg)]
        end
      end

      def apply_trace(trace)
        trace.each do |action, *args|
          case action
          when :pre then nil
          when :text then @cur << args[0]
          when :word then @cur << args[0]
          when :fold_synthetic
            @lines << @cur.dup
            @cur = +(' ' + args[0])
            @first = false
          when :fold_leader
            @lines << @cur.dup
            @cur = +args[0]
            @first = false
          when :fold_absorb
            removed, word = args
            @lines << (@cur.byteslice(0, @cur.bytesize - removed) || +'')
            @cur = +(' ' + word)
            @first = false
          when :fold_before_word
            removed, leader, word = args
            @lines << (@cur.byteslice(0, @cur.bytesize - removed) || +'')
            @cur = +(leader + word)
            @first = false
          when :retract
            @cur = @cur.byteslice(0, @cur.bytesize - args[0]) || +''
          end
        end
      end

      def q_byte(b)
        (b == 0x20 || (b >= 33 && b <= 126 && b != 0x3D && b != 0x3F && b != 0x5F)) ? 1 : 3
      end

      def q_payload(bytes)
        bytes.map { |b|
          if b == 0x20 then '_'
          elsif b >= 33 && b <= 126 && b != 0x3D && b != 0x3F && b != 0x5F then b.chr
          else '=%02X' % b end
        }.join
      end

      def b_payload(bytes)
        ::Base64.strict_encode64(bytes.pack('C*'))
      end

      State = Struct.new(:u, :first, :kind, :cost, :nw, :rb, :sig, :trace) do
        def key = [u, first, kind]
      end

      # Shortest-path DP over the region chars with a raw prefix (the current
      # @cur content) already emitted.
      def plan(chars, pre_str, on_first)
        pre = pre_str.each_char.to_a
        pn  = pre.size
        all = pre + chars
        n   = all.size
        boff = [0]; all.each { |c| boff << boff.last + c.bytesize }
        ab = all.join.bytes

        best = Array.new(n + 1) { {} }
        seed = State.new(pre_str.bytesize, on_first, :pre, 0, 0, 0, [], [[:pre]])
        best[pn][seed.key] = seed

        (pn...n).each do |i|
          best[i].each_value do |s|
            u, first, kind, cost, nw, rb, sig, trace =
              s.u, s.first, s.kind, s.cost, s.nw, s.rb, s.sig, s.trace
            rem = (first ? @first_rem : @cont_rem) - u
            ci = all[i]

            emit_raw_nonwsp(best, all, boff, i, u, first, kind, cost, nw, rb, sig, trace, rem)
            emit_raw_wsp(best, all, boff, i, u, first, kind, cost, nw, rb, sig, trace, rem, n)
            emit_words(best, all, boff, ab, i, u, first, kind, cost, nw, rb, sig, trace, rem, n, pn)
          end
        end

        finals = best[n].reject { |key, _| key[2] == :wsp || key[2] == :lead }.values
        raise "cannot compact encode #{@value.inspect}" if finals.empty?
        ordered = finals.sort_by { |s| [s.cost, s.nw, -s.rb, s.sig] }
        chosen = ordered.find { |s| trace_roundtrips?(s.trace, all, n, pn) } || ordered.first
        chosen.trace
      end

      # Render a region trace (the DP pre-string is all[0...pn]) and confirm
      # the result decodes back to the combined pre+region source.
      def trace_roundtrips?(trace, all, n, pn)
        lines = []
        cur = +''
        trace.each do |action, *args|
          case action
          when :pre then cur << all[0...pn].join
          when :text, :word then cur << args[0]
          when :fold_synthetic
            lines << cur.dup
            cur = +(' ' + args[0])
          when :fold_leader
            lines << cur.dup
            cur = +args[0]
          when :fold_absorb
            lines << (cur.byteslice(0, cur.bytesize - args[0]) || +'')
            cur = +(' ' + args[1])
          when :fold_before_word
            removed, leader, word = args
            lines << (cur.byteslice(0, cur.bytesize - removed) || +'')
            cur = +(leader + word)
          when :retract
            cur = cur.byteslice(0, cur.bytesize - args[0]) || +''
          end
        end
        lines << cur.dup
        wire = lines.first.to_s + lines[1..].map { |l| "\r\n" + l }.join
        return false if wire.split("\r\n").any? { |l| l.bytesize > @limit }
        expected = all[0...n].join
        begin
          Mail::Field.parse("#{@name}: #{wire}\r\n").decoded == expected
        rescue StandardError
          false
        end
      end

      def emit_raw_nonwsp(best, all, boff, i, u, first, kind, cost, nw, rb, sig, trace, rem)
        ci = all[i]
        return unless rawable?(ci) && !wsp?(ci)
        jf = i + 1
        jf += 1 while jf < all.size && rawable?(all[jf]) && !wsp?(all[jf])
        len = boff[jf] - boff[i]
        if len <= rem
          put(best[jf], State.new(u + len, first, :text, cost + len, nw, rb + len,
                                  sig + [0, i, jf], trace + [[:text, all[i...jf].join]]))
        elsif rem > 0
          jp = i + 1
          jp += 1 while jp < jf && (boff[jp+1] - boff[i]) <= rem
          if jp > i
            l = boff[jp] - boff[i]
            put(best[jp], State.new(u + l, first, :text, cost + l, nw, rb + l,
                                    sig + [0, i, jp], trace + [[:text, all[i...jp].join]]))
          end
        end
      end

      def emit_raw_wsp(best, all, boff, i, u, first, kind, cost, nw, rb, sig, trace, rem, n)
        return unless wsp?(all[i])
        k = i
        k += 1 while k < n && wsp?(all[k])
        len = boff[k] - boff[i]
        run = all[i...k].join
        field_end = k == n
        if kind != :word && len <= rem
          # A field-end WSP run after an encoded word is dropped by the
          # decoder; mark it so the word-end retraction transition can absorb
          # it into a final word.
          illegal_end = field_end && trace.any? { |a| a == :word }
          put(best[k], State.new(u + len, first, :wsp, cost + len, nw, rb + len,
                                 sig + [0, i, k], trace + [[:text, run]]))
        end
        # Fold at this WSP run, keeping it as the continuation leader, only
        # when the next content is raw (for a following encoded word the WSP
        # must be absorbed via the word fold transition instead, otherwise a
        # spurious line is produced).
        if u > 0 && kind != :word && len <= @cont_rem - 1 && next_is_raw?(all, k, n)
          put(best[k], State.new(1 + len, false, :lead, cost + 2 + len, nw, rb + len,
                                 sig + [0, i, k, 1], trace + [[:fold_leader, run]]))
        end
        # A WSP run at the field end after an encoded word must be absorbed
        # into an extra final encoded word to survive.
        if field_end && trace.any? { |a| a == :word } &&
           (WRAPPER + len) <= @cont_rem - 1
          seg = all.bytes[boff[i]...boff[k]]
          ql = seg.sum { |b| q_byte(b) }
          bl = 4 * ((seg.size + 2) / 3)
          { Q: WRAPPER + ql, B: WRAPPER + bl }.each do |m2, len2|
            next if len2 > MAX_WORD
            word = "=?#{CHARSET}?#{m2}?#{m2 == :Q ? q_payload(seg) : b_payload(seg)}?="
            if 1 + len2 <= @cont_rem - 1
              put(best[k], State.new(1 + len2, false, :word, cost + 2 + 1 + len2,
                                     nw + 1, rb, sig + [1, i, k, m2 == :Q ? 0 : 1, 7],
                                     trace + [[:fold_synthetic, word]]))
            end
          end
        end
      end

      def next_is_raw?(all, k, n)
        k < n && rawable?(all[k]) && !wsp?(all[k])
      end

      def emit_words(best, all, boff, ab, i, u, first, kind, cost, nw, rb, sig, trace, rem, n, pn)
        ((i + 1)..n).each do |j|
          nb = boff[j] - boff[i]
          break if nb > MAX_WORD_RAW
          seg = ab[boff[i]...boff[j]]
          ql = seg.sum { |b| q_byte(b) }
          bl = 4 * ((nb + 2) / 3)
          { Q: WRAPPER + ql, B: WRAPPER + bl }.each do |mode, wlen|
            next if wlen > MAX_WORD
            word = "=?#{CHARSET}?#{mode}?#{mode == :Q ? q_payload(seg) : b_payload(seg)}?="

            case kind
            when :word
              if 1 + wlen <= rem
                put(best[j], State.new(u + 1 + wlen, first, :word, cost + 1 + wlen,
                                        nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 0],
                                        trace + [[:text, ' '], [:word, word]]))
              end
              if wlen <= @cont_rem - 1
                put(best[j], State.new(1 + wlen, false, :word, cost + 2 + 1 + wlen,
                                        nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 1],
                                        trace + [[:fold_synthetic, word]]))
              end
            when :lead
              # The continuation line begins with the retained fold-leader
              # WSP run already on the line (u includes those bytes). The
              # word always fits: max encoded word is 75 chars and the line
              # allows 77, and the leader is at most a short WSP run.
              if wlen <= rem
                put(best[j], State.new(u + wlen, first, :word, cost + wlen,
                                       nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 0],
                                       trace + [[:word, word]]))
              end
            when :wsp
              run_start = i
              run_start -= 1 while run_start > 0 && wsp?(all[run_start-1])
              run_bytes = boff[i] - boff[run_start]
              field_start = first && (u - run_bytes) == 0
              if wlen <= rem && !field_start
                put(best[j], State.new(u + wlen, first, :word, cost + wlen,
                                        nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 0],
                                        trace + [[:word, word]]))
              end
              offer_wsp_fold(best, all, boff, ab, i, j, u, cost, nw, rb, sig, trace, pn)
              offer_inline_retractions(best, all, boff, ab, i, j, u, first, kind, cost, nw, rb, sig, trace, pn)
            else
              # A plain word after a pre-string that is only a WSP run at the
              # start of the first line is illegal (the decoder drops the
              # field-start WSP); the retraction transition absorbs it.
              pre_is_leading_wsp = first && kind == :pre &&
                pre_str_leading_wsp?(pre_str_for(all, pn))
              if wlen <= rem && !pre_is_leading_wsp
                put(best[j], State.new(u + wlen, first, :word, cost + wlen,
                                        nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 0],
                                        trace + [[:word, word]]))
              end
              offer_inline_retractions(best, all, boff, ab, i, j, u, first, kind, cost, nw, rb, sig, trace, pn)
              # Fold before the first word when it does not fit the current
              # line: find the last WSP run in the pre-string (or region
              # prefix) and use it as the retained fold leader.
              offer_first_word_fold(best, all, boff, ab, i, j, mode, wlen,
                                    u, first, cost, nw, rb, sig, trace, pn)
            end
          end
        end
      end

      # Fold where the raw WSP run before position i is absorbed into the
      # word [s2..j), content before the WSP closes the line and the word
      # starts the continuation line with a (discarded) synthetic leader.
      # Fold before the first encoded word: locate the last raw WSP run on
      # the current line (searching pre-string + emitted region raw text),
      # close the line with content before it, and start the continuation
      # with the retained WSP leader plus the word. The source WSP is the
      # fold leader (preserved on unfold before a word that follows raw text).
      def offer_first_word_fold(best, all, boff, ab, i, j, mode, wlen,
                                u, first, cost, nw, rb, sig, trace, pn)
        return unless wlen <= @cont_rem - 1
        # Position i in `all`; find the last raw WSP run on the current line
        # at or before i by walking back over on-line raw bytes (region raw
        # and pre-string bytes).
        p = i
        # skip non-WSP raw suffix immediately preceding i
        p -= 1 while p > 0 && rawable?(all[p-1]) && !wsp?(all[p-1])
        return unless p > 0 && wsp?(all[p-1])
        s = p
        s -= 1 while s > 0 && wsp?(all[s-1])
        # [s..i) = WSP run (no non-WSP between)
        removed = boff[i] - boff[s]
        return if removed > u
        seg = ab[boff[i]...boff[j]]
        ql = seg.sum { |b| q_byte(b) }
        bl = 4 * ((seg.size + 2) / 3)
        wl2 = mode == :Q ? WRAPPER + ql : WRAPPER + bl
        return if wl2 > @cont_rem - 1
        word = "=?#{CHARSET}?#{mode}?#{mode == :Q ? q_payload(seg) : b_payload(seg)}?="
        leader = all[s...i].join
        # wire: remove the WSP run from cur (raw prefix stays), CRLF, then a
        # continuation line whose first `removed` bytes are the retained
        # leader WSP, followed directly by the word.
        put(best[j], State.new(removed + wl2, false, :word,
                               cost - removed + 2 + removed + wl2,
                               nw + 1, rb, sig + [1, i, j, mode == :Q ? 0 : 1, 6],
                               trace + [[:fold_before_word, removed, leader, word]]))
      end

      def offer_wsp_fold(best, all, boff, ab, i, j, u, cost, nw, rb, sig, trace, pn)
        return unless i > pn && wsp?(all[i-1])
        s2 = i
        s2 -= 1 while s2 > pn && wsp?(all[s2-1])
        seg = ab[boff[s2]...boff[j]]
        ql = seg.sum { |b| q_byte(b) }
        bl = 4 * ((seg.size + 2) / 3)
        { Q: WRAPPER + ql, B: WRAPPER + bl }.each do |m2, len2|
          next if len2 > MAX_WORD || len2 > @cont_rem - 1
          removed = boff[i] - boff[s2]
          next if removed > u
          word2 = "=?#{CHARSET}?#{m2}?#{m2 == :Q ? q_payload(seg) : b_payload(seg)}?="
          put(best[j], State.new(1 + len2, false, :word,
                                 cost - removed + 2 + 1 + len2, nw + 1, rb,
                                 sig + [1, s2, j, m2 == :Q ? 0 : 1, 3],
                                 trace + [[:fold_absorb, removed, word2]]))
        end
      end

      # Word [s2..j) absorbing an inline raw suffix [s2..i) already emitted
      # on the current line (no fold). s2 may reach into the pre-string.
      def offer_inline_retractions(best, all, boff, ab, i, j, u, first, kind, cost, nw, rb, sig, trace, pn)
        return unless kind == :text || kind == :wsp || kind == :pre
        # Boundaries where the word absorbs an already-emitted raw suffix:
        #  - the start of a raw WSP run immediately preceding i (the WSP must
        #    be swallowed or it is dropped before the word), and
        #  - a short raw prefix (up to RAW_RETRACT_LIMIT bytes) ending at that
        #    WSP run (absorbing nearby raw text can be cheaper than emitting
        #    it raw plus a separate word).
        s = i
        candidates = []
        while s > 0
          s -= 1 while s > 0 && rawable?(all[s-1]) && !wsp?(all[s-1])
          break unless s > 0 && wsp?(all[s-1])
          w = s
          w -= 1 while w > 0 && wsp?(all[w-1])
          candidates << w
          # also absorb a short raw run immediately before the WSP run
          t = w
          taken = 0
          while t > 0 && rawable?(all[t-1]) && !wsp?(all[t-1]) &&
                (boff[w] - boff[t]) <= RAW_RETRACT_LIMIT
            t -= 1
            candidates << t
            taken = boff[w] - boff[t]
          end
          s = w
        end
        # Also consider absorbing a short raw prefix with no WSP at all
        # (e.g. "=aæ" -> raw "=" + word "aæ"), which can shave off the
        # wrapper of a separate preceding word.
        t = i
        taken = 0
        while t > 0 && rawable?(all[t-1]) && !wsp?(all[t-1]) &&
              (boff[i] - boff[t]) <= RAW_RETRACT_LIMIT
          t -= 1
          candidates << t
        end
        candidates.each do |s2|
          removed = boff[i] - boff[s2]
          next if removed > u
          seg = ab[boff[s2]...boff[j]]
          next if seg.size > MAX_WORD_RAW
          ql = seg.sum { |b| q_byte(b) }
          bl = 4 * ((seg.size + 2) / 3)
          { Q: WRAPPER + ql, B: WRAPPER + bl }.each do |m2, len2|
            next if len2 > MAX_WORD
            newu = u - removed + len2
            next if newu > (first ? @first_rem : @cont_rem)
            word2 = "=?#{CHARSET}?#{m2}?#{m2 == :Q ? q_payload(seg) : b_payload(seg)}?="
            put(best[j], State.new(newu, first, :word, cost - removed + len2,
                                   nw + 1, rb, sig + [1, s2, j, m2 == :Q ? 0 : 1, 5],
                                   trace + [[:retract, removed], [:word, word2]]))
          end
        end
      end

      RAW_RETRACT_LIMIT = 6

      def pre_str_for(all, pn)
        all[0...pn].join
      end

      def pre_str_leading_wsp?(pre)
        !pre.empty? && pre.each_char.all? { |c| wsp?(c) }
      end

      def put(best_at_j, st)
        old = best_at_j[st.key]
        if old.nil? ||
           ([st.cost, st.nw, -st.rb, st.sig] <=>
            [old.cost, old.nw, -old.rb, old.sig]) == -1
          best_at_j[st.key] = st
        end
      end
    end
  end
end
