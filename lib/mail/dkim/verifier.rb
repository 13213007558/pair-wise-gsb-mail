# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'time'

module Mail
  class DKIM
    # Verifies the RFC 6376 DKIM-Signature header fields on a received
    # message.
    #
    # Verification always works from the *original received bytes*: pass the
    # raw message string rather than a re-encoded Mail::Message.
    #
    #   verifier = Mail::DKIM::Verifier.new(resolver: ->(name) { txt_data })
    #   results  = verifier.verify(raw_mail)
    #   results.any?(&:pass?)
    #
    # Every signature found is evaluated independently; one failing
    # signature never erases the independent result of another.
    class Verifier
      SIGNATURE_HEADER = 'dkim-signature'.freeze
      SUPPORTED_ALGORITHM = 'rsa-sha256'.freeze

      def initialize(resolver: nil)
        @resolver = resolver || DNS::Resolver.new
      end

      # Verify all signatures on a raw message (String) or Mail::Message.
      # Returns an Array of Result objects, one per DKIM-Signature field, in
      # the order the fields appeared.
      def verify(message)
        raw = message.is_a?(String) ? message : message.encoded
        verify_raw(raw)
      end

      # Returns true if at least one signature verifies successfully.
      def valid?(message)
        verify(message).any?(&:pass?)
      end

      def verify_raw(raw)
        raw = raw.to_s
        header_block, body = Canonicalization.split_message(raw)
        fields = Canonicalization.parse_headers(header_block)

        signature_fields = fields.select { |name, _| name.downcase == SIGNATURE_HEADER }
        dns_cache = {}

        signature_fields.map do |_, unfolded_value|
          verify_signature(fields, body, unfolded_value, dns_cache)
        end
      end

      private

      def verify_signature(fields, body, unfolded_value, dns_cache)
        tags =
          begin
            TagList.parse(unfolded_value)
          rescue TagList::DuplicateTag => e
            return Result.new(status: :permerror, reason: e.message,
                              raw_field: unfolded_value)
          end
        result = Result.new(
          status: :permerror,
          tags: tags,
          raw_field: unfolded_value,
          domain: tags['d'],
          selector: tags['s'],
          identity: tags['i']
        )

        validate_required_tags!(tags)
        validate_version!(tags)
        validate_algorithm!(tags)
        validate_query!(tags)
        validate_signed_headers!(tags)
        validate_identity!(result, tags)
        check_expiration!(tags)

        header_alg, body_alg =
          begin
            Canonicalization.algorithms(tags['c'])
          rescue ArgumentError => e
            raise PermanentError, e.message
          end
        result.header_algorithm = header_alg
        result.body_algorithm = body_alg

        public_key = resolve_public_key(result, tags, dns_cache)

        validate_public_key!(tags, public_key)
        verify_body_hash!(result, tags, body, body_alg)
        verify_signature_value!(result, tags, fields, public_key, header_alg)

        result
      rescue PermanentError => e
        result.status = :permerror
        result.reason = e.message
        result
      rescue TemporalError => e
        result.status = :temperror
        result.reason = e.message
        result
      rescue NeutralError => e
        result.status = :neutral
        result.reason = e.message
        result
      rescue ArgumentError => e
        result.status = :permerror
        result.reason = e.message
        result
      end

      def validate_required_tags!(tags)
        %w[v a b bh d h s].each do |name|
          if tags[name].nil?
            raise PermanentError, "missing required tag: #{name}="
          end
        end
      end

      def validate_version!(tags)
        # v= is REQUIRED and must be 1 (RFC 6376 3.2).
        raise PermanentError, "unsupported DKIM version: #{tags['v'].inspect}" unless tags['v'] == '1'
      end

      def validate_algorithm!(tags)
        unless tags['a'] == SUPPORTED_ALGORITHM
          raise NeutralError, "unsupported algorithm: #{tags['a'].inspect}"
        end
      end

      def validate_query!(tags)
        q = tags['q']
        return if q.nil? || q.split(':').include?('dns/txt')
        raise NeutralError, "unsupported query method: #{q.inspect}"
      end

      def validate_signed_headers!(tags)
        names = tag_list_names(tags['h'])
        raise PermanentError, 'empty h= tag list' if names.empty?
        unless names.include?('from')
          raise PermanentError, 'From header is not signed (RFC 6376 5.4.1)'
        end
      end

      def tag_list_names(value)
        value.split(':').map { |n| n.gsub(/\s+/, '').downcase }.reject(&:empty?)
      end

      def validate_identity!(result, tags)
        identity = tags['i'] || "@#{tags['d']}"
        result.identity = identity
        domain = tags['d'].to_s.downcase
        # i= is an "local-part@domain" address; the local-part may be empty
        # (the default value "@d" has one). Split on the final @ so quoted
        # local-parts containing @ are handled reasonably.
        at = identity.rindex('@')
        raise PermanentError, "invalid AUID (missing @): #{identity.inspect}" unless at
        local_part = identity[0, at]
        id_domain = identity[(at + 1)..-1].to_s.downcase
        unless id_domain == domain || id_domain.end_with?(".#{domain}")
          raise PermanentError,
                "AUID #{identity.inspect} domain does not match SDID #{domain.inspect}"
        end
        result.tags['_local_part'] = local_part
      end

      def check_expiration!(tags)
        if tags['x']
          x = integer_tag(tags['x'])
          raise PermanentError, 'invalid x= expiration tag' unless x
          if Time.now.to_i > x
            raise PermanentError, "signature expired at x=#{x}"
          end
        end
        if tags['t'] && tags['x']
          t = integer_tag(tags['t'])
          x = integer_tag(tags['x'])
          if t && x && x < t
            raise PermanentError, 'x= (expiration) precedes t= (signature time)'
          end
        end
      end

      def integer_tag(value)
        value =~ /\A\d+\z/ ? value.to_i : nil
      end

      def resolve_public_key(result, tags, dns_cache)
        name = DNS.record_name(tags['s'], tags['d'])
        record =
          if dns_cache.key?(name)
            dns_cache[name]
          else
            begin
              dns_cache[name] = DNS.fetch(tags['s'], tags['d'], @resolver)
            rescue => e
              raise TemporalError, "DNS lookup failed for #{name}: #{e.class}: #{e.message}"
            end
            dns_cache[name]
          end

        if record.nil? || record.strip.empty?
          raise TemporalError, "no DKIM public key TXT record at #{name}"
        end

        key_tags = TagList.parse(record, on_duplicate: :keep_first)
        result.tags = result.tags.merge('_key' => key_tags)

        if key_tags['k'] && key_tags['k'].downcase != 'rsa'
          raise NeutralError, "unsupported key type: #{key_tags['k'].inspect}"
        end
        if key_tags['p'].nil?
          raise PermanentError, "key for #{tags['s']}._domainkey.#{tags['d']} has been revoked (p= empty/absent)"
        end
        if key_tags['p'].gsub(/\s+/, '').empty?
          raise PermanentError, "key for #{name} has been revoked"
        end

        check_granularity!(key_tags, result.identity)

        begin
          key = DNS.public_key(key_tags['p'])
        rescue => e
          raise PermanentError, "cannot parse public key: #{e.class}: #{e.message}"
        end
        key
      end

      # g= granularity restricts which local-parts of i= may use the key.
      def check_granularity!(key_tags, identity)
        g = key_tags['g']
        return if g.nil?
        at = identity.to_s.rindex('@') || identity.to_s.length
        local_part = identity.to_s[0, at]
        pattern = g.gsub(/[.+$|{}()\[\]\\^]/) { |c| "\\#{c}" }.gsub('*', '.*')
        unless /\A#{pattern}\z/.match?(local_part)
          raise PermanentError,
                "identity local-part #{local_part.inspect} does not match g=#{g.inspect}"
        end
      end

      def validate_public_key!(tags, key)
        unless key.is_a?(OpenSSL::PKey::RSA)
          raise PermanentError, "public key is not RSA: #{key.class}"
        end
        bits = key.n.num_bits
        if bits < DNS::MINIMUM_KEY_BITS
          raise PermanentError, "RSA key is too short: #{bits} < #{DNS::MINIMUM_KEY_BITS} bits"
        end
        sig_bytes = decode_b64!(tags['b'], 'b=')
        if key.n.num_bytes < sig_bytes.bytesize
          raise PermanentError, 'signature is longer than the RSA modulus'
        end
      end

      # Decode whitespace-tolerant base64 (RFC 2045 allows WSP inside DKIM
      # base64 values), rejecting malformed input.
      def decode_b64!(value, label)
        compact = value.to_s.gsub(/\s+/, '')
        Base64.strict_decode64(compact)
      rescue ArgumentError
        raise PermanentError, "#{label} is not valid base64"
      end

      def verify_body_hash!(result, tags, body, body_alg)
        length = tags['l'] ? integer_tag(tags['l']) : nil
        if tags['l'] && length.nil?
          raise PermanentError, "invalid l= tag: #{tags['l'].inspect}"
        end
        if length && length > body.bytesize
          raise PermanentError,
                "l=#{length} exceeds actual body length of #{body.bytesize}"
        end
        canonical = Canonicalization.canonical_body(body, body_alg, length)
        expected = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical))
        actual = tags['bh'].to_s.gsub(/\s+/, '')
        unless base64?(actual) && secure_compare(expected, actual)
          result.body_length = length
          raise PermanentError, 'body hash did not verify'
        end
        result.body_length = length
      end

      def base64?(value)
        value =~ /\A[A-Za-z0-9+\/]*={0,2}\z/ && (value.length % 4).zero?
      end

      def verify_signature_value!(result, tags, fields, public_key, header_alg)
        names = tag_list_names(tags['h'])
        header_data = Canonicalization.canonical_headers(
          fields, names, header_alg, signature_input(tags)
        )
        signature = decode_b64!(tags['b'], 'b=')
        verified =
          begin
            public_key.verify(OpenSSL::Digest::SHA256.new, signature, header_data)
          rescue OpenSSL::PKey::PKeyError => e
            raise PermanentError, "RSA verification error: #{e.message}"
          end
        unless verified
          raise PermanentError, 'RSA-SHA256 signature did not verify'
        end
        result.status = :pass
        result.reason = nil
      end

      # Rebuild the unfolded DKIM-Signature tag list with b= emptied, exactly
      # as it was signed (RFC 6376 3.7). The hash order of +tags+ preserves
      # the field order from TagList.parse and internal "_" tags are dropped.
      def signature_input(tags)
        parts = tags.reject { |k, _| k.start_with?('_') }.map do |name, value|
          value = '' if name == 'b'
          "#{name}=#{value}"
        end
        # Match the signer: one separating space follows the colon (stripped
        # by relaxed canonicalization, preserved by simple).
        " #{parts.join('; ')}"
      end

      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize
        l = a.unpack("C#{a.bytesize}")
        r = 0
        b.each_byte { |byte| r |= byte ^ l.shift }
        r.zero?
      end

      class PermanentError < StandardError; end
      class TemporalError < StandardError; end
      class NeutralError < StandardError; end
    end
  end
end
