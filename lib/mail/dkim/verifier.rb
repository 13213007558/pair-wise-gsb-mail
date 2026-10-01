# frozen_string_literal: true
require 'openssl'
require 'base64'
require 'digest'
require 'time'

module Mail
  module DKIM
    # Verifies DKIM-Signature header fields on a received message per
    # RFC 6371 section 6.  Verification is performed against the exact
    # received bytes; every signature found gets an independent Result,
    # so a failing signature can never erase the verdict of another.
    class Verifier
      SIGNATURE_HEADER = 'dkim-signature'

      def initialize(resolver:, now: Time.now)
        @resolver = Resolver::ResolvDns.coerce(resolver)
        @now = now
      end

      def verify(message)
        raw =
          if message.respond_to?(:raw_source) && message.raw_source && !message.raw_source.empty?
            message.raw_source
          elsif message.respond_to?(:encoded)
            message.encoded
          else
            message.to_s
          end
        verify_raw(raw)
      end

      def verify_raw(raw)
        raw = Canonicalization.to_crlf(raw)
        header_block, body = Canonicalization.split_message(raw)
        headers = Canonicalization.parse_headers(header_block)

        signatures = headers.each_index.select do |i|
          headers[i][0].downcase == SIGNATURE_HEADER
        end

        results = VerificationResult.new
        return results if signatures.empty?

        signatures.each do |index|
          results << verify_signature(headers, index, body)
        end
        results
      end

      private

      def verify_signature(headers, index, body)
        result = Result.new
        _, sig_value = headers[index]

        tags =
          begin
            TagList.parse(Canonicalization.unfold(sig_value), base64_tags: %w[b bh])
          rescue TagList::ParseError => e
            result.fail!(:signature_syntax_error, e)
            return result
          end

        populate_result(result, tags)

        # Required tags (3.2 / 6.1.1).
        unless %w[v a b bh d h s].all? { |t| tags.key?(t) }
          result.fail!(:signature_missing_tag)
          return result
        end

        unless tags['v'] == 'DKIM1'
          result.fail!(:incompatible_version)
          return result
        end

        unless tags['a'] == 'rsa-sha256'
          result.fail!(:unsupported_algorithm)
          return result
        end

        if tags['b'].empty?
          result.fail!(:signature_missing)
          return result
        end

        # Canonicalization.
        header_canon, body_canon = parse_canon(tags['c'])
        unless [:simple, :relaxed].include?(header_canon) &&
               [:simple, :relaxed].include?(body_canon)
          result.fail!(:unsupported_canonicalization)
          return result
        end

        # Timestamps (t=/x=) are advisory; x= is enforced once present.
        timestamp, expiration = parse_times(tags, result)
        return result if result.fail?
        if expiration && expiration < @now
          result.fail!(:signature_expired)
          return result
        end
        if timestamp && timestamp > @now + 1
          result.warnings << 't= timestamp is in the future'
        end

        # Signed header selection.
        signed_names = parse_header_names(tags['h'])
        unless signed_names.map(&:downcase).include?('from')
          result.fail!(:from_not_signed)
          return result
        end

        # l= tag.
        body_length = parse_length(tags['l'], result)
        return result if result.fail?

        # DNS lookup of the public key.
        query_name = "#{tags['s']}._domainkey.#{tags['d']}"
        record_text =
          begin
            @resolver.call(query_name)
          rescue => e
            result.fail!(:key_dns_error, e)
            return result
          end

        if record_text.nil?
          result.fail!(:key_unknown)
          return result
        end

        record = KeyRecord.new(record_text)
        result.key_record = record
        unless record.valid?
          result.fail!(:key_record_syntax_error, record.error)
          return result
        end

        unless record.rsa?
          result.fail!(:incompatible_key_type)
          return result
        end

        if record.revoked?
          result.fail!(:key_revoked)
          return result
        end

        public_key = record.public_key
        unless public_key
          result.fail!(:public_key_invalid)
          return result
        end

        # Body hash check (6.1.2 step 6).
        canonical_body = Canonicalization.canonical_body(body_canon, body, body_length)
        if body_length && canonical_body.bytesize < body_length
          result.fail!(:body_length_too_short)
          return result
        end
        actual_bh = [OpenSSL::Digest::SHA256.digest(canonical_body)].pack('m0')
        unless fixed_time_equal?(actual_bh, tags['bh'])
          result.fail!(:body_hash_mismatch)
          return result
        end
        if body_length
          remainder = body.to_s.byteslice(canonical_body.bytesize) || ''
          unless remainder.empty? || remainder.match?(/\A\r\n*\z/n)
            # Non empty body text appeared after the signed l= count;
            # allowed by RFC 6376 but worth surfacing to callers.
            result.warnings << 'message added non-empty content after the signed l= body length'
          end
        end

        # Header hash + signature check (6.1.3).
        #
        # Ordinary headers appearing after the DKIM-Signature remain
        # eligible (signatures use trace-header placement), and an
        # earlier DKIM-Signature can be covered by a later one
        # (countersignatures).  The header field being verified never
        # covers itself; RFC 5322 ordering plus the bottom-up instance
        # selection in Canonicalization#canonical_headers then resolves
        # duplicate instances (3.7 / 5.4.2).
        eligible = headers.dup
        eligible.delete_at(index)
        header_data =
          Canonicalization.canonical_headers(header_canon, eligible, signed_names) <<
          Canonicalization.signature_header(header_canon, sig_value)

        begin
          signature = TagList.decode_base64(tags['b'])
        rescue TagList::ParseError => e
          result.fail!(:signature_syntax_error, e)
          return result
        end

        verified =
          begin
            public_key.verify(OpenSSL::Digest::SHA256.new, signature, header_data)
          rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error => e
            result.fail!(:signature_verification_error, e)
            return result
          end

        if verified
          result.pass!
        else
          result.fail!(:signature_mismatch)
        end
        result
      end

      def populate_result(result, tags)
        result.domain = tags['d']
        result.selector = tags['s']
        result.identity = tags['i'] || "@#{tags['d']}"
        result.algorithm = tags['a']
        result.header_canonicalization, result.body_canonicalization = parse_canon(tags['c'])
        result.signed_headers = tags.key?('h') ? parse_header_names(tags['h']) : nil
        result.body_length = tags['l']&.match?(/\A[0-9]+\z/n) ? Integer(tags['l']) : nil
      end

      def parse_canon(value)
        value ||= 'simple/simple'
        header, body = value.split('/')
        [
          (header || 'simple').downcase.to_sym,
          (body || header || 'simple').downcase.to_sym
        ]
      end

      def parse_header_names(value)
        value.split(':').map(&:strip).reject(&:empty?)
      end

      def parse_length(value, result)
        return nil unless value
        unless value.match?(/\A[0-9]+\z/n)
          result.fail!(:invalid_length_tag)
          return
        end
        Integer(value)
      end

      def parse_times(tags, result)
        t = parse_time_tag(tags['t'], 't', result)
        return if result.fail?
        x = parse_time_tag(tags['x'], 'x', result)
        return if result.fail?
        result.timestamp = t
        result.expiration = x
        [t, x]
      end

      def parse_time_tag(value, name, result)
        return nil if value.nil?
        unless value.match?(/\A[0-9]+\z/n)
          result.fail!(:invalid_time_tag)
          return
        end
        Time.at(Integer(value))
      end

      def fixed_time_equal?(a, b)
        return false unless a.bytesize == b.bytesize
        l = a.unpack("C#{a.bytesize}")
        r = 0
        b.each_byte { |byte| r |= byte ^ l.shift }
        r == 0
      end
    end
  end
end
