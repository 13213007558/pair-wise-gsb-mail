# frozen_string_literal: true

module Mail
  module ARC
    class Verifier
      def initialize(message, key_finder, allow_modified_body: false)
        @message = message
        @key_finder = key_finder
        @allow_modified_body = allow_modified_body
        @canonicalization = Canonicalization.new(message)
      end

      def verify
        results = Chain.results(@message)
        expected = (1..results.map(&:i).max.to_i).to_a
        if results.map(&:i) != expected
          missing = (expected - results.map(&:i)).first
          placeholder = InstanceResult.new(missing)
          placeholder.add_error('ARC-Authentication-Results', 'missing ARC set')
          results << placeholder
        end

        results.sort_by(&:i).each { |result| verify_instance(result) }
        Result.new(results)
      end

      private

      def verify_instance(result)
        verify_aar(result)
        result.add_error('ARC-Message-Signature', 'missing message signature') unless result.ams
        result.add_error('ARC-Seal', 'missing seal') unless result.as
        verify_ams(result)
        verify_as(result)
      end

      def verify_aar(result)
        return unless result.aar
        tags = result.aar_tags
        authserv_id = tags['authserv-id'] || result.aar.value.to_s.split(';', 2).first.to_s.strip
        if tags['i'].to_s != result.i.to_s || authserv_id.empty?
          result.add_error('ARC-Authentication-Results', 'invalid authentication results header')
        end
      end

      def verify_ams(result)
        return unless result.ams
        tags = result.ams_tags
        required = %w[i a b bh d h s]
        missing = required.reject { |name| !tags[name].to_s.empty? }
        unless missing.empty?
          result.add_error('ARC-Message-Signature', "missing #{missing.join(', ')} tag")
          return
        end
        unless tags['i'] == result.i.to_s && tags['a'] == ALGORITHM &&
                 (tags['c'].to_s.empty? || tags['c'] == 'relaxed/relaxed')
          result.add_error('ARC-Message-Signature', 'unsupported signature algorithm or canonicalization')
          return
        end

        header_names = tags['h'].to_s.split(':').reject(&:empty?)
        unless header_names.any?
          result.add_error('ARC-Message-Signature', 'empty signed header list')
          return
        end
        expected_body_hash = Base64.strict_encode64(OpenSSL::Digest.digest(DIGEST, @canonicalization.body))
        body_valid = secure_compare(tags['bh'].to_s.gsub(/\s+/, ''), expected_body_hash)
        prior_instance = result.i < Chain.instances(@message).max.to_i
        verify_chain_headers(result, header_names)
        return if result.errors.any? { |error| error[:field] == 'ARC-Message-Signature' }
        unless body_valid
          unless @allow_modified_body || prior_instance
            result.add_error('ARC-Message-Signature', 'body was modified after this signature')
            return
          end
        end
        signed_data = @canonicalization.headers(
          header_names,
          signer_name: 'ARC-Message-Signature',
          signer_value: result.ams.value
        )
        if valid_signature?(tags, signed_data)
          result.instance_variable_set(:@body_modified, true) if !body_valid && prior_instance
        else
          result.add_error('ARC-Message-Signature', 'signature verification failed')
        end
      rescue ArgumentError
        result.add_error('ARC-Message-Signature', 'malformed signature tag')
      end

      def verify_chain_headers(result, header_names)
        return unless result.i > 1
        normalized_names = header_names.map(&:downcase)
        %w[arc-authentication-results arc-message-signature arc-seal].each do |name|
          unless normalized_names.include?(name)
            result.add_error('ARC-Message-Signature', "missing signed #{name} from prior instance")
          end
        end
      end

      def verify_as(result)
        return unless result.as
        tags = result.as_tags
        required = %w[i a b cv d s]
        missing = required.reject { |name| !tags[name].to_s.empty? }
        unless missing.empty?
          result.add_error('ARC-Seal', "missing #{missing.join(', ')} tag")
          return
        end

        expected_cv = result.i == 1 ? 'none' : 'pass'
        unless tags['i'] == result.i.to_s && tags['a'] == ALGORITHM && tags['cv'] == expected_cv
          result.add_error('ARC-Seal', 'invalid seal metadata')
        end

        signed_data = @canonicalization.signature('ARC-Seal', result.as.value) +
          if result.ams
            @canonicalization.signature('ARC-Message-Signature', result.ams.value)
          else
            ''
          end
        unless valid_signature?(tags, signed_data)
          result.add_error('ARC-Seal', 'signature verification failed')
        end
      rescue ArgumentError
        result.add_error('ARC-Seal', 'malformed seal tag')
      end

      def valid_signature?(tags, data)
        key = resolve_key(tags['d'], tags['s'])
        return false unless key
        signature = Tags.signature(tags['b'] ? "b=#{tags['b']}" : '')
        return false if signature.nil? || signature.empty?
        key.verify(OpenSSL::Digest.new(DIGEST), signature, data)
      rescue StandardError
        false
      end

      def resolve_key(domain, selector)
        key = @key_finder.call(domain, selector)
        key = OpenSSL::PKey.read(key) if key.is_a?(String)
        key
      rescue StandardError
        nil
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize
        left.each_byte.zip(right.each_byte).reduce(0) { |result, (a, b)| result | (a ^ b) } == 0
      end
    end
  end
end
