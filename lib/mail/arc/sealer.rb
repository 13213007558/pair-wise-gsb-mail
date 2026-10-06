# frozen_string_literal: true

module Mail
  module ARC
    class Sealer
      ARC_FIELD_NAMES = [
        'ARC-Authentication-Results',
        'ARC-Seal',
        'ARC-Message-Signature'
      ].freeze

      def initialize(message, options)
        @message = message
        @authentication_results = options.fetch(:authentication_results)
        @domain = options.fetch(:domain)
        @selector = options.fetch(:selector)
        @key_finder = options.fetch(:key_finder)
        @time = options.fetch(:time, Time.now.to_i)
      end

      def append
        yield @message if block_given?
        @message.encoded
        existing = Verifier.new(@message, @key_finder, allow_modified_body: true).verify
        unless existing.status == :none || existing.valid_for_seal?
          raise ArgumentError, "cannot append ARC set to invalid chain at instance #{existing.break&.fetch(:instance)}"
        end

        instance = Chain.next_instance(@message)
        previous_cv = instance == 1 ? 'none' : 'pass'
        add_field('ARC-Authentication-Results', authentication_results(instance))

        body_hash = Base64.strict_encode64(OpenSSL::Digest.digest(DIGEST, Canonicalization.new(@message).body))
        header_names = signed_header_names(instance)
        unsigned_ams = Tags.dump(
          'i' => instance,
          'a' => ALGORITHM,
          'b' => '',
          'bh' => body_hash,
          'c' => 'relaxed/relaxed',
          'd' => @domain,
          'h' => header_names.join(':'),
          's' => @selector,
          't' => @time
        )
        ams_data = Canonicalization.new(@message).headers(
          header_names,
          signer_name: 'ARC-Message-Signature',
          signer_value: unsigned_ams
        )
        ams_value = sign(unsigned_ams, ams_data)
        add_field('ARC-Message-Signature', ams_value)

        unsigned_as = Tags.dump(
          'i' => instance,
          'a' => ALGORITHM,
          'b' => '',
          'cv' => previous_cv,
          'd' => @domain,
          's' => @selector,
          't' => @time
        )
        seal_canonicalization = Canonicalization.new(@message)
        as_data = seal_canonicalization.signature('ARC-Seal', unsigned_as) +
          seal_canonicalization.signature('ARC-Message-Signature', ams_value)
        as_value = sign(unsigned_as, as_data)
        add_field('ARC-Seal', as_value)

        @message
      end

      private

      def signed_header_names(instance)
        @message.header.fields.select do |field|
          !ARC_FIELD_NAMES.include?(field.name) || field_instance(field).to_i < instance
        end
        .map(&:name)
      end

      def field_instance(field)
        field && Tags.instance(field.value)
      end

      def authentication_results(instance)
        value = @authentication_results.to_s.strip
        Tags.parse(value)['i'] ? value : "i=#{instance}; #{value}"
      end

      def add_field(name, value)
        field = Mail::Field.new(name, value)
        field.instance_variable_set(:@field_order_id, field_order(name, value))
        @message.header.fields.unshift(field)
      end

      def field_order(name, value)
        kind =
          case name
          when 'ARC-Seal' then 0
          when 'ARC-Message-Signature' then 1
          else 2
          end
        -300 - (Tags.instance(value).to_i * 3) + kind
      end

      def sign(template, data)
        signature = private_key.sign(OpenSSL::Digest.new(DIGEST), data)
        encoded = Base64.strict_encode64(signature).gsub(/.{1,64}/, '\0').strip
        template.sub(/b=/, "b=#{encoded}")
      end

      def private_key
        key = resolve_key
        key = OpenSSL::PKey.read(key) if key.is_a?(String)
        raise ArgumentError, 'ARC signing key must be an RSA private key' unless key.is_a?(OpenSSL::PKey::RSA)
        key
      rescue OpenSSL::PKey::PKeyError, ArgumentError => error
        raise ArgumentError, "unable to load ARC signing key: #{error.message}"
      end

      def resolve_key
        if @key_finder.respond_to?(:call)
          if @key_finder.respond_to?(:arity) && @key_finder.arity == 1
            @key_finder.call(domain: @domain, selector: @selector)
          else
            @key_finder.call(@domain, @selector)
          end
        else
          @key_finder
        end
      end
    end
  end
end
