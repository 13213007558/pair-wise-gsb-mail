# frozen_string_literal: true

require 'set'
require 'mail/arc/errors'
require 'mail/arc/tag_list'
require 'mail/arc/canonicalization'
require 'mail/arc/cryptography'
require 'mail/arc/result'

module Mail
  module ARC
    class Chain
      AAR = 'ARC-Authentication-Results'
      AMS = 'ARC-Message-Signature'
      AS = 'ARC-Seal'

      AMS_TAG_ORDER = %w[i a b bh c d h s t].freeze
      AS_TAG_ORDER = %w[i cv a b d h s t].freeze

      def self.verify(message, key_fetcher = nil)
        new(message, key_fetcher).verify
      end

      def self.seal(message, authentication_results:, domain:, selector:, key_fetcher: nil, private_key: nil, **options)
        new(message, key_fetcher, signing_key: private_key).seal(
          authentication_results, domain, selector, **options
        )
      end

      def initialize(message, key_fetcher = nil, signing_key: nil)
        @message = message
        @key_fetcher = key_fetcher
        @signing_key = signing_key
      end

      def verify
        return VerificationResult.new([], status: :none) if instances.empty?

        hops = instances.sort.map { |instance| verify_hop(instance) }
        break_hop = hops.find(&:chain_break?)
        VerificationResult.new(
          hops,
          status: break_hop ? :fail : :pass,
          failure_instance: break_hop&.instance
        )
      end

      def seal(authentication_results, domain, selector, cv: nil)
        authentication_results = authentication_results.to_s.strip
        raise ArgumentError, 'authentication_results is required' if authentication_results.empty?

        @message.ready_to_send!
        instance = (instances.max || 0) + 1
        @message.ready_to_send!
        incoming = verify_for_sealing
        claimed_cv = cv || (instance == 1 ? 'none' : (incoming.pass? ? 'pass' : 'fail'))

        prepend_field(AAR, "i=#{instance}; #{authentication_results}")

        _header_text, body_text = Canonicalization.message_parts(@message)
        ams_tags = {
          'i' => instance.to_s,
          'a' => Cryptography::ALGORITHM,
          'b' => '',
          'bh' => Cryptography.body_hash(body_text.to_s),
          'c' => 'relaxed/relaxed',
          'd' => domain,
          'h' => ams_header_names(instance).join(':'),
          's' => selector,
          't' => Time.now.to_i.to_s
        }
        ams_field = prepend_field(AMS, TagList.new(ams_tags).render(AMS_TAG_ORDER))
        update_tags(ams_field) do |tags|
          tags['b'] = sign(domain, selector, instance, :message_signature, ams_canonical(instance))
        end

        as_tags = {
          'i' => instance.to_s,
          'cv' => claimed_cv,
          'a' => Cryptography::ALGORITHM,
          'b' => '',
          'd' => domain,
          'h' => seal_header_names(instance).join(':'),
          's' => selector,
          't' => Time.now.to_i.to_s
        }
        as_field = prepend_field(AS, TagList.new(as_tags).render(AS_TAG_ORDER))
        update_tags(as_field) do |tags|
          tags['b'] = sign(domain, selector, instance, :seal, as_canonical(instance))
        end

        @message
      end

      private

      def verify_for_sealing
        result = verify
        return result if result.pass?

        chain_break = result.find { |hop| hop.seal_status == :fail || hop.header_status == :fail }
        VerificationResult.new(
          result.instances,
          status: chain_break ? :fail : :pass,
          failure_instance: chain_break&.instance
        )
      end

      def verify_hop(instance)
        latest = instance == instances.max
        as_field = required_field(AS, instance)
        ams_field = required_field(AMS, instance)
        aar_field = required_field(AAR, instance)
        as_tags = parse_tags(as_field)
        ams_tags = parse_tags(ams_field)

        seal_status, seal_error = verify_cryptographic_signature(as_tags, instance, :seal)
        if latest
          header_status, body_status, ams_error = verify_message_signature(ams_tags, instance, latest)
        else
          header_status = body_status = message_signature_status = :superseded
          ams_error = nil
        end
        claimed_status = as_tags['cv']

        unless %w[none pass fail].include?(claimed_status)
          seal_status = :fail
          seal_error = "invalid cv=#{claimed_status.inspect}"
        end
        if instance == 1 && claimed_status != 'none'
          seal_status = :fail
          seal_error = 'the first ARC seal must have cv=none'
        end
        if instance > 1 && claimed_status == 'none'
          seal_status = :fail
          seal_error = 'ARC seal cv must not be none after instance 1'
        end

        message_signature_status ||= header_status == :pass ? :pass : :fail
        hop_status = if latest
                       seal_status == :pass && message_signature_status == :pass && body_status == :pass ? :pass : :fail
                     else
                       seal_status == :pass ? :pass : :fail
                     end
        fields = latest ? :latest : (body_status == :superseded ? :superseded_body : :previous)

        HopResult.new(
          instance,
          fields,
          status: hop_status,
          authentication_results: aar_field.value.sub(/\Ai=#{instance}\s*;\s*/, ''),
          domain: as_tags['d'],
          selector: as_tags['s'],
          claimed_status: claimed_status,
          seal_status: seal_status,
          seal_error: seal_status == :pass ? nil : seal_error,
          message_signature_status: message_signature_status,
          message_signature_error: message_signature_status == :pass ? nil : ams_error,
          header_status: header_status,
          body_status: body_status
        )
      rescue => error
        malformed_hop(instance, error)
      end

      def verify_cryptographic_signature(tags, instance, kind)
        validate_required_tags!(tags, kind)
        validate_header_list!(tags, instance, kind)
        signature = tags.decoded_b
        canonical = kind == :seal ? as_canonical(instance) : ams_canonical(instance, tags)
        key = lookup_key(tags['d'], tags['s'], instance, kind, tags)
        valid = Cryptography.verify(key, signature, canonical, tags['a'])
        valid ? [:pass, nil] : [:fail, 'signature verification failed']
      rescue => error
        [:fail, error.message]
      end

      def verify_message_signature(tags, instance, latest)
        header_status, error = verify_cryptographic_signature(tags, instance, :message_signature)
        _header_text, body_text = Canonicalization.message_parts(@message)
        expected = Cryptography.body_hash(body_text.to_s, tags['a'])
        body_status = expected == tags['bh'] ? :pass : :fail
        [header_status, body_status, error]
      rescue => error
        [:fail, :fail, error.message]
      end

      def validate_required_tags!(tags, kind)
        names = kind == :seal ? %w[i a b d s cv] : %w[i a b bh c d s]
        names.each { |name| tags.fetch(name) }
      end

      def validate_header_list!(tags, instance, kind)
        expected = kind == :seal ? seal_header_names(instance) : ams_header_names(instance)
        actual = tags.fetch('h').to_s.split(':').map(&:downcase)
        return if kind == :message_signature && instance < instances.max
        raise MalformedHeader, 'ARC header list does not match the authenticated chain' unless actual == expected
      end

      def ams_canonical(instance, tags = nil)
        fields_for_ams(instance, tags).map do |field|
          value = field_value(field)
          value = with_blank_b(value, AMS_TAG_ORDER) if field.responsible_for?(AMS) && arc_instance(field) == instance
          Canonicalization.relaxed_header(field.name, value)
        end.join
      end

      def as_canonical(instance)
        fields_for_as(instance).map do |field|
          value = field_value(field)
          value = with_blank_b(value, AS_TAG_ORDER) if blank_seal?(field, instance)
          Canonicalization.relaxed_header(field.name, value)
        end.join
      end

      def field_value(field)
        field.field.respond_to?(:decoded) ? field.decoded : field.value
      end

      def fields_for_ams(instance, tags = nil)
        return build_ams_fields(instance) unless tags

        names = tags.fetch('h').split(':').map(&:downcase)
        queues = Hash.new { |hash, key| hash[key] = fields(display_name(key)).reverse }
        names.each_with_object([]) do |name, selected|
          occurrence = selected.count { |item| item.responsible_for?(name) }
          field = consume_ams_field(queues, name, instance, occurrence)
          raise MalformedHeader, "missing signed header #{name}" unless field

          selected << field
        end
      end

      def build_ams_fields(instance)
        aar = fields(AAR)
        seals = fields(AS)
        messages = fields(AMS)
        selected = []
        selected.concat(aar.select { |field| arc_instance(field) == instance })
        selected.concat(aar.select { |field| arc_instance(field) < instance }.sort_by { |field| -arc_instance(field) })
        selected.concat(seals.select { |field| arc_instance(field) < instance }.sort_by { |field| -arc_instance(field) })
        selected.concat(messages.select { |field| arc_instance(field) < instance }.sort_by { |field| -arc_instance(field) })
        selected.concat(normal_fields.reverse)
        selected.concat(messages.select { |field| arc_instance(field) == instance })
        selected
      end

      def consume_ams_field(queues, name, current_instance, occurrence)
        case name.to_s.downcase
        when AAR.downcase then select_by_occurrence(queues[AAR].sort_by { |field| -arc_instance(field) }, occurrence)
        when AS.downcase then select_by_occurrence(queues[AS].reject { |field| arc_instance(field) == current_instance }, occurrence)
        when AMS.downcase then select_ams_occurrence(queues[AMS], occurrence, current_instance)
        else queues[name].shift
        end
      end

      def select_by_occurrence(collection, occurrence)
        collection.sort_by { |field| -arc_instance(field) }[occurrence]
      end

      def select_ams_occurrence(collection, occurrence, current_instance)
        previous = collection.reject { |field| arc_instance(field) == current_instance }
        if previous.length == occurrence
          collection.detect { |field| arc_instance(field) == current_instance }
        else
          select_by_occurrence(previous, occurrence)
        end
      end

      def name_for(name)
        normalized = name.to_s.downcase
        return normalized if [AAR, AMS, AS].map(&:downcase).include?(normalized)

        canonical = Mail::Field::FIELD_NAME_MAP.fetch(normalized, normalized)
        canonical.downcase
      end

      def display_name(name)
        Mail::Field::FIELD_NAME_MAP.fetch(name, name)
      end

      def fields_for_as(instance)
        current = fields(AS).select { |field| arc_instance(field) == instance }
        previous = fields(AS).select { |field| arc_instance(field) < instance }.sort_by { |field| -arc_instance(field) }
        fields(AMS).select { |field| arc_instance(field) == instance } + current + previous
      end

      def blank_seal?(field, current_instance)
        field.responsible_for?(AS) && arc_instance(field) == current_instance
      end

      def ams_header_names(instance)
        names = []
        names.concat([AAR] * instance)
        names.concat([AS] * (instance - 1))
        names.concat([AMS] * (instance - 1))
        names.concat(normal_fields.reverse.map(&:name))
        names << AMS
        names.map(&:downcase)
      end

      def seal_header_names(instance)
        [AMS, AS, *Array.new(instance - 1, AS)].map(&:downcase)
      end

      def normal_fields
        @message.header.fields.reject { |field| arc_field?(field) }
      end

      def fields(name)
        @message.header.fields.select { |field| field.responsible_for?(name) }
      end

      def required_field(name, instance)
        field = fields(name).detect { |candidate| arc_instance(candidate) == instance }
        raise MalformedHeader, "missing #{name} for i=#{instance}" unless field

        field
      end

      def instances
        @instances ||= begin
          grouped = [AAR, AMS, AS].each_with_object({}) do |name, counts|
            fields(name).each do |field|
              instance = arc_instance(field)
              counts[instance] ||= 0
              counts[instance] += 1
            end
          end
          values = grouped.keys.select { |instance| grouped[instance] == 3 }.sort
          raise MalformedHeader, 'ARC instances must be contiguous and begin at 1' unless values == (1..(values.max || 0)).to_a

          values
        end
      end

      def parse_tags(field)
        TagList.parse(field.value)
      end

      def arc_instance(field)
        value = parse_tags(field)['i']
        raise MalformedHeader, "#{field.name} has an invalid i tag" unless /\A[0-9]+\z/.match?(value.to_s)

        Integer(value, 10)
      end

      def with_blank_b(value, order)
        tags = TagList.parse(value)
        tags['b'] = ''
        tags.render(order)
      end

      def arc_field?(field)
        [AAR, AMS, AS].any? { |name| field.responsible_for?(name) }
      end

      def prepend_field(name, value)
        field = Mail::Field.new(name, value)
        @message.header.fields.unshift(field)
        @instances = nil
        field
      end

      def update_tags(field)
        tags = parse_tags(field)
        yield tags
        order = field.responsible_for?(AS) ? AS_TAG_ORDER : AMS_TAG_ORDER
        field.value = tags.render(order)
        field
      end

      def lookup_key(domain, selector, instance, kind, tags)
        Cryptography.public_key(call_fetcher(domain, selector, instance, kind, tags, false))
      end

      def sign(domain, selector, instance, kind, canonical)
        key = @signing_key || call_fetcher(domain, selector, instance, kind, nil, true)
        Cryptography.sign(key, canonical, Cryptography::ALGORITHM)
      end

      def call_fetcher(domain, selector, instance, kind, tags, signing)
        raise MissingKey, 'an ARC key callback is required' unless @key_fetcher

        context = { i: instance, instance: instance, kind: kind, signing: signing, tags: tags&.to_h }
        args = [domain, selector, context]
        arity = @key_fetcher.respond_to?(:arity) ? @key_fetcher.arity : args.size
        args = args.first(arity) if arity >= 0 && arity <= args.size
        args = args.first([arity.abs, args.size].min) if arity < 0
        @key_fetcher.call(*args)
      end

      def malformed_hop(instance, error)
        HopResult.new(
          instance,
          :malformed,
          status: :fail,
          seal_status: :fail,
          seal_error: error.message,
          message_signature_status: :fail,
          message_signature_error: error.message,
          header_status: :fail,
          body_status: :fail,
          error: error.message
        )
      end
    end
  end
end
