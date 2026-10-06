# frozen_string_literal: true

module Mail
  module ARC
    class Chain
      FIELD_TO_ACCESSOR = {
        'ARC-Authentication-Results' => :aar,
        'ARC-Message-Signature' => :ams,
        'ARC-Seal' => :as
      }.freeze

      def self.results(message)
        grouped = {}
        message.header.fields.each do |field|
          next unless FIELD_TO_ACCESSOR.key?(field.name)
          instance = Tags.instance(field.value)
          next unless instance
          grouped[instance] ||= {}
          grouped[instance][field.name] = field
        end

        grouped.keys.sort.map do |instance|
          values = grouped[instance]
          result = InstanceResult.new(
            instance,
            aar: values['ARC-Authentication-Results'],
            ams: values['ARC-Message-Signature'],
            as: values['ARC-Seal']
          )
          mark_duplicates(message, instance, result)
          result
        end
      end

      def self.mark_duplicates(message, instance, result)
        FIELD_TO_ACCESSOR.each do |name, accessor|
          count = message.header.fields.count do |field|
            field.responsible_for?(name) && Tags.instance(field.value) == instance
          end
          result.add_error(name, 'duplicate ARC set field') if count > 1
        end
      end

      def self.next_instance(message)
        instances(message).max.to_i + 1
      end

      def self.instances(message)
        message.header.fields.map { |field| Tags.instance(field.value) if arc_field?(field.name) }.compact.uniq
      end

      def self.arc_field?(name)
        FIELD_TO_ACCESSOR.key?(name)
      end
    end
  end
end
