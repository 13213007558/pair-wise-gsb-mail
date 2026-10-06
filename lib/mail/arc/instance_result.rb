# frozen_string_literal: true

module Mail
  module ARC
    class InstanceResult
      attr_reader :i, :aar, :ams, :as, :errors

      def initialize(i, aar: nil, ams: nil, as: nil)
        @i = i
        @aar = aar
        @ams = ams
        @as = as
        @errors = []
      end

      def add_error(field, message)
        @errors << { instance: i, field: field, message: message }
      end

      def aar_tags
        aar ? Tags.parse(aar.value) : {}
      end

      def ams_tags
        ams ? Tags.parse(ams.value) : {}
      end

      def as_tags
        as ? Tags.parse(as.value) : {}
      end
      alias_method :seal, :as_tags

      def aar_status
        status_for('ARC-Authentication-Results')
      end

      def ams_status
        present = status_for('ARC-Message-Signature')
        return :missing if present == :missing
        return :invalid if present == :invalid
        @body_modified ? :body_modified : present
      end

      def as_status
        status_for('ARC-Seal')
      end

      def status
        return :missing if i.nil?
        return :fail if component_statuses.include?(:invalid)
        return :body_modified if aar_status == :valid && as_status == :valid && ams_status == :body_modified
        component_statuses.include?(:missing) ? :fail : :pass
      end

      def valid_for_seal?
        aar_status == :valid && as_status == :valid && [:valid, :body_modified].include?(ams_status)
      end

      def to_h
        {
          i: i,
          status: status,
          aar_status: aar_status,
          ams_status: ams_status,
          as_status: as_status,
          errors: errors
        }
      end

      private

      def component_statuses
        [aar_status, ams_status, as_status]
      end

      def status_for(field)
        return :missing unless field_present?(field)
        @errors.any? { |error| error[:field] == field } ? :invalid : :valid
      end

      def field_present?(field)
        case field
        when 'ARC-Authentication-Results' then !aar.nil?
        when 'ARC-Message-Signature' then !ams.nil?
        when 'ARC-Seal' then !as.nil?
        end
      end
    end
  end
end
