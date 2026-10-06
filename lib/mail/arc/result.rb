# frozen_string_literal: true

module Mail
  module ARC
    class Result
      include Enumerable

      attr_reader :instances

      def initialize(instances = [])
        @instances = instances.sort_by(&:i)
      end

      def each(&block)
        instances.each(&block)
      end

      def [](index)
        instances[index]
      end

      def size
        instances.size
      end

      def status
        return :none if instances.empty?
        instances.all? { |instance| [:pass, :body_modified].include?(instance.status) } ? :pass : :fail
      end

      def valid?
        status == :pass
      end

      def break
        instances.flat_map(&:errors).min_by { |error| [error[:instance], FIELD_ORDER.fetch(error[:field], 99)] }
      end

      def valid_for_seal?
        instances.all?(&:valid_for_seal?)
      end

      def to_h
        {
          status: status,
          valid: valid?,
          :break => self.break,
          instances: instances.map(&:to_h)
        }
      end

      FIELD_ORDER = {
        'ARC-Authentication-Results' => 0,
        'ARC-Message-Signature' => 1,
        'ARC-Seal' => 2
      }.freeze
    end
  end
end
