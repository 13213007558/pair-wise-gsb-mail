# frozen_string_literal: true

module Mail
  module ARC
    class Canonicalization
      def initialize(message)
        @message = message
      end

      def body
        raw_body = encoded_message.split(/\r\n\r\n/, 2).last.to_s
        canonical_body(raw_body)
      end

      def headers(field_names, signer_name: nil, signer_value: nil)
        selected = select_fields(field_names, signer_name)
        selected.map do |field|
          canonical_header(field.name, field.value)
        end.join + canonical_signer(signer_name, signer_value)
      end

      def signature(signer_name, signer_value)
        canonical_header(signer_name, Tags.without_signature(signer_value))
      end

      private

      def encoded_message
        Mail::Utilities.to_crlf(@message.encoded).b
      end

      def select_fields(field_names, signer_name)
        fields = @message.header.fields.dup
        field_names.map do |wanted_name|
          index = fields.rindex { |field| field.responsible_for?(wanted_name) }
          index ? fields.delete_at(index) : nil
        end.compact
      end

      def canonical_signer(name, value)
        value.nil? ? '' : canonical_header(name, Tags.without_signature(value))
      end

      def canonical_header(name, value)
        unfolded = value.to_s.gsub(/\r?\n[ \t]+/, ' ')
        normalized = unfolded.gsub(/[ \t]+/, ' ').sub(/\s+\z/, '')
        "#{name.to_s.downcase.strip}:#{normalized}\r\n"
      end

      def canonical_body(raw_body)
        text = raw_body.dup.force_encoding(Encoding::BINARY)
        text = Mail::Utilities.to_lf(text)
        text.gsub!(/[ \t]+\r?\n/, "\n")
        text.gsub!(/[ \t]+/, ' ')
        lines = text.split(/\n/, -1)
        lines.pop while lines.length > 1 && lines.last.empty?
        lines.map! { |line| line.sub(/ +\z/, '') }
        lines.join("\r\n")
      end
    end
  end
end
