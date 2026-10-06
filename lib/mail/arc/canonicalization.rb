# frozen_string_literal: true

module Mail
  module ARC
    module Canonicalization
      module_function

      def relaxed_header(name, value)
        name = name.to_s.downcase.gsub(/\s+/, '')
        value = unfold(value.to_s).gsub(/\s+/, ' ').strip
        "#{name}:#{value}\r\n"
      end

      def relaxed_body(body)
        body = body.to_s.dup.force_encoding(Encoding::BINARY)
        body = body.gsub(/\r\n?|\n/, "\r\n")
        body = body.each_line.map { |line| line.sub(/[ \t]+\r\n\z/, "\r\n") }.join
        body = body.gsub(/[ \t]+/, ' ')
        body = body.sub(/(?:\r\n)+\z/, "\r\n")
        body << "\r\n" if body.empty?
        body
      end

      def unfold(value)
        value.gsub(/\r\n[ \t]/, '')
      end

      def message_parts(message)
        message.body.send(:process_body_raw) if message.body.instance_variable_defined?(:@body_raw) && message.body.instance_variable_get(:@body_raw)
        encoded_body = message.body.encoded(message.content_transfer_encoding)
        message.body.send(:process_body_raw) if message.body.instance_variable_defined?(:@body_raw) && message.body.instance_variable_get(:@body_raw)
        source = "#{message.header.encoded}\r\n#{encoded_body}"
        source.split(/\r\n\r\n/, 2)
      end
    end
  end
end
