# frozen_string_literal: true

module Mail
  class ArcField < UnstructuredField
    def self.arc_field?
      true
    end

    def self.parse(name, value, charset = nil)
      new(name, value, charset).tap(&:parse)
    end

    private

    def do_encode
      return '' if Utilities.blank?(value)

      line = String.new
      folded = [line]
      value.split(/(\s+)/).each do |token|
        whitespace = token =~ /\A\s+\z/
        if whitespace && line.empty?
          next
        elsif !whitespace && !line.empty? && line.length + token.length + 1 > 72
          line = String.new
          folded << line
        end
        line << (whitespace ? ' ' : token)
      end

      "#{name}: #{folded.join("\r\n\t")}\r\n"
    end
  end
end
