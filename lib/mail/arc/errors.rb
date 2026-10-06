# frozen_string_literal: true

module Mail
  module ARC
    class Error < StandardError; end
    class MalformedHeader < Error; end
    class MissingKey < Error; end
  end
end
