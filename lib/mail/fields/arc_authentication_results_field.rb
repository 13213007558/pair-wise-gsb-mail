# frozen_string_literal: true

module Mail
  require_relative 'arc_field'

  class ArcAuthenticationResultsField < ArcField
    NAME = 'ARC-Authentication-Results'
  end
end
