# frozen_string_literal: true

module Mail
  require_relative 'arc_field'

  class ArcSealField < ArcField
    NAME = 'ARC-Seal'
  end
end
