# frozen_string_literal: true

module Mail
  require_relative 'arc_field'

  class ArcMessageSignatureField < ArcField
    NAME = 'ARC-Message-Signature'
  end
end
