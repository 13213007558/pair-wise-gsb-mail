# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = Resent-Cc Field
  #
  # The Resent-Cc field inherits resent-cc StructuredField and handles the Resent-Cc: header
  # field in the email.
  #
  # Sending resent_cc to a mail message will instantiate a Mail::Field object that
  # has a ResentCcField as its field type.  This includes all Mail::CommonAddress
  # module instance metods.
  #
  # Exactly one Resent-Cc field appears per resent block (RFC 5322 3.6.6);
  # a header may carry one per resending event, and it can have multiple
  # addresses and groups of addresses.
  #
  # == Examples:
  #
  #  mail = Mail.new
  #  mail.resent_cc = 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
  #  mail.resent_cc    #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
  #  mail[:resent_cc]  #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentCcField:0x180e1c4
  #  mail['resent-cc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentCcField:0x180e1c4
  #  mail['Resent-Cc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentCcField:0x180e1c4
  #
  #  mail[:resent_cc].encoded   #=> 'Resent-Cc: Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net\r\n'
  #  mail[:resent_cc].decoded   #=> 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
  #  mail[:resent_cc].addresses #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
  #  mail[:resent_cc].formatted #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
  class ResentCcField < CommonAddressField #:nodoc:
    NAME = 'Resent-Cc'

    # RFC 5322 3.6.6: one Resent-Cc per resent block; multiple blocks
    # may be present, so the field is not singular across a header.
    def self.singular?
      false
    end
  end
end
