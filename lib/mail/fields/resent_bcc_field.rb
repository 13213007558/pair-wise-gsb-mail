# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = Resent-Bcc Field
  #
  # The Resent-Bcc field inherits resent-bcc StructuredField and handles the
  # Resent-Bcc: header field in the email.
  #
  # Sending resent_bcc to a mail message will instantiate a Mail::Field object that
  # has a ResentBccField as its field type.  This includes all Mail::CommonAddress
  # module instance metods.
  #
  # Exactly one Resent-Bcc field appears per resent block (RFC 5322 3.6.6);
  # a header may carry one per resending event, and it can have multiple
  # addresses and groups of addresses.
  #
  # == Examples:
  #
  #  mail = Mail.new
  #  mail.resent_bcc = 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
  #  mail.resent_bcc    #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
  #  mail[:resent_bcc]  #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentBccField:0x180e1c4
  #  mail['resent-bcc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentBccField:0x180e1c4
  #  mail['Resent-Bcc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::ResentBccField:0x180e1c4
  #
  #  mail[:resent_bcc].encoded   #=> 'Resent-Bcc: Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net\r\n'
  #  mail[:resent_bcc].decoded   #=> 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
  #  mail[:resent_bcc].addresses #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
  #  mail[:resent_bcc].formatted #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
  class ResentBccField < CommonAddressField #:nodoc:
    NAME = 'Resent-Bcc'

    # RFC 5322 3.6.6: one Resent-Bcc per resent block; multiple blocks
    # may be present, so the field is not singular across a header.
    def self.singular?
      false
    end
  end
end
