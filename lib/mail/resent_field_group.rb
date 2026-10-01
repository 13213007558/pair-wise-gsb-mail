# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = Resent Field Group
  #
  # Represents one independent block of Resent-* header fields.  Each time
  # a message is reintroduced into the transport system, a new set of
  # resent fields is prepended to it (RFC 5322 3.6.6), so a message that
  # has been resent more than once carries several groups of same-named
  # Resent-Date, Resent-From, Resent-To, etc. fields.
  #
  # A group is delimited by its Resent-Date field: every Resent-* field
  # that follows it (up to the next Resent-Date) belongs to the same
  # resending event.
  #
  # Per RFC 5322 3.6.6, a complete group MUST contain Resent-Date and
  # Resent-From, and MUST contain Resent-Sender when Resent-From holds
  # more than one address.
  #
  # Groups are usually accessed through Mail::Message#resent_groups and
  # are ordered most recent first, matching their order in the header.
  #
  #  mail = Mail.new(raw_message_with_two_resend_blocks)
  #  mail.resent_groups.size               #=> 2
  #  group = mail.resent_groups.first      # the most recent resending
  #  group.resent_from                     #=> ['resender@example.com']
  #  group.complete?                       #=> true
  class ResentFieldGroup
    # The Resent-* fields, in the order they are defined in RFC 5322 3.6.6.
    FIELD_NAMES = %w[ Resent-Date Resent-From Resent-Sender Resent-To
                      Resent-Cc Resent-Bcc Resent-Message-ID ].freeze

    # Fields that must be present for the group to be complete.
    REQUIRED_FIELDS = %w[ Resent-Date Resent-From ].freeze

    # The Mail::Field objects that make up this group, in header order.
    attr_reader :fields

    def initialize(fields = [])
      @fields = fields
    end

    # Returns the first field in the group responsible for the given field
    # name, e.g. group['Resent-From'] or group[:resent_from].
    def [](field_name)
      name = Utilities.dasherize(field_name)
      @fields.find { |field| field.responsible_for?(name) }
    end

    # Returns the Resent-Date of this group as a DateTime, or nil.
    def resent_date
      field = self['Resent-Date']
      field.default if field
    end

    # Returns an array of addresses in the Resent-From field of this group.
    def resent_from
      addresses_of 'Resent-From'
    end

    # Returns the Resent-Sender address of this group, or nil.
    def resent_sender
      addresses_of('Resent-Sender').first
    end

    # Returns an array of addresses in the Resent-To field of this group.
    def resent_to
      addresses_of 'Resent-To'
    end

    # Returns an array of addresses in the Resent-Cc field of this group.
    def resent_cc
      addresses_of 'Resent-Cc'
    end

    # Returns an array of addresses in the Resent-Bcc field of this group.
    def resent_bcc
      addresses_of 'Resent-Bcc'
    end

    # Returns the Resent-Message-ID of this group, or nil.
    def resent_message_id
      field = self['Resent-Message-ID']
      field.default if field
    end

    # Returns every address this resending was addressed to: the Resent-To,
    # Resent-Cc and Resent-Bcc addresses of this group.
    def destinations
      resent_to + resent_cc + resent_bcc
    end

    # Returns the address to use as the envelope sender when redelivering
    # this group: the Resent-Sender if present, otherwise the first
    # Resent-From address.
    def envelope_from
      resent_sender || resent_from.first
    end

    # Returns a list of strings describing why this group is not a complete
    # resent block per RFC 5322 3.6.6.  An empty list means the group is
    # complete.
    def errors
      errs = REQUIRED_FIELDS.reject { |name| self[name] }.
        map { |name| "missing #{name}" }
      if resent_from.length > 1 && !self['Resent-Sender']
        errs << 'missing Resent-Sender (required when Resent-From contains more than one address)'
      end
      errs
    end

    # Returns true if this group has all fields required by RFC 5322 3.6.6:
    # Resent-Date, Resent-From, and Resent-Sender when Resent-From holds
    # more than one address.
    def complete?
      errors.empty?
    end

    # Raises Mail::Field::FieldError unless this group is complete.
    # Returns self when valid.
    def validate!
      unless complete?
        raise Mail::Field::FieldError, "Incomplete resent field group: #{errors.join(', ')}"
      end
      self
    end

    # Returns the encoded fields of this group, in header order.
    def encoded
      @fields.map(&:encoded).join
    end

    def to_s
      encoded
    end

    private

    def addresses_of(field_name)
      field = self[field_name]
      field ? [field.default].flatten : []
    end
  end
end
