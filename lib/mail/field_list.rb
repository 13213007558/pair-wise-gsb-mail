# encoding: utf-8
# frozen_string_literal: true
module Mail

  # Field List class provides an enhanced array that keeps a list of
  # email fields in order.  And allows you to insert new fields without
  # having to worry about the order they will appear in.
  class FieldList < Array
    # RFC 5322 3.6.6: each set of resent fields corresponds to a separate
    # resending event and MUST NOT be reordered. Unlike every other
    # structured field, Resent-* fields may therefore occur more than once
    # and must keep the order in which they were read.
    RESENT_FIELD_PREFIX = 'resent-'

    def has_field?(field_name)
      any? { |f| f.responsible_for? field_name }
    end

    def get_field(field_name)
      fields = select_fields(field_name)
      case fields.size
      when 0; nil
      when 1; fields.first
      else fields
      end
    end

    def add_field(field)
      if field.singular?
        replace_field field
      else
        insert_field field
      end
    end
    alias_method :<<, :add_field

    def replace_field(field)
      if first_offset = index { |f| f.responsible_for? field.name }
        delete_field field.name
        insert first_offset, field
      else
        insert_field field
      end
    end

    # Insert the field in sorted order.
    #
    # Resent fields are inserted immediately after the existing resent
    # fields (immediately before the first non-resent field if no resent
    # fields exist yet) so independent resent batches keep the order in
    # which they were read instead of being grouped by field name.
    def insert_field(field)
      return insert_resent_field(field) if resent_field?(field.name)

      insert(index { |f| field < f } || size, field)
    end

    def delete_field(name)
      delete_if { |f| f.responsible_for? name }
    end

    def summary
      map { |f| "<#{f.name}: #{f.value}>" }.join(", ")
    end

    # Returns all Resent-* fields in the order they appear in the header.
    def resent_fields
      select { |f| resent_field?(f.name) }
    end

    private

    def resent_field?(field_name)
      field_name.to_s.downcase.start_with?(RESENT_FIELD_PREFIX)
    end

    # Append a new resent field immediately after the existing resent
    # fields. If no resent fields exist yet, insert it directly before the
    # original message headers, keeping the resent block prepended.
    def insert_resent_field(field)
      if (last_resent = rindex { |f| resent_field?(f.name) })
        insert(last_resent + 1, field)
      else
        insert(index { |f| field < f } || size, field)
      end
    end

    def select_fields(field_name)
      fields = select { |f| f.responsible_for? field_name }
      if fields.size > 1 && singular?(field_name)
        Array(fields.detect { |f| f.errors.size == 0 } || fields.first)
      else
        fields
      end
    end

    def singular?(field_name)
      if klass = Mail::Field.field_class_for(field_name)
        klass.singular?
      else
        false
      end
    end
  end
end
