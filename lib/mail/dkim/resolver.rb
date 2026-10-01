# frozen_string_literal: true

module Mail
  module DKIM
    # Looks up DKIM DNS TXT records.  The mail library never performs DNS
    # itself in production code: an implementation of this interface is
    # injected into the verifier.  Two adapters are provided for tests
    # and for stand alone use:
    #
    #   * a Hash mapping "selector._domainkey.example" => "v=DKIM1; p=..."
    #   * a Proc/lambda receiving the name and returning the TXT string
    #
    # ResolverDns is a thin wrapper over stdlib Resolv for applications
    # that are happy to do real DNS lookups.
    module Resolver
      # Answer a query with a static mapping.  A missing name (or an
      # explicit nil) behaves like NXDOMAIN.
      class Static
        def initialize(records = {})
          @records = records
        end

        def call(name)
          value = @records[name]
          if value.is_a?(Array)
            value.join
          else
            value
          end
        end
      end

      # Answer queries by delegating to a callable.
      class ProcResolver
        def initialize(callable)
          @callable = callable
        end

        def call(name)
          @callable.call(name)
        end
      end

      # Stdlib Resolv::DNS based resolver, loaded lazily so that the
      # resolv library is only needed when real queries are performed.
      class ResolvDns
        def self.coerce(resolver)
          case resolver
          when nil, self
            resolver || new
          when Hash
            Static.new(resolver)
          when Proc, Method
            ProcResolver.new(resolver)
          else
            if resolver.respond_to?(:call)
              ProcResolver.new(resolver)
            else
              raise ArgumentError, "unsupported DKIM DNS resolver: #{resolver.class}"
            end
          end
        end

        def call(name)
          require 'resolv'
          values = nil
          ::Resolv::DNS.open do |dns|
            values = dns.getresources(name, ::Resolv::DNS::Resource::IN::TXT).flat_map do |r|
              r.data.strings
            end
          end
          values && !values.empty? ? values.join : nil
        end
      end
    end
  end
end
