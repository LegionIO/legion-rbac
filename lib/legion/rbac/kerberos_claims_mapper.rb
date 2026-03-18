# frozen_string_literal: true

module Legion
  module Rbac
    module KerberosClaimsMapper
      DEFAULT_ROLE = 'worker'

      module_function

      def map(principal:, groups:, role_map: {}, default_role: DEFAULT_ROLE, **profile)
        parts = principal.split('@', 2)
        username = parts.first
        realm = parts.length > 1 ? parts.last : nil
        roles = Array(groups).filter_map { |g| role_map[g] }.uniq
        roles = [default_role] if roles.empty?

        {
          sub:            username,
          samaccountname: username,
          ad_fqdn:        realm&.downcase,
          first_name:     profile[:first_name],
          last_name:      profile[:last_name],
          email:          profile[:email],
          display_name:   profile[:display_name],
          roles:          roles,
          scope:          'human',
          auth_method:    'kerberos'
        }.compact
      end

      def map_with_fallback(principal:, groups: nil, fallback: :entra, role_map: {},
                            default_role: DEFAULT_ROLE, **profile)
        if groups&.any?
          map(principal: principal, groups: groups, role_map: role_map, default_role: default_role, **profile)
        elsif fallback == :entra && defined?(Legion::Rbac::EntraClaimsMapper)
          entra_claims = { sub: principal, preferred_username: principal }
          result = EntraClaimsMapper.map_claims(entra_claims)
          result&.merge(auth_method: 'kerberos') || map(principal: principal, groups: [],
                                                        role_map: role_map, default_role: default_role)
        else
          map(principal: principal, groups: [], role_map: role_map, default_role: default_role, **profile)
        end
      end
    end
  end
end
