# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module KerberosClaimsMapper
      extend Legion::Logging::Helper

      DEFAULT_ROLE = 'worker'

      module_function

      def map(principal:, groups:, role_map: {}, default_role: DEFAULT_ROLE, **profile)
        parts = principal.split('@', 2)
        username = parts.first
        realm = parts.length > 1 ? parts.last : nil
        roles = Array(groups).filter_map { |g| role_map[g] }.uniq
        used_default_role = roles.empty?
        roles = [default_role] if used_default_role

        claims = {
          sub:            username,
          samaccountname: username,
          ad_fqdn:        realm&.downcase,
          roles:          roles,
          scope:          'human',
          auth_method:    'kerberos',
          **profile
        }.compact
        log.info(
          "RBAC kerberos_claims map principal=#{username} roles=#{claims[:roles].size} " \
          "default_role=#{used_default_role} realm=#{claims[:ad_fqdn]}"
        )
        claims
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.kerberos_claims_mapper.map', principal: principal)
        raise
      end

      def map_with_fallback(principal:, groups: nil, fallback: :entra, role_map: {},
                            default_role: DEFAULT_ROLE, **profile)
        if groups&.any?
          claims = map(principal: principal, groups: groups, role_map: role_map, default_role: default_role, **profile)
          log.info("RBAC kerberos_claims fallback principal=#{principal} path=groups")
        elsif fallback == :entra && defined?(Legion::Rbac::EntraClaimsMapper)
          entra_claims = { sub: principal, preferred_username: principal, **profile }.compact
          result = EntraClaimsMapper.map_claims(entra_claims, role_map: role_map, default_role: default_role)
          claims = result&.merge(auth_method: 'kerberos', **profile) || map(
            principal:    principal,
            groups:       [],
            role_map:     role_map,
            default_role: default_role,
            **profile
          )
          log.info("RBAC kerberos_claims fallback principal=#{principal} path=entra")
        else
          claims = map(principal: principal, groups: [], role_map: role_map, default_role: default_role, **profile)
          log.info("RBAC kerberos_claims fallback principal=#{principal} path=default_role")
        end
        claims
      rescue StandardError => e
        handle_exception(
          e,
          level:     :error,
          operation: 'rbac.kerberos_claims_mapper.map_with_fallback',
          principal: principal,
          fallback:  fallback
        )
        raise
      end
    end
  end
end
