# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module KerberosClaimsMapper
      extend Legion::Logging::Helper

      DEFAULT_ROLE = 'worker'
      DEFAULT_TEAM_KEYS = %i[team legion_team].freeze

      module_function

      def map(principal:, groups:, role_map: {}, default_role: DEFAULT_ROLE, team_keys: DEFAULT_TEAM_KEYS,
              team_map: nil, **profile)
        parts = principal.split('@', 2)
        username = parts.first
        realm = parts.length > 1 ? parts.last : nil
        roles = Array(groups).filter_map { |g| role_map[g] }.uniq
        used_default_role = roles.empty?
        roles = [default_role] if used_default_role
        team = resolve_team(profile, team_keys: team_keys, team_map: team_map)

        claims = {
          sub:            username,
          samaccountname: username,
          ad_fqdn:        realm&.downcase,
          roles:          roles,
          scope:          'human',
          auth_method:    'kerberos',
          **profile,
          team:           team
        }.compact
        log.info(
          "RBAC kerberos_claims map principal=#{username} roles=#{claims[:roles].size} " \
          "default_role=#{used_default_role} realm=#{claims[:ad_fqdn]} team=#{claims[:team] || 'none'}"
        )
        claims
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.kerberos_claims_mapper.map', principal: principal)
        raise
      end

      def map_with_fallback(principal:, groups: nil, fallback: :entra, role_map: {},
                            default_role: DEFAULT_ROLE, **profile)
        profile, team_resolution = extract_team_resolution(profile)
        if groups&.any?
          claims = mapped_claims(
            principal:       principal,
            groups:          groups,
            role_map:        role_map,
            default_role:    default_role,
            team_resolution: team_resolution,
            profile:         profile
          )
          path = 'groups'
        elsif fallback == :entra && defined?(Legion::Rbac::EntraClaimsMapper)
          claims = entra_fallback_claims(
            principal:       principal,
            role_map:        role_map,
            default_role:    default_role,
            team_resolution: team_resolution,
            profile:         profile
          )
          path = 'entra'
        else
          claims = mapped_claims(
            principal:       principal,
            groups:          [],
            role_map:        role_map,
            default_role:    default_role,
            team_resolution: team_resolution,
            profile:         profile
          )
          path = 'default_role'
        end
        log.info("RBAC kerberos_claims fallback principal=#{principal} path=#{path}")
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

      def resolve_team(profile, team_keys:, team_map:)
        Array(team_keys).each do |key|
          value = profile[key] || profile[key.to_s]
          return value if value && (team_map.nil? || team_map.empty?)
          return team_map[value] || team_map[value.to_s] || team_map[value.to_sym] if value
        end
        nil
      end

      def extract_team_resolution(profile)
        sanitized_profile = profile.dup
        team_resolution = {
          team_keys: sanitized_profile.delete(:team_keys) || DEFAULT_TEAM_KEYS,
          team_map:  sanitized_profile.delete(:team_map)
        }
        [sanitized_profile, team_resolution]
      end

      def mapped_claims(principal:, groups:, role_map:, default_role:, team_resolution:, profile:)
        map(
          principal:    principal,
          groups:       groups,
          role_map:     role_map,
          default_role: default_role,
          **team_resolution,
          **profile
        )
      end

      def entra_fallback_claims(principal:, role_map:, default_role:, team_resolution:, profile:)
        entra_claims = { sub: principal, preferred_username: principal, **profile }.compact
        result = EntraClaimsMapper.map_claims(
          entra_claims,
          role_map:     role_map,
          default_role: default_role,
          **team_resolution
        )
        result&.merge(**profile, auth_method: 'kerberos', team: result[:team]) || mapped_claims(
          principal:       principal,
          groups:          [],
          role_map:        role_map,
          default_role:    default_role,
          team_resolution: team_resolution,
          profile:         profile
        )
      end

      private :resolve_team, :extract_team_resolution, :mapped_claims, :entra_fallback_claims
    end
  end
end
