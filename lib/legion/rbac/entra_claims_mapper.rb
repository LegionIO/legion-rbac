# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module EntraClaimsMapper
      extend Legion::Logging::Helper

      DEFAULT_ROLE_MAP = {
        'Legion.Admin'      => 'admin',
        'Legion.Supervisor' => 'supervisor',
        'Legion.Worker'     => 'worker',
        'Legion.Observer'   => 'governance-observer'
      }.freeze
      DEFAULT_TEAM_KEYS = %i[legion_team extension_legion_team tid].freeze

      module_function

      def map_claims(entra_claims, role_map: DEFAULT_ROLE_MAP, group_map: {}, default_role: 'worker',
                     team_keys: DEFAULT_TEAM_KEYS, team_map: nil)
        roles = resolve_roles(entra_claims, role_map: role_map, group_map: group_map)
        used_default_role = roles.empty?
        roles << default_role if used_default_role
        team = resolve_team(entra_claims, team_keys: team_keys, team_map: team_map)

        claims = {
          sub:   claim_value(entra_claims, :oid, :sub),
          name:  claim_value(entra_claims, :name, :preferred_username),
          roles: roles.to_a,
          team:  team,
          scope: 'human'
        }
        log.info(
          "RBAC entra_claims map sub=#{claims[:sub]} roles=#{claims[:roles].size} " \
          "team=#{claims[:team]} default_role=#{used_default_role}"
        )
        claims
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.entra_claims_mapper.map_claims')
        raise
      end

      def resolve_roles(entra_claims, role_map:, group_map:)
        roles = Set.new

        Array(claim_value(entra_claims, :roles)).each do |entra_role|
          legion_role = role_map[entra_role]
          roles << legion_role if legion_role
        end

        Array(claim_value(entra_claims, :groups)).each do |group_oid|
          legion_role = group_map[group_oid]
          roles << legion_role if legion_role
        end

        roles
      end

      def resolve_team(entra_claims, team_keys:, team_map:)
        raw_team = claim_value(entra_claims, *Array(team_keys))
        return raw_team if raw_team.nil? || team_map.nil? || team_map.empty?

        team_map[raw_team] || team_map[raw_team.to_s] || team_map[raw_team.to_sym]
      end

      def claim_value(claims, *keys)
        keys.each do |key|
          value = claims[key] || claims[key.to_s]
          return value unless value.nil?
        end

        nil
      end

      private :resolve_roles, :resolve_team, :claim_value
    end
  end
end
