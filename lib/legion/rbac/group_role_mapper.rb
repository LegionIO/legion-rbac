# frozen_string_literal: true

module Legion
  module Rbac
    module GroupRoleMapper
      # Resolve RBAC roles from group memberships using a configurable map.
      #
      # @param groups [Array<String>] group names or OIDs from identity provider
      # @param group_role_map [Hash, nil] { group_name => role_name }; reads default_map when nil
      # @return [Array<String>] resolved role names (may be empty)
      #
      # NOTE: v1 supports exact string match only. Regexp keys in group_role_map are NOT supported —
      # JSON settings cannot represent Regexp objects. All map keys are compared via `to_s == to_s`.
      # Pattern matching is deferred to Phase 9.
      def self.resolve_roles(groups:, group_role_map: nil)
        return [] unless Legion::Rbac.enabled?

        map = group_role_map || default_map
        return [] if groups.nil? || groups.empty? || map.empty?

        roles = Set.new
        groups.each do |group|
          map.each do |key, role|
            roles << role.to_s if group.to_s == key.to_s
          end
        end
        roles.to_a
      end

      # Enrich an RBAC principal hash with group-derived roles (additive, never removes).
      #
      # @param principal [Hash] from Identity::Request#to_rbac_principal
      # @param groups [Array<String>] from identity provider
      # @return [Hash] principal with :roles enriched
      def self.enrich_principal(principal:, groups:)
        return principal unless Legion::Rbac.enabled?

        additional_roles = resolve_roles(groups: groups)
        return principal if additional_roles.empty?

        existing_roles = principal[:roles] || []
        principal.merge(roles: (existing_roles + additional_roles).uniq)
      end

      def self.default_map
        return {} unless defined?(Legion::Settings)

        Legion::Settings.dig(:rbac, :group_role_map) || {}
      end

      private_class_method :default_map
    end
  end
end
