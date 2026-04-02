# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module TeamScope
      extend Legion::Logging::Helper

      def self.allowed?(principal:, target_team:, role_index: nil)
        if target_team.nil?
          log.debug("RBAC team_scope allowed principal=#{principal.id} reason=no_target_team")
          return true
        end
        if principal.team.nil?
          log.debug("RBAC team_scope allowed principal=#{principal.id} reason=no_principal_team")
          return true
        end
        if principal.team == target_team
          log.debug("RBAC team_scope allowed principal=#{principal.id} reason=same_team team=#{target_team}")
          return true
        end

        role_index ||= Legion::Rbac.role_index || {}
        resolved_roles = principal.roles.filter_map { |name| role_index[name.to_sym] }
        allowed = resolved_roles.any?(&:cross_team?)
        log.info(
          "RBAC team_scope principal=#{principal.id} principal_team=#{principal.team} " \
          "target_team=#{target_team} allowed=#{allowed}"
        )
        allowed
      rescue StandardError => e
        handle_exception(
          e,
          level:        :error,
          operation:    'rbac.team_scope.allowed',
          principal_id: principal&.id,
          target_team:  target_team
        )
        raise
      end
    end
  end
end
