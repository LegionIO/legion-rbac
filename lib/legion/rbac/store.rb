# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Rbac
    module Store
      extend Legion::Logging::Helper

      class << self
        def db_available?
          available = defined?(Legion::Data) ? Legion::Settings[:data]&.dig(:connected) == true : false
          log.debug("RBAC store db_available=#{available}")
          available
        end

        def roles_for(principal_id:, principal_type: nil)
          source = db_available? ? 'db' : 'static'
          roles = if source == 'db'
                    query = { principal_id: principal_id }
                    query[:principal_type] = principal_type if principal_type
                    Legion::Data::Model::RbacRoleAssignment.where(query).all.select(&:active?).map(&:role)
                  else
                    static_roles_for(principal_id)
                  end
          log.info(
            "RBAC roles_for principal_id=#{principal_id} principal_type=#{principal_type || 'any'} " \
            "source=#{source} count=#{roles.size}"
          )
          roles
        rescue StandardError => e
          handle_exception(
            e,
            level:          :error,
            operation:      'rbac.store.roles_for',
            principal_id:   principal_id,
            principal_type: principal_type
          )
          raise
        end

        def runner_grants_for(team:)
          return [] unless db_available?

          grants = Legion::Data::Model::RbacRunnerGrant.where(team: team).all
          log.info("RBAC runner_grants_for team=#{team} count=#{grants.size}")
          grants
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'rbac.store.runner_grants_for', team: team)
          raise
        end

        def cross_team_grants_for(source_team:)
          return [] unless db_available?

          grants = Legion::Data::Model::RbacCrossTeamGrant.where(source_team: source_team).all.select(&:active?)
          log.info("RBAC cross_team_grants_for source_team=#{source_team} count=#{grants.size}")
          grants
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'rbac.store.cross_team_grants_for', source_team: source_team)
          raise
        end

        private

        def static_roles_for(principal_id)
          assignments = Legion::Settings[:rbac][:static_assignments] || []
          roles = assignments.select { |a| a[:principal_id] == principal_id }.map { |a| a[:role] }
          log.debug("RBAC static_roles_for principal_id=#{principal_id} count=#{roles.size}")
          roles
        end
      end
    end
  end
end
