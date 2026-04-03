# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module Store
      extend Legion::Logging::Helper

      class << self
        def db_available?
          available = (defined?(Legion::Data) &&
                      Legion::Settings[:data]&.dig(:connected) == true &&
                      defined?(Legion::Data::Model::RbacRoleAssignment)) || false
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
                    static_roles_for(principal_id, principal_type)
                  end
          log.debug(
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

        def static_roles_for(principal_id, principal_type)
          assignments = Legion::Settings[:rbac][:static_assignments] || []
          matching_assignments = assignments.select do |assignment|
            next false unless assignment[:principal_id] == principal_id
            next true if principal_type.nil?

            assignment[:principal_type].to_s == principal_type.to_s
          end
          roles = matching_assignments.map { |assignment| assignment[:role] }
          log.debug(
            "RBAC static_roles_for principal_id=#{principal_id} principal_type=#{principal_type || 'any'} " \
            "count=#{roles.size}"
          )
          roles
        end
      end
    end
  end
end
