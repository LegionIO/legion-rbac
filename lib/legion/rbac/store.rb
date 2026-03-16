# frozen_string_literal: true

module Legion
  module Rbac
    module Store
      class << self
        def db_available?
          !!(defined?(Legion::Data) && Legion::Settings[:data]&.dig(:connected) == true)
        end

        def roles_for(principal_id:, principal_type: nil)
          if db_available?
            query = { principal_id: principal_id }
            query[:principal_type] = principal_type if principal_type
            Legion::Data::Model::RbacRoleAssignment.where(query).all.select(&:active?).map(&:role)
          else
            static_roles_for(principal_id)
          end
        end

        def runner_grants_for(team:)
          return [] unless db_available?

          Legion::Data::Model::RbacRunnerGrant.where(team: team).all
        end

        def cross_team_grants_for(source_team:)
          return [] unless db_available?

          Legion::Data::Model::RbacCrossTeamGrant.where(source_team: source_team).all.select(&:active?)
        end

        private

        def static_roles_for(principal_id)
          assignments = Legion::Settings[:rbac][:static_assignments] || []
          assignments.select { |a| a[:principal_id] == principal_id }.map { |a| a[:role] }
        end
      end
    end
  end
end
