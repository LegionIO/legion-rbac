# frozen_string_literal: true

module Legion
  module Rbac
    module TeamScope
      def self.allowed?(principal:, target_team:, role_index: nil)
        return true if target_team.nil?
        return true if principal.team.nil?
        return true if principal.team == target_team

        role_index ||= Legion::Rbac.role_index || {}
        resolved_roles = principal.roles.filter_map { |name| role_index[name.to_sym] }
        resolved_roles.any?(&:cross_team?)
      end
    end
  end
end
