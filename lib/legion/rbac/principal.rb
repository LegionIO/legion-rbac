# frozen_string_literal: true

module Legion
  module Rbac
    class Principal
      attr_reader :id, :type, :roles, :team

      def initialize(id:, type: :human, roles: [], team: nil)
        @id = id
        @type = type.to_sym
        @roles = roles.map(&:to_s)
        @team = team
      end

      def self.from_claims(claims)
        scope = claims[:scope] || claims['scope']
        if scope == 'worker'
          new(
            id:    claims[:worker_id] || claims['worker_id'],
            type:  :worker,
            roles: claims[:roles] || claims['roles'] || [],
            team:  claims[:team] || claims['team']
          )
        else
          new(
            id:    claims[:sub] || claims['sub'],
            type:  :human,
            roles: claims[:roles] || claims['roles'] || [],
            team:  claims[:team] || claims['team']
          )
        end
      end

      def self.local_admin
        role = Legion::Settings[:rbac][:default_local_role] || 'admin'
        new(id: 'local', type: :human, roles: [role])
      end

      def self.anonymous
        new(id: 'anonymous', type: :human, roles: [])
      end
    end
  end
end
