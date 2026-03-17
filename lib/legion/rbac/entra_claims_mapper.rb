# frozen_string_literal: true

module Legion
  module Rbac
    module EntraClaimsMapper
      DEFAULT_ROLE_MAP = {
        'Legion.Admin'      => 'admin',
        'Legion.Supervisor' => 'supervisor',
        'Legion.Worker'     => 'worker',
        'Legion.Observer'   => 'governance-observer'
      }.freeze

      module_function

      def map_claims(entra_claims, role_map: DEFAULT_ROLE_MAP, group_map: {}, default_role: 'worker')
        roles = Set.new

        Array(entra_claims[:roles] || entra_claims['roles']).each do |entra_role|
          legion_role = role_map[entra_role]
          roles << legion_role if legion_role
        end

        Array(entra_claims[:groups] || entra_claims['groups']).each do |group_oid|
          legion_role = group_map[group_oid]
          roles << legion_role if legion_role
        end

        roles << default_role if roles.empty?

        {
          sub:   entra_claims[:oid] || entra_claims[:sub] || entra_claims['oid'] || entra_claims['sub'],
          name:  entra_claims[:name] || entra_claims[:preferred_username] ||
            entra_claims['name'] || entra_claims['preferred_username'],
          roles: roles.to_a,
          team:  entra_claims[:tid] || entra_claims['tid'],
          scope: 'human'
        }
      end
    end
  end
end
