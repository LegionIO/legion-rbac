# frozen_string_literal: true

module Legion
  module Rbac
    module Settings
      def self.default
        {
          enabled:            true,
          enforce:            true,
          connected:          false,
          default_local_role: 'admin',
          static_assignments: [],
          route_permissions:  {},
          roles:              default_roles,
          entra:              entra_defaults
        }
      end

      def self.default_roles
        {
          worker:                worker_role,
          supervisor:            supervisor_role,
          admin:                 admin_role,
          'governance-observer': governance_observer_role
        }
      end

      def self.entra_defaults
        {
          tenant_id:    nil,
          role_map:     {
            'Legion.Admin'      => 'admin',
            'Legion.Supervisor' => 'supervisor',
            'Legion.Worker'     => 'worker',
            'Legion.Observer'   => 'governance-observer'
          },
          group_map:    {},
          default_role: 'worker'
        }
      end

      def self.worker_role
        {
          description: 'Execute assigned runners within team scope',
          permissions: [
            { resource: 'runners/*', actions: %w[execute] },
            { resource: 'tasks/*', actions: %w[read create] },
            { resource: 'schedules/*', actions: %w[read] },
            { resource: 'workers/self', actions: %w[read] }
          ],
          deny:        [
            { resource: 'runners/lex-extinction/*' },
            { resource: 'runners/lex-governance/*' },
            { resource: 'workers/*/lifecycle' }
          ]
        }
      end

      def self.supervisor_role
        {
          description: 'Manage workers and schedules within team scope',
          permissions: [
            { resource: 'runners/*', actions: %w[execute] },
            { resource: 'tasks/*', actions: %w[read create delete] },
            { resource: 'schedules/*', actions: %w[read create update delete] },
            { resource: 'workers/team', actions: %w[read create lifecycle] },
            { resource: 'extensions/*', actions: %w[read] },
            { resource: 'events/*', actions: %w[read] }
          ],
          deny:        [
            { resource: 'runners/lex-extinction/escalate', above_level: 2 },
            { resource: 'workers/*/lifecycle/terminated' }
          ]
        }
      end

      def self.admin_role
        {
          description: 'Full access, cross-team capability',
          permissions: [
            { resource: '*', actions: %w[read create update delete execute manage] }
          ],
          deny:        [],
          cross_team:  true
        }
      end

      def self.governance_observer_role
        {
          description: 'Read-only visibility across all teams for audit and compliance',
          permissions: [
            { resource: 'workers/*', actions: %w[read] },
            { resource: 'tasks/*', actions: %w[read] },
            { resource: 'events/*', actions: %w[read] },
            { resource: 'schedules/*', actions: %w[read] },
            { resource: 'extensions/*', actions: %w[read] },
            { resource: 'runners/lex-governance/*', actions: %w[read execute] }
          ],
          deny:        [],
          cross_team:  true
        }
      end
    end
  end
end
