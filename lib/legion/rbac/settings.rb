# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module Settings
      extend Legion::Logging::Helper

      def self.default
        log.debug('RBAC default settings requested')
        {
          enabled:            true,
          enforce:            true,
          connected:          false,
          default_local_role: 'admin',
          static_assignments: [],
          route_permissions:  {},
          roles:              default_roles,
          entra:              entra_defaults,
          capability_audit:   capability_audit_defaults
        }
      end

      def self.capability_audit_defaults
        log.debug('RBAC capability audit defaults requested')
        {
          enabled:           true,
          mode:              'enforce',
          undeclared_policy: 'block'
        }
      end

      def self.default_roles
        log.debug('RBAC default roles requested')
        {
          worker:                worker_role,
          supervisor:            supervisor_role,
          admin:                 admin_role,
          'governance-observer': governance_observer_role
        }
      end

      def self.entra_defaults
        log.debug('RBAC Entra defaults requested')
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
        log.debug('RBAC worker role template requested')
        {
          description:        'Execute assigned runners within team scope',
          permissions:        [
            { resource: 'runners/*', actions: %w[execute] },
            { resource: 'tasks/*', actions: %w[read create] },
            { resource: 'schedules/*', actions: %w[read] },
            { resource: 'workers/self', actions: %w[read] }
          ],
          deny:               [
            { resource: 'runners/lex-extinction/*' },
            { resource: 'runners/lex-governance/*' },
            { resource: 'workers/*/lifecycle' }
          ],
          capability_grants:  %w[network_outbound filesystem_write],
          capability_denials: %w[shell_execute code_eval]
        }
      end

      def self.supervisor_role
        log.debug('RBAC supervisor role template requested')
        {
          description:        'Manage workers and schedules within team scope',
          permissions:        [
            { resource: 'runners/*', actions: %w[execute] },
            { resource: 'tasks/*', actions: %w[read create delete] },
            { resource: 'schedules/*', actions: %w[read create update delete] },
            { resource: 'workers/team', actions: %w[read create lifecycle] },
            { resource: 'extensions/*', actions: %w[read] },
            { resource: 'events/*', actions: %w[read] }
          ],
          deny:               [
            { resource: 'runners/lex-extinction/escalate', above_level: 2 },
            { resource: 'workers/*/lifecycle/terminated' }
          ],
          capability_grants:  %w[network_outbound filesystem_write shell_execute],
          capability_denials: %w[code_eval]
        }
      end

      def self.admin_role
        log.debug('RBAC admin role template requested')
        {
          description:        'Full access, cross-team capability',
          permissions:        [
            { resource: '*', actions: %w[read create update delete execute manage] }
          ],
          deny:               [],
          cross_team:         true,
          capability_grants:  %w[shell_execute code_eval network_outbound filesystem_write],
          capability_denials: []
        }
      end

      def self.governance_observer_role
        log.debug('RBAC governance observer role template requested')
        {
          description:        'Read-only visibility across all teams for audit and compliance',
          permissions:        [
            { resource: 'workers/*', actions: %w[read] },
            { resource: 'tasks/*', actions: %w[read] },
            { resource: 'events/*', actions: %w[read] },
            { resource: 'schedules/*', actions: %w[read] },
            { resource: 'extensions/*', actions: %w[read] },
            { resource: 'runners/lex-governance/*', actions: %w[read execute] }
          ],
          deny:               [],
          cross_team:         true,
          capability_grants:  [],
          capability_denials: %w[shell_execute code_eval network_outbound filesystem_write]
        }
      end
    end
  end
end
