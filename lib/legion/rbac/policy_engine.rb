# frozen_string_literal: true

module Legion
  module Rbac
    module PolicyEngine
      def self.evaluate(principal:, action:, resource:, role_index: nil, enforce: nil, **)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = Legion::Settings[:rbac][:enforce] if enforce.nil?

        resolved_roles = resolve_roles(principal, role_index)

        if resolved_roles.empty?
          return build_result(allowed: false, reason: 'no roles assigned', principal: principal,
                              action: action, resource: resource, enforce: enforce)
        end

        denied, deny_reason = check_deny_rules(resolved_roles, resource, **)
        if denied
          return build_result(allowed: false, reason: deny_reason, principal: principal,
                              action: action, resource: resource, enforce: enforce)
        end

        permitted = check_permissions(resolved_roles, resource, action)
        if permitted
          return build_result(allowed: true, principal: principal, action: action,
                              resource: resource, enforce: enforce)
        end

        build_result(allowed: false, reason: 'no matching permission', principal: principal,
                     action: action, resource: resource, enforce: enforce)
      end

      def self.resolve_roles(principal, role_index)
        principal.roles.filter_map { |name| role_index[name.to_sym] }
      end

      def self.check_deny_rules(roles, resource, **)
        roles.each do |role|
          role.deny_rules.each do |rule|
            return [true, "denied by #{role.name} deny rule: #{rule.resource_pattern}"] if rule.matches?(resource, **)
          end
        end
        [false, nil]
      end

      def self.check_permissions(roles, resource, action)
        roles.any? do |role|
          role.permissions.any? { |perm| perm.matches?(resource, action) }
        end
      end

      def self.build_result(allowed:, principal:, action:, resource:, enforce:, reason: nil)
        result = {
          allowed:      enforce ? allowed : true,
          action:       action.to_s,
          resource:     resource,
          principal_id: principal.id
        }
        result[:reason] = reason if reason
        result[:would_deny] = true if !enforce && !allowed
        result
      end
    end
  end
end
