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

      def self.evaluate_capability(principal:, capability:, extension_name: nil, role_index: nil, enforce: nil)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = Legion::Settings[:rbac][:enforce] if enforce.nil?

        resolved_roles = resolve_roles(principal, role_index)

        if resolved_roles.empty?
          return build_capability_result(
            allowed: false, reason: 'no roles assigned',
            principal: principal, capability: capability,
            extension_name: extension_name, enforce: enforce
          )
        end

        denied = resolved_roles.any? { |role| role.capability_denials.include?(capability.to_sym) }
        if denied
          return build_capability_result(
            allowed: false, reason: "capability #{capability} denied by role policy",
            principal: principal, capability: capability,
            extension_name: extension_name, enforce: enforce
          )
        end

        granted = resolved_roles.any? { |role| role.capability_grants.include?(capability.to_sym) }
        unless granted
          return build_capability_result(
            allowed: false, reason: "capability #{capability} not granted by any role",
            principal: principal, capability: capability,
            extension_name: extension_name, enforce: enforce
          )
        end

        build_capability_result(
          allowed: true, principal: principal, capability: capability,
          extension_name: extension_name, enforce: enforce
        )
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

      def self.build_capability_result(allowed:, principal:, capability:, enforce:, extension_name: nil, reason: nil)
        result = {
          allowed:      enforce ? allowed : true,
          capability:   capability.to_s,
          principal_id: principal.id
        }
        result[:extension_name] = extension_name if extension_name
        result[:reason] = reason if reason
        result[:would_deny] = true if !enforce && !allowed
        result
      end
    end
  end
end
