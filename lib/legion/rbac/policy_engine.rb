# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module PolicyEngine
      extend Legion::Logging::Helper

      def self.evaluate(principal:, action:, resource:, role_index: nil, enforce: nil, **)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = Legion::Settings[:rbac][:enforce] if enforce.nil?
        enforce = false unless Legion::Rbac.enabled?

        resolved_roles = resolve_roles(principal, role_index)

        result = if resolved_roles.empty?
                   build_result(allowed: false, reason: 'no roles assigned', principal: principal,
                                action: action, resource: resource, enforce: enforce)
                 else
                   denied, deny_reason = check_deny_rules(resolved_roles, resource, **)
                   if denied
                     build_result(allowed: false, reason: deny_reason, principal: principal,
                                  action: action, resource: resource, enforce: enforce)
                   elsif check_permissions(resolved_roles, resource, action)
                     build_result(allowed: true, principal: principal, action: action,
                                  resource: resource, enforce: enforce)
                   else
                     build_result(allowed: false, reason: 'no matching permission', principal: principal,
                                  action: action, resource: resource, enforce: enforce)
                   end
                 end

        log.info(
          "RBAC evaluate principal=#{principal.id} action=#{action} resource=#{resource} " \
          "allowed=#{result[:allowed]} enforce=#{enforce} reason=#{result[:reason] || 'none'}"
        )
        result
      rescue StandardError => e
        handle_exception(
          e,
          level:        :error,
          operation:    'rbac.policy_engine.evaluate',
          principal_id: principal&.id,
          action:       action,
          resource:     resource
        )
        raise
      end

      def self.resolve_roles(principal, role_index)
        roles = principal.roles.filter_map { |name| role_index[name.to_sym] }
        log.debug("RBAC resolve_roles principal=#{principal.id} roles=#{roles.map(&:name).join(',')}")
        roles
      end

      def self.check_deny_rules(roles, resource, **)
        roles.each do |role|
          role.deny_rules.each do |rule|
            next unless rule.matches?(resource, **)

            reason = "denied by #{role.name} deny rule: #{rule.resource_pattern}"
            log.debug("RBAC deny rule triggered role=#{role.name} resource=#{resource} reason=#{reason}")
            return [true, reason]
          end
        end
        [false, nil]
      end

      def self.check_permissions(roles, resource, action)
        roles.any? do |role|
          role.permissions.any? do |perm|
            matched = perm.matches?(resource, action)
            log.debug("RBAC permission granted role=#{role.name} action=#{action} resource=#{resource}") if matched
            matched
          end
        end
      end

      def self.evaluate_capability(principal:, capability:, extension_name: nil, role_index: nil, enforce: nil)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = Legion::Settings[:rbac][:enforce] if enforce.nil?
        enforce = false unless Legion::Rbac.enabled?

        resolved_roles = resolve_roles(principal, role_index)

        capability = capability.to_sym
        result = if resolved_roles.empty?
                   build_capability_result(
                     allowed: false, reason: 'no roles assigned',
                     principal: principal, capability: capability,
                     extension_name: extension_name, enforce: enforce
                   )
                 elsif resolved_roles.any? { |role| role.capability_denials.include?(capability) }
                   build_capability_result(
                     allowed: false, reason: "capability #{capability} denied by role policy",
                     principal: principal, capability: capability,
                     extension_name: extension_name, enforce: enforce
                   )
                 elsif resolved_roles.any? { |role| role.capability_grants.include?(capability) }
                   build_capability_result(
                     allowed: true, principal: principal, capability: capability,
                     extension_name: extension_name, enforce: enforce
                   )
                 else
                   build_capability_result(
                     allowed: false, reason: "capability #{capability} not granted by any role",
                     principal: principal, capability: capability,
                     extension_name: extension_name, enforce: enforce
                   )
                 end

        log.info(
          "RBAC evaluate_capability principal=#{principal.id} capability=#{capability} " \
          "extension=#{extension_name} allowed=#{result[:allowed]} enforce=#{enforce} reason=#{result[:reason] || 'none'}"
        )
        result
      rescue StandardError => e
        handle_exception(
          e,
          level:          :error,
          operation:      'rbac.policy_engine.evaluate_capability',
          principal_id:   principal&.id,
          capability:     capability,
          extension_name: extension_name
        )
        raise
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
