# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    module PolicyEngine
      extend Legion::Logging::Helper

      # rubocop:disable Metrics/ParameterLists
      def self.evaluate(principal:, action:, resource:, role_index: nil, enforce: nil, resolved_roles: nil,
                        target_team: nil, skip_team_scope: false, **options)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = resolve_enforcement(enforce)
        resolved_roles ||= resolve_roles(principal, role_index)
        result = evaluate_result(
          principal:          principal,
          action:             action,
          resource:           resource,
          enforce:            enforce,
          resolved_roles:     resolved_roles,
          decision_options:   options,
          team_scope_context: {
            target_team:     target_team,
            role_index:      role_index,
            skip_team_scope: skip_team_scope
          }
        )

        log.debug(
          "RBAC evaluate principal=#{principal.id} action=#{action} resource=#{resource} " \
          "target_team=#{target_team || 'none'} allowed=#{result[:allowed]} " \
          "enforce=#{enforce} reason=#{result[:reason] || 'none'}"
        )
        emit_decision_event(
          result:    result,
          principal: principal,
          roles:     resolved_roles,
          context:   build_decision_context(
            enforce:       enforce,
            operation:     'rbac.policy_engine.evaluate',
            event_context: decision_event_context(options),
            target_team:   target_team,
            action:        action,
            resource:      resource
          )
        )
        result
      rescue StandardError => e
        handle_exception(
          e,
          level:        :error,
          operation:    'rbac.policy_engine.evaluate',
          principal_id: principal&.id,
          action:       action,
          resource:     resource,
          target_team:  target_team
        )
        raise
      end

      def self.resolve_roles(principal, role_index)
        direct_role_names = principal.roles.map(&:to_s)
        assigned_role_names = Store.roles_for(
          principal_id:   principal.id,
          principal_type: principal.type.to_s
        ).map(&:to_s)
        role_names = case role_resolution_mode
                     when 'assignments_only'
                       assigned_role_names
                     when 'principal_only'
                       direct_role_names
                     else
                       (direct_role_names + assigned_role_names).uniq
                     end
        roles = role_names.filter_map { |name| role_index[name.to_sym] }
        log.debug(
          "RBAC resolve_roles principal=#{principal.id} mode=#{role_resolution_mode} " \
          "direct=#{direct_role_names.join(',')} assigned=#{assigned_role_names.join(',')} " \
          "roles=#{roles.map(&:name).join(',')}"
        )
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

      def self.evaluate_execution(principal:, resource:, action: :execute, target_team: nil, role_index: nil, enforce: nil,
                                  resolved_roles: nil, **options)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = resolve_enforcement(enforce)
        resolved_roles ||= resolve_roles(principal, role_index)
        result = evaluate_execution_result(
          principal:        principal,
          resource:         resource,
          action:           action,
          target_team:      target_team,
          enforce:          enforce,
          resolved_roles:   resolved_roles,
          decision_options: options
        )

        log.info(
          "RBAC evaluate_execution principal=#{principal.id} action=#{action} resource=#{resource} " \
          "target_team=#{target_team || principal.team || 'none'} allowed=#{result[:allowed]} " \
          "enforce=#{enforce} reason=#{result[:reason] || 'none'}"
        )
        emit_decision_event(
          result:    result,
          principal: principal,
          roles:     resolved_roles,
          context:   build_decision_context(
            enforce:       enforce,
            operation:     'rbac.policy_engine.evaluate_execution',
            event_context: decision_event_context(options),
            target_team:   target_team || principal.team,
            action:        action,
            resource:      resource
          )
        )
        result
      rescue StandardError => e
        handle_exception(
          e,
          level:        :error,
          operation:    'rbac.policy_engine.evaluate_execution',
          principal_id: principal&.id,
          action:       action,
          resource:     resource,
          target_team:  target_team
        )
        raise
      end
      # rubocop:enable Metrics/ParameterLists

      def self.evaluate_capability(principal:, capability:, extension_name: nil, role_index: nil, enforce: nil, **options)
        role_index ||= Legion::Rbac.role_index || {}
        enforce = resolve_enforcement(enforce)
        resolved_roles = resolve_roles(principal, role_index)
        capability = capability.to_sym
        result = evaluate_capability_result(
          principal:      principal,
          capability:     capability,
          extension_name: extension_name,
          enforce:        enforce,
          resolved_roles: resolved_roles
        )

        log.info(
          "RBAC evaluate_capability principal=#{principal.id} capability=#{capability} " \
          "extension=#{extension_name} allowed=#{result[:allowed]} enforce=#{enforce} reason=#{result[:reason] || 'none'}"
        )
        emit_decision_event(
          result:    result,
          principal: principal,
          roles:     resolved_roles,
          context:   build_decision_context(
            enforce:       enforce,
            operation:     'rbac.policy_engine.evaluate_capability',
            event_context: decision_event_context(options)
          )
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

      def self.resolve_enforcement(enforce)
        enforce = Legion::Settings[:rbac][:enforce] if enforce.nil?
        enforce = false unless Legion::Rbac.enabled?
        enforce
      end

      def self.evaluate_result(principal:, action:, resource:, enforce:, resolved_roles:, decision_options:,
                               team_scope_context:)
        return denied_result(principal:, action:, resource:, enforce:, reason: 'no roles assigned') if resolved_roles.empty?

        if !team_scope_context[:skip_team_scope] && !team_scope_allowed?(
          principal:          principal,
          resolved_roles:     resolved_roles,
          team_scope_context: team_scope_context
        )
          return denied_result(principal:, action:, resource:, enforce:, reason: 'outside team scope')
        end

        denied, deny_reason = check_deny_rules(resolved_roles, resource, **decision_options)
        return denied_result(principal:, action:, resource:, enforce:, reason: deny_reason) if denied
        return allowed_result(principal:, action:, resource:, enforce:) if check_permissions(resolved_roles, resource, action)

        denied_result(principal:, action:, resource:, enforce:, reason: 'no matching permission')
      end

      def self.evaluate_execution_result(principal:, resource:, action:, target_team:, enforce:, resolved_roles:,
                                         decision_options:)
        return denied_result(principal:, action:, resource:, enforce:, reason: 'no roles assigned') if resolved_roles.empty?

        denied, deny_reason = check_deny_rules(resolved_roles, resource, **decision_options)
        return denied_result(principal:, action:, resource:, enforce:, reason: deny_reason) if denied
        return denied_result(principal:, action:, resource:, enforce:, reason: 'no matching permission') unless check_permissions(resolved_roles, resource,
                                                                                                                                  action)

        allowed, reason = execution_scope_decision(
          principal:   principal,
          target_team: target_team,
          resource:    resource,
          action:      action,
          roles:       resolved_roles
        )
        build_result(
          allowed:   allowed,
          reason:    reason,
          principal: principal,
          action:    action,
          resource:  resource,
          enforce:   enforce
        )
      end

      def self.evaluate_capability_result(principal:, capability:, extension_name:, enforce:, resolved_roles:)
        if resolved_roles.empty?
          return build_capability_result(
            allowed:        false,
            reason:         'no roles assigned',
            principal:      principal,
            capability:     capability,
            extension_name: extension_name,
            enforce:        enforce
          )
        end

        if resolved_roles.any? { |role| role.capability_denials.include?(capability) }
          return build_capability_result(
            allowed:        false,
            reason:         "capability #{capability} denied by role policy",
            principal:      principal,
            capability:     capability,
            extension_name: extension_name,
            enforce:        enforce
          )
        end

        if resolved_roles.any? { |role| role.capability_grants.include?(capability) }
          return build_capability_result(
            allowed:        true,
            principal:      principal,
            capability:     capability,
            extension_name: extension_name,
            enforce:        enforce
          )
        end

        build_capability_result(
          allowed:        false,
          reason:         "capability #{capability} not granted by any role",
          principal:      principal,
          capability:     capability,
          extension_name: extension_name,
          enforce:        enforce
        )
      end

      def self.team_scope_allowed?(principal:, resolved_roles:, team_scope_context:)
        TeamScope.allowed?(
          principal:      principal,
          target_team:    team_scope_context[:target_team],
          role_index:     team_scope_context[:role_index],
          resolved_roles: resolved_roles
        )
      end

      def self.allowed_result(principal:, action:, resource:, enforce:)
        build_result(
          allowed:   true,
          principal: principal,
          action:    action,
          resource:  resource,
          enforce:   enforce
        )
      end

      def self.denied_result(principal:, action:, resource:, enforce:, reason:)
        build_result(
          allowed:   false,
          reason:    reason,
          principal: principal,
          action:    action,
          resource:  resource,
          enforce:   enforce
        )
      end

      def self.role_resolution_mode
        configured = Legion::Settings[:rbac]&.fetch(:role_resolution_mode, 'merge')
        mode = configured.to_s
        return mode if %w[merge assignments_only principal_only].include?(mode)

        log.warn("RBAC invalid role_resolution_mode=#{mode} defaulting=merge")
        'merge'
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'rbac.policy_engine.role_resolution_mode')
        'merge'
      end

      def self.build_decision_context(enforce:, operation:, event_context:, target_team: nil, action: nil, resource: nil)
        {
          enforce:       enforce,
          operation:     operation,
          event_context: event_context,
          target_team:   target_team,
          action:        action,
          resource:      resource
        }
      end

      def self.emit_decision_event(result:, principal:, roles:, context:)
        return unless Legion::Rbac.events_enabled?

        event_name = result[:would_deny] || !result[:allowed] ? 'rbac.denied' : 'rbac.granted'
        payload = {
          operation:      context[:operation],
          principal_id:   principal.id,
          principal_type: principal.type.to_s,
          principal_team: principal.team,
          target_team:    context[:target_team],
          roles:          roles.map(&:name),
          action:         context[:action]&.to_s || result[:action],
          resource:       context[:resource] || result[:resource],
          capability:     result[:capability],
          extension_name: result[:extension_name],
          allowed:        result[:allowed],
          would_deny:     result[:would_deny] == true,
          enforce:        context[:enforce],
          reason:         result[:reason]
        }.merge(context[:event_context]).compact
        Legion::Events.emit(event_name, payload)
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'rbac.policy_engine.emit_decision_event', event: event_name)
      end

      def self.decision_event_context(options)
        {
          source:         options[:source],
          correlation_id: options[:correlation_id],
          method:         options[:method]&.to_s,
          path:           options[:path]
        }.compact
      end

      def self.execution_scope_decision(principal:, target_team:, resource:, action:, roles:)
        if roles.any?(&:cross_team?)
          log.debug("RBAC execution scope allowed principal=#{principal.id} reason=cross_team_role")
          return [true, nil]
        end

        effective_target_team = target_team || principal.team
        same_team = effective_target_team.nil? || principal.team.nil? || effective_target_team == principal.team

        return [true, nil] if same_team && !Store.db_available?

        unless Store.db_available?
          reason = 'outside team scope'
          log.info("RBAC execution scope denied principal=#{principal.id} reason=#{reason}")
          return [false, reason]
        end

        if principal.team && !runner_grant_allowed?(team: principal.team, resource: resource, action: action)
          reason = "runner grant required for team #{principal.team}"
          log.info("RBAC execution scope denied principal=#{principal.id} reason=#{reason}")
          return [false, reason]
        end

        return [true, nil] if same_team

        if cross_team_grant_allowed?(
          source_team: principal.team,
          target_team: effective_target_team,
          resource:    resource,
          action:      action
        )
          return [true, nil]
        end

        reason = "cross-team grant required for #{principal.team} -> #{effective_target_team}"
        log.info("RBAC execution scope denied principal=#{principal.id} reason=#{reason}")
        [false, reason]
      end

      def self.runner_grant_allowed?(team:, resource:, action:)
        grants = Store.runner_grants_for(team: team)
        allowed = grants.any? { |grant| grant_matches?(grant, resource, action) }
        log.info("RBAC runner_grant team=#{team} action=#{action} resource=#{resource} allowed=#{allowed}")
        allowed
      end

      def self.cross_team_grant_allowed?(source_team:, target_team:, resource:, action:)
        grants = Store.cross_team_grants_for(source_team: source_team)
        allowed = grants.any? do |grant|
          grant.target_team == target_team && grant_matches?(grant, resource, action)
        end
        log.info(
          "RBAC cross_team_grant source_team=#{source_team} target_team=#{target_team} " \
          "action=#{action} resource=#{resource} allowed=#{allowed}"
        )
        allowed
      end

      def self.grant_matches?(grant, resource, action)
        Permission.new(
          resource_pattern: normalize_runner_pattern(grant.runner_pattern),
          actions:          grant_actions(grant)
        ).matches?(resource, action)
      end

      def self.normalize_runner_pattern(pattern)
        pattern.start_with?('runners/') ? pattern : "runners/#{pattern}"
      end

      def self.grant_actions(grant)
        return grant.actions_list if grant.respond_to?(:actions_list)

        actions = grant.respond_to?(:actions) ? grant.actions : []
        actions.is_a?(String) ? actions.split(',').map(&:strip) : Array(actions).map(&:to_s)
      end
    end
  end
end
