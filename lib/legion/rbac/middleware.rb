# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    class Middleware
      include Legion::Logging::Helper

      SKIP_PATHS = %w[/api/health /api/ready /api/openapi.json].freeze

      DEFAULT_ROUTE_PERMISSIONS = {
        'GET /api/tasks'                       => { resource: 'tasks/*', action: :read },
        'POST /api/tasks'                      => { resource: 'tasks/*', action: :create },
        'DELETE /api/tasks/*'                  => { resource: 'tasks/*', action: :delete },
        'GET /api/workers'                     => { resource: 'workers/team', action: :read },
        'POST /api/workers'                    => { resource: 'workers/team', action: :create },
        'PATCH /api/workers/*'                 => { resource: 'workers/team', action: :lifecycle },
        'PUT /api/settings/*'                  => { resource: 'settings/*', action: :manage },
        'POST /api/transport/*'                => { resource: 'transport/*', action: :manage },
        'GET /api/events'                      => { resource: 'events/*', action: :read },
        'GET /api/events/*'                    => { resource: 'events/*', action: :read },
        'GET /api/extensions'                  => { resource: 'extensions/*', action: :read },
        'GET /api/extensions/*'                => { resource: 'extensions/*', action: :read },
        'GET /api/schedules'                   => { resource: 'schedules/*', action: :read },
        'POST /api/schedules'                  => { resource: 'schedules/*', action: :create },
        'PUT /api/schedules/*'                 => { resource: 'schedules/*', action: :update },
        'DELETE /api/schedules/*'              => { resource: 'schedules/*', action: :delete },
        'GET /api/rbac/roles'                  => { resource: 'settings/rbac', action: :read },
        'GET /api/rbac/roles/*'                => { resource: 'settings/rbac', action: :read },
        'POST /api/rbac/check'                 => { resource: 'settings/rbac', action: :read },
        'GET /api/rbac/assignments'            => { resource: 'settings/rbac', action: :read },
        'POST /api/rbac/assignments'           => { resource: 'settings/rbac', action: :manage },
        'DELETE /api/rbac/assignments/*'       => { resource: 'settings/rbac', action: :manage },
        'GET /api/rbac/grants'                 => { resource: 'settings/rbac', action: :read },
        'POST /api/rbac/grants'                => { resource: 'settings/rbac', action: :manage },
        'DELETE /api/rbac/grants/*'            => { resource: 'settings/rbac', action: :manage },
        'GET /api/rbac/grants/cross-team'      => { resource: 'settings/rbac', action: :read },
        'POST /api/rbac/grants/cross-team'     => { resource: 'settings/rbac', action: :manage },
        'DELETE /api/rbac/grants/cross-team/*' => { resource: 'settings/rbac', action: :manage }
      }.freeze

      INVOKE_PATTERN = %r{\A/api/extensions/[^/]+/runners/[^/]+/functions/[^/]+/invoke\z}

      def initialize(app)
        @app = app
      end

      def call(env)
        return @app.call(env) unless Legion::Rbac.enabled?

        path = env['PATH_INFO']
        return bypass(env, path, :skip_path) if skip_path?(path)
        return bypass(env, path, :invoke_route) if invoke_route?(path)

        principal = env['legion.rbac_principal'] || env['legion.principal']
        return guard_missing(env, path, 'unauthenticated') unless principal

        perm = find_permission(env['REQUEST_METHOD'], path)
        return guard_missing(env, path, 'unmapped route') unless perm

        dispatch_policy(env, principal, effective_permission(env, perm))
      rescue StandardError => e
        handle_exception(
          e,
          level:     :error,
          operation: 'rbac.middleware.call',
          method:    env['REQUEST_METHOD'],
          path:      env['PATH_INFO']
        )
        raise
      end

      private

      def skip_path?(path)
        SKIP_PATHS.include?(path)
      end

      def invoke_route?(path)
        INVOKE_PATTERN.match?(path)
      end

      def find_permission(method, path)
        compiled_route_permissions.each do |entry|
          next unless entry[:method] == method

          if entry[:exact]
            if entry[:exact] == path
              log.debug("RBAC middleware route_permission method=#{method} path=#{path} match=exact")
              return entry[:permission]
            end
          elsif path.match?(entry[:regex])
            log.debug(
              "RBAC middleware route_permission method=#{method} path=#{path} match=pattern pattern=#{entry[:pattern]}"
            )
            return entry[:permission]
          end
        end
        nil
      end

      def bypass(env, path, reason)
        log.debug("RBAC middleware bypass path=#{path} reason=#{reason}")
        @app.call(env)
      end

      def guard_missing(env, path, reason)
        log.warn("RBAC middleware denied method=#{env['REQUEST_METHOD']} path=#{path} reason=#{reason.tr(' ', '_')}")
        Legion::Rbac.enforcing? ? denied_response(reason) : audit_and_proceed(env, reason)
      end

      def dispatch_policy(env, principal, perm)
        result = policy_result(env, principal, perm)
        path = env['PATH_INFO']

        if result[:would_deny]
          log.info(
            "[RBAC audit] would_deny: #{result[:reason]} principal=#{result[:principal_id]} " \
            "action=#{result[:action]} resource=#{result[:resource]}"
          )
          @app.call(env)
        elsif result[:allowed]
          log.info(
            "RBAC middleware allowed principal=#{principal.id} method=#{env['REQUEST_METHOD']} " \
            "path=#{path} resource=#{perm[:resource]} action=#{perm[:action]} " \
            "target_team=#{env['legion.rbac.target_team'] || 'none'}"
          )
          @app.call(env)
        else
          log.warn(
            "RBAC middleware denied principal=#{principal.id} method=#{env['REQUEST_METHOD']} " \
            "path=#{path} resource=#{perm[:resource]} action=#{perm[:action]} " \
            "target_team=#{env['legion.rbac.target_team'] || 'none'} reason=#{result[:reason]}"
          )
          denied_response(result[:reason])
        end
      end

      def audit_and_proceed(env, reason)
        log.info(
          "[RBAC audit] would_deny: #{reason} method=#{env['REQUEST_METHOD']} path=#{env['PATH_INFO']}"
        )
        @app.call(env)
      end

      def denied_response(reason)
        log.debug("RBAC middleware denied_response reason=#{reason}")
        body = Legion::JSON.dump({ error: 'access_denied', reason: reason })
        [403, { 'content-type' => 'application/json' }, [body]]
      end

      def effective_permission(env, permission)
        resource = env['legion.rbac.resource'] || permission[:resource]
        action = normalize_action(env['legion.rbac.action']) || permission[:action]
        return permission if resource == permission[:resource] && action == permission[:action]

        log.info(
          "RBAC middleware permission_override method=#{env['REQUEST_METHOD']} path=#{env['PATH_INFO']} " \
          "resource=#{resource} action=#{action}"
        )
        permission.merge(resource: resource, action: action)
      end

      def normalize_action(action)
        action&.to_sym
      end

      def policy_result(env, principal, permission)
        PolicyEngine.evaluate(
          principal:   principal,
          action:      permission[:action],
          resource:    permission[:resource],
          target_team: env['legion.rbac.target_team'],
          **request_context(env)
        )
      end

      def request_context(env)
        {
          method:         env['REQUEST_METHOD'],
          path:           env['PATH_INFO'],
          source:         request_source(env),
          correlation_id: request_correlation_id(env)
        }.compact
      end

      def request_source(env)
        env['legion.rbac.source'] || env['legion.request_source'] || env['HTTP_X_LEGION_SOURCE'] || 'rbac.middleware'
      end

      def request_correlation_id(env)
        env['legion.correlation_id'] || env['HTTP_X_REQUEST_ID'] || env['HTTP_X_CORRELATION_ID'] ||
          env['action_dispatch.request_id'] || env['REQUEST_ID']
      end

      def compiled_route_permissions
        raw = Legion::Settings[:rbac]&.dig(:route_permissions)
        return @compiled_route_permissions if @compiled_route_permissions_settings_id == raw.object_id

        routes = DEFAULT_ROUTE_PERMISSIONS.merge(build_custom_route_permissions(raw))
        @compiled_route_permissions = routes.map do |pattern, permission|
          http_method, path_pattern = pattern.split(' ', 2)
          entry = {
            method:     http_method,
            pattern:    pattern,
            permission: permission
          }

          if path_pattern.include?('*')
            entry[:regex] = route_pattern_regex(path_pattern)
          else
            entry[:exact] = path_pattern
          end

          entry
        end.freeze
        @compiled_route_permissions_settings_id = raw.object_id
        @compiled_route_permissions
      end

      def build_custom_route_permissions(overrides)
        return {} unless overrides.is_a?(Hash)

        overrides.each_with_object({}) do |(pattern, permission), normalized|
          pattern_str = pattern.to_s
          parts = pattern_str.split(' ', 2)
          unless parts.length == 2 && !parts[0].empty? && parts[1].start_with?('/')
            log.warn("RBAC invalid route_permissions pattern=#{pattern_str.inspect} skipping")
            next
          end

          normalized[pattern_str] = normalize_permission(permission)
        end
      end

      def normalize_permission(permission)
        raise ArgumentError, 'Invalid rbac.route_permissions entry: permission must be a hash' unless permission.is_a?(Hash)

        resource = permission[:resource] || permission['resource']
        raise ArgumentError, 'Invalid rbac.route_permissions entry: resource is required' if resource.nil?
        raise ArgumentError, 'Invalid rbac.route_permissions entry: resource must be a string' unless resource.is_a?(String)

        action = permission[:action] || permission['action']
        raise ArgumentError, 'Invalid rbac.route_permissions entry: action is required' if action.nil?
        raise ArgumentError, 'Invalid rbac.route_permissions entry: action must be a string or symbol' unless action.respond_to?(:to_sym)

        {
          resource: resource,
          action:   action.to_sym
        }
      end

      def route_pattern_regex(path_pattern)
        segments = path_pattern.split('/').map { |segment| segment == '*' ? '[^/]+' : Regexp.escape(segment) }
        /\A#{segments.join('/')}\z/
      end
    end
  end
end
