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
        return @app.call(env) unless enforce?

        path = env['PATH_INFO']
        if skip_path?(path)
          log.debug("RBAC middleware bypass path=#{path} reason=skip_path")
          return @app.call(env)
        end
        if invoke_route?(path)
          log.debug("RBAC middleware bypass path=#{path} reason=invoke_route")
          return @app.call(env)
        end

        principal = env['legion.principal']
        unless principal
          log.warn("RBAC middleware denied method=#{env['REQUEST_METHOD']} path=#{path} reason=unauthenticated")
          return denied_response('unauthenticated')
        end

        perm = find_permission(env['REQUEST_METHOD'], path)
        unless perm
          log.warn("RBAC middleware denied method=#{env['REQUEST_METHOD']} path=#{path} reason=unmapped_route")
          return denied_response('unmapped route')
        end
        perm = effective_permission(env, perm)
        result = policy_result(env, principal, perm)

        if result[:allowed]
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

      def enforce?
        return false unless defined?(Legion::Settings)
        return false if Legion::Settings[:rbac]&.fetch(:enabled, true) == false

        Legion::Settings[:rbac][:enforce]
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'rbac.middleware.enforce')
        true
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
        routes = route_permissions
        cache_key = routes.hash
        return @compiled_route_permissions if @compiled_route_permissions_key == cache_key

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
        @compiled_route_permissions_key = cache_key
        @compiled_route_permissions
      end

      def route_permissions
        DEFAULT_ROUTE_PERMISSIONS.merge(custom_route_permissions)
      end

      def custom_route_permissions
        overrides = Legion::Settings[:rbac]&.dig(:route_permissions)
        return {} unless overrides.is_a?(Hash)

        overrides.each_with_object({}) do |(pattern, permission), normalized|
          normalized[pattern.to_s] = normalize_permission(permission)
        end
      end

      def normalize_permission(permission)
        raise ArgumentError, 'Invalid rbac.route_permissions entry: permission must be a hash' unless permission.is_a?(Hash)

        action = permission[:action] || permission['action']
        raise ArgumentError, 'Invalid rbac.route_permissions entry: action is required' if action.nil?
        raise ArgumentError, 'Invalid rbac.route_permissions entry: action must be a string or symbol' unless action.respond_to?(:to_sym)

        {
          resource: permission[:resource] || permission['resource'],
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
