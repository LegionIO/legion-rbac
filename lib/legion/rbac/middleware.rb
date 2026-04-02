# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Rbac
    class Middleware
      include Legion::Logging::Helper

      SKIP_PATHS = %w[/api/health /api/ready /api/openapi.json].freeze

      ROUTE_PERMISSIONS = {
        'GET /api/tasks'          => { resource: 'tasks/*', action: :read },
        'POST /api/tasks'         => { resource: 'tasks/*', action: :create },
        'DELETE /api/tasks/*'     => { resource: 'tasks/*', action: :delete },
        'GET /api/workers'        => { resource: 'workers/team', action: :read },
        'POST /api/workers'       => { resource: 'workers/team', action: :create },
        'PATCH /api/workers/*'    => { resource: 'workers/team', action: :lifecycle },
        'PUT /api/settings/*'     => { resource: 'settings/*', action: :manage },
        'POST /api/transport/*'   => { resource: 'transport/*', action: :manage },
        'GET /api/events'         => { resource: 'events/*', action: :read },
        'GET /api/events/*'       => { resource: 'events/*', action: :read },
        'GET /api/extensions'     => { resource: 'extensions/*', action: :read },
        'GET /api/extensions/*'   => { resource: 'extensions/*', action: :read },
        'GET /api/schedules'      => { resource: 'schedules/*', action: :read },
        'POST /api/schedules'     => { resource: 'schedules/*', action: :create },
        'PUT /api/schedules/*'    => { resource: 'schedules/*', action: :update },
        'DELETE /api/schedules/*' => { resource: 'schedules/*', action: :delete }
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

        result = PolicyEngine.evaluate(
          principal: principal,
          action:    perm[:action],
          resource:  perm[:resource]
        )

        if result[:allowed]
          log.info(
            "RBAC middleware allowed principal=#{principal.id} method=#{env['REQUEST_METHOD']} " \
            "path=#{path} resource=#{perm[:resource]} action=#{perm[:action]}"
          )
          @app.call(env)
        else
          Legion::Events.emit('rbac.deny', reason: result[:reason]) if defined?(Legion::Events)
          log.warn(
            "RBAC middleware denied principal=#{principal.id} method=#{env['REQUEST_METHOD']} " \
            "path=#{path} reason=#{result[:reason]}"
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
        key = "#{method} #{path}"
        if ROUTE_PERMISSIONS.key?(key)
          log.debug("RBAC middleware route_permission method=#{method} path=#{path} match=exact")
          return ROUTE_PERMISSIONS[key]
        end

        ROUTE_PERMISSIONS.each do |pattern, perm|
          pattern_method, pattern_path = pattern.split(' ', 2)
          next unless pattern_method == method

          regex = pattern_path.gsub('*', '[^/]+')
          if path.match?(/\A#{regex}\z/)
            log.debug("RBAC middleware route_permission method=#{method} path=#{path} match=pattern pattern=#{pattern}")
            return perm
          end
        end
        nil
      end

      def enforce?
        return false unless defined?(Legion::Settings)

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
    end
  end
end
