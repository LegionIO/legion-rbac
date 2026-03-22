# frozen_string_literal: true

module Legion
  module Rbac
    class Middleware
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
        return @app.call(env) if skip_path?(path)
        return @app.call(env) if invoke_route?(path)

        principal = env['legion.principal']
        return denied_response('unauthenticated') unless principal

        perm = find_permission(env['REQUEST_METHOD'], path)
        return denied_response('unmapped route') unless perm

        result = PolicyEngine.evaluate(
          principal: principal,
          action:    perm[:action],
          resource:  perm[:resource]
        )

        if result[:allowed]
          @app.call(env)
        else
          Legion::Events.emit('rbac.deny', reason: result[:reason]) if defined?(Legion::Events)
          denied_response(result[:reason])
        end
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
        return ROUTE_PERMISSIONS[key] if ROUTE_PERMISSIONS.key?(key)

        ROUTE_PERMISSIONS.each do |pattern, perm|
          pattern_method, pattern_path = pattern.split(' ', 2)
          next unless pattern_method == method

          regex = pattern_path.gsub('*', '[^/]+')
          return perm if path.match?(/\A#{regex}\z/)
        end
        nil
      end

      def enforce?
        return false unless defined?(Legion::Settings)

        Legion::Settings[:rbac][:enforce]
      rescue StandardError => e
        Legion::Logging.warn("Legion::Rbac::Middleware#enforce? failed, defaulting to enforce: #{e.message}") if defined?(Legion::Logging)
        true
      end

      def denied_response(reason)
        body = Legion::JSON.dump({ error: 'access_denied', reason: reason })
        [403, { 'content-type' => 'application/json' }, [body]]
      end
    end
  end
end
