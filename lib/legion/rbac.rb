# frozen_string_literal: true

require 'legion/rbac/version'
require 'legion/rbac/settings'
require 'legion/rbac/permission'
require 'legion/rbac/role'
require 'legion/rbac/config_loader'
require 'legion/rbac/principal'
require 'legion/rbac/policy_engine'
require 'legion/rbac/team_scope'
require 'legion/rbac/store'
require 'legion/rbac/entra_claims_mapper'
require 'legion/rbac/middleware'
require 'legion/rbac/routes'
require 'legion/rbac/capability_audit'
require 'legion/rbac/capability_registry'

module Legion
  module Rbac
    class AccessDenied < StandardError
      attr_reader :result

      def initialize(result)
        @result = result
        super("Access denied: #{result[:reason]} (#{result[:resource]} / #{result[:action]})")
      end
    end

    class << self
      attr_reader :role_index

      def register_routes
        return unless defined?(Legion::API) && Legion::API.respond_to?(:register_library_routes)

        Legion::API.register_library_routes('rbac', Legion::Rbac::Routes)
        Legion::Logging.debug 'Legion::Rbac routes registered with API' if defined?(Legion::Logging)
      rescue StandardError => e
        Legion::Logging.warn "Legion::Rbac route registration failed: #{e.message}" if defined?(Legion::Logging)
      end

      def setup
        Legion::Settings.merge_settings(:rbac, Legion::Rbac::Settings.default)
        @role_index = ConfigLoader.load_roles
        Legion::Settings[:rbac][:connected] = true
        register_routes
      end

      def shutdown
        @role_index = nil
        Legion::Settings[:rbac][:connected] = false
      end

      def authorize!(principal:, action:, resource:, **)
        result = PolicyEngine.evaluate(principal: principal, action: action, resource: resource, **)
        raise AccessDenied, result unless result[:allowed]

        result
      end

      def authorize_execution!(principal:, runner_class:, function:, **)
        runner_path = build_runner_path(runner_class, function)
        authorize!(principal: principal, action: :execute, resource: runner_path, **)
      end

      def audit_extension(extension_name:, source_path:, declared_capabilities: [])
        result = CapabilityAudit.audit(
          extension_name:        extension_name,
          source_path:           source_path,
          declared_capabilities: declared_capabilities
        )
        CapabilityRegistry.register(
          extension_name,
          capabilities: result.detected_capabilities,
          audit_result: result
        )
        result
      end

      def authorize_capability!(principal:, capability:, extension_name: nil)
        result = PolicyEngine.evaluate_capability(
          principal:      principal,
          capability:     capability,
          extension_name: extension_name
        )
        raise AccessDenied, result unless result[:allowed]

        result
      end

      private

      def build_runner_path(runner_class, function)
        class_name = runner_class.is_a?(String) ? runner_class : runner_class.name
        parts = class_name.gsub('::', '/').split('/')
        lex_parts = parts.select { |p| p != 'Legion' && p != 'Extensions' }
        segments = lex_parts.map.with_index do |p, i|
          snake = p.gsub(/([A-Z])/, '_\1').sub(/^_/, '').downcase
          i.zero? ? snake.tr('_', '-') : snake
        end
        "runners/#{segments.join('/')}/#{function}"
      end
    end
  end
end
