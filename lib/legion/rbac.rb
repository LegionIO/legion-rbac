# frozen_string_literal: true

require 'legion/logging'
require 'legion/rbac/version'
require 'legion/rbac/settings'
require 'legion/rbac/permission'
require 'legion/rbac/role'
require 'legion/rbac/config_loader'
require 'legion/rbac/principal'
require 'legion/rbac/policy_engine'
require 'legion/rbac/team_scope'
require 'legion/rbac/store'
require 'legion/rbac/kerberos_claims_mapper'
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

      include Legion::Logging::Helper

      def register_routes
        return unless defined?(Legion::API) && Legion::API.respond_to?(:register_library_routes)

        Legion::API.register_library_routes('rbac', Legion::Rbac::Routes)
        log.debug 'Legion::Rbac routes registered with API'
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'rbac.register_routes')
      end

      def setup
        log.info 'Legion::Rbac setup started'
        Legion::Settings.merge_settings(:rbac, Legion::Rbac::Settings.default)
        unless enabled?
          @role_index = nil
          Legion::Settings[:rbac][:connected] = false
          log.info 'Legion::Rbac disabled via settings'
          return
        end

        @role_index = ConfigLoader.load_roles
        Legion::Settings[:rbac][:connected] = true
        register_routes
        log.info "Legion::Rbac connected roles=#{@role_index&.size || 0}"
      end

      def shutdown
        @role_index = nil
        Legion::Settings[:rbac][:connected] = false
        log.info 'Legion::Rbac shutdown complete'
      end

      def enabled?
        return true unless defined?(Legion::Settings)

        Legion::Settings[:rbac]&.fetch(:enabled, true) != false
      end

      def authorize!(principal:, action:, resource:, **)
        result = PolicyEngine.evaluate(principal: principal, action: action, resource: resource, **)
        log.info("RBAC authorize principal=#{principal.id} action=#{action} resource=#{resource} allowed=#{result[:allowed]}")
        log.warn("RBAC authorize denied principal=#{principal.id} reason=#{result[:reason]}") unless result[:allowed]
        raise AccessDenied, result unless result[:allowed]

        result
      end

      def authorize_execution!(principal:, runner_class:, function:, target_team: nil, **)
        runner_path = build_runner_path(runner_class, function)
        log.info(
          "RBAC authorize_execution principal=#{principal.id} runner=#{runner_path} " \
          "target_team=#{target_team || principal.team || 'none'}"
        )
        result = PolicyEngine.evaluate_execution(
          principal:   principal,
          action:      :execute,
          resource:    runner_path,
          target_team: target_team,
          **
        )
        log.warn("RBAC authorize_execution denied principal=#{principal.id} reason=#{result[:reason]}") unless result[:allowed]
        raise AccessDenied, result unless result[:allowed]

        result
      end

      def audit_extension(extension_name:, source_path:, declared_capabilities: [])
        log.info("RBAC audit_extension extension=#{extension_name} source_path=#{source_path}")
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
        log.info(
          "RBAC audit_extension result extension=#{extension_name} allowed=#{result.allowed} " \
          "detected=#{result.detected_capabilities.size} undeclared=#{result.undeclared.size}"
        )
        result
      end

      def authorize_capability!(principal:, capability:, extension_name: nil)
        result = PolicyEngine.evaluate_capability(
          principal:      principal,
          capability:     capability,
          extension_name: extension_name
        )
        log.info(
          "RBAC authorize_capability principal=#{principal.id} capability=#{capability} " \
          "extension=#{extension_name} allowed=#{result[:allowed]}"
        )
        log.warn("RBAC authorize_capability denied principal=#{principal.id} reason=#{result[:reason]}") unless result[:allowed]
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
        runner_path = "runners/#{segments.join('/')}/#{function}"
        log.debug("RBAC runner path built class_name=#{class_name} runner_path=#{runner_path}")
        runner_path
      end
    end
  end
end
