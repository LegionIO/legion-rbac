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
require 'legion/rbac/middleware'

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

      def setup
        Legion::Settings.merge_settings(:rbac, Legion::Rbac::Settings.default)
        @role_index = ConfigLoader.load_roles
        Legion::Settings[:rbac][:connected] = true
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
