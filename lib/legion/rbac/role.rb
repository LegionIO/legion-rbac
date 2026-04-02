# frozen_string_literal: true

require 'legion/logging'
require 'legion/rbac/permission'

module Legion
  module Rbac
    class Role
      include Legion::Logging::Helper

      attr_reader :name, :description, :permissions, :deny_rules, :cross_team,
                  :capability_grants, :capability_denials

      def initialize(name:, description: '', permissions: [], deny: [], cross_team: false,
                     capability_grants: [], capability_denials: [])
        @name = name.to_s
        @description = description
        @permissions = permissions.map do |p|
          Permission.new(resource_pattern: p[:resource], actions: p[:actions])
        end
        @deny_rules = deny.map do |d|
          DenyRule.new(resource_pattern: d[:resource], above_level: d[:above_level])
        end
        @cross_team = cross_team
        @capability_grants = Array(capability_grants).map(&:to_sym)
        @capability_denials = Array(capability_denials).map(&:to_sym)
        log.debug(
          "RBAC role initialized name=#{@name} permissions=#{@permissions.size} deny_rules=#{@deny_rules.size} " \
          "cross_team=#{@cross_team} capability_grants=#{@capability_grants.size} capability_denials=#{@capability_denials.size}"
        )
      end

      def cross_team?
        @cross_team == true
      end

      def capability_allowed?(capability)
        cap = capability.to_sym
        if @capability_denials.include?(cap)
          log.debug("RBAC role capability name=#{@name} capability=#{cap} allowed=false reason=denied")
          return false
        end

        allowed = @capability_grants.include?(cap)
        log.debug("RBAC role capability name=#{@name} capability=#{cap} allowed=#{allowed}")
        allowed
      end
    end
  end
end
