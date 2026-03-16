# frozen_string_literal: true

require 'legion/rbac/permission'

module Legion
  module Rbac
    class Role
      attr_reader :name, :description, :permissions, :deny_rules, :cross_team

      def initialize(name:, description: '', permissions: [], deny: [], cross_team: false)
        @name = name.to_s
        @description = description
        @permissions = permissions.map do |p|
          Permission.new(resource_pattern: p[:resource], actions: p[:actions])
        end
        @deny_rules = deny.map do |d|
          DenyRule.new(resource_pattern: d[:resource], above_level: d[:above_level])
        end
        @cross_team = cross_team
      end

      def cross_team?
        @cross_team == true
      end
    end
  end
end
