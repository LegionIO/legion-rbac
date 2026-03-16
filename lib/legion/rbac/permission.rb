# frozen_string_literal: true

module Legion
  module Rbac
    class Permission
      attr_reader :resource_pattern, :actions

      def initialize(resource_pattern:, actions:)
        @resource_pattern = resource_pattern
        @actions = actions.map(&:to_s)
      end

      def matches?(resource, action)
        pattern_matches?(resource) && action_matches?(action)
      end

      private

      def action_matches?(action)
        actions.include?(action.to_s)
      end

      def pattern_matches?(resource)
        regex = pattern_to_regex(resource_pattern)
        resource.match?(regex)
      end

      def pattern_to_regex(pattern)
        parts = pattern.split('/').map do |segment|
          case segment
          when '*'  then '.*'
          when '+'  then '[^/]+'
          else Regexp.escape(segment)
          end
        end
        Regexp.new("\\A#{parts.join('/')}\\z")
      end
    end

    class DenyRule
      attr_reader :resource_pattern, :above_level

      def initialize(resource_pattern:, above_level: nil)
        @resource_pattern = resource_pattern
        @above_level = above_level
      end

      def matches?(resource, **opts)
        return false unless pattern_matches?(resource)
        return true if above_level.nil?

        level = opts[:level]
        return false if level.nil?

        level > above_level
      end

      private

      def pattern_matches?(resource)
        regex = pattern_to_regex(resource_pattern)
        resource.match?(regex)
      end

      def pattern_to_regex(pattern)
        parts = pattern.split('/').map do |segment|
          case segment
          when '*'  then '.*'
          when '+'  then '[^/]+'
          else Regexp.escape(segment)
          end
        end
        Regexp.new("\\A#{parts.join('/')}\\z")
      end
    end
  end
end
