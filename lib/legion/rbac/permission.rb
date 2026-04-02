# frozen_string_literal: true

require 'legion/logging'

module Legion
  module Rbac
    class Permission
      include Legion::Logging::Helper

      attr_reader :resource_pattern, :actions

      def initialize(resource_pattern:, actions:)
        @resource_pattern = resource_pattern
        @actions = actions.map(&:to_s)
        @resource_regex = self.class.send(:pattern_to_regex, resource_pattern)
      end

      def matches?(resource, action)
        matched = pattern_matches?(resource) && action_matches?(action)
        log.debug("RBAC permission matched pattern=#{resource_pattern} action=#{action} resource=#{resource}") if matched
        matched
      end

      private

      def action_matches?(action)
        actions.include?(action.to_s)
      end

      def pattern_matches?(resource)
        resource.match?(@resource_regex)
      end

      def self.pattern_to_regex(pattern)
        parts = pattern.split('/').map do |segment|
          case segment
          when '*'  then '.*'
          when '+'  then '[^/]+'
          else Regexp.escape(segment)
          end
        end
        Regexp.new("\\A#{parts.join('/')}\\z")
      end
      private_class_method :pattern_to_regex
    end

    class DenyRule
      include Legion::Logging::Helper

      attr_reader :resource_pattern, :above_level

      def initialize(resource_pattern:, above_level: nil)
        @resource_pattern = resource_pattern
        @above_level = above_level
        @resource_regex = self.class.send(:pattern_to_regex, resource_pattern)
      end

      def matches?(resource, **opts)
        return false unless pattern_matches?(resource)

        if above_level.nil?
          log.debug("RBAC deny rule matched pattern=#{resource_pattern} resource=#{resource}")
          return true
        end

        level = opts[:level]
        return false if level.nil?

        matched = level > above_level
        log.debug("RBAC deny rule matched pattern=#{resource_pattern} resource=#{resource} level=#{level} above_level=#{above_level}") if matched
        matched
      end

      private

      def pattern_matches?(resource)
        resource.match?(@resource_regex)
      end

      def self.pattern_to_regex(pattern)
        parts = pattern.split('/').map do |segment|
          case segment
          when '*'  then '.*'
          when '+'  then '[^/]+'
          else Regexp.escape(segment)
          end
        end
        Regexp.new("\\A#{parts.join('/')}\\z")
      end
      private_class_method :pattern_to_regex
    end
  end
end
