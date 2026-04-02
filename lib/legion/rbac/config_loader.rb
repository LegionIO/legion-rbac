# frozen_string_literal: true

require 'legion/logging'
require 'legion/rbac/role'

module Legion
  module Rbac
    module ConfigLoader
      extend Legion::Logging::Helper

      def self.load_roles(roles_config = nil)
        roles_config ||= Legion::Settings[:rbac][:roles]
        roles = roles_config.each_with_object({}) do |(name, config), index|
          index[name.to_sym] = Role.new(
            name:               name,
            description:        config[:description] || '',
            permissions:        config[:permissions] || [],
            deny:               config[:deny] || [],
            cross_team:         config[:cross_team] || false,
            capability_grants:  config[:capability_grants] || [],
            capability_denials: config[:capability_denials] || []
          )
          log.debug("RBAC role loaded name=#{name} permissions=#{config[:permissions]&.size || 0} deny=#{config[:deny]&.size || 0}")
        end
        log.info("RBAC roles loaded count=#{roles.size}")
        roles
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.config_loader.load_roles')
        raise
      end
    end
  end
end
