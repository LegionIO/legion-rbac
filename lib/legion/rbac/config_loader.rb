# frozen_string_literal: true

require 'legion/rbac/role'

module Legion
  module Rbac
    module ConfigLoader
      def self.load_roles(roles_config = nil)
        roles_config ||= Legion::Settings[:rbac][:roles]
        roles_config.each_with_object({}) do |(name, config), index|
          index[name.to_sym] = Role.new(
            name:               name,
            description:        config[:description] || '',
            permissions:        config[:permissions] || [],
            deny:               config[:deny] || [],
            cross_team:         config[:cross_team] || false,
            capability_grants:  config[:capability_grants] || [],
            capability_denials: config[:capability_denials] || []
          )
        end
      end
    end
  end
end
