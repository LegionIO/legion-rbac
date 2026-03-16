# frozen_string_literal: true

require 'legion/rbac/version'
require 'legion/rbac/settings'
require 'legion/rbac/permission'
require 'legion/rbac/role'
require 'legion/rbac/config_loader'

module Legion
  module Rbac
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
    end
  end
end
