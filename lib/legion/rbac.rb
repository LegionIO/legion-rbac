# frozen_string_literal: true

require 'legion/rbac/version'

module Legion
  module Rbac
    class << self
      def setup
        Legion::Settings.merge_settings(:rbac, { connected: false }) unless Legion::Settings[:rbac]
        Legion::Settings[:rbac][:connected] = true
      end

      def shutdown
        Legion::Settings[:rbac][:connected] = false
      end
    end
  end
end
