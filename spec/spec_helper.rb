# frozen_string_literal: true

require 'bundler/setup'
require 'simplecov'
SimpleCov.start

require 'legion/settings'

Legion::Settings.load

require 'legion/rbac/settings'
Legion::Settings.merge_settings(:rbac, Legion::Rbac::Settings.default)

require 'legion/rbac'

RSpec.configure do |config|
  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
