# frozen_string_literal: true

require 'bundler/setup'
require 'legion/logging'
require 'simplecov'
SimpleCov.start

require 'legion/settings'

Legion::Settings.loader = Legion::Settings::Loader.new
Legion::Logging.setup(level: 'fatal', async: false)

require 'legion/rbac/settings'
Legion::Settings.merge_settings(:rbac, Legion::Rbac::Settings.default)

require 'legion/rbac'

RSpec.shared_context 'with an audit event subscriber' do
  let(:observed_events) { [] }

  before do
    subscriber = observed_events
    event_bus = Module.new
    event_bus.define_singleton_method(:emit) do |name, **payload|
      subscriber << [name, payload]
    end
    stub_const('Legion::Events', event_bus)
  end
end

RSpec.configure do |config|
  config.around do |example|
    original_settings = Legion::Settings[:rbac]
    Legion::Settings.loader.settings[:rbac] = Legion::Rbac::Settings.default
    Legion::Rbac.setup
    example.run
  ensure
    Legion::Settings.loader.settings[:rbac] = original_settings
  end

  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
