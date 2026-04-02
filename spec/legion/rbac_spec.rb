# frozen_string_literal: true

require 'open3'
require 'rbconfig'

RSpec.describe Legion::Rbac do
  it 'has a version number' do
    expect(Legion::Rbac::VERSION).not_to be_nil
  end

  it 'loads KerberosClaimsMapper from the gem entrypoint' do
    expect(defined?(Legion::Rbac::KerberosClaimsMapper)).to eq('constant')
  end

  it 'boots from the gem entrypoint without preloading legion/logging' do
    root = File.expand_path('../..', __dir__)
    script = <<~RUBY
      require 'bundler/setup'
      require 'legion/settings'
      Legion::Settings.load
      require 'legion/rbac'
      Legion::Rbac.setup
      puts 'rbac_boot_ok'
    RUBY

    stdout = nil
    stderr = nil
    status = nil

    Bundler.with_unbundled_env do
      stdout, stderr, status = Open3.capture3(
        { 'BUNDLE_GEMFILE' => File.join(root, 'Gemfile') },
        'bundle', 'exec', RbConfig.ruby, '-Ilib', '-e', script,
        chdir: root
      )
    end

    expect(status.success?).to be(true), "stdout:\n#{stdout}\n\nstderr:\n#{stderr}"
    expect(stdout).to include('rbac_boot_ok')
  end

  describe '.register_routes' do
    it 'handles route registration exceptions' do
      stub_const('Legion::API', Module.new)
      allow(Legion::API).to receive(:register_library_routes).and_raise(StandardError, 'boom')
      allow(described_class).to receive(:handle_exception)

      described_class.register_routes

      expect(described_class).to have_received(:handle_exception).with(
        instance_of(StandardError),
        level:     :warn,
        operation: 'rbac.register_routes'
      )
    end
  end

  it 'marks connected on setup' do
    described_class.setup
    expect(Legion::Settings[:rbac][:connected]).to be true
  end

  it 'marks disconnected on shutdown' do
    described_class.setup
    described_class.shutdown
    expect(Legion::Settings[:rbac][:connected]).to be false
  end
end
