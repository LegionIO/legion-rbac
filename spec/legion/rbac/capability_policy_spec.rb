# frozen_string_literal: true

require 'tmpdir'
require 'fileutils'

RSpec.describe Legion::Rbac::PolicyEngine, '.evaluate_capability' do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  def principal_with(roles:)
    Legion::Rbac::Principal.new(id: 'test', roles: roles)
  end

  context 'admin role' do
    it 'grants shell_execute' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['admin']),
        capability: :shell_execute,
        role_index: role_index
      )
      expect(result[:allowed]).to be true
    end

    it 'grants code_eval' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['admin']),
        capability: :code_eval,
        role_index: role_index
      )
      expect(result[:allowed]).to be true
    end
  end

  context 'worker role' do
    it 'grants network_outbound' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['worker']),
        capability: :network_outbound,
        role_index: role_index
      )
      expect(result[:allowed]).to be true
    end

    it 'denies shell_execute' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['worker']),
        capability: :shell_execute,
        role_index: role_index
      )
      expect(result[:allowed]).to be false
      expect(result[:reason]).to include('denied by role policy')
    end

    it 'denies code_eval' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['worker']),
        capability: :code_eval,
        role_index: role_index
      )
      expect(result[:allowed]).to be false
      expect(result[:reason]).to include('denied by role policy')
    end
  end

  context 'supervisor role' do
    it 'grants shell_execute' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['supervisor']),
        capability: :shell_execute,
        role_index: role_index
      )
      expect(result[:allowed]).to be true
    end

    it 'denies code_eval' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['supervisor']),
        capability: :code_eval,
        role_index: role_index
      )
      expect(result[:allowed]).to be false
    end
  end

  context 'governance-observer role' do
    it 'denies all capabilities' do
      %i[shell_execute code_eval network_outbound filesystem_write].each do |cap|
        result = described_class.evaluate_capability(
          principal:  principal_with(roles: ['governance-observer']),
          capability: cap,
          role_index: role_index
        )
        expect(result[:allowed]).to be false
      end
    end
  end

  context 'no roles' do
    it 'denies with no roles assigned reason' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: []),
        capability: :shell_execute,
        role_index: role_index
      )
      expect(result[:allowed]).to be false
      expect(result[:reason]).to eq('no roles assigned')
    end
  end

  context 'enforce: false' do
    it 'returns allowed: true with would_deny flag' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['worker']),
        capability: :shell_execute,
        role_index: role_index,
        enforce:    false
      )
      expect(result[:allowed]).to be true
      expect(result[:would_deny]).to be true
    end
  end

  context 'with extension_name' do
    it 'includes extension_name in result' do
      result = described_class.evaluate_capability(
        principal:      principal_with(roles: ['admin']),
        capability:     :shell_execute,
        extension_name: 'lex-codegen',
        role_index:     role_index
      )
      expect(result[:extension_name]).to eq('lex-codegen')
    end
  end

  context 'capability not granted and not denied' do
    it 'reports not granted' do
      result = described_class.evaluate_capability(
        principal:  principal_with(roles: ['worker']),
        capability: :some_unknown_cap,
        role_index: role_index
      )
      expect(result[:allowed]).to be false
      expect(result[:reason]).to include('not granted')
    end
  end
end

RSpec.describe Legion::Rbac do
  before { described_class.setup }

  describe '.audit_extension' do
    let(:tmpdir) { Dir.mktmpdir('audit-ext') }

    after do
      FileUtils.remove_entry(tmpdir)
      Legion::Rbac::CapabilityRegistry.clear!
    end

    it 'audits and registers in capability registry' do
      File.write(File.join(tmpdir, 'runner.rb'), "system('deploy')")
      result = described_class.audit_extension(
        extension_name:        'lex-deployer',
        source_path:           tmpdir,
        declared_capabilities: [:shell_execute]
      )
      expect(result.blocked?).to be false
      expect(Legion::Rbac::CapabilityRegistry.for_extension('lex-deployer')).to include(:shell_execute)
    end

    it 'blocks undeclared capabilities in enforce mode' do
      # Test file contains a dangerous pattern (Kernel.eval) without declaration
      File.write(File.join(tmpdir, 'runner.rb'), 'Kernel.eval(code)')
      result = described_class.audit_extension(
        extension_name:        'lex-bad',
        source_path:           tmpdir,
        declared_capabilities: []
      )
      expect(result.blocked?).to be true
    end
  end

  describe '.authorize_capability!' do
    it 'raises AccessDenied when capability is denied' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'])
      expect do
        described_class.authorize_capability!(principal: principal, capability: :shell_execute)
      end.to raise_error(Legion::Rbac::AccessDenied, /capability shell_execute/)
    end

    it 'returns result when capability is granted' do
      principal = Legion::Rbac::Principal.new(id: 'admin-1', roles: ['admin'])
      result = described_class.authorize_capability!(principal: principal, capability: :shell_execute)
      expect(result[:allowed]).to be true
    end
  end
end

RSpec.describe Legion::Rbac::Role do
  describe '#capability_allowed?' do
    it 'returns true for granted capability' do
      role = described_class.new(
        name:              'deployer',
        capability_grants: %w[shell_execute network_outbound]
      )
      expect(role.capability_allowed?(:shell_execute)).to be true
    end

    it 'returns false for denied capability' do
      role = described_class.new(
        name:               'restricted',
        capability_grants:  %w[shell_execute],
        capability_denials: %w[code_eval]
      )
      expect(role.capability_allowed?(:code_eval)).to be false
    end

    it 'returns false for ungranted capability' do
      role = described_class.new(name: 'basic', capability_grants: %w[network_outbound])
      expect(role.capability_allowed?(:shell_execute)).to be false
    end

    it 'denial takes precedence over grant' do
      role = described_class.new(
        name:               'conflicted',
        capability_grants:  %w[shell_execute],
        capability_denials: %w[shell_execute]
      )
      expect(role.capability_allowed?(:shell_execute)).to be false
    end
  end
end
