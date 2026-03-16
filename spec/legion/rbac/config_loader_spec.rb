# frozen_string_literal: true

RSpec.describe Legion::Rbac::ConfigLoader do
  describe '.load_roles' do
    subject(:roles) { described_class.load_roles }

    it 'returns a hash keyed by symbol name' do
      expect(roles).to be_a(Hash)
      expect(roles.keys).to include(:worker, :supervisor, :admin, :'governance-observer')
    end

    it 'returns Role objects' do
      expect(roles[:worker]).to be_a(Legion::Rbac::Role)
    end

    it 'loads worker permissions' do
      worker = roles[:worker]
      expect(worker.permissions.any? { |p| p.resource_pattern == 'runners/*' }).to be true
    end

    it 'loads worker deny rules' do
      worker = roles[:worker]
      expect(worker.deny_rules.any? { |d| d.resource_pattern == 'runners/lex-extinction/*' }).to be true
    end

    it 'sets cross_team on admin' do
      expect(roles[:admin].cross_team?).to be true
    end

    it 'accepts custom roles config' do
      custom = {
        tester: {
          description: 'Test role',
          permissions: [{ resource: 'tasks/*', actions: %w[read] }],
          deny:        []
        }
      }
      result = described_class.load_roles(custom)
      expect(result[:tester]).to be_a(Legion::Rbac::Role)
      expect(result[:tester].name).to eq('tester')
    end
  end
end
