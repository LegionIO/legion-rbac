# frozen_string_literal: true

RSpec.describe Legion::Rbac::Principal do
  describe '.from_claims' do
    it 'creates a worker principal from worker scope' do
      claims = { scope: 'worker', worker_id: 'w-123', roles: ['worker'], team: 'alpha' }
      principal = described_class.from_claims(claims)
      expect(principal.type).to eq(:worker)
      expect(principal.id).to eq('w-123')
      expect(principal.roles).to eq(['worker'])
      expect(principal.team).to eq('alpha')
    end

    it 'creates a human principal from non-worker scope' do
      claims = { scope: 'human', sub: 'msid-456', roles: %w[supervisor admin], team: 'beta' }
      principal = described_class.from_claims(claims)
      expect(principal.type).to eq(:human)
      expect(principal.id).to eq('msid-456')
      expect(principal.roles).to eq(%w[supervisor admin])
    end
  end

  describe '.local_admin' do
    it 'returns a principal with the default local role' do
      principal = described_class.local_admin
      expect(principal.id).to eq('local')
      expect(principal.roles).to include('admin')
    end
  end

  describe '.anonymous' do
    it 'returns a principal with no roles' do
      principal = described_class.anonymous
      expect(principal.id).to eq('anonymous')
      expect(principal.roles).to be_empty
    end
  end
end
