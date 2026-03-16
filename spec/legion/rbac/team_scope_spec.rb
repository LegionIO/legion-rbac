# frozen_string_literal: true

RSpec.describe Legion::Rbac::TeamScope do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  def principal_with(roles:, team: nil)
    Legion::Rbac::Principal.new(id: 'test', roles: roles, team: team)
  end

  describe '.allowed?' do
    it 'allows same team access' do
      p = principal_with(roles: ['worker'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: 'alpha', role_index: role_index)).to be true
    end

    it 'denies cross-team for worker' do
      p = principal_with(roles: ['worker'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: 'beta', role_index: role_index)).to be false
    end

    it 'denies cross-team for supervisor' do
      p = principal_with(roles: ['supervisor'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: 'beta', role_index: role_index)).to be false
    end

    it 'allows cross-team for admin' do
      p = principal_with(roles: ['admin'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: 'beta', role_index: role_index)).to be true
    end

    it 'allows cross-team for governance-observer' do
      p = principal_with(roles: ['governance-observer'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: 'beta', role_index: role_index)).to be true
    end

    it 'allows nil target team' do
      p = principal_with(roles: ['worker'], team: 'alpha')
      expect(described_class.allowed?(principal: p, target_team: nil, role_index: role_index)).to be true
    end

    it 'allows nil principal team (unscoped)' do
      p = principal_with(roles: ['worker'], team: nil)
      expect(described_class.allowed?(principal: p, target_team: 'beta', role_index: role_index)).to be true
    end

    it 'allows when both teams are nil' do
      p = principal_with(roles: ['worker'], team: nil)
      expect(described_class.allowed?(principal: p, target_team: nil, role_index: role_index)).to be true
    end
  end
end
