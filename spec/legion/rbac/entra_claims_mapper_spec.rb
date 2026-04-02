# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Rbac::EntraClaimsMapper do
  describe '.map_claims' do
    let(:base_claims) do
      { oid: 'user-oid-123', name: 'Jane Doe', preferred_username: 'jane@uhg.com',
        tid: 'tenant-456', roles: ['Legion.Supervisor'], groups: [] }
    end

    it 'maps Entra app roles to Legion roles' do
      result = described_class.map_claims(base_claims)
      expect(result[:roles]).to eq(['supervisor'])
      expect(result[:sub]).to eq('user-oid-123')
      expect(result[:team]).to eq('tenant-456')
      expect(result[:scope]).to eq('human')
    end

    it 'maps multiple roles' do
      claims = base_claims.merge(roles: %w[Legion.Supervisor Legion.Observer])
      result = described_class.map_claims(claims)
      expect(result[:roles]).to contain_exactly('supervisor', 'governance-observer')
    end

    it 'maps group OIDs to roles' do
      claims = base_claims.merge(roles: [], groups: ['group-oid-789'])
      group_map = { 'group-oid-789' => 'admin' }
      result = described_class.map_claims(claims, group_map: group_map)
      expect(result[:roles]).to eq(['admin'])
    end

    it 'combines role and group mappings' do
      claims = base_claims.merge(groups: ['group-oid-789'])
      group_map = { 'group-oid-789' => 'admin' }
      result = described_class.map_claims(claims, group_map: group_map)
      expect(result[:roles]).to contain_exactly('supervisor', 'admin')
    end

    it 'uses default_role when no roles or groups match' do
      claims = base_claims.merge(roles: ['Unknown.Role'], groups: [])
      result = described_class.map_claims(claims)
      expect(result[:roles]).to eq(['worker'])
    end

    it 'uses custom default_role' do
      claims = base_claims.merge(roles: [], groups: [])
      result = described_class.map_claims(claims, default_role: 'governance-observer')
      expect(result[:roles]).to eq(['governance-observer'])
    end

    it 'uses custom role_map' do
      custom_map = { 'MyApp.Admin' => 'admin' }
      claims = base_claims.merge(roles: ['MyApp.Admin'])
      result = described_class.map_claims(claims, role_map: custom_map)
      expect(result[:roles]).to eq(['admin'])
    end

    it 'prefers oid over sub for principal id' do
      claims = base_claims.merge(sub: 'pairwise-sub', oid: 'stable-oid')
      result = described_class.map_claims(claims)
      expect(result[:sub]).to eq('stable-oid')
    end

    it 'falls back to sub when oid is missing' do
      claims = base_claims.except(:oid).merge(sub: 'fallback-sub')
      result = described_class.map_claims(claims)
      expect(result[:sub]).to eq('fallback-sub')
    end

    it 'handles string keys from JWT decode' do
      claims = { 'oid' => 'str-oid', 'name' => 'String User', 'tid' => 't-1',
                 'roles' => ['Legion.Admin'], 'groups' => [] }
      result = described_class.map_claims(claims)
      expect(result[:sub]).to eq('str-oid')
      expect(result[:roles]).to eq(['admin'])
    end

    it 'extracts name with preferred_username fallback' do
      claims = base_claims.except(:name)
      result = described_class.map_claims(claims)
      expect(result[:name]).to eq('jane@uhg.com')
    end

    it 'prefers explicit team keys over tid' do
      claims = base_claims.merge(extension_legion_team: 'platform-ops')
      result = described_class.map_claims(claims)

      expect(result[:team]).to eq('platform-ops')
    end

    it 'maps raw team values when team_map is provided' do
      result = described_class.map_claims(base_claims, team_map: { 'tenant-456' => 'platform-core' })

      expect(result[:team]).to eq('platform-core')
    end

    it 'fails closed for unmapped team values when team_map is provided' do
      result = described_class.map_claims(base_claims, team_map: { 'different-tenant' => 'platform-core' })

      expect(result[:team]).to be_nil
    end
  end
end
