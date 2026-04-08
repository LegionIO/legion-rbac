# frozen_string_literal: true

RSpec.describe Legion::Rbac::GroupRoleMapper do
  let(:group_role_map) do
    {
      'a1b2c3d4-oid'     => 'admin',
      'Legion Admins'    => 'admin',
      'Legion Operators' => 'operator',
      'Legion Workers'   => 'worker'
    }
  end

  describe '.resolve_roles' do
    context 'with explicit group_role_map' do
      it 'returns roles for exact matching groups' do
        roles = described_class.resolve_roles(groups: ['Legion Admins'], group_role_map: group_role_map)
        expect(roles).to contain_exactly('admin')
      end

      it 'resolves multiple groups to multiple roles' do
        roles = described_class.resolve_roles(
          groups:         ['Legion Admins', 'Legion Workers'],
          group_role_map: group_role_map
        )
        expect(roles).to contain_exactly('admin', 'worker')
      end

      it 'deduplicates roles when multiple groups map to the same role' do
        roles = described_class.resolve_roles(
          groups:         ['Legion Admins', 'a1b2c3d4-oid'],
          group_role_map: group_role_map
        )
        expect(roles).to contain_exactly('admin')
      end

      it 'resolves OID string groups by exact match' do
        roles = described_class.resolve_roles(groups: ['a1b2c3d4-oid'], group_role_map: group_role_map)
        expect(roles).to contain_exactly('admin')
      end

      it 'returns empty array when no groups match' do
        roles = described_class.resolve_roles(groups: ['Unknown Group'], group_role_map: group_role_map)
        expect(roles).to be_empty
      end

      it 'returns empty array for empty groups' do
        roles = described_class.resolve_roles(groups: [], group_role_map: group_role_map)
        expect(roles).to be_empty
      end

      it 'returns empty array for nil groups' do
        roles = described_class.resolve_roles(groups: nil, group_role_map: group_role_map)
        expect(roles).to be_empty
      end

      it 'returns empty array when map is empty' do
        roles = described_class.resolve_roles(groups: ['Legion Admins'], group_role_map: {})
        expect(roles).to be_empty
      end

      it 'does NOT match partial group names (exact string only)' do
        roles = described_class.resolve_roles(groups: ['Legion'], group_role_map: group_role_map)
        expect(roles).to be_empty
      end

      it 'is case-sensitive' do
        roles = described_class.resolve_roles(groups: ['legion admins'], group_role_map: group_role_map)
        expect(roles).to be_empty
      end

      it 'coerces both group and key to string before comparing' do
        map = { 'worker-group' => 'worker' }
        roles = described_class.resolve_roles(groups: ['worker-group'], group_role_map: map)
        expect(roles).to contain_exactly('worker')
      end
    end

    context 'with default_map from settings' do
      before do
        Legion::Settings[:rbac][:group_role_map] = { 'Ops Team' => 'operator' }
      end

      after do
        Legion::Settings[:rbac][:group_role_map] = {}
      end

      it 'reads group_role_map from settings when no explicit map is passed' do
        roles = described_class.resolve_roles(groups: ['Ops Team'])
        expect(roles).to contain_exactly('operator')
      end

      it 'returns empty array when settings group_role_map has no match' do
        roles = described_class.resolve_roles(groups: ['Other Group'])
        expect(roles).to be_empty
      end
    end

    context 'when RBAC is disabled' do
      before { Legion::Settings[:rbac][:enabled] = false }

      after { Legion::Settings[:rbac][:enabled] = true }

      it 'returns empty array regardless of groups' do
        roles = described_class.resolve_roles(groups: ['Legion Admins'], group_role_map: group_role_map)
        expect(roles).to be_empty
      end
    end
  end

  describe '.enrich_principal' do
    let(:principal) { { id: 'user-1', type: :human, roles: ['worker'] } }

    before do
      Legion::Settings[:rbac][:group_role_map] = group_role_map
    end

    after do
      Legion::Settings[:rbac][:group_role_map] = {}
    end

    it 'adds group-derived roles to principal roles' do
      enriched = described_class.enrich_principal(
        principal: principal,
        groups:    ['Legion Admins']
      )
      expect(enriched[:roles]).to contain_exactly('worker', 'admin')
    end

    it 'deduplicates roles already in principal' do
      enriched = described_class.enrich_principal(
        principal: { id: 'user-1', roles: ['admin'] },
        groups:    ['Legion Admins']
      )
      expect(enriched[:roles]).to contain_exactly('admin')
    end

    it 'returns principal unchanged when no groups match' do
      enriched = described_class.enrich_principal(
        principal: principal,
        groups:    ['Unknown Group']
      )
      expect(enriched).to eq(principal)
    end

    it 'returns principal unchanged when groups is empty' do
      enriched = described_class.enrich_principal(
        principal: principal,
        groups:    []
      )
      expect(enriched).to eq(principal)
    end

    it 'handles principal with no existing roles key' do
      enriched = described_class.enrich_principal(
        principal: { id: 'user-1', type: :human },
        groups:    ['Legion Workers']
      )
      expect(enriched[:roles]).to contain_exactly('worker')
    end

    it 'does not mutate the original principal hash' do
      original_roles = principal[:roles].dup
      described_class.enrich_principal(
        principal: principal,
        groups:    ['Legion Admins']
      )
      expect(principal[:roles]).to eq(original_roles)
    end

    context 'when RBAC is disabled' do
      before { Legion::Settings[:rbac][:enabled] = false }

      after { Legion::Settings[:rbac][:enabled] = true }

      it 'returns principal unchanged' do
        enriched = described_class.enrich_principal(
          principal: principal,
          groups:    ['Legion Admins']
        )
        expect(enriched).to eq(principal)
      end
    end
  end
end
