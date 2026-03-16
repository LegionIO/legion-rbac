# frozen_string_literal: true

RSpec.describe Legion::Rbac::Store do
  describe '.db_available?' do
    it 'returns false when Legion::Data is not defined' do
      expect(described_class.db_available?).to be false
    end
  end

  describe '.roles_for' do
    context 'when DB is unavailable' do
      it 'falls back to static_assignments' do
        Legion::Settings[:rbac][:static_assignments] = [
          { principal_id: 'local', principal_type: 'human', role: 'admin' },
          { principal_id: 'worker-1', principal_type: 'worker', role: 'worker' }
        ]
        roles = described_class.roles_for(principal_id: 'local')
        expect(roles).to eq(['admin'])
      end

      it 'returns empty array for unknown principal' do
        Legion::Settings[:rbac][:static_assignments] = [
          { principal_id: 'local', principal_type: 'human', role: 'admin' }
        ]
        roles = described_class.roles_for(principal_id: 'unknown')
        expect(roles).to be_empty
      end

      it 'returns multiple roles for same principal' do
        Legion::Settings[:rbac][:static_assignments] = [
          { principal_id: 'user-1', principal_type: 'human', role: 'admin' },
          { principal_id: 'user-1', principal_type: 'human', role: 'supervisor' }
        ]
        roles = described_class.roles_for(principal_id: 'user-1')
        expect(roles).to contain_exactly('admin', 'supervisor')
      end
    end
  end

  describe '.runner_grants_for' do
    it 'returns empty array when DB unavailable' do
      expect(described_class.runner_grants_for(team: 'alpha')).to eq([])
    end
  end

  describe '.cross_team_grants_for' do
    it 'returns empty array when DB unavailable' do
      expect(described_class.cross_team_grants_for(source_team: 'alpha')).to eq([])
    end
  end
end
