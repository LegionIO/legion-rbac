# frozen_string_literal: true

RSpec.describe Legion::Rbac::Role do
  subject(:role) do
    described_class.new(
      name:        'supervisor',
      description: 'Manage workers',
      permissions: [
        { resource: 'tasks/*', actions: %w[read create delete] }
      ],
      deny:        [
        { resource: 'workers/*/lifecycle/terminated' }
      ],
      cross_team:  false
    )
  end

  it 'stores the name as a string' do
    expect(role.name).to eq('supervisor')
  end

  it 'builds Permission objects from config' do
    expect(role.permissions).to all(be_a(Legion::Rbac::Permission))
    expect(role.permissions.first.resource_pattern).to eq('tasks/*')
  end

  it 'builds DenyRule objects from config' do
    expect(role.deny_rules).to all(be_a(Legion::Rbac::DenyRule))
    expect(role.deny_rules.first.resource_pattern).to eq('workers/*/lifecycle/terminated')
  end

  it 'returns false for cross_team?' do
    expect(role.cross_team?).to be false
  end

  it 'returns true for cross_team? when set' do
    admin = described_class.new(name: 'admin', cross_team: true)
    expect(admin.cross_team?).to be true
  end
end
