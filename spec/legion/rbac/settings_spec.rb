# frozen_string_literal: true

RSpec.describe Legion::Rbac::Settings do
  subject(:defaults) { described_class.default }

  it 'returns a hash with expected top-level keys' do
    expect(defaults).to include(
      :enabled, :enforce, :connected, :emit_events, :role_resolution_mode,
      :default_local_role, :static_assignments, :route_permissions, :roles
    )
  end

  it 'defines four built-in roles' do
    role_names = defaults[:roles].keys
    expect(role_names).to contain_exactly(:worker, :supervisor, :admin, :'governance-observer')
  end

  it 'defaults enforce to true' do
    expect(defaults[:enforce]).to be true
  end

  it 'defaults default_local_role to admin' do
    expect(defaults[:default_local_role]).to eq('admin')
  end

  it 'defaults role_resolution_mode to merge' do
    expect(defaults[:role_resolution_mode]).to eq('merge')
  end

  it 'defaults emit_events to true' do
    expect(defaults[:emit_events]).to be true
  end

  it 'sets admin as cross_team' do
    expect(defaults[:roles][:admin][:cross_team]).to be true
  end

  it 'sets governance-observer as cross_team' do
    expect(defaults[:roles][:'governance-observer'][:cross_team]).to be true
  end
end
