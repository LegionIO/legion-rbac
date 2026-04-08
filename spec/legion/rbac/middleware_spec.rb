# frozen_string_literal: true

RSpec.describe Legion::Rbac::Middleware do
  let(:inner_app) { ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] } }
  let(:middleware) { described_class.new(inner_app) }
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  before { Legion::Rbac.setup }

  def env_for(method, path, principal: nil)
    {
      'REQUEST_METHOD'   => method,
      'PATH_INFO'        => path,
      'legion.principal' => principal
    }
  end

  def admin_principal
    Legion::Rbac::Principal.new(id: 'admin-user', roles: ['admin'])
  end

  def worker_principal
    Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'])
  end

  def supervisor_principal(team: 'team-a')
    Legion::Rbac::Principal.new(id: 'supervisor-1', roles: ['supervisor'], team: team)
  end

  describe 'skip paths' do
    it 'passes /api/health through without auth' do
      status, = middleware.call(env_for('GET', '/api/health'))
      expect(status).to eq(200)
    end

    it 'passes /api/ready through' do
      status, = middleware.call(env_for('GET', '/api/ready'))
      expect(status).to eq(200)
    end

    it 'passes /api/openapi.json through' do
      status, = middleware.call(env_for('GET', '/api/openapi.json'))
      expect(status).to eq(200)
    end
  end

  describe 'invoke routes' do
    it 'defers invoke routes to execution layer' do
      status, = middleware.call(env_for('POST', '/api/extensions/1/runners/2/functions/3/invoke'))
      expect(status).to eq(200)
    end
  end

  describe 'unauthenticated requests' do
    it 'returns 403 for unauthenticated requests' do
      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(403)
    end
  end

  describe 'authorization' do
    it 'allows admin to access any route' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: admin_principal))
      expect(status).to eq(200)
    end

    it 'allows admin to access rbac routes' do
      status, = middleware.call(env_for('GET', '/api/rbac/roles', principal: admin_principal))
      expect(status).to eq(200)
    end

    it 'allows worker to read tasks' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(status).to eq(200)
    end

    it 'denies worker from managing settings' do
      status, = middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(status).to eq(403)
    end

    it 'honors permission overrides from the rack env' do
      status, = middleware.call(
        env_for('GET', '/api/tasks', principal: worker_principal).merge(
          'legion.rbac.resource' => 'settings/*',
          'legion.rbac.action'   => 'manage'
        )
      )

      expect(status).to eq(403)
    end

    it 'enforces team scope when target_team is supplied in the rack env' do
      status, = middleware.call(
        env_for('PATCH', '/api/workers/worker-2', principal: supervisor_principal(team: 'team-a')).merge(
          'legion.rbac.target_team' => 'team-b'
        )
      )

      expect(status).to eq(403)
    end

    it 'denies unmapped routes' do
      status, = middleware.call(env_for('GET', '/api/unknown', principal: admin_principal))
      expect(status).to eq(403)
    end

    it 'returns JSON error body on denial' do
      _, _, body = middleware.call(env_for('GET', '/api/unknown', principal: admin_principal))
      parsed = Legion::JSON.load(body.first)
      expect(parsed[:error] || parsed['error']).to eq('access_denied')
    end
  end

  describe 'route permission overrides' do
    it 'allows custom routes from settings' do
      Legion::Settings[:rbac][:route_permissions] = {
        'GET /api/custom/tasks' => { resource: 'tasks/*', action: :read }
      }

      status, = middleware.call(env_for('GET', '/api/custom/tasks', principal: worker_principal))

      expect(status).to eq(200)
    ensure
      Legion::Settings[:rbac][:route_permissions] = {}
    end

    it 'overrides default route permissions from settings' do
      Legion::Settings[:rbac][:route_permissions] = {
        'GET /api/tasks' => { resource: 'settings/*', action: :manage }
      }

      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))

      expect(status).to eq(403)
    ensure
      Legion::Settings[:rbac][:route_permissions] = {}
    end

    it 'raises ArgumentError when permission entry is not a hash' do
      overrides = { 'GET /api/bad' => 'not-a-hash' }
      expect do
        middleware.send(:build_custom_route_permissions, overrides)
      end.to raise_error(ArgumentError, /permission must be a hash/)
    end

    it 'raises ArgumentError when resource is missing from permission entry' do
      overrides = { 'GET /api/bad' => { action: :read } }
      expect do
        middleware.send(:build_custom_route_permissions, overrides)
      end.to raise_error(ArgumentError, /resource is required/)
    end

    it 'raises ArgumentError when resource is not a string' do
      overrides = { 'GET /api/bad' => { resource: 123, action: :read } }
      expect do
        middleware.send(:build_custom_route_permissions, overrides)
      end.to raise_error(ArgumentError, /resource must be a string/)
    end

    it 'raises ArgumentError when action is missing from permission entry' do
      overrides = { 'GET /api/bad' => { resource: 'tasks/*' } }
      expect do
        middleware.send(:build_custom_route_permissions, overrides)
      end.to raise_error(ArgumentError, /action is required/)
    end
  end

  describe 'disabled mode' do
    it 'bypasses enforcement when rbac.enabled is false' do
      Legion::Settings[:rbac][:enabled] = false

      status, = middleware.call(env_for('GET', '/api/tasks'))

      expect(status).to eq(200)
    ensure
      Legion::Settings[:rbac][:enabled] = true
    end
  end

  describe 'principal env key bridge' do
    it 'reads legion.rbac_principal when present' do
      rbac_principal = Legion::Rbac::Principal.new(id: 'bridged-user', roles: ['admin'])
      env = env_for('GET', '/api/tasks').merge('legion.rbac_principal' => rbac_principal)

      status, = middleware.call(env)
      expect(status).to eq(200)
    end

    it 'falls back to legion.principal when legion.rbac_principal is absent' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: admin_principal))
      expect(status).to eq(200)
    end
  end
end
