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

  describe '#enforce?' do
    it 'logs and defaults to true when settings lookup fails' do
      allow(Legion::Settings).to receive(:[]).with(:rbac).and_raise(StandardError, 'settings boom')
      allow(middleware).to receive(:handle_exception)

      expect(middleware.send(:enforce?)).to be true
      expect(middleware).to have_received(:handle_exception).with(
        instance_of(StandardError),
        level:     :warn,
        operation: 'rbac.middleware.enforce'
      )
    end
  end
end
