# frozen_string_literal: true

RSpec.describe Legion::Rbac::Middleware do
  let(:inner_app) { ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] } }
  let(:middleware) { described_class.new(inner_app) }

  before { Legion::Rbac.setup }

  def env_for(method, path, principal: nil)
    {
      'REQUEST_METHOD'   => method,
      'PATH_INFO'        => path,
      'legion.principal' => principal
    }
  end

  def worker_principal
    Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'])
  end

  def admin_principal
    Legion::Rbac::Principal.new(id: 'admin-user', roles: ['admin'])
  end

  describe 'behavior matrix: enabled=false (full bypass)' do
    before { Legion::Settings[:rbac][:enabled] = false }

    after { Legion::Settings[:rbac][:enabled] = true }

    it 'bypasses entirely without evaluating policy' do
      expect(Legion::Rbac::PolicyEngine).not_to receive(:evaluate)
      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(200)
    end

    it 'allows unauthenticated requests through' do
      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(200)
    end

    it 'allows requests that would otherwise be denied' do
      status, = middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(status).to eq(200)
    end
  end

  describe 'behavior matrix: enabled=true, enforce=false (audit mode)' do
    before do
      Legion::Settings[:rbac][:enabled] = true
      Legion::Settings[:rbac][:enforce] = false
    end

    after do
      Legion::Settings[:rbac][:enforce] = true
    end

    it 'runs PolicyEngine for requests with a principal' do
      expect(Legion::Rbac::PolicyEngine).to receive(:evaluate).and_call_original
      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(status).to eq(200)
    end

    it 'allows requests that would be denied in enforce mode' do
      status, = middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(status).to eq(200)
    end

    it 'logs a would_deny message when policy would deny' do
      logged = []
      fake_log = double('logger')
      allow(fake_log).to receive(:warn)
      allow(fake_log).to receive(:debug)
      allow(fake_log).to receive(:info) { |msg| logged << msg }
      allow(middleware).to receive(:log).and_return(fake_log)

      middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))

      expect(logged).to include(a_string_including('[RBAC audit] would_deny'))
    end

    it 'does not return 403 for denied principals' do
      status, = middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(status).not_to eq(403)
    end

    it 'allows unauthenticated requests and logs audit message' do
      logged = []
      fake_log = double('logger')
      allow(fake_log).to receive(:warn)
      allow(fake_log).to receive(:debug)
      allow(fake_log).to receive(:info) { |msg| logged << msg }
      allow(middleware).to receive(:log).and_return(fake_log)

      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(200)
      expect(logged).to include(a_string_including('[RBAC audit] would_deny'))
    end

    it 'allows requests to unmapped routes in audit mode' do
      status, = middleware.call(env_for('GET', '/api/unknown', principal: admin_principal))
      expect(status).to eq(200)
    end

    it 'allows requests to mapped routes that would be allowed anyway' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(status).to eq(200)
    end
  end

  describe 'behavior matrix: enabled=true, enforce=true (full enforcement)' do
    it 'denies unauthenticated requests with 403' do
      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(403)
    end

    it 'denies unauthorized principals with 403' do
      status, = middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(status).to eq(403)
    end

    it 'allows authorized principals' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(status).to eq(200)
    end

    it 'denies unmapped routes with 403' do
      status, = middleware.call(env_for('GET', '/api/unknown', principal: admin_principal))
      expect(status).to eq(403)
    end
  end

  describe 'principal env key: legion.rbac_principal takes priority' do
    it 'uses legion.rbac_principal over legion.principal when both are present' do
      rbac_principal = Legion::Rbac::Principal.new(id: 'rbac-user', roles: ['admin'])
      limited_principal = Legion::Rbac::Principal.new(id: 'limited', roles: ['worker'])
      env = env_for('PUT', '/api/settings/rbac', principal: limited_principal)
            .merge('legion.rbac_principal' => rbac_principal)

      status, = middleware.call(env)
      expect(status).to eq(200)
    end

    it 'falls back to legion.principal when legion.rbac_principal is absent' do
      status, = middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(status).to eq(200)
    end

    it 'treats request as unauthenticated when both keys are nil' do
      status, = middleware.call(env_for('GET', '/api/tasks'))
      expect(status).to eq(403)
    end
  end

  describe 'audit mode with would_deny result from PolicyEngine' do
    before do
      Legion::Settings[:rbac][:enforce] = false
    end

    after do
      Legion::Settings[:rbac][:enforce] = true
    end

    it 'includes principal_id in audit log when would_deny fires' do
      logged_messages = []
      fake_log = double('logger')
      allow(fake_log).to receive(:warn)
      allow(fake_log).to receive(:debug)
      allow(fake_log).to receive(:info) { |msg| logged_messages << msg }
      allow(middleware).to receive(:log).and_return(fake_log)

      middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))

      audit_entries = logged_messages.select { |m| m.include?('[RBAC audit] would_deny') }
      expect(audit_entries).not_to be_empty
      expect(audit_entries.first).to include('worker-1')
    end
  end
end
