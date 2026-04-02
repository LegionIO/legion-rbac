# frozen_string_literal: true

unless defined?(Legion::Events)
  module Legion
    module Events
      def self.emit(*); end
    end
  end
end

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

  describe 'rbac decision event emission' do
    it 'emits rbac.denied when access is denied' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))

      expect(Legion::Events).to have_received(:emit).with(
        'rbac.denied',
        hash_including(
          principal_id: 'worker-1',
          action:       'manage',
          resource:     'settings/*',
          operation:    'rbac.policy_engine.evaluate',
          reason:       'no matching permission'
        )
      )
    end

    it 'emits rbac.granted when access is allowed' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))

      expect(Legion::Events).to have_received(:emit).with(
        'rbac.granted',
        hash_including(
          principal_id: 'worker-1',
          action:       'read',
          resource:     'tasks/*',
          operation:    'rbac.policy_engine.evaluate'
        )
      )
    end
  end
end
