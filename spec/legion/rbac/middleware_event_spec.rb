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

  def supervisor_principal(team: 'team-a')
    Legion::Rbac::Principal.new(id: 'supervisor-1', roles: ['supervisor'], team: team)
  end

  describe 'rbac decision event emission' do
    it 'emits rbac.denied when access is denied' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(
        env_for('PUT', '/api/settings/rbac', principal: worker_principal).merge(
          'HTTP_X_REQUEST_ID'       => 'req-123',
          'legion.rbac.source'      => 'settings.api',
          'legion.rbac.target_team' => 'team-b'
        )
      )

      expect(Legion::Events).to have_received(:emit).with(
        'rbac.denied',
        hash_including(
          principal_id:   'worker-1',
          action:         'manage',
          resource:       'settings/*',
          operation:      'rbac.policy_engine.evaluate',
          reason:         'no matching permission',
          method:         'PUT',
          path:           '/api/settings/rbac',
          source:         'settings.api',
          correlation_id: 'req-123',
          target_team:    'team-b'
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

    it 'does not emit the legacy rbac.deny event' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))

      expect(Legion::Events).not_to have_received(:emit).with('rbac.deny', anything)
    end

    it 'emits target_team metadata for team-scoped denials' do
      allow(Legion::Events).to receive(:emit)

      middleware.call(
        env_for('PATCH', '/api/workers/worker-2', principal: supervisor_principal(team: 'team-a')).merge(
          'legion.rbac.target_team' => 'team-b'
        )
      )

      expect(Legion::Events).to have_received(:emit).with(
        'rbac.denied',
        hash_including(
          principal_id: 'supervisor-1',
          action:       'lifecycle',
          resource:     'workers/team',
          target_team:  'team-b',
          reason:       'outside team scope'
        )
      )
    end
  end
end
