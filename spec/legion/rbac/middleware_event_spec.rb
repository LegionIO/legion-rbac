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

  describe 'rbac.deny event emission' do
    it 'emits rbac.deny event when access is denied' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(env_for('PUT', '/api/settings/rbac', principal: worker_principal))
      expect(Legion::Events).to have_received(:emit).with('rbac.deny', hash_including(:reason))
    end

    it 'does not emit rbac.deny when access is allowed' do
      allow(Legion::Events).to receive(:emit)
      middleware.call(env_for('GET', '/api/tasks', principal: worker_principal))
      expect(Legion::Events).not_to have_received(:emit).with('rbac.deny', anything)
    end
  end
end
