# frozen_string_literal: true

RSpec.describe Legion::Rbac::PolicyEngine do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  def principal_with(roles:, team: nil)
    Legion::Rbac::Principal.new(id: 'test', roles: roles, team: team)
  end

  describe '.evaluate' do
    context 'admin role' do
      it 'allows access to any resource' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['admin']),
          action: :manage, resource: 'anything/at/all',
          role_index: role_index
        )
        expect(result[:allowed]).to be true
      end
    end

    context 'worker role' do
      it 'allows executing runners' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['worker']),
          action: :execute, resource: 'runners/lex-github/pull_requests/create',
          role_index: role_index
        )
        expect(result[:allowed]).to be true
      end

      it 'denies lex-extinction runners' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['worker']),
          action: :execute, resource: 'runners/lex-extinction/terminate',
          role_index: role_index
        )
        expect(result[:allowed]).to be false
        expect(result[:reason]).to include('deny rule')
      end

      it 'denies lex-governance runners' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['worker']),
          action: :execute, resource: 'runners/lex-governance/propose',
          role_index: role_index
        )
        expect(result[:allowed]).to be false
      end
    end

    context 'supervisor role' do
      it 'allows managing team workers' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['supervisor']),
          action: :lifecycle, resource: 'workers/team',
          role_index: role_index
        )
        expect(result[:allowed]).to be true
      end

      it 'denies termination of workers' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['supervisor']),
          action: :lifecycle, resource: 'workers/w-123/lifecycle/terminated',
          role_index: role_index
        )
        expect(result[:allowed]).to be false
      end
    end

    context 'governance-observer role' do
      it 'allows reading workers' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['governance-observer']),
          action: :read, resource: 'workers/any',
          role_index: role_index
        )
        expect(result[:allowed]).to be true
      end

      it 'allows executing governance runners' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['governance-observer']),
          action: :execute, resource: 'runners/lex-governance/propose',
          role_index: role_index
        )
        expect(result[:allowed]).to be true
      end

      it 'denies executing non-governance runners' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['governance-observer']),
          action: :execute, resource: 'runners/lex-github/pull',
          role_index: role_index
        )
        expect(result[:allowed]).to be false
      end
    end

    context 'no roles' do
      it 'denies everything' do
        result = described_class.evaluate(
          principal: principal_with(roles: []),
          action: :read, resource: 'tasks/123',
          role_index: role_index
        )
        expect(result[:allowed]).to be false
        expect(result[:reason]).to eq('no roles assigned')
      end
    end

    context 'enforce: false' do
      it 'returns allowed: true with would_deny: true' do
        result = described_class.evaluate(
          principal: principal_with(roles: []),
          action: :read, resource: 'tasks/123',
          role_index: role_index, enforce: false
        )
        expect(result[:allowed]).to be true
        expect(result[:would_deny]).to be true
      end
    end
  end
end

RSpec.describe Legion::Rbac do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  before do
    Legion::Rbac.setup
  end

  describe '.authorize!' do
    it 'raises AccessDenied on denial' do
      principal = Legion::Rbac::Principal.new(id: 'nobody', roles: [])
      expect do
        described_class.authorize!(principal: principal, action: :read, resource: 'tasks/123')
      end.to raise_error(Legion::Rbac::AccessDenied)
    end

    it 'returns result on success' do
      principal = Legion::Rbac::Principal.new(id: 'admin-user', roles: ['admin'])
      result = described_class.authorize!(principal: principal, action: :read, resource: 'tasks/123')
      expect(result[:allowed]).to be true
    end
  end

  describe '.authorize_execution!' do
    it 'builds runner path from class and function' do
      principal = Legion::Rbac::Principal.new(id: 'admin-user', roles: ['admin'])
      result = described_class.authorize_execution!(
        principal: principal, runner_class: 'Legion::Extensions::LexGithub::PullRequests', function: 'create'
      )
      expect(result[:allowed]).to be true
    end

    it 'raises AccessDenied for denied runner' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'])
      expect do
        described_class.authorize_execution!(
          principal: principal, runner_class: 'Legion::Extensions::LexExtinction::Terminate', function: 'execute'
        )
      end.to raise_error(Legion::Rbac::AccessDenied)
    end
  end
end
