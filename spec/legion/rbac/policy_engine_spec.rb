# frozen_string_literal: true

RSpec.describe Legion::Rbac::PolicyEngine do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  def principal_with(roles:, team: nil)
    Legion::Rbac::Principal.new(id: 'test', roles: roles, team: team)
  end

  around do |example|
    original_assignments = Legion::Settings[:rbac][:static_assignments]
    Legion::Settings[:rbac][:static_assignments] = []
    example.run
  ensure
    Legion::Settings[:rbac][:static_assignments] = original_assignments
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

      it 'allows same-team access when target_team matches principal team' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['supervisor'], team: 'alpha'),
          action: :lifecycle, resource: 'workers/team',
          role_index: role_index, target_team: 'alpha'
        )
        expect(result[:allowed]).to be true
      end

      it 'denies cross-team access when target_team differs' do
        result = described_class.evaluate(
          principal: principal_with(roles: ['supervisor'], team: 'alpha'),
          action: :lifecycle, resource: 'workers/team',
          role_index: role_index, target_team: 'beta'
        )
        expect(result[:allowed]).to be false
        expect(result[:reason]).to eq('outside team scope')
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

    context 'assigned roles' do
      it 'resolves static assignments when the principal carries no roles' do
        Legion::Settings[:rbac][:static_assignments] = [
          { principal_id: 'assigned-admin', principal_type: 'human', role: 'admin' }
        ]

        result = described_class.evaluate(
          principal: Legion::Rbac::Principal.new(id: 'assigned-admin', roles: [], team: 'alpha'),
          action: :read, resource: 'tasks/123',
          role_index: role_index, target_team: 'beta'
        )

        expect(result[:allowed]).to be true
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

    context 'when rbac is disabled' do
      it 'does not enforce denials' do
        Legion::Settings[:rbac][:enabled] = false

        result = described_class.evaluate(
          principal: principal_with(roles: []),
          action: :read, resource: 'tasks/123',
          role_index: role_index
        )

        expect(result[:allowed]).to be true
        expect(result[:would_deny]).to be true
      ensure
        Legion::Settings[:rbac][:enabled] = true
      end
    end
  end
end

RSpec.describe Legion::Rbac do
  let(:role_index) { Legion::Rbac::ConfigLoader.load_roles }

  before do
    Legion::Rbac.setup
  end

  around do |example|
    original_assignments = Legion::Settings[:rbac][:static_assignments]
    Legion::Settings[:rbac][:static_assignments] = []
    example.run
  ensure
    Legion::Settings[:rbac][:static_assignments] = original_assignments
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

    it 'enforces runner grants for same-team execution when db grants are available' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'], team: 'alpha')
      grant = instance_double('RbacRunnerGrant', runner_pattern: 'lex-github/*', actions_list: ['execute'])

      allow(Legion::Rbac::Store).to receive(:roles_for).and_return([])
      allow(Legion::Rbac::Store).to receive(:db_available?).and_return(true)
      allow(Legion::Rbac::Store).to receive(:runner_grants_for).with(team: 'alpha').and_return([grant])

      result = described_class.authorize_execution!(
        principal: principal, runner_class: 'Legion::Extensions::LexGithub::PullRequests', function: 'create'
      )

      expect(result[:allowed]).to be true
    end

    it 'denies same-team execution when the runner grant is missing' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'], team: 'alpha')

      allow(Legion::Rbac::Store).to receive(:roles_for).and_return([])
      allow(Legion::Rbac::Store).to receive(:db_available?).and_return(true)
      allow(Legion::Rbac::Store).to receive(:runner_grants_for).with(team: 'alpha').and_return([])

      expect do
        described_class.authorize_execution!(
          principal: principal, runner_class: 'Legion::Extensions::LexGithub::PullRequests', function: 'create'
        )
      end.to raise_error(Legion::Rbac::AccessDenied, /runner grant required/)
    end

    it 'allows cross-team execution when runner and cross-team grants both match' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'], team: 'alpha')
      runner_grant = instance_double('RbacRunnerGrant', runner_pattern: 'lex-github/*', actions_list: ['execute'])
      cross_team_grant = instance_double(
        'RbacCrossTeamGrant',
        target_team:    'beta',
        runner_pattern: 'lex-github/*',
        actions_list:   ['execute']
      )

      allow(Legion::Rbac::Store).to receive(:roles_for).and_return([])
      allow(Legion::Rbac::Store).to receive(:db_available?).and_return(true)
      allow(Legion::Rbac::Store).to receive(:runner_grants_for).with(team: 'alpha').and_return([runner_grant])
      allow(Legion::Rbac::Store).to receive(:cross_team_grants_for).with(source_team: 'alpha').and_return([cross_team_grant])

      result = described_class.authorize_execution!(
        principal:    principal,
        runner_class: 'Legion::Extensions::LexGithub::PullRequests',
        function:     'create',
        target_team:  'beta'
      )

      expect(result[:allowed]).to be true
    end

    it 'denies cross-team execution when the cross-team grant is missing' do
      principal = Legion::Rbac::Principal.new(id: 'worker-1', roles: ['worker'], team: 'alpha')
      runner_grant = instance_double('RbacRunnerGrant', runner_pattern: 'lex-github/*', actions_list: ['execute'])

      allow(Legion::Rbac::Store).to receive(:roles_for).and_return([])
      allow(Legion::Rbac::Store).to receive(:db_available?).and_return(true)
      allow(Legion::Rbac::Store).to receive(:runner_grants_for).with(team: 'alpha').and_return([runner_grant])
      allow(Legion::Rbac::Store).to receive(:cross_team_grants_for).with(source_team: 'alpha').and_return([])

      expect do
        described_class.authorize_execution!(
          principal:    principal,
          runner_class: 'Legion::Extensions::LexGithub::PullRequests',
          function:     'create',
          target_team:  'beta'
        )
      end.to raise_error(Legion::Rbac::AccessDenied, /cross-team grant required/)
    end
  end
end
