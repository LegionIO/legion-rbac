# frozen_string_literal: true

RSpec.describe Legion::Rbac::Permission do
  describe '#matches?' do
    it 'matches exact resource and action' do
      perm = described_class.new(resource_pattern: 'tasks/123', actions: %w[read])
      expect(perm.matches?('tasks/123', :read)).to be true
    end

    it 'rejects wrong action' do
      perm = described_class.new(resource_pattern: 'tasks/123', actions: %w[read])
      expect(perm.matches?('tasks/123', :delete)).to be false
    end

    it 'matches wildcard * across segments' do
      perm = described_class.new(resource_pattern: 'runners/*', actions: %w[execute])
      expect(perm.matches?('runners/lex-github/pull_requests/create', :execute)).to be true
    end

    it 'matches + for single segment' do
      perm = described_class.new(resource_pattern: 'workers/+/status', actions: %w[read])
      expect(perm.matches?('workers/abc/status', :read)).to be true
    end

    it 'rejects + when multiple segments present' do
      perm = described_class.new(resource_pattern: 'workers/+/status', actions: %w[read])
      expect(perm.matches?('workers/abc/def/status', :read)).to be false
    end

    it 'matches global wildcard *' do
      perm = described_class.new(resource_pattern: '*', actions: %w[read])
      expect(perm.matches?('anything/at/all', :read)).to be true
    end
  end
end

RSpec.describe Legion::Rbac::DenyRule do
  describe '#matches?' do
    it 'matches resource pattern' do
      rule = described_class.new(resource_pattern: 'runners/lex-extinction/*')
      expect(rule.matches?('runners/lex-extinction/terminate')).to be true
    end

    it 'does not match unrelated resource' do
      rule = described_class.new(resource_pattern: 'runners/lex-extinction/*')
      expect(rule.matches?('runners/lex-github/pull')).to be false
    end

    it 'matches when above_level is exceeded' do
      rule = described_class.new(resource_pattern: 'runners/lex-extinction/escalate', above_level: 2)
      expect(rule.matches?('runners/lex-extinction/escalate', level: 3)).to be true
    end

    it 'does not match when level is within limit' do
      rule = described_class.new(resource_pattern: 'runners/lex-extinction/escalate', above_level: 2)
      expect(rule.matches?('runners/lex-extinction/escalate', level: 2)).to be false
    end

    it 'does not match when above_level set but no level provided' do
      rule = described_class.new(resource_pattern: 'runners/lex-extinction/escalate', above_level: 2)
      expect(rule.matches?('runners/lex-extinction/escalate')).to be false
    end
  end
end
