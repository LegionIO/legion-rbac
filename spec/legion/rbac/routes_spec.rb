# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Rbac::Routes do
  describe '.parse_optional_time' do
    it 'returns nil for a blank timestamp' do
      expect(described_class.send(:parse_optional_time, nil, field: 'expires_at')).to be_nil
    end

    it 'parses a valid ISO8601 timestamp' do
      parsed = described_class.send(:parse_optional_time, '2026-04-02T18:30:00Z', field: 'expires_at')

      expect(parsed.utc.iso8601).to eq('2026-04-02T18:30:00Z')
    end

    it 'raises InvalidTimestamp for malformed values' do
      expect do
        described_class.send(:parse_optional_time, 'not-a-time', field: 'expires_at')
      end.to raise_error(Legion::Rbac::Routes::InvalidTimestamp)
    end
  end

  describe '.collection_payload' do
    it 'caps oversized limits and normalizes invalid offsets' do
      expect(described_class.send(:collection_limit, { 'limit' => '9999' })).to eq(described_class::MAX_COLLECTION_LIMIT)
      expect(described_class.send(:collection_limit, { 'limit' => 'nope' })).to eq(described_class::DEFAULT_COLLECTION_LIMIT)
      expect(described_class.send(:collection_offset, { 'offset' => '-4' })).to eq(0)
    end
  end

  describe '.request_correlation_id' do
    it 'prefers explicit legion correlation ids before headers' do
      env = {
        'legion.correlation_id' => 'legion-req',
        'HTTP_X_REQUEST_ID'     => 'header-req',
        'HTTP_X_CORRELATION_ID' => 'header-corr'
      }

      expect(described_class.send(:request_correlation_id, env)).to eq('legion-req')
    end
  end

  describe 'policy-change audit delivery' do
    include_context 'with an audit event subscriber'

    it 'notifies the subscriber when a runner grant is removed' do
      described_class.send(
        :emit_policy_changed,
        change_type:   'runner_grant.deleted',
        target_type:   'runner_grant',
        record_values: { id: 9, team: 'alpha', runner_pattern: 'lex/*', actions: 'execute' },
        context:       { actor_id: 'policy-admin', source: 'rbac.api', correlation_id: 'mutation-1',
                   method: 'DELETE', path: '/api/rbac/grants/9' }
      )

      expect(observed_events).to contain_exactly([
                                                   'rbac.policy_changed',
                                                   include(change_type: 'runner_grant.deleted', target_id: 9,
                                                           actor_id: 'policy-admin', correlation_id: 'mutation-1')
                                                 ])
    end
  end
end
