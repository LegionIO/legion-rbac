# frozen_string_literal: true

require 'spec_helper'

unless defined?(Legion::Events)
  module Legion
    module Events
      def self.emit(*); end
    end
  end
end

RSpec.describe Legion::Rbac::Routes do
  it 'is a module' do
    expect(Legion::Rbac::Routes).to be_a(Module)
  end

  it 'responds to registered' do
    expect(Legion::Rbac::Routes).to respond_to(:registered)
  end

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
      end.to raise_error(Legion::Rbac::Routes::InvalidTimestamp, 'expires_at must be a valid ISO8601 timestamp')
    end
  end

  describe '.collection_payload' do
    let(:row_one) { instance_double('RowOne', values: { id: 1 }) }
    let(:row_two) { instance_double('RowTwo', values: { id: 2 }) }
    let(:windowed_dataset) { instance_double('WindowedDataset', all: [row_one, row_two]) }
    let(:dataset) { instance_double('Dataset') }

    it 'applies limit and offset bounds to collection responses' do
      expect(dataset).to receive(:limit).with(25, 10).and_return(windowed_dataset)

      payload = described_class.send(:collection_payload, dataset, { 'limit' => '25', 'offset' => '10' })

      expect(payload).to eq(
        data:       [{ id: 1 }, { id: 2 }],
        pagination: { limit: 25, offset: 10, returned: 2 }
      )
    end

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

  describe '.request_source' do
    it 'defaults to rbac.api' do
      expect(described_class.send(:request_source, {})).to eq('rbac.api')
    end
  end

  describe '.policy_change_payload' do
    it 'includes audit metadata and normalized record values' do
      context = described_class.send(
        :policy_change_context,
        actor_id:       'alice',
        source:         'rbac.api',
        correlation_id: 'req-1',
        method:         'POST',
        path:           '/api/rbac/assignments'
      )

      payload = described_class.send(
        :policy_change_payload,
        change_type:   'assignment.created',
        target_type:   'role_assignment',
        record_values: { 'id' => 7, 'principal_id' => 'user-1', 'role' => 'admin', 'team' => 'ops' },
        context:       context
      )

      expect(payload).to include(
        change_type:    'assignment.created',
        target_type:    'role_assignment',
        target_id:      7,
        actor_id:       'alice',
        source:         'rbac.api',
        correlation_id: 'req-1',
        method:         'POST',
        path:           '/api/rbac/assignments',
        principal_id:   'user-1',
        role:           'admin',
        team:           'ops'
      )
    end
  end

  describe '.emit_policy_changed' do
    it 'emits rbac.policy_changed with the built payload' do
      allow(Legion::Events).to receive(:emit)
      context = described_class.send(
        :policy_change_context,
        actor_id:       'bob',
        source:         'rbac.api',
        correlation_id: 'req-2',
        method:         'DELETE',
        path:           '/api/rbac/grants/9'
      )

      described_class.send(
        :emit_policy_changed,
        change_type:   'runner_grant.deleted',
        target_type:   'runner_grant',
        record_values: { id: 9, team: 'alpha', runner_pattern: 'lex/*', actions: 'execute' },
        context:       context
      )

      expect(Legion::Events).to have_received(:emit).with(
        'rbac.policy_changed',
        hash_including(
          change_type:    'runner_grant.deleted',
          target_type:    'runner_grant',
          target_id:      9,
          actor_id:       'bob',
          source:         'rbac.api',
          correlation_id: 'req-2',
          method:         'DELETE',
          path:           '/api/rbac/grants/9',
          team:           'alpha',
          runner_pattern: 'lex/*',
          actions:        'execute'
        )
      )
    end
  end
end
