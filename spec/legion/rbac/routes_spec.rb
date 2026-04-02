# frozen_string_literal: true

require 'spec_helper'

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
end
