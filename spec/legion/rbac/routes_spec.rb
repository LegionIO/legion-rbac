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
end
