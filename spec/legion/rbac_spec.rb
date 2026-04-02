# frozen_string_literal: true

RSpec.describe Legion::Rbac do
  it 'has a version number' do
    expect(Legion::Rbac::VERSION).not_to be_nil
  end

  describe '.register_routes' do
    it 'handles route registration exceptions' do
      stub_const('Legion::API', Module.new)
      allow(Legion::API).to receive(:register_library_routes).and_raise(StandardError, 'boom')
      allow(described_class).to receive(:handle_exception)

      described_class.register_routes

      expect(described_class).to have_received(:handle_exception).with(
        instance_of(StandardError),
        level:     :warn,
        operation: 'rbac.register_routes'
      )
    end
  end

  it 'marks connected on setup' do
    described_class.setup
    expect(Legion::Settings[:rbac][:connected]).to be true
  end

  it 'marks disconnected on shutdown' do
    described_class.setup
    described_class.shutdown
    expect(Legion::Settings[:rbac][:connected]).to be false
  end
end
