# frozen_string_literal: true

RSpec.describe Legion::Rbac do
  it 'has a version number' do
    expect(Legion::Rbac::VERSION).not_to be_nil
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
