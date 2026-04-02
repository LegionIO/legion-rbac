# frozen_string_literal: true

RSpec.describe Legion::Rbac::CapabilityRegistry do
  before { described_class.clear! }

  describe '.register and .for_extension' do
    it 'stores and retrieves capabilities for an extension' do
      described_class.register('lex-codegen', capabilities: %i[shell_execute filesystem_write])
      expect(described_class.for_extension('lex-codegen')).to contain_exactly(:shell_execute, :filesystem_write)
    end

    it 'returns empty array for unknown extension' do
      expect(described_class.for_extension('lex-unknown')).to eq([])
    end

    it 'deduplicates capabilities' do
      described_class.register('lex-dup', capabilities: %i[shell_execute shell_execute network_outbound])
      expect(described_class.for_extension('lex-dup')).to contain_exactly(:shell_execute, :network_outbound)
    end

    it 'returns a copy of the stored capabilities array' do
      described_class.register('lex-copy', capabilities: [:shell_execute])

      capabilities = described_class.for_extension('lex-copy')
      capabilities << :code_eval

      expect(described_class.for_extension('lex-copy')).to eq([:shell_execute])
    end

    it 'stores audit_result when provided' do
      audit = instance_double(Legion::Rbac::CapabilityAudit::AuditResult)
      described_class.register('lex-audited', capabilities: [:shell_execute], audit_result: audit)
      expect(described_class.audit_result_for('lex-audited')).to eq(audit)
    end
  end

  describe '.extensions_with' do
    before do
      described_class.register('lex-exec', capabilities: [:shell_execute])
      described_class.register('lex-codegen', capabilities: %i[shell_execute filesystem_write])
      described_class.register('lex-http', capabilities: [:network_outbound])
    end

    it 'returns extensions with the given capability' do
      expect(described_class.extensions_with(:shell_execute)).to contain_exactly('lex-exec', 'lex-codegen')
    end

    it 'returns empty for unmatched capability' do
      expect(described_class.extensions_with(:code_eval)).to eq([])
    end
  end

  describe '.all' do
    it 'returns all registered entries' do
      described_class.register('lex-a', capabilities: [:shell_execute])
      described_class.register('lex-b', capabilities: [:network_outbound])
      expect(described_class.all.keys).to contain_exactly('lex-a', 'lex-b')
    end

    it 'returns a copy of the registry entries' do
      described_class.register('lex-a', capabilities: [:shell_execute])

      registry = described_class.all
      registry['lex-a'][:capabilities] << :code_eval

      expect(described_class.for_extension('lex-a')).to eq([:shell_execute])
    end
  end

  describe '.registered?' do
    it 'returns true for registered extensions' do
      described_class.register('lex-known', capabilities: [])
      expect(described_class.registered?('lex-known')).to be true
    end

    it 'returns false for unknown extensions' do
      expect(described_class.registered?('lex-unknown')).to be false
    end
  end

  describe '.clear!' do
    it 'removes all entries' do
      described_class.register('lex-temp', capabilities: [:shell_execute])
      described_class.clear!
      expect(described_class.all).to be_empty
    end
  end

  describe '.audit_result_for' do
    it 'returns nil for unregistered extension' do
      expect(described_class.audit_result_for('lex-missing')).to be_nil
    end
  end
end
