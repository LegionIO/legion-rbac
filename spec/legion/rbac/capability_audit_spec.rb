# frozen_string_literal: true

require 'tmpdir'
require 'fileutils'

RSpec.describe Legion::Rbac::CapabilityAudit do
  let(:tmpdir) { Dir.mktmpdir('cap-audit') }

  after do
    FileUtils.remove_entry(tmpdir)
    Legion::Settings[:rbac][:capability_audit][:mode] = 'enforce'
    Legion::Settings[:rbac][:capability_audit][:enabled] = true
  end

  def write_source(filename, content)
    File.write(File.join(tmpdir, filename), content)
  end

  describe '.audit' do
    context 'when source contains system() without declaring shell_execute' do
      before { write_source('runner.rb', "system('ls -la')") }

      it 'blocks the extension in enforce mode' do
        Legion::Settings[:rbac][:capability_audit][:mode] = 'enforce'
        result = described_class.audit(
          extension_name:        'lex-danger',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.blocked?).to be true
        expect(result.undeclared).to eq([:shell_execute])
        expect(result.reason).to include('undeclared capabilities')
      end

      it 'allows with warning in warn mode' do
        Legion::Settings[:rbac][:capability_audit][:mode] = 'warn'
        result = described_class.audit(
          extension_name:        'lex-danger',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.blocked?).to be false
        expect(result.reason).to include('warn mode')
      end
    end

    context 'when source contains exec() with shell_execute declared' do
      before { write_source('runner.rb', "Kernel.exec('bin/start')") }

      it 'allows the extension' do
        result = described_class.audit(
          extension_name:        'lex-runner',
          source_path:           tmpdir,
          declared_capabilities: [:shell_execute]
        )
        expect(result.blocked?).to be false
        expect(result.undeclared).to be_empty
      end
    end

    context 'when source contains eval()' do
      before { write_source('dynamic.rb', 'eval(some_code)') }

      it 'detects code_eval capability' do
        result = described_class.audit(
          extension_name:        'lex-dynamic',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:code_eval)
        expect(result.blocked?).to be true
      end
    end

    context 'when source contains Open3' do
      before { write_source('shell.rb', "Open3.capture3('ls')") }

      it 'detects shell_execute capability' do
        result = described_class.audit(
          extension_name:        'lex-shell',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:shell_execute)
      end
    end

    context 'when source contains backtick subshell' do
      before { write_source('cmd.rb', 'output = `whoami`') }

      it 'detects shell_execute capability' do
        result = described_class.audit(
          extension_name:        'lex-cmd',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:shell_execute)
      end
    end

    context 'when source contains IO.popen' do
      before { write_source('io.rb', "IO.popen('cat', 'r')") }

      it 'detects shell_execute capability' do
        result = described_class.audit(
          extension_name:        'lex-io',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:shell_execute)
      end
    end

    context 'when source contains Net::HTTP' do
      before { write_source('http.rb', 'Net::HTTP.get(uri)') }

      it 'detects network_outbound capability' do
        result = described_class.audit(
          extension_name:        'lex-http',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:network_outbound)
      end
    end

    context 'when source contains Faraday' do
      before { write_source('api.rb', 'Faraday.get(url)') }

      it 'detects network_outbound capability' do
        result = described_class.audit(
          extension_name:        'lex-api',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:network_outbound)
      end
    end

    context 'when source contains File.write' do
      before { write_source('writer.rb', "File.write('/tmp/out.txt', data)") }

      it 'detects filesystem_write capability' do
        result = described_class.audit(
          extension_name:        'lex-writer',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:filesystem_write)
      end
    end

    context 'when source contains FileUtils' do
      before { write_source('files.rb', 'FileUtils.cp(src, dst)') }

      it 'detects filesystem_write capability' do
        result = described_class.audit(
          extension_name:        'lex-files',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:filesystem_write)
      end
    end

    context 'when source is clean' do
      before { write_source('safe.rb', "puts 'hello world'") }

      it 'allows the extension with no capabilities detected' do
        result = described_class.audit(
          extension_name:        'lex-safe',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.blocked?).to be false
        expect(result.detected_capabilities).to be_empty
      end
    end

    context 'when source has multiple patterns' do
      before do
        write_source('multi.rb', <<~RUBY)
          system('deploy')
          Net::HTTP.get(uri)
          eval(code)
        RUBY
      end

      it 'detects all capabilities' do
        result = described_class.audit(
          extension_name:        'lex-multi',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to contain_exactly(:code_eval, :network_outbound, :shell_execute)
      end

      it 'passes when all capabilities are declared' do
        result = described_class.audit(
          extension_name:        'lex-multi',
          source_path:           tmpdir,
          declared_capabilities: %i[shell_execute network_outbound code_eval]
        )
        expect(result.blocked?).to be false
        expect(result.undeclared).to be_empty
      end
    end

    context 'when source_path does not exist' do
      it 'returns allowed with skip reason' do
        result = described_class.audit(
          extension_name:        'lex-missing',
          source_path:           '/nonexistent/path',
          declared_capabilities: []
        )
        expect(result.blocked?).to be false
        expect(result.reason).to eq('no source path')
      end
    end

    context 'when capability audit is disabled' do
      before { Legion::Settings[:rbac][:capability_audit][:enabled] = false }

      after { Legion::Settings[:rbac][:capability_audit][:enabled] = true }

      it 'returns allowed with skip reason' do
        write_source('danger.rb', "system('rm -rf /')")
        result = described_class.audit(
          extension_name:        'lex-danger',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.blocked?).to be false
        expect(result.reason).to eq('capability audit disabled')
      end
    end

    context 'with nested source files' do
      before do
        nested = File.join(tmpdir, 'lib', 'runners')
        FileUtils.mkdir_p(nested)
        File.write(File.join(nested, 'deep.rb'), "system('deploy')")
      end

      it 'scans recursively' do
        result = described_class.audit(
          extension_name:        'lex-nested',
          source_path:           tmpdir,
          declared_capabilities: []
        )
        expect(result.detected_capabilities).to include(:shell_execute)
      end
    end
  end

  describe '.enabled?' do
    it 'returns true by default' do
      expect(described_class.enabled?).to be true
    end

    it 'returns false when disabled' do
      Legion::Settings[:rbac][:capability_audit][:enabled] = false
      expect(described_class.enabled?).to be false
      Legion::Settings[:rbac][:capability_audit][:enabled] = true
    end
  end

  describe '.mode' do
    it 'defaults to enforce' do
      expect(described_class.mode).to eq('enforce')
    end

    it 'reads from settings' do
      Legion::Settings[:rbac][:capability_audit][:mode] = 'warn'
      expect(described_class.mode).to eq('warn')
      Legion::Settings[:rbac][:capability_audit][:mode] = 'enforce'
    end
  end

  describe 'AuditResult' do
    subject(:result) do
      described_class::AuditResult.new(
        extension_name: 'lex-test',
        detected:       %i[shell_execute network_outbound],
        declared:       [:shell_execute],
        allowed:        false,
        reason:         'undeclared capabilities: network_outbound'
      )
    end

    it 'tracks undeclared capabilities' do
      expect(result.undeclared).to eq([:network_outbound])
    end

    it 'converts to hash' do
      hash = result.to_h
      expect(hash[:extension_name]).to eq('lex-test')
      expect(hash[:allowed]).to be false
      expect(hash[:reason]).to include('network_outbound')
    end
  end
end
