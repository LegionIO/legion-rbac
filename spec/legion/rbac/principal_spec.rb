# frozen_string_literal: true

RSpec.describe Legion::Rbac::Principal do
  describe '.from_claims' do
    it 'creates a worker principal from worker scope' do
      claims = { scope: 'worker', worker_id: 'w-123', roles: ['worker'], team: 'alpha' }
      principal = described_class.from_claims(claims)
      expect(principal.type).to eq(:worker)
      expect(principal.id).to eq('w-123')
      expect(principal.roles).to eq(['worker'])
      expect(principal.team).to eq('alpha')
    end

    it 'creates a human principal from non-worker scope' do
      claims = { scope: 'human', sub: 'msid-456', roles: %w[supervisor admin], team: 'beta' }
      principal = described_class.from_claims(claims)
      expect(principal.type).to eq(:human)
      expect(principal.id).to eq('msid-456')
      expect(principal.roles).to eq(%w[supervisor admin])
    end

    it 'creates a principal with kerberos identity attributes' do
      claims = {
        scope: 'human', sub: 'miverso2', roles: ['admin'],
        auth_method: 'kerberos', samaccountname: 'miverso2', ad_fqdn: 'ms.ds.uhc.com',
        first_name: 'Matthew', last_name: 'Iverson', email: 'miverso2@uhc.com',
        display_name: 'Iverson, Matthew'
      }
      principal = described_class.from_claims(claims)
      expect(principal.auth_method).to eq('kerberos')
      expect(principal.samaccountname).to eq('miverso2')
      expect(principal.ad_fqdn).to eq('ms.ds.uhc.com')
      expect(principal.first_name).to eq('Matthew')
      expect(principal.last_name).to eq('Iverson')
      expect(principal.email).to eq('miverso2@uhc.com')
      expect(principal.display_name).to eq('Iverson, Matthew')
    end

    it 'leaves identity attributes nil when not in claims' do
      claims = { scope: 'human', sub: 'user-1', roles: ['worker'] }
      principal = described_class.from_claims(claims)
      expect(principal.auth_method).to be_nil
      expect(principal.samaccountname).to be_nil
      expect(principal.first_name).to be_nil
      expect(principal.email).to be_nil
    end
  end

  describe '.local_admin' do
    it 'returns a principal with the default local role' do
      principal = described_class.local_admin
      expect(principal.id).to eq('local')
      expect(principal.roles).to include('admin')
    end
  end

  describe '.anonymous' do
    it 'returns a principal with no roles' do
      principal = described_class.anonymous
      expect(principal.id).to eq('anonymous')
      expect(principal.roles).to be_empty
    end
  end
end
