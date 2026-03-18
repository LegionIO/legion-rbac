# frozen_string_literal: true

require 'spec_helper'
require 'legion/rbac/kerberos_claims_mapper'

RSpec.describe Legion::Rbac::KerberosClaimsMapper do
  let(:role_map) do
    {
      'CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'  => 'admin',
      'CN=Legion-Workers,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com' => 'worker'
    }
  end

  describe '.map' do
    it 'maps AD groups to Legion roles' do
      result = described_class.map(
        principal: 'miverso2@MS.DS.UHC.COM',
        groups:    ['CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'],
        role_map:  role_map
      )
      expect(result[:sub]).to eq('miverso2')
      expect(result[:roles]).to eq(['admin'])
      expect(result[:scope]).to eq('human')
      expect(result[:auth_method]).to eq('kerberos')
    end

    it 'defaults to worker role when no groups match' do
      result = described_class.map(
        principal: 'miverso2@MS.DS.UHC.COM',
        groups:    ['CN=Unrelated,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'],
        role_map:  role_map
      )
      expect(result[:roles]).to eq(['worker'])
    end

    it 'deduplicates roles' do
      result = described_class.map(
        principal: 'miverso2@MS.DS.UHC.COM',
        groups:    [
          'CN=Legion-Workers,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com',
          'CN=Legion-Workers,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'
        ],
        role_map:  role_map
      )
      expect(result[:roles]).to eq(['worker'])
    end

    it 'handles empty groups array' do
      result = described_class.map(principal: 'user@REALM', groups: [], role_map: role_map)
      expect(result[:roles]).to eq(['worker'])
    end

    it 'allows custom default role' do
      result = described_class.map(principal: 'user@REALM', groups: [], role_map: role_map,
                                   default_role: 'observer')
      expect(result[:roles]).to eq(['observer'])
    end

    it 'handles principal without realm' do
      result = described_class.map(principal: 'miverso2', groups: [], role_map: role_map)
      expect(result[:sub]).to eq('miverso2')
    end
  end

  describe '.map_with_fallback' do
    context 'when groups are present' do
      it 'maps directly without fallback' do
        result = described_class.map_with_fallback(
          principal: 'miverso2@MS.DS.UHC.COM',
          groups:    ['CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'],
          role_map:  role_map
        )
        expect(result[:roles]).to eq(['admin'])
        expect(result[:auth_method]).to eq('kerberos')
      end
    end

    context 'when groups are nil and fallback is :none' do
      it 'assigns default worker role' do
        result = described_class.map_with_fallback(
          principal: 'miverso2@MS.DS.UHC.COM',
          groups:    nil,
          fallback:  :none,
          role_map:  role_map
        )
        expect(result[:roles]).to eq(['worker'])
        expect(result[:auth_method]).to eq('kerberos')
      end
    end

    context 'when groups are nil and fallback is :entra' do
      context 'when EntraClaimsMapper is available' do
        before do
          stub_const('Legion::Rbac::EntraClaimsMapper', Module.new)
          allow(Legion::Rbac::EntraClaimsMapper).to receive(:map_claims)
            .and_return({ sub: 'miverso2', roles: ['supervisor'], scope: 'human' })
        end

        it 'delegates to EntraClaimsMapper and adds auth_method' do
          result = described_class.map_with_fallback(
            principal: 'miverso2@MS.DS.UHC.COM',
            groups:    nil,
            fallback:  :entra,
            role_map:  role_map
          )
          expect(result[:sub]).to eq('miverso2')
          expect(result[:roles]).to eq(['supervisor'])
          expect(result[:auth_method]).to eq('kerberos')
        end
      end

      context 'when EntraClaimsMapper returns nil' do
        before do
          stub_const('Legion::Rbac::EntraClaimsMapper', Module.new)
          allow(Legion::Rbac::EntraClaimsMapper).to receive(:map_claims).and_return(nil)
        end

        it 'falls back to default role' do
          result = described_class.map_with_fallback(
            principal: 'miverso2@MS.DS.UHC.COM',
            groups:    nil,
            fallback:  :entra,
            role_map:  role_map
          )
          expect(result[:roles]).to eq(['worker'])
        end
      end
    end

    context 'when groups are empty array' do
      it 'treats empty as no groups (uses fallback)' do
        result = described_class.map_with_fallback(
          principal: 'miverso2@MS.DS.UHC.COM',
          groups:    [],
          fallback:  :none,
          role_map:  role_map
        )
        expect(result[:roles]).to eq(['worker'])
        expect(result[:auth_method]).to eq('kerberos')
      end
    end
  end
end
