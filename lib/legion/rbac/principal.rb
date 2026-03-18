# frozen_string_literal: true

module Legion
  module Rbac
    class Principal
      PROFILE_KEYS = %i[
        first_name last_name email display_name cn title
        department company country country_code city state ad_created_at
      ].freeze

      attr_reader :id, :type, :roles, :team, :auth_method,
                  :samaccountname, :ad_fqdn, :profile

      def initialize(id:, type: :human, roles: [], team: nil, auth_method: nil, # rubocop:disable Metrics/ParameterLists
                     samaccountname: nil, ad_fqdn: nil, **extra)
        @id = id
        @type = type.to_sym
        @roles = roles.map(&:to_s)
        @team = team
        @auth_method = auth_method
        @samaccountname = samaccountname
        @ad_fqdn = ad_fqdn
        @profile = extra.slice(*PROFILE_KEYS).compact
      end

      PROFILE_KEYS.each do |key|
        define_method(key) { @profile[key] }
      end

      def self.from_claims(claims)
        scope = claims[:scope] || claims['scope']
        common = {
          roles:          claims[:roles] || claims['roles'] || [],
          team:           claims[:team] || claims['team'],
          auth_method:    claims[:auth_method] || claims['auth_method'],
          samaccountname: claims[:samaccountname] || claims['samaccountname'],
          ad_fqdn:        claims[:ad_fqdn] || claims['ad_fqdn']
        }
        PROFILE_KEYS.each { |key| common[key] = claims[key] || claims[key.to_s] }

        if scope == 'worker'
          new(id: claims[:worker_id] || claims['worker_id'], type: :worker, **common)
        else
          new(id: claims[:sub] || claims['sub'], type: :human, **common)
        end
      end

      def self.local_admin
        role = Legion::Settings[:rbac][:default_local_role] || 'admin'
        new(id: 'local', type: :human, roles: [role])
      end

      def self.anonymous
        new(id: 'anonymous', type: :human, roles: [])
      end
    end
  end
end
