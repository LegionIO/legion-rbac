# frozen_string_literal: true

module Legion
  module Rbac
    class Principal
      attr_reader :id, :type, :roles, :team, :auth_method,
                  :samaccountname, :ad_fqdn, :first_name, :last_name, :email, :display_name

      def initialize(id:, type: :human, roles: [], team: nil, auth_method: nil, # rubocop:disable Metrics/ParameterLists
                     samaccountname: nil, ad_fqdn: nil, first_name: nil, last_name: nil,
                     email: nil, display_name: nil)
        @id = id
        @type = type.to_sym
        @roles = roles.map(&:to_s)
        @team = team
        @auth_method = auth_method
        @samaccountname = samaccountname
        @ad_fqdn = ad_fqdn
        @first_name = first_name
        @last_name = last_name
        @email = email
        @display_name = display_name
      end

      def self.from_claims(claims)
        scope = claims[:scope] || claims['scope']
        common = {
          roles:          claims[:roles] || claims['roles'] || [],
          team:           claims[:team] || claims['team'],
          auth_method:    claims[:auth_method] || claims['auth_method'],
          samaccountname: claims[:samaccountname] || claims['samaccountname'],
          ad_fqdn:        claims[:ad_fqdn] || claims['ad_fqdn'],
          first_name:     claims[:first_name] || claims['first_name'],
          last_name:      claims[:last_name] || claims['last_name'],
          email:          claims[:email] || claims['email'],
          display_name:   claims[:display_name] || claims['display_name']
        }

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
