# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Rbac
    class Principal
      include Legion::Logging::Helper

      PROFILE_KEYS = %i[
        first_name last_name email display_name cn title
        department company country country_code city state ad_created_at
      ].freeze

      attr_reader :id, :type, :roles, :team, :auth_method,
                  :samaccountname, :ad_fqdn, :profile

      class << self
        include Legion::Logging::Helper
      end

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
        log.debug("RBAC principal initialized id=#{@id} type=#{@type} roles=#{@roles.size} team=#{@team}")
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

        principal = if scope == 'worker'
                      new(id: claims[:worker_id] || claims['worker_id'], type: :worker, **common)
                    else
                      new(id: claims[:sub] || claims['sub'], type: :human, **common)
                    end
        log.info(
          "RBAC principal mapped from claims id=#{principal.id} type=#{principal.type} " \
          "roles=#{principal.roles.size} team=#{principal.team}"
        )
        principal
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.principal.from_claims', scope: scope)
        raise
      end

      def self.local_admin
        role = Legion::Settings[:rbac][:default_local_role] || 'admin'
        principal = new(id: 'local', type: :human, roles: [role])
        log.info("RBAC local_admin principal created role=#{role}")
        principal
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.principal.local_admin')
        raise
      end

      def self.anonymous
        principal = new(id: 'anonymous', type: :human, roles: [])
        log.info('RBAC anonymous principal created')
        principal
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'rbac.principal.anonymous')
        raise
      end
    end
  end
end
