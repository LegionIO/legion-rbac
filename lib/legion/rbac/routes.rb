# frozen_string_literal: true

# Self-registering route module for legion-rbac.
# All routes previously defined in LegionIO/lib/legion/api/rbac.rb now live here
# and are mounted via Legion::API.register_library_routes when legion-rbac boots.
#
# LegionIO/lib/legion/api/rbac.rb is preserved for backward compatibility but guards
# its registration with defined?(Legion::Rbac::Routes) so double-registration is avoided.

require 'time'

module Legion
  module Rbac
    module Routes
      class InvalidTimestamp < StandardError; end

      DEFAULT_COLLECTION_LIMIT = 100
      MAX_COLLECTION_LIMIT = 500

      def self.registered(app)
        register_helpers(app)
        register_roles(app)
        register_check(app)
        register_assignments(app)
        register_grants(app)
        register_cross_team_grants(app)
      end

      def self.register_helpers(app) # rubocop:disable Metrics/AbcSize,Metrics/CyclomaticComplexity,Metrics/MethodLength,Metrics/PerceivedComplexity
        app.helpers do # rubocop:disable Metrics/BlockLength
          unless method_defined?(:parse_request_body)
            define_method(:parse_request_body) do
              raw = request.body.read
              return {} if raw.nil? || raw.empty?

              begin
                parsed = Legion::JSON.load(raw)
              rescue StandardError
                halt 400, { 'Content-Type' => 'application/json' },
                     Legion::JSON.dump({ error: { code: 'invalid_json', message: 'request body is not valid JSON' } })
              end

              unless parsed.respond_to?(:transform_keys)
                halt 400, { 'Content-Type' => 'application/json' },
                     Legion::JSON.dump({ error: { code:    'invalid_request_body',
                                                  message: 'request body must be a JSON object' } })
              end

              parsed.transform_keys(&:to_sym)
            end
          end

          unless method_defined?(:json_response)
            define_method(:json_response) do |data, status_code: 200|
              content_type :json
              status status_code
              Legion::JSON.dump({ data: data })
            end
          end

          unless method_defined?(:json_error)
            define_method(:json_error) do |code, message, status_code: 400|
              content_type :json
              status status_code
              Legion::JSON.dump({ error: { code: code, message: message } })
            end
          end

          unless method_defined?(:json_collection)
            define_method(:json_collection) do |dataset|
              content_type :json
              Legion::JSON.dump(Legion::Rbac::Routes.send(:collection_payload, dataset, params))
            end
          end

          unless method_defined?(:current_owner_msid)
            define_method(:current_owner_msid) do
              env['legion.owner_msid']
            end
          end

          unless method_defined?(:current_rbac_actor_id)
            define_method(:current_rbac_actor_id) do
              current_owner_msid || env['legion.principal']&.id || 'api'
            end
          end

          unless method_defined?(:rbac_request_correlation_id)
            define_method(:rbac_request_correlation_id) do
              Legion::Rbac::Routes.send(:request_correlation_id, env)
            end
          end

          unless method_defined?(:rbac_request_source)
            define_method(:rbac_request_source) do
              Legion::Rbac::Routes.send(:request_source, env)
            end
          end

          unless method_defined?(:emit_rbac_policy_changed)
            define_method(:emit_rbac_policy_changed) do |change_type, target_type, record_values|
              Legion::Rbac::Routes.send(
                :emit_policy_changed,
                change_type:   change_type,
                target_type:   target_type,
                record_values: record_values,
                context:       Legion::Rbac::Routes.send(
                  :policy_change_context,
                  actor_id:       current_rbac_actor_id,
                  source:         rbac_request_source,
                  correlation_id: rbac_request_correlation_id,
                  method:         request.request_method,
                  path:           request.path_info
                )
              )
            end
          end
        end
      end

      def self.register_roles(app)
        app.get '/api/rbac/roles' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)

          roles = Legion::Rbac.role_index.transform_values do |role|
            { name: role.name, description: role.description, cross_team: role.cross_team? }
          end
          json_response(roles)
        end

        app.get '/api/rbac/roles/:name' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)

          role = Legion::Rbac.role_index[params[:name].to_sym]
          halt 404, json_error('not_found', "Role #{params[:name]} not found", status_code: 404) unless role

          json_response({
                          name:        role.name,
                          description: role.description,
                          cross_team:  role.cross_team?,
                          permissions: role.permissions.map { |p| { resource: p.resource_pattern, actions: p.actions } },
                          deny_rules:  role.deny_rules.map { |d| { resource: d.resource_pattern, above_level: d.above_level } }
                        })
        end
      end

      def self.register_check(app)
        app.post '/api/rbac/check' do
          Legion::Logging.debug "API: POST /api/rbac/check params=#{params.keys}" if defined?(Legion::Logging)
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)

          body = parse_request_body
          principal = Legion::Rbac::Principal.new(
            id:    body[:principal] || 'anonymous',
            roles: body[:roles] || [],
            team:  body[:team]
          )
          result = Legion::Rbac::PolicyEngine.evaluate(
            principal: principal,
            action:    body[:action] || 'read',
            resource:  body[:resource] || '*',
            enforce:   false
          )
          json_response(result)
        rescue StandardError => e
          Legion::Logging.error "API POST /api/rbac/check: #{e.class} — #{e.message}" if defined?(Legion::Logging)
          json_error('rbac_error', e.message, status_code: 500)
        end
      end

      def self.register_assignments(app) # rubocop:disable Metrics/AbcSize,Metrics/CyclomaticComplexity,Metrics/PerceivedComplexity
        app.get '/api/rbac/assignments' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          dataset = Legion::Data::Model::RbacRoleAssignment.order(:id)
          dataset = dataset.where(team: params[:team]) if params[:team]
          dataset = dataset.where(role: params[:role]) if params[:role]
          dataset = dataset.where(principal_id: params[:principal]) if params[:principal]
          json_collection(dataset)
        end

        app.post '/api/rbac/assignments' do
          Legion::Logging.debug "API: POST /api/rbac/assignments params=#{params.keys}" if defined?(Legion::Logging)
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          body = parse_request_body
          record = Legion::Data::Model::RbacRoleAssignment.create(
            principal_type: body[:principal_type] || 'human',
            principal_id:   body[:principal_id],
            role:           body[:role],
            team:           body[:team],
            granted_by:     current_owner_msid || 'api',
            expires_at:     parse_optional_time(body[:expires_at], field: 'expires_at')
          )
          Legion::Logging.info "API: created RBAC assignment #{record.id} role=#{body[:role]} principal=#{body[:principal_id]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('assignment.created', 'role_assignment', record.values)
          json_response(record.values, status_code: 201)
        rescue Legion::Rbac::Routes::InvalidTimestamp => e
          json_error('validation_error', e.message, status_code: 422)
        rescue Sequel::ValidationFailed => e
          Legion::Logging.warn "API POST /api/rbac/assignments returned 422: #{e.message}" if defined?(Legion::Logging)
          json_error('validation_error', e.message, status_code: 422)
        end

        app.delete '/api/rbac/assignments/:id' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          record = Legion::Data::Model::RbacRoleAssignment[params[:id].to_i]
          halt 404, json_error('not_found', 'Assignment not found', status_code: 404) unless record

          snapshot = record.values.dup
          record.destroy
          Legion::Logging.info "API: deleted RBAC assignment #{params[:id]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('assignment.deleted', 'role_assignment', snapshot)
          json_response({ deleted: true })
        end
      end

      def self.register_grants(app)
        app.get '/api/rbac/grants' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          dataset = Legion::Data::Model::RbacRunnerGrant.order(:id)
          dataset = dataset.where(team: params[:team]) if params[:team]
          json_collection(dataset)
        end

        app.post '/api/rbac/grants' do
          Legion::Logging.debug "API: POST /api/rbac/grants params=#{params.keys}" if defined?(Legion::Logging)
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          body = parse_request_body
          record = Legion::Data::Model::RbacRunnerGrant.create(
            team:           body[:team],
            runner_pattern: body[:runner_pattern],
            actions:        Array(body[:actions]).join(','),
            granted_by:     current_owner_msid || 'api'
          )
          Legion::Logging.info "API: created RBAC grant #{record.id} team=#{body[:team]} pattern=#{body[:runner_pattern]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('runner_grant.created', 'runner_grant', record.values)
          json_response(record.values, status_code: 201)
        rescue Sequel::ValidationFailed => e
          Legion::Logging.warn "API POST /api/rbac/grants returned 422: #{e.message}" if defined?(Legion::Logging)
          json_error('validation_error', e.message, status_code: 422)
        end

        app.delete '/api/rbac/grants/:id' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          record = Legion::Data::Model::RbacRunnerGrant[params[:id].to_i]
          halt 404, json_error('not_found', 'Grant not found', status_code: 404) unless record

          snapshot = record.values.dup
          record.destroy
          Legion::Logging.info "API: deleted RBAC grant #{params[:id]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('runner_grant.deleted', 'runner_grant', snapshot)
          json_response({ deleted: true })
        end
      end

      def self.register_cross_team_grants(app)
        app.get '/api/rbac/grants/cross-team' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          dataset = Legion::Data::Model::RbacCrossTeamGrant.order(:id)
          json_collection(dataset)
        end

        app.post '/api/rbac/grants/cross-team' do
          Legion::Logging.debug "API: POST /api/rbac/grants/cross-team params=#{params.keys}" if defined?(Legion::Logging)
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          body = parse_request_body
          record = Legion::Data::Model::RbacCrossTeamGrant.create(
            source_team:    body[:source_team],
            target_team:    body[:target_team],
            runner_pattern: body[:runner_pattern],
            actions:        Array(body[:actions]).join(','),
            granted_by:     current_owner_msid || 'api',
            expires_at:     parse_optional_time(body[:expires_at], field: 'expires_at')
          )
          Legion::Logging.info "API: created cross-team RBAC grant #{record.id} #{body[:source_team]}->#{body[:target_team]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('cross_team_grant.created', 'cross_team_grant', record.values)
          json_response(record.values, status_code: 201)
        rescue Legion::Rbac::Routes::InvalidTimestamp => e
          json_error('validation_error', e.message, status_code: 422)
        rescue Sequel::ValidationFailed => e
          Legion::Logging.warn "API POST /api/rbac/grants/cross-team returned 422: #{e.message}" if defined?(Legion::Logging)
          json_error('validation_error', e.message, status_code: 422)
        end

        app.delete '/api/rbac/grants/cross-team/:id' do
          return json_error('rbac_unavailable', 'legion-rbac not installed', status_code: 501) unless defined?(Legion::Rbac)
          return json_error('db_unavailable', 'legion-data not connected', status_code: 503) unless Legion::Rbac::Store.db_available?

          record = Legion::Data::Model::RbacCrossTeamGrant[params[:id].to_i]
          halt 404, json_error('not_found', 'Grant not found', status_code: 404) unless record

          snapshot = record.values.dup
          record.destroy
          Legion::Logging.info "API: deleted cross-team RBAC grant #{params[:id]}" if defined?(Legion::Logging)
          emit_rbac_policy_changed('cross_team_grant.deleted', 'cross_team_grant', snapshot)
          json_response({ deleted: true })
        end
      end

      class << self
        private

        def parse_optional_time(value, field:)
          return nil if value.nil?
          raise InvalidTimestamp, "#{field} must be a valid ISO8601 timestamp" unless value.is_a?(String)
          return nil if value.empty?

          Time.iso8601(value)
        rescue ArgumentError
          raise InvalidTimestamp, "#{field} must be a valid ISO8601 timestamp"
        end

        def collection_payload(dataset, params)
          limit = collection_limit(params)
          offset = collection_offset(params)
          rows = dataset.limit(limit, offset).all.map(&:values)
          {
            data:       rows,
            pagination: {
              limit:    limit,
              offset:   offset,
              returned: rows.size
            }
          }
        end

        def collection_limit(params)
          requested = collection_integer(params, :limit)
          return DEFAULT_COLLECTION_LIMIT unless requested&.positive?

          [requested, MAX_COLLECTION_LIMIT].min
        end

        def collection_offset(params)
          requested = collection_integer(params, :offset)
          requested&.positive? ? requested : 0
        end

        def collection_integer(params, key)
          value = params[key] || params[key.to_s]
          return nil if value.nil? || value.to_s.empty?

          Integer(value, exception: false)
        end

        def request_correlation_id(env)
          env['legion.correlation_id'] || env['HTTP_X_REQUEST_ID'] || env['HTTP_X_CORRELATION_ID'] ||
            env['action_dispatch.request_id'] || env['REQUEST_ID']
        end

        def request_source(env)
          env['legion.request_source'] || env['HTTP_X_LEGION_SOURCE'] || 'rbac.api'
        end

        def policy_change_context(actor_id:, source:, correlation_id:, method:, path:)
          {
            actor_id:       actor_id,
            source:         source,
            correlation_id: correlation_id,
            method:         method,
            path:           path
          }
        end

        def emit_policy_changed(change_type:, target_type:, record_values:, context:)
          return unless defined?(Legion::Events) && Legion::Rbac.events_enabled?

          Legion::Events.emit(
            'rbac.policy_changed',
            policy_change_payload(
              change_type:   change_type,
              target_type:   target_type,
              record_values: record_values,
              context:       context
            )
          )
        rescue StandardError => e
          return unless defined?(Legion::Logging)

          Legion::Logging.warn("API policy change event failed type=#{target_type} change=#{change_type} error=#{e.class}: #{e.message}")
        end

        def policy_change_payload(change_type:, target_type:, record_values:, context:)
          values = normalize_record_values(record_values)
          {
            change_type:    change_type,
            target_type:    target_type,
            target_id:      values[:id],
            actor_id:       context[:actor_id],
            source:         context[:source],
            correlation_id: context[:correlation_id],
            method:         context[:method],
            path:           context[:path]
          }.merge(values).compact
        end

        def normalize_record_values(record_values)
          (record_values || {}).each_with_object({}) do |(key, value), normalized|
            normalized[key.to_sym] = value
          end
        end

        private :register_helpers, :register_roles, :register_check, :register_assignments, :register_grants,
                :register_cross_team_grants,
                :parse_optional_time, :collection_payload, :collection_limit, :collection_offset, :collection_integer,
                :request_correlation_id, :request_source, :policy_change_context, :emit_policy_changed,
                :policy_change_payload,
                :normalize_record_values
      end
    end
  end
end
