# frozen_string_literal: true

require 'legion/logging/helper'
require 'monitor'

module Legion
  module Rbac
    module CapabilityRegistry
      class << self
        include Legion::Logging::Helper

        def register(extension_name, capabilities:, audit_result: nil)
          mon.synchronize do
            entries[extension_name.to_s] = {
              capabilities:  Array(capabilities).map(&:to_sym).uniq,
              audit_result:  audit_result,
              registered_at: Time.now
            }
          end
          log.info("RBAC capability_registry register extension=#{extension_name} count=#{Array(capabilities).uniq.size}")
        end

        def for_extension(extension_name)
          capabilities = mon.synchronize do
            entry = entries[extension_name.to_s]
            entry ? entry[:capabilities] : []
          end
          log.debug("RBAC capability_registry for_extension extension=#{extension_name} count=#{capabilities.size}")
          capabilities
        end

        def extensions_with(capability)
          cap_sym = capability.to_sym
          extensions = mon.synchronize do
            entries.select { |_, entry| entry[:capabilities].include?(cap_sym) }.keys
          end
          log.debug("RBAC capability_registry extensions_with capability=#{capability} count=#{extensions.size}")
          extensions
        end

        def audit_result_for(extension_name)
          audit_result = mon.synchronize do
            entry = entries[extension_name.to_s]
            entry&.dig(:audit_result)
          end
          log.debug("RBAC capability_registry audit_result_for extension=#{extension_name} present=#{!audit_result.nil?}")
          audit_result
        end

        def all
          registry = mon.synchronize { entries.dup }
          log.debug("RBAC capability_registry all count=#{registry.size}")
          registry
        end

        def registered?(extension_name)
          registered = mon.synchronize { entries.key?(extension_name.to_s) }
          log.debug("RBAC capability_registry registered extension=#{extension_name} value=#{registered}")
          registered
        end

        def clear!
          mon.synchronize { @entries = {} }
          log.info('RBAC capability_registry cleared')
        end

        private

        def entries
          @entries ||= {}
        end

        def mon
          @mon ||= Monitor.new
        end
      end
    end
  end
end
