# frozen_string_literal: true

require 'monitor'

module Legion
  module Rbac
    module CapabilityRegistry
      class << self
        def register(extension_name, capabilities:, audit_result: nil)
          mon.synchronize do
            entries[extension_name.to_s] = {
              capabilities:  Array(capabilities).map(&:to_sym).uniq,
              audit_result:  audit_result,
              registered_at: Time.now
            }
          end
        end

        def for_extension(extension_name)
          mon.synchronize do
            entry = entries[extension_name.to_s]
            entry ? entry[:capabilities] : []
          end
        end

        def extensions_with(capability)
          cap_sym = capability.to_sym
          mon.synchronize do
            entries.select { |_, entry| entry[:capabilities].include?(cap_sym) }.keys
          end
        end

        def audit_result_for(extension_name)
          mon.synchronize do
            entry = entries[extension_name.to_s]
            entry&.dig(:audit_result)
          end
        end

        def all
          mon.synchronize { entries.dup }
        end

        def registered?(extension_name)
          mon.synchronize { entries.key?(extension_name.to_s) }
        end

        def clear!
          mon.synchronize { @entries = {} }
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
