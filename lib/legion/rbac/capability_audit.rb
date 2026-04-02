# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Rbac
    module CapabilityAudit
      extend Legion::Logging::Helper

      PATTERN_TO_CAPABILITY = {
        /\bKernel\.system\b|\bsystem\s*\(/     => :shell_execute,
        /\bKernel\.exec\b|\bexec\s*\(/         => :shell_execute,
        /\bOpen3\b/                            => :shell_execute,
        /`[^`]+`/                              => :shell_execute,
        /\bIO\.popen\b/                        => :shell_execute,
        /\bKernel\.eval\b|\beval\s*\(/         => :code_eval,
        /\bNet::HTTP\b/                        => :network_outbound,
        /\bFaraday\b/                          => :network_outbound,
        /\bHTTParty\b/                         => :network_outbound,
        /\bFile\.(write|open|delete|rename)\b/ => :filesystem_write,
        /\bFileUtils\b/                        => :filesystem_write
      }.freeze

      class AuditResult
        attr_reader :extension_name, :detected_capabilities, :declared_capabilities,
                    :undeclared, :allowed, :reason

        def initialize(extension_name:, detected:, declared:, allowed:, reason: nil)
          @extension_name = extension_name
          @detected_capabilities = detected.uniq.sort
          @declared_capabilities = declared.map(&:to_sym).uniq.sort
          @undeclared = (@detected_capabilities - @declared_capabilities).sort
          @allowed = allowed
          @reason = reason
        end

        def blocked?
          !@allowed
        end

        def to_h
          hash = {
            extension_name:        @extension_name,
            allowed:               @allowed,
            detected_capabilities: @detected_capabilities,
            declared_capabilities: @declared_capabilities,
            undeclared:            @undeclared
          }
          hash[:reason] = @reason if @reason
          hash
        end
      end

      class << self
        def audit(extension_name:, source_path:, declared_capabilities: [])
          log.info(
            "RBAC capability_audit start extension=#{extension_name} source_path=#{source_path} " \
            "declared=#{Array(declared_capabilities).size}"
          )
          unless enabled?
            result = skip_result(extension_name, 'capability audit disabled')
            log.info("RBAC capability_audit skipped extension=#{extension_name} reason=#{result.reason}")
            return result
          end

          unless source_path && Dir.exist?(source_path.to_s)
            result = skip_result(extension_name, 'no source path')
            log.info("RBAC capability_audit skipped extension=#{extension_name} reason=#{result.reason}")
            return result
          end

          detected = scan_source(source_path)
          declared_syms = Array(declared_capabilities).map(&:to_sym)
          undeclared = (detected.uniq - declared_syms)

          result = if undeclared.empty?
                     AuditResult.new(
                       extension_name: extension_name,
                       detected:       detected,
                       declared:       declared_syms,
                       allowed:        true
                     )
                   else
                     handle_undeclared(extension_name, detected, declared_syms, undeclared)
                   end
          log.info(
            "RBAC capability_audit extension=#{extension_name} allowed=#{result.allowed} " \
            "detected=#{result.detected_capabilities.size} undeclared=#{result.undeclared.size}"
          )
          result
        rescue StandardError => e
          handle_exception(
            e,
            level:          :error,
            operation:      'rbac.capability_audit.audit',
            extension_name: extension_name,
            source_path:    source_path
          )
          raise
        end

        def enabled?
          settings = capability_audit_settings
          settings[:enabled] != false
        end

        def mode
          settings = capability_audit_settings
          (settings[:mode] || 'enforce').to_s
        end

        private

        def scan_source(source_path)
          capabilities = []
          files = Dir.glob(File.join(source_path, '**', '*.rb'))
          files.each do |file|
            File.foreach(file) do |line|
              PATTERN_TO_CAPABILITY.each do |pattern, capability|
                capabilities << capability if line.match?(pattern)
              end
            end
          end
          log.debug("RBAC capability_audit scanned source_path=#{source_path} files=#{files.size}")
          capabilities.uniq
        end

        def handle_undeclared(extension_name, detected, declared, undeclared)
          if mode == 'warn'
            log_warning(extension_name, undeclared)
            AuditResult.new(
              extension_name: extension_name,
              detected:       detected,
              declared:       declared,
              allowed:        true,
              reason:         "undeclared capabilities (warn mode): #{undeclared.join(', ')}"
            )
          else
            log.warn("CapabilityAudit: #{extension_name} blocked for undeclared capabilities: #{undeclared.join(', ')}")
            AuditResult.new(
              extension_name: extension_name,
              detected:       detected,
              declared:       declared,
              allowed:        false,
              reason:         "undeclared capabilities: #{undeclared.join(', ')}"
            )
          end
        end

        def log_warning(extension_name, undeclared)
          log.warn("CapabilityAudit: #{extension_name} uses undeclared capabilities: #{undeclared.join(', ')}")
        end

        def skip_result(extension_name, reason)
          log.debug("RBAC capability_audit skip_result extension=#{extension_name} reason=#{reason}")
          AuditResult.new(
            extension_name: extension_name,
            detected:       [],
            declared:       [],
            allowed:        true,
            reason:         reason
          )
        end

        def capability_audit_settings
          return {} unless defined?(Legion::Settings)

          Legion::Settings[:rbac]&.dig(:capability_audit) || {}
        end
      end
    end
  end
end
