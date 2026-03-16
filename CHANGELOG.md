# Changelog

## [0.1.0] - 2026-03-16

### Added
- Gem scaffold with version, gemspec, and spec infrastructure
- Settings module with four built-in roles (worker, supervisor, admin, governance-observer)
- Permission and DenyRule classes with glob pattern matching (`*`, `+`)
- Role data class with permissions and deny rules
- ConfigLoader for building role index from settings
- Principal identity wrapper with factory methods (from_claims, local_admin, anonymous)
- PolicyEngine evaluator: deny-always-wins, union of permissions, dry-run support
- TeamScope module for cross-team access control
- Dual-mode Store: DB-backed via Sequel models or static_assignments fallback
- Rack middleware with route-level permission enforcement
- AccessDenied exception with structured result payload
- `authorize!` and `authorize_execution!` convenience methods
- 74 specs across all components
