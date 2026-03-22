# Changelog

## [0.2.7] - 2026-03-22

### Changed
- Corrected legion-settings version constraint to `>= 1.3.12`

## [0.2.6] - 2026-03-22

### Changed
- Updated gemspec dependency version constraints to explicit 3-part versions: `legion-json >= 1.2.0`, `legion-settings >= 1.3.9`

## [0.2.5] - 2026-03-22

### Changed
- Added logging to silent rescue block in middleware.rb enforce? method

## [0.2.4] - 2026-03-22

### Changed
- Bumped version for rbac.deny event emission

## [0.2.3] - 2026-03-20

### Added
- Emit `rbac.deny` event on access denial for safety metrics integration

## [0.2.2] - 2026-03-18

### Added
- Organizational profile attributes on `Principal`: `title`, `department`, `company`, `city`, `state`, `country`, `country_code`, `cn`, `ad_created_at`
- `Principal#profile` hash accessor for all extended identity attributes
- `PROFILE_KEYS` constant defines the full set of identity/org fields
- `define_method` generates individual accessors from `PROFILE_KEYS`

### Changed
- `Principal` constructor accepts `**extra` kwargs for profile fields (replaces individual keyword args)
- `from_claims` iterates `PROFILE_KEYS` to extract all profile fields from claims
- `KerberosClaimsMapper.map` uses `**profile` splat directly (passes all profile kwargs through)

## [0.2.1] - 2026-03-18

### Added
- `samaccountname`, `ad_fqdn`, `first_name`, `last_name`, `email`, `display_name` attributes on `Principal`
- `from_claims` extracts identity attributes from Kerberos claims
- `KerberosClaimsMapper.map` emits `samaccountname` and `ad_fqdn` from principal, accepts `**profile` kwargs
- `KerberosClaimsMapper.map_with_fallback` passes profile through to `map`

### Changed
- `KerberosClaimsMapper.map` now returns `.compact` hash (omits nil values)

## [0.2.0] - 2026-03-17

### Added
- `KerberosClaimsMapper` module: maps Kerberos principals and AD group memberships to Legion roles
- LDAP group-to-role mapping with configurable `role_map`
- Entra fallback via `map_with_fallback` when LDAP groups unavailable
- `auth_method: 'kerberos'` claim injection for identity signal tracking

## [0.2.0] - 2026-03-17

### Added
- `EntraClaimsMapper` module: maps Entra ID claims (oid, roles, groups) to Legion RBAC principals
- Configurable role_map (app roles) and group_map (security group OIDs) with default_role fallback
- Entra settings defaults (tenant_id, role_map, group_map, default_role)
- String and symbol key support for JWT claim payloads

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
