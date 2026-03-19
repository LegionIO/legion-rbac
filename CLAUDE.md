# Legion::Rbac

**Parent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`
**GitHub**: https://github.com/LegionIO/legion-rbac
**Version**: 0.2.2

Optional RBAC gem for LegionIO. Vault-style flat policy model with deny-always-wins semantics.

## Architecture

- **Permission**: glob pattern + action list. `*` matches any path segments, `+` matches one segment.
- **DenyRule**: glob pattern + optional `above_level` threshold. Deny always wins over allow.
- **Role**: named collection of permissions and deny rules. `cross_team?` flag for cross-team access.
- **PolicyEngine**: resolves roles -> checks deny rules -> checks permissions (union). `enforce: false` for dry-run.
- **TeamScope**: validates cross-team access requires explicit `cross_team?` role.
- **Store**: dual-mode. Uses Sequel models when legion-data connected, falls back to `static_assignments` hash.
- **Middleware**: Rack middleware for API route protection. ROUTE_PERMISSIONS map, default-deny for unmapped routes.

## Key Files

```
lib/legion/rbac.rb              # Entry point: setup, shutdown, authorize!, authorize_execution!
lib/legion/rbac/settings.rb     # Default settings with 4 built-in roles
lib/legion/rbac/permission.rb   # Permission + DenyRule (glob matching)
lib/legion/rbac/role.rb         # Role data class
lib/legion/rbac/config_loader.rb # Builds role index from settings
lib/legion/rbac/principal.rb    # Identity wrapper + factory methods
lib/legion/rbac/policy_engine.rb # Core evaluator
lib/legion/rbac/team_scope.rb   # Cross-team access validation
lib/legion/rbac/store.rb        # Dual-mode data access
lib/legion/rbac/middleware.rb              # Rack middleware
lib/legion/rbac/entra_claims_mapper.rb    # Entra ID claims -> Legion roles
lib/legion/rbac/kerberos_claims_mapper.rb # Kerberos principal + AD groups -> Legion roles
```

## Integration Points

- **LegionIO/lib/legion/service.rb**: `setup_rbac` called after `setup_data`
- **LegionIO/lib/legion/ingress.rb**: `authorize_execution!` guard on task execution
- **LegionIO/lib/legion/api.rb**: Middleware registered, routes module loaded
- **LegionIO/lib/legion/api/rbac.rb**: REST API routes for RBAC management
- **LegionIO/lib/legion/cli/rbac_command.rb**: Thor CLI subcommand
- **LegionIO/lib/legion/mcp/tools/rbac_*.rb**: 3 MCP tools (check, assignments, grants)
- **legion-data**: Migration 015 + 3 Sequel models (RbacRoleAssignment, RbacRunnerGrant, RbacCrossTeamGrant)

## Claims Mappers

Two identity provider mappers convert external claims to Legion principals:

- **EntraClaimsMapper**: Maps Entra ID `roles` and `groups` claims to Legion roles. Uses `module_function` pattern. Configurable `role_map` and `group_map` with `default_role` fallback.
- **KerberosClaimsMapper**: Maps Kerberos principal (`user@REALM`) and AD group DNs to Legion roles. `map_with_fallback` tries LDAP groups first, falls back to Entra if configured. Passes through all `**profile` kwargs (identity + org attributes) from LDAP into the claims hash.

## Principal Identity Model

`Principal` carries core identity (`id`, `type`, `roles`, `team`, `auth_method`, `samaccountname`, `ad_fqdn`) plus a `profile` hash of extended attributes populated from AD/LDAP:

| Accessor | LDAP Source | Example |
|----------|-------------|---------|
| `first_name` | `givenName` | Jane |
| `last_name` | `sn` | Doe |
| `email` | `mail` | jane.doe@example.com |
| `display_name` | `displayName` | Doe, Jane A |
| `title` | `title` | Senior Engineer |
| `department` | `department` | Platform Engineering |
| `company` | `company` | Acme Corp |
| `city` | `l` | Minneapolis |
| `state` | `st` | MN |
| `country` | `co` | USA |
| `country_code` | `c` | US |
| `cn` | `cn` | jdoe1 |
| `ad_created_at` | `whenCreated` | 20200115093012.0Z |

All profile fields are accessible as direct methods (`principal.title`) or via `principal.profile` hash.

## Guards

All integration uses `if defined?(Legion::Rbac)` guards so the gem is fully optional.
