# Legion::Rbac

**Parent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

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
lib/legion/rbac/middleware.rb   # Rack middleware
```

## Integration Points

- **LegionIO/lib/legion/service.rb**: `setup_rbac` called after `setup_data`
- **LegionIO/lib/legion/ingress.rb**: `authorize_execution!` guard on task execution
- **LegionIO/lib/legion/api.rb**: Middleware registered, routes module loaded
- **LegionIO/lib/legion/api/rbac.rb**: REST API routes for RBAC management
- **LegionIO/lib/legion/cli/rbac_command.rb**: Thor CLI subcommand
- **LegionIO/lib/legion/mcp/tools/rbac_*.rb**: 3 MCP tools (check, assignments, grants)
- **legion-data**: Migration 015 + 3 Sequel models (RbacRoleAssignment, RbacRunnerGrant, RbacCrossTeamGrant)

## Guards

All integration uses `if defined?(Legion::Rbac)` guards so the gem is fully optional.
