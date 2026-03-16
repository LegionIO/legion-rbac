# legion-rbac Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create `legion-rbac`, a new optional core gem providing role-based access control for LegionIO, following UHG-Vault policy patterns.

**Architecture:** Two-layer enforcement (Rack middleware for API routes + `authorize_execution!` in Ingress). Config defines role permissions, DB stores role assignments and team grants. `if defined?(Legion::Rbac)` guards in LegionIO make it fully optional.

**Tech Stack:** Ruby 3.4+, Sequel (migrations/models), Sinatra (middleware/routes), Thor (CLI), RSpec, SimpleCov

**Design Doc:** `docs/plans/2026-03-16-legion-rbac-design.md`

---

## Task 1: Gem Scaffold

Create the legion-rbac gem with version, gemspec, Gemfile, rubocop config, spec_helper, and a minimal entry point that boots and shuts down.

**Files:**
- Create: `legion-rbac/legion-rbac.gemspec`
- Create: `legion-rbac/Gemfile`
- Create: `legion-rbac/.rubocop.yml`
- Create: `legion-rbac/.rspec`
- Create: `legion-rbac/LICENSE`
- Create: `legion-rbac/lib/legion/rbac/version.rb`
- Create: `legion-rbac/lib/legion/rbac.rb`
- Create: `legion-rbac/spec/spec_helper.rb`
- Create: `legion-rbac/spec/legion/rbac_spec.rb`

Smoke test: 3 specs (version exists, setup marks connected, shutdown marks disconnected).

Run: `bundle exec rspec` (3 pass), `bundle exec rubocop` (0 offenses).

Commit: `scaffold legion-rbac gem with version, settings, and smoke test`

---

## Task 2: Settings, Role, Permission, and ConfigLoader

Define the four built-in roles (worker, supervisor, admin, governance-observer) in settings. Create Role, Permission, and DenyRule data classes. ConfigLoader reads settings and returns a hash of Role objects.

**Files:**
- Create: `legion-rbac/lib/legion/rbac/settings.rb`
- Create: `legion-rbac/lib/legion/rbac/role.rb`
- Create: `legion-rbac/lib/legion/rbac/permission.rb`
- Create: `legion-rbac/lib/legion/rbac/config_loader.rb`
- Test: `legion-rbac/spec/legion/rbac/settings_spec.rb`
- Test: `legion-rbac/spec/legion/rbac/config_loader_spec.rb`
- Test: `legion-rbac/spec/legion/rbac/permission_spec.rb`
- Test: `legion-rbac/spec/legion/rbac/role_spec.rb`

Key behaviors to test:
- Settings.default returns all expected keys and four role definitions
- Permission#matches? handles `*` wildcard, `+` single-segment, exact match
- DenyRule#matches? uses same glob pattern matching
- Role.new builds Permission and DenyRule arrays from config hashes
- ConfigLoader.load_roles returns Role objects keyed by symbol name

Run: `bundle exec rspec` (all pass), `bundle exec rubocop` (0 offenses).

Commit: `add settings, role, permission, deny rule, and config loader`

---

## Task 3: Principal and PolicyEngine

Principal wraps identity (from JWT claims, local admin, or anonymous). PolicyEngine evaluates permissions: resolve roles, check deny (deny wins), check permissions (union across roles), emit audit events.

**Files:**
- Create: `legion-rbac/lib/legion/rbac/principal.rb`
- Create: `legion-rbac/lib/legion/rbac/policy_engine.rb`
- Modify: `legion-rbac/lib/legion/rbac.rb` — add role_index, authorize!, authorize_execution!, AccessDenied
- Test: `legion-rbac/spec/legion/rbac/principal_spec.rb`
- Test: `legion-rbac/spec/legion/rbac/policy_engine_spec.rb`

Key behaviors to test:
- Principal.from_claims handles worker vs human scope
- Principal.local_admin returns admin role from settings
- Admin can access anything
- Worker can execute runners but is denied lex-extinction and lex-governance
- Supervisor can manage team workers but is denied termination
- Governance-observer can read everything cross-team but can only execute lex-governance runners
- No-role principal is denied everything
- enforce: false returns allowed: true with would_deny: true
- authorize! raises AccessDenied on denial
- authorize_execution! builds runner path from class/function

Run: `bundle exec rspec` (all pass), `bundle exec rubocop` (0 offenses).

Commit: `add principal, policy engine, authorize!, and access denied exception`

---

## Task 4: Team Scoping

TeamScope checks whether a principal can access resources in a target team. Same team = allowed. Cross-team requires a role with `cross_team: true`. Nil team = allowed (unscoped).

**Files:**
- Create: `legion-rbac/lib/legion/rbac/team_scope.rb`
- Test: `legion-rbac/spec/legion/rbac/team_scope_spec.rb`

Key behaviors to test:
- Same team access allowed
- Cross-team denied for worker/supervisor
- Cross-team allowed for admin and governance-observer
- Nil target team always allowed
- Nil principal team always allowed (unscoped principal)

Run: `bundle exec rspec` (all pass), `bundle exec rubocop` (0 offenses).

Commit: `add team scope with cross-team role checking`

---

## Task 5: DB Store (legion-data migration + models)

Create three tables (rbac_role_assignments, rbac_runner_grants, rbac_cross_team_grants) via Sequel migration in legion-data. Create Sequel models with validation. Create Store module in legion-rbac with CRUD operations and static config fallback.

**Files:**
- Create: `legion-data/lib/legion/data/migrations/015_add_rbac_tables.rb`
- Create: `legion-data/lib/legion/data/models/rbac_role_assignment.rb`
- Create: `legion-data/lib/legion/data/models/rbac_runner_grant.rb`
- Create: `legion-data/lib/legion/data/models/rbac_cross_team_grant.rb`
- Create: `legion-rbac/lib/legion/rbac/store.rb`
- Test: `legion-rbac/spec/legion/rbac/store_spec.rb`

Key behaviors to test:
- Store.db_available? returns false when Legion::Data not defined
- Store.roles_for falls back to static_assignments when DB unavailable
- Static assignments filter by principal_id
- Model validations (principal_type in worker/human, non-empty fields, source != target for cross-team)
- RbacRoleAssignment#expired? and #active?
- RbacRunnerGrant#actions_list splits comma-separated string

Run: `bundle exec rspec` in both legion-rbac and legion-data.

Commit legion-rbac: `add db store with static config fallback`
Commit legion-data: `add migration 015 and models for rbac tables`

---

## Task 6: Rack Middleware

API route authorization middleware. Maps HTTP method+path to permission requirements. Uses PolicyEngine for evaluation. Returns 403 JSON on denial. Defers invoke routes to execution layer. Unmapped routes are denied by default.

**Files:**
- Create: `legion-rbac/lib/legion/rbac/middleware.rb`
- Test: `legion-rbac/spec/legion/rbac/middleware_spec.rb`

Key behaviors to test:
- Skip paths (/api/health, /api/ready, /api/openapi.json) pass through
- Admin can access any route
- Unauthenticated requests get 403
- Worker denied from managing settings (PUT /api/settings/*)
- Worker allowed to read tasks (GET /api/tasks)
- Invoke routes deferred to execution layer (pass through)
- Unmapped routes get 403

Run: `bundle exec rspec` (all pass), `bundle exec rubocop` (0 offenses).

Commit: `add rack middleware for api route authorization`

---

## Task 7: LegionIO Integration

Wire legion-rbac into LegionIO: service boot (setup_rbac), Ingress guard (authorize_execution!), API middleware mount, RBAC REST routes.

**Files:**
- Modify: `LegionIO/lib/legion/service.rb` — add setup_rbac method after setup_data
- Modify: `LegionIO/lib/legion/ingress.rb` — add authorize_execution! guard
- Modify: `LegionIO/lib/legion/api.rb` — mount RBAC middleware, register RBAC routes
- Create: `LegionIO/lib/legion/api/rbac.rb` — REST routes for roles, assignments, grants, check
- Modify: `LegionIO/Gemfile` — add legion-rbac as optional path dependency

REST endpoints:
- GET /api/rbac/roles, GET /api/rbac/roles/:name
- POST /api/rbac/check
- GET/POST/DELETE /api/rbac/assignments
- GET/POST/DELETE /api/rbac/grants
- GET/POST/DELETE /api/rbac/grants/cross-team

Run: `cd LegionIO && bundle exec rspec` — existing specs must still pass.

Commit: `integrate legion-rbac: service boot, ingress guard, api routes, middleware`

---

## Task 8: CLI Commands

Thor subcommand `legion rbac` with: roles, show, assignments, assign, revoke, grants, grant, check.

**Files:**
- Create: `LegionIO/lib/legion/cli/rbac_command.rb`
- Modify: `LegionIO/lib/legion/cli.rb` — register subcommand

Key commands:
- `legion rbac roles` — list role definitions from config
- `legion rbac show <role>` — show permissions for a role
- `legion rbac assignments` — list from DB (--team, --role, --principal filters)
- `legion rbac assign <principal> <role>` — assign (--type, --team, --expires)
- `legion rbac revoke <principal> <role>` — remove assignment
- `legion rbac grants` — list runner grants (--team filter)
- `legion rbac grant <team> <pattern>` — grant runner access (--actions)
- `legion rbac check <principal> <resource>` — dry-run (--action, --roles, --team)

Run: `cd LegionIO && bundle exec rspec` — existing specs pass.

Commit: `add legion rbac cli subcommand`

---

## Task 9: MCP Tools

Three read-oriented MCP tools for RBAC.

**Files:**
- Create: `LegionIO/lib/legion/mcp/tools/rbac_check.rb`
- Create: `LegionIO/lib/legion/mcp/tools/rbac_assignments.rb`
- Create: `LegionIO/lib/legion/mcp/tools/rbac_grants.rb`
- Modify: `LegionIO/lib/legion/mcp/server.rb` — add to TOOL_CLASSES

Tools:
- `legion.rbac_check` — dry-run authorization check
- `legion.rbac_assignments` — list role assignments (filterable)
- `legion.rbac_grants` — list runner grants (filterable)

All tools return `{ error: 'legion-rbac not installed' }` when gem absent.

Run: `cd LegionIO && bundle exec rspec` — existing specs pass.

Commit: `add rbac mcp tools: check, assignments, grants`

---

## Task 10: Documentation and Pre-Push Pipeline

**Files:**
- Create: `legion-rbac/README.md`
- Create: `legion-rbac/CHANGELOG.md`
- Create: `legion-rbac/CLAUDE.md`
- Modify: `legion/CLAUDE.md` — add legion-rbac to Core Libraries in repo organization

Pre-push pipeline for each repo:
1. `bundle exec rspec` — 0 failures
2. `bundle exec rubocop` — 0 offenses
3. Version bump if lib/ changed (legion-rbac 0.1.0, legion-data patch, LegionIO patch)
4. CHANGELOG.md updated
5. README.md updated

Push: `git push # pipeline-complete`

---

## Summary

| Task | Component | Repos | Est. Specs |
|------|-----------|-------|-----------|
| 1 | Gem scaffold | legion-rbac | ~3 |
| 2 | Settings + Role + Permission + ConfigLoader | legion-rbac | ~15 |
| 3 | Principal + PolicyEngine | legion-rbac | ~15 |
| 4 | TeamScope | legion-rbac | ~8 |
| 5 | DB Store + Migration + Models | legion-rbac, legion-data | ~10 |
| 6 | Rack Middleware | legion-rbac | ~10 |
| 7 | LegionIO Integration | LegionIO | ~15 |
| 8 | CLI Commands | LegionIO | ~5 |
| 9 | MCP Tools | LegionIO | ~5 |
| 10 | Documentation + Pipeline | all three | 0 |
| **Total** | | **3 repos** | **~86 specs** |
