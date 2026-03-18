# Legion::Rbac

Role-based access control for LegionIO, following Vault-style flat policy patterns.

## Features

- Flat policy model: deny-always-wins, no role inheritance
- Glob pattern matching for resources (`*` any segments, `+` single segment)
- Four built-in roles: worker, supervisor, admin, governance-observer
- Team scoping with cross-team as explicit privilege
- Two-layer enforcement: Rack middleware for API routes + `authorize_execution!` for all execution sources
- Dual-mode store: DB-backed via Sequel or static fallback
- Entra ID claims mapping (roles and groups to Legion roles)
- Kerberos claims mapping (AD group DNs to Legion roles, with Entra fallback)
- Fully optional: guarded by `if defined?(Legion::Rbac)` in LegionIO

## Installation

Add to your Gemfile:

```ruby
gem 'legion-rbac'
```

## Usage

### Setup

```ruby
require 'legion/rbac'
Legion::Rbac.setup
```

### Authorization Check

```ruby
principal = Legion::Rbac::Principal.new(id: 'user-1', roles: [:worker], team: 'team-a')
Legion::Rbac.authorize!(principal: principal, action: :execute, resource: 'runners/lex-http/request/get')
```

### Execution Authorization

```ruby
Legion::Rbac.authorize_execution!(principal: principal, runner_class: 'Legion::Extensions::LexHttp::Runners::Request', function: :get)
```

### Dry-Run Check

```ruby
result = Legion::Rbac::PolicyEngine.evaluate(principal: principal, action: :read, resource: 'runners/*', enforce: false)
# => { allowed: true, reason: "...", would_deny: false }
```

### CLI

```bash
legion rbac roles              # list role definitions
legion rbac show admin         # show role permissions
legion rbac assignments        # list role assignments from DB
legion rbac assign user-1 worker --team team-a
legion rbac check user-1 runners/lex-http/* --action execute --roles worker
```

## Configuration

Default roles are defined in settings under `rbac.roles`. Custom roles can be added via settings merge or config files.

## Requirements

- Ruby >= 3.4
- legion-json >= 1.2
- legion-settings >= 1.3

## License

Apache-2.0
