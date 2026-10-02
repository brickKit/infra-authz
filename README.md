[English](README.md) · [中文](README.zh.md)

# infra/authz

Permission key catalogue, roles as plain unions, the policy bundle served at /authz/bundle, and login-time claims.

## Use it in a project

```bash
brickkit add infra/authz@2.0.0
brickkit up
```

Prepare first: see "Before you deploy" in BRICKKIT.md (a PostgreSQL schema and login role, NATS, the permission-key registry file, the first administrator's `sub`, and the bundle and JWKS URLs).

## Documentation

| To find out | Read |
|---|---|
| What it does and does not do, how to configure it, what to prepare | [BRICKKIT.md](BRICKKIT.md) |
| Its gRPC, REST and event contracts | [contracts/](contracts/) |
| Why it is designed this way: boundary, the bundle, stale tokens, open questions | [docs/design.md](docs/design.md) |
| What it depends on (nothing) and its configuration keys | [component.yaml](component.yaml) |
| How to develop it: code map, tests, pitfalls | [AGENTS.md](AGENTS.md) |

## Development

Go 1.25, Gin, `database/sql` with pgx, golang-migrate through be-sdk-go. Tests need a real PostgreSQL (`TEST_PG_DSN`); the commands and what success looks like are in AGENTS.md, section "Build and test". Inside the BrickEnterprise project, `make verify ID=infra/authz FOCUS=1` at the project root runs it for real, in a container and as a local process, and tears down afterwards.
