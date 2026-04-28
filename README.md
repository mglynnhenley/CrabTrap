# Crabs Love Probes

<p align="center">
  <img src="assets/logo.png" alt="Crabs Love Probes logo" width="600" />
</p>

A CrabTrap fork that puts trained safety probes in front of every AI-agent request — DENY or ALLOW in ~380 ms before the LLM judge sees the call.

> **Fork of [brexhq/CrabTrap](https://github.com/brexhq/CrabTrap).** Original code MIT-licensed by Brex. This fork keeps the upstream proxy, TLS, audit, and policy machinery intact and adds a probes-first safety layer in front of the LLM judge. See [What this fork adds](#what-this-fork-adds) below.

If you run AI agents that call external services — Slack, Gmail, GitHub, or anything else — Crabs Love Probes (CLP) gives you guardrails. It intercepts every outbound HTTP/HTTPS request, runs trained activation probes against the prompt, and either short-circuits the decision (probe trip → DENY, all-clear → ALLOW) or escalates to an LLM judge for the gray zone. Every request and decision is logged to PostgreSQL.

## What this fork adds

- **Probes-first flow.** Trained activation probes can DENY or ALLOW *before* the LLM judge runs. A trip is a hard block; an all-clear is a free pass. Only ambiguous traffic reaches the judge.
- **AllClear path.** When every configured probe scores at or below its `clear_threshold`, the request is approved with `approved_by: "probe:all-clear"` and the LLM judge is skipped entirely. This is the cost-saving path for normal traffic.
- **Modal-hosted probe protocol.** Don't want to run Qwen on a local GPU? Set `protocol: modal` in `config/gateway.yaml` and point at a public Modal endpoint — you're scoring real prompts in your gateway in under five minutes.
- **Per-policy probe attachment.** The admin UI lets each LLM policy carry its own probe set with its own thresholds — see `web/src/components/PolicyProbesEditor.tsx` and the `/admin/policies/{id}/probes` API.

> **Why this isn't a toy.** Activation probes are already production-deployed at Google DeepMind for Gemini misuse mitigation ([Kramár et al., 2026](https://arxiv.org/abs/2601.11516)), and Anthropic's Constitutional Classifiers++ uses the same probes-then-judge cascade for a 40× compute reduction at a 0.05% production refusal rate ([Cunningham et al., 2026](https://arxiv.org/abs/2601.04603)). This fork puts that pattern in an open-source HTTP proxy.

## Quickstart (with the live Modal probe endpoint)

CLP runs as a Docker container alongside PostgreSQL. The short version, configured to call the live Modal probe API so you don't need a GPU:

```yaml
# config/gateway.yaml
approval:
  mode: llm

probes:
  enabled: true
  endpoint: https://mglynnhenley--probe-api.modal.run
  protocol: modal
  model: default
  timeout: 30s
  probes:
    - name: qwen_mac_financial_advice
      threshold: 0.7
      aggregation: max
```

```bash
docker compose up -d                                                    # start CLP + Postgres
docker compose cp crabtrap:/app/certs/ca.crt ./ca.crt                   # copy the generated CA cert
admin_token=$(docker compose exec -it crabtrap ./gateway create-admin-user test-admin \
    | tail -n1 | cut -d" " -f2)
token=$(curl -X POST http://localhost:8081/admin/users \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${admin_token}" \
    -d '{"id": "alice@example.com", "is_admin": false}' \
    | jq -r '.channels[] | select(.channel_type == "gateway_auth") | .gateway_auth_token')

# Run the side-by-side smoke test (probe trips vs. judge fallthrough):
./scripts/smoke-probes.sh
# === approval decisions in gateway.log ===
#   1 "approved_by":"llm"
#   3 "approved_by":"probe:qwen_mac_financial_advice"
```

The proxy listens on `localhost:8080`, the admin UI on `localhost:8081`. Log in to the UI with `$admin_token`. See [QUICKSTART.md](QUICKSTART.md) for the full walkthrough and [docs/probe-demo-recipe.md](docs/probe-demo-recipe.md) for the 5-minute probe demo.

## How It Works

1. **Agent connects** — set `HTTP_PROXY` and `HTTPS_PROXY` to point at the gateway.
2. **TLS termination** — the gateway generates a per-host certificate from a custom CA and decrypts the request.
3. **Static rules** — the request is matched against URL pattern rules (prefix, exact, or glob). A match short-circuits the decision; deny rules win over allow.
4. **Probes** *(new in this fork)* — when `probes.enabled: true`, trained activation probes score the prompt:
   - Any probe ≥ its `threshold` → **DENY** with `approved_by: "probe:<name>"`. Judge skipped.
   - Every probe ≤ its `clear_threshold` → **ALLOW** with `approved_by: "probe:all-clear"`. Judge skipped.
   - Otherwise → fall through to the judge.
5. **LLM judge** — if no static rule matched and probes were ambiguous (or disabled, or the circuit breaker is open), the request is evaluated by an LLM against the agent's natural-language security policy.
6. **Audit logged** — every request, decision, probe score, and response is recorded in PostgreSQL.

```
                         agent request
                              │
                              ▼
                    ┌───────────────────┐
                    │   static rules    │──── match ───► DENY / ALLOW
                    └─────────┬─────────┘
                              │ no match
                              ▼
                    ┌───────────────────┐
                    │      probes       │
                    │  (~380 ms, GPU)   │
                    └─┬─────────┬─────┬─┘
                 trip │  clear  │ gray│
                      ▼         ▼     ▼
                    DENY      ALLOW  LLM judge ──► DENY / ALLOW
                                       (~1.5 s)
```

The upstream-only flow is still rendered as `docs/crabtrap-flow.svg` for reference.

## Features

### Security

- **HTTPS interception** — transparent MITM proxy with custom TLS server certificate generation
- **SSRF protection** — blocks requests to private networks (RFC 1918, loopback, link-local, Carrier-Grade NAT, IPv6 ULA/NAT64/6to4) with DNS-rebinding prevention
- **Prompt injection defense** — request payloads are JSON-encoded and policy content is JSON-escaped before being sent to the LLM judge
- **Per-IP rate limiting** — token bucket rate limiter (default 50 req/s, burst 100)

### Probes *(new in this fork)*

- **Protocol switch** — `protocol: probe_demo` for local Qwen + activation probes, or `protocol: modal` to call a Modal-hosted probe API (last-message-assistant convention forces Mode A scoring without an upstream completion).
- **Per-policy attachment** — each LLM policy can carry its own probe set with its own thresholds and aggregation (`max` | `mean`); the runner resolves the policy-scoped specs at evaluation time.
- **Gray-zone judge escalation** — a probe in its own gray zone can name a per-probe `judge_policy_id`, and the manager swaps that prompt in for the user's default policy on escalation.
- **Audit columns** — every decision records `probe_scores`, `probe_tripped`, `probe_aggregation`, and `probe_circuit_open` (migration `002_probe_columns.sql`).
- **Circuit breaker** — trips after 5 consecutive probe failures, half-opens after 10 s; failures fall through to the judge instead of denying.

### Policy Evaluation

- **Two-tier evaluation** — deterministic static rules are checked first; the LLM judge is only invoked if no rule matches and probes are ambiguous.
- **Static rules** — prefix, exact, and glob URL pattern matching with optional HTTP method filters
- **Per-agent LLM policies** — natural-language security policies evaluated via LLM
- **Circuit breaker** — trips after 5 consecutive LLM failures, reopens after 10s cooldown
- **Configurable fallback** — deny (default) or passthrough when the LLM judge is unavailable

### Operations

- **Policy builder** — an agentic loop that analyzes observed traffic and drafts security policies automatically
- **Eval system** — replay historical audit log entries against a policy to measure accuracy
- **Web UI** — audit trail viewer, policy editor (with per-policy probe attachment), eval results, and agent management

## What CLP Does NOT Do

- **Not a WAF or inbound firewall** — CLP is a forward proxy (outbound-only) for agent-originated traffic. It does not inspect inbound requests to your services.
- **Does not redact sensitive data** — the proxy sees all request content in cleartext, including headers like Authorization and Cookie. This is by design; the trust boundary is the proxy itself.
- **Does not provide human-in-the-loop approval** — there is no approval queue, no Slack prompts, and no escalation path. Decisions are made automatically by static rules, probes, and the LLM judge.
- **Does not filter API responses** — only outbound requests are evaluated. Responses from upstream APIs are streamed back to the agent unexamined.
- **Does not inspect WebSocket frames** — only the WebSocket upgrade request is evaluated. Once upgraded, frames pass through uninspected.

## Configuration

| Section | Key Settings |
|---|---|
| `proxy` | Port (default 8080), timeouts, rate limits, SSRF CIDR allowlist |
| `tls` | CA cert/key paths, certificate cache size (default 10,000) |
| `approval` | Mode: `llm` or `passthrough`, timeout (default 30s) |
| `llm_judge` | Provider, model IDs, fallback mode (`deny`/`passthrough`), circuit breaker |
| `probes` | `enabled`, `protocol` (`probe_demo` \| `modal`), `endpoint`, `model`, `timeout`, `max_body_bytes`, circuit-breaker knobs, and a `probes[]` list (each entry: `name`, `threshold`, optional `clear_threshold`, `aggregation`) |
| `database` | PostgreSQL connection URL (supports `${DATABASE_URL}` expansion) |
| `audit` | Output destination: `stderr` (default), `stdout`, or a file path |
| `log_level` | `debug`, `info` (default), `warn`, `error` |

See [`config/gateway.yaml.example`](config/gateway.yaml.example) for the full reference with inline comments — especially the `probes:` block, which documents how the four mode combinations (`llm`+probes, `passthrough`+probes, `llm` alone, `passthrough` alone) interact.

## Project Structure

```
crabs-love-probes/
├── cmd/gateway/          # Entry point, admin API wiring, web UI serving
├── internal/
│   ├── proxy/            # MITM proxy, TLS cert generation, SSRF protection, rate limiting
│   ├── approval/         # Static rules engine + approval orchestration (probes-first short-circuit)
│   ├── probes/           # NEW: probe client (probe_demo + modal protocols), runner, store
│   ├── judge/            # LLM judge prompt construction + response parsing
│   ├── judgeprompt/      # NEW: prompt-builder helpers reused by judge + per-probe escalation
│   ├── llm/              # LLM adapters, circuit breaker, concurrency control
│   ├── builder/          # Policy agent (agentic loop with tools)
│   ├── eval/             # Eval system (replay audit entries against policies)
│   ├── admin/            # Admin API routes (incl. /admin/probes and /admin/policies/{id}/probes), auth, stores
│   ├── llmpolicy/        # Policy storage and versioning
│   ├── audit/            # Structured JSON logging + event dispatch
│   ├── config/           # YAML config loading, validation, defaults (incl. probes.protocol)
│   ├── db/migrations/    # 001_initial_schema, 002_probe_columns, 003_probes, 004_policy_probes
│   └── notifications/    # SSE channel + event dispatcher
├── pkg/types/            # Shared types (StaticRule, LLMPolicy, AuditEntry with probe fields, etc.)
├── web/src/              # React + TypeScript admin UI (Vite)
│   └── components/       # incl. ProbesPanel.tsx, PolicyProbesEditor.tsx
├── config/               # YAML configuration files
├── certs/                # Generated TLS certificates (not committed)
└── scripts/              # Certificate generation, database migrations, smoke-probes.sh
```

## Development

```bash
make test          # lint (go vet + staticcheck) then tests with -race
make fmt           # format Go code
make lint          # go vet + staticcheck
make build         # production binary with embedded web UI
make build-web     # rebuild web UI only
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow, PR guidelines, and coding conventions (these are upstream Brex docs and still apply to the fork).

## Releases

Releases are automated with [GoReleaser](https://goreleaser.com/) via GitHub Actions. The upstream registry (`quay.io/brexhq/crabtrap`) and module path (`github.com/brexhq/CrabTrap`) are unchanged in this fork — renaming them is out of scope for the docs pass and would touch 140+ imports. Tag a commit on `main` and push:

```bash
git tag v1.2.3
git push origin v1.2.3
```

See [CONTRIBUTING.md](CONTRIBUTING.md#releasing-with-goreleaser) for release notes and commit message conventions.

## License

This project is licensed under the [MIT License](LICENSE).

- **Original CrabTrap** © 2026 Brex, LLC, MIT licensed.
- **Crabs Love Probes fork additions** © Crabs Love Probes contributors, MIT licensed.

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on getting started, running tests, and submitting pull requests.

## More

- 5-minute probe demo: [docs/probe-demo-recipe.md](docs/probe-demo-recipe.md)
- Launch post: [ANNOUNCEMENT.md](ANNOUNCEMENT.md)
- Troubleshooting: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Architecture: [DESIGN.md](DESIGN.md)
- Issues: https://github.com/YOURFORK/crabs-love-probes/issues <!-- TODO: swap when fork is live -->
- Upstream project: https://github.com/brexhq/CrabTrap
