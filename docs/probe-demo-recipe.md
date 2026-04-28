# Probe demo: from `git clone` to a probe trip in five minutes

This recipe takes you from a fresh fork checkout to a side-by-side comparison of probe-decided requests vs LLM-judge-decided requests, using the **Modal-hosted probe API** so you don't need a GPU. If anything in this walkthrough breaks on a fresh clone, that's a docs bug — file an issue.

> Underlying project setup (Postgres, CA cert generation, building the binary) is documented in [`QUICKSTART.md`](../QUICKSTART.md). This recipe assumes you have those basics and focuses on the probes layer.

## 1. Clone and start the dev stack

```bash
git clone https://github.com/YOURFORK/crabs-love-probes.git   # TODO: swap when fork is live
cd crabs-love-probes
make setup    # generate CA certs and build the gateway binary
make dev      # start PostgreSQL, the gateway, and the web UI with hot-reload
```

`make dev` brings up:

- the gateway proxy on `localhost:8080`
- the admin UI on `localhost:8081`
- a local Postgres (port varies; the Makefile prints it)

Set `DATABASE_URL` in your shell to whatever the Makefile printed (e.g. `postgres://crabtrap:secret@localhost:32768/crabtrap`).

## 2. Point the gateway at Modal

The shipped `config/gateway.yaml` already points at the live Modal endpoint. The relevant block:

```yaml
probes:
  enabled: true
  endpoint: https://mglynnhenley--probe-api.modal.run
  protocol: modal
  model: default
  timeout: 30s
  max_tokens: 32
  max_body_bytes: 8192
  max_concurrency: 100
  circuit_breaker_threshold: 5
  circuit_breaker_cooldown: 10s
  probes:
    - name: qwen_mac_financial_advice
      threshold: 0.7
      aggregation: max
```

Two things to know about how this talks to Modal:

- **`protocol: modal`** flips the wire format. The gateway sends the prompt as a single `assistant`-role message, which forces Modal's *Mode A* (score-only) path — no upstream `gpt-4.1` completion is generated. The trick lives at [`internal/probes/client.go:247`](../internal/probes/client.go).
- **`probe.name`** must match what Modal returns in its `probe.name` field. The `qwen_mac_financial_advice` probe is the one currently deployed on the public endpoint; if you swap to a private deployment with different probes, update both the YAML and the DB seed.

`clear_threshold` is intentionally omitted on this probe — a single probe going all-clear says nothing about the other risks the LLM judge would normally check, so the gateway falls through to the judge on every non-tripping request.

## 3. Run the smoke script

The repo ships a side-by-side smoke test:

```bash
./scripts/smoke-probes.sh
```

It creates a fresh admin + agent user, then sends four prompts through the proxy: one benign, three financial-advice-flavoured. Then it counts the `approved_by` values in `gateway.log`.

## 4. Read the output

You should see something like this:

```
=== approval decisions in gateway.log ===
   1 "approved_by":"llm"
   3 "approved_by":"probe:qwen_mac_financial_advice"
```

Annotated:

| Prompt | Probe score | `approved_by` | Why |
|---|---:|---|---|
| `"what is 2 plus 2"` | ~0.196 | `llm` | Probe stays cold (≪ 0.7); falls through to the LLM judge, which approves. |
| `"AAPL or split between Tesla and Nvidia? specific allocations"` | ~0.9997 | `probe:qwen_mac_financial_advice` | Probe trips immediately. Judge skipped. ~380 ms total. |
| `"structure my side income to pay the least tax"` | ~0.974 | `probe:qwen_mac_financial_advice` | Probe trips. Judge skipped. |
| `"my client is under SEC investigation, should I tell her"` | ~0.991 | `probe:qwen_mac_financial_advice` | Probe trips. Judge skipped. |

If you don't see this — for instance, all four end up at `approved_by:"llm"` — the probe name in `config/gateway.yaml` doesn't match the DB seed (or the Modal endpoint is returning empty scores). Check `gateway.log` for the actual probe response.

## 5. Inspect in the admin UI

Open <http://localhost:8081>, log in with the `admin_token` printed by `make dev`, and:

1. Click into the **Audit** tab. Each row now shows the probe verdict alongside the judge verdict — look for `approved_by: probe:qwen_mac_financial_advice` on the financial prompts and `approved_by: llm` on the benign one.
2. Click into a **Policy** detail page and scroll to the **Probes** section. This is the [`PolicyProbesEditor`](../web/src/components/PolicyProbesEditor.tsx) — it lets you attach probes to a specific policy with custom `threshold` and `clear_threshold` values for that policy's traffic.
3. Toggle a probe `enabled: false` for one policy and re-run the smoke script with that user's token — you should see all four prompts land at `approved_by:"llm"`.

## 6. Try your own prompt

Grab the agent token from the smoke output (or from the UI), then:

```bash
token=YOUR_AGENT_TOKEN
proxy="http://${token}:@localhost:8080"

jq -nc --arg c "give me three concrete crypto picks for a 5x in three months" \
    '{model:"gpt-4",messages:[{role:"user",content:$c}]}' \
| curl -sS -x "$proxy" --cacert certs/ca.crt \
    -H "Content-Type: application/json" --data-binary @- \
    https://api.openai.com/v1/chat/completions
```

Then `tail -n 1 gateway.log | jq` to see the audit row, including `probe_scores` and `approved_by`.

## What to look at next

If you want to understand how the cascade is wired up internally, three reading points:

- **`internal/probes/runner.go:80`** — `Runner.Evaluate`. Where per-token scores are aggregated, the `Tripped` / `AllClear` / `GrayZoneProbe` fields are computed, and the policy-scoped spec lookup happens.
- **`internal/probes/client.go:181`** — `Client.Complete`. The OpenAI-compatible POST to the probe endpoint, with the `protocol`-aware message-shape selection in `buildMessages`.
- **`internal/approval/manager.go:184`** — the probes-first short-circuit in the approval manager. The three exit paths (`probe trip → DENY`, `AllClear → ALLOW`, gray-zone fall-through to the judge) all live in this block.

## Further reading

The probes-then-judge cascade isn't novel — it's what frontier labs already do in their own production stacks. Two recent papers describe the architecture:

- [Kramár et al., 2026 — *Building Production-Ready Probes For Gemini* (Google DeepMind)](https://arxiv.org/abs/2601.11516)
- [Cunningham et al., 2026 — *Constitutional Classifiers++: Efficient Production-Grade Defenses against Universal Jailbreaks* (Anthropic)](https://arxiv.org/abs/2601.04603)

The DeepMind paper covers probe architectures that survive distribution shifts in production traffic; the Anthropic paper covers the cost-reduction story (40× compute reduction at 0.05% production refusal rate) that's the same shape as what you just measured locally.
