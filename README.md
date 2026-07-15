# ReentbotPro

ReentbotPro is an automated smart contract audit harness. It drives an LLM
agent over a Solidity project inside a Docker sandbox stocked with Slither,
Foundry, Echidna, Medusa, Halmos, and standard shell tools, augmented by
host-side web search and optional on-chain data (Alchemy / Etherscan).

The agent is designed to produce evidence-backed findings, not static-analysis
lists. It maintains campaign state, runs validation experiments, generates a
report, and can enter an interactive follow-up chat.

## Quick Start

```bash
git clone https://github.com/Sachin-Buluswar/ReentbotPro.git
cd ReentbotPro
uv tool install -e .
reentbotpro ./path/to/contracts
```

On the first interactive run, ReentbotPro opens a browser for ChatGPT/Codex
login unless `--api-key` or `OPENAI_API_KEY` is set.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Docker running locally
- ChatGPT/Codex account, or an OpenAI API key

## Install

For normal use:

```bash
cd /path/to/ReentbotPro
uv tool install -e .
uv tool update-shell
```

Restart your terminal after `uv tool update-shell` if `reentbotpro` is not on
your `PATH`. The editable install means local code changes take effect without
reinstalling.

For development:

```bash
cd /path/to/ReentbotPro
uv sync
uv run reentbotpro /path/to/contracts
```

To uninstall the global tool:

```bash
uv tool uninstall reentbotpro
```

## Configuration

CLI flags take priority over environment variables. In an interactive terminal,
the setup wizard is shown unless `--no-chat` is used. Its on-chain credential
portion collects only your Alchemy and Etherscan keys — the target chain is
inferred from scope/deployment metadata at audit time — and offers to save them
to local config so you do not re-enter them each run. The wizard also collects
run settings such as model, reasoning, time limit, and verbosity. A default chain
and an explicit RPC override are optional advanced defaults behind a single
opt-in prompt (default no). In non-interactive mode, the CLI uses flags,
environment variables, and defaults without prompting.

### Normal setup

The normal credential model is just two keys — `ALCHEMY_API_KEY` +
`ETHERSCAN_API_KEY`. You do not configure a chain: the agent infers the target
chain(s) from scope and deployment metadata during recon, so no-chain startup is
the normal path and source-only analysis proceeds until a chain is known. For
durable local defaults, create `~/.reentbotpro/config.json` (set
`REENTBOTPRO_HOME` to use a different app config directory; environment
variables still override the file):

```json
{
  "alchemy_api_key": "<ALCHEMY_API_KEY>",
  "etherscan_api_key": "<ETHERSCAN_API_KEY>"
}
```

or the equivalent environment variables:

```bash
export ALCHEMY_API_KEY=<...>
export ETHERSCAN_API_KEY=<...>
```

RPC endpoints are resolved **per chain**: given an Alchemy key (`ALCHEMY_API_KEY`,
top-level `alchemy_api_key`, or `api_keys.alchemy`) plus the chain the agent has
inferred, the harness derives the correct chain-specific Alchemy RPC URL — so the
key alone is enough on Ethereum, Base, Arbitrum, Optimism, and other
Alchemy-enabled chains. The same **bare key** also powers the agent's live
on-chain investigation tools (call traces, cheap call simulation, state diffs,
fund-flow history, USD pricing, and decoded asset-change simulation) across every
Alchemy-enabled EVM chain; set the bare key (not only a full `ETH_RPC_URL`) to use
them on non-mainnet chains or alongside a non-Alchemy node. Without a key they
degrade cleanly and the agent falls back to `cast`/`anvil`. A bare Alchemy key is
never silently treated as Ethereum mainnet: until a chain is known the CLI derives
no endpoint and the container starts without `ETH_RPC_URL`, but still receives the
bare key, so the chain-aware tools select a chain per call once recon fixes it.
When no chain can be inferred the on-chain tools return `chain_not_inferred`
rather than querying mainnet — a mainnet endpoint is used only when the chain is
explicitly set or recorded. Spend is governed by your Alchemy account usage limits.

The Etherscan key powers **verified contract source** lookups with
`get_contract_source` (`ETHERSCAN_API_KEY` or `api_keys.etherscan`) over
Etherscan's V2 multichain API (one key across Etherscan-supported chains) —
verified Solidity, ABI, and
proxy→implementation, the source-truth complement to Alchemy's runtime data.
Mainnet verified source is free on Etherscan; some L2s may require a paid Etherscan
plan (the tool degrades cleanly without it).

### Optional: target-chain hint

You normally do not set a chain. Use this when you already know the target chain
or want to force a branch/run toward one chain; the agent can otherwise infer
chains from scope/deployment metadata:

```bash
reentbotpro ./target --chain base
reentbotpro ./target --chain-id 8453
```

`--chain` / `--network` accepts a name like `base`, an Alchemy subdomain like
`base-mainnet`, or a chain id; `--chain-id` takes the numeric id. To persist the
hint, add `default_chain` (or `default_network` / `default_chain_id`) to local
config:

```json
{
  "alchemy_api_key": "<ALCHEMY_API_KEY>",
  "etherscan_api_key": "<ETHERSCAN_API_KEY>",
  "default_chain": "base"
}
```

`default_chain` is a hint, not a requirement and not a single-chain constraint.
Multi-chain scopes can override it per target, branch, fork context, or
experiment.

### Advanced: explicit RPC override

ReentbotPro normally derives chain-specific Alchemy RPC endpoints from
`ALCHEMY_API_KEY` and inferred chain context. Use `--rpc-url`, `ETH_RPC_URL`, or
`rpc_urls` only for custom/local/non-Alchemy endpoints, Tenderly/Anvil, debugging,
or unsupported networks. These explicit overrides take precedence over the derived
URL:

```bash
# Explicit RPC endpoint for a custom/local/non-Alchemy node
reentbotpro ./target --rpc-url http://127.0.0.1:8545
```

```json
{
  "alchemy_api_key": "<ALCHEMY_API_KEY>",
  "etherscan_api_key": "<ETHERSCAN_API_KEY>",
  "rpc_urls": {
    "base-mainnet": "https://custom-base.example"
  }
}
```

Per-chain `rpc_urls` entries are keyed by Alchemy subdomain (`base-mainnet`),
decimal or hex chain id (`8453`, `0x2105`), friendly name, or the legacy mainnet
aliases (`ethereum_mainnet`, `mainnet`, `ethereum`, `eth`); a top-level
`eth_rpc_url` / `rpc_url` sets a single chain-agnostic override. Generated fork
experiments do not need a manually exported `ETH_RPC_URL`: `run_experiment` (and
`run_sequence_minimization`) derive the chain-specific endpoint(s) from the
experiment's fork context / chain metadata (or an explicit
`rpc_url`/`network`/`chain_id`/`fork_context`) and inject `ETH_RPC_URL` plus
per-chain `RPC_URL_<chain_id>`/`RPC_URL_<NETWORK>` into the run.
Direct attack-graph sequence materialization also requires one unambiguous
candidate/live-profile chain (or an explicit `fork_context`); an address alone
is never assumed to mean Ethereum mainnet.

Common environment variables:

```bash
export OPENAI_API_KEY=sk-...                 # Optional; use API billing instead of ChatGPT/Codex login
export OPENAI_BASE_URL=https://...           # Optional; OpenAI-compatible gateway base URL (e.g. OpenRouter)
export ALCHEMY_API_KEY=...                   # Normal on-chain setup; derives chain-specific RPC + powers enhanced-API tools across chains
export ETHERSCAN_API_KEY=...                 # Normal on-chain setup; verified source (get_contract_source) + in-container tools
export ETH_RPC_URL=https://...               # Advanced; explicit RPC override for a custom/local/non-Alchemy node
export REENTBOTPRO_MODEL=gpt-5.6-sol      # Optional
export REENTBOTPRO_HOME=~/.reentbotpro # Optional; app-local config/auth directory
```

Without `--api-key` or `OPENAI_API_KEY`, ReentbotPro uses ChatGPT/Codex
OAuth. It first checks `${REENTBOTPRO_HOME:-~/.reentbotpro}/auth.json`,
then reuses the official Codex CLI login from `${CODEX_HOME:-~/.codex}/auth.json`
when available. Use `--login` to force a fresh ReentbotPro browser login.
`--login` cannot be combined with `--api-key`.

## Usage

```bash
# Basic audit
reentbotpro ./path/to/contracts

# Batch audit without follow-up chat
reentbotpro ./contracts --no-chat

# Choose model and wall-clock limit in minutes
reentbotpro ./contracts --model gpt-5.6-sol --max-time 30

# Use another model; context, output, and reasoning settings are inferred
reentbotpro ./contracts --model gpt-5.6-terra

# Advanced context overrides
reentbotpro ./contracts --context-window 1000000
# Pin a hard cap on retained history (default auto-sizes per turn to tools in use)
reentbotpro ./contracts --max-context 200000

# Optional: hint the target chain (otherwise inferred from scope/deployment metadata)
reentbotpro ./contracts --chain base
reentbotpro ./contracts --chain-id 8453

# Advanced: explicit RPC endpoint override for a custom/local/non-Alchemy node
reentbotpro ./contracts --rpc-url http://127.0.0.1:8545

# Fresh ChatGPT/Codex login
reentbotpro ./contracts --login

# Custom output directory or Docker image tag
reentbotpro ./contracts --output ./my-audit-results --image my-custom-tools

# Tool output verbosity
reentbotpro ./contracts --verbosity off
reentbotpro ./contracts --verbosity partial
reentbotpro ./contracts --verbosity full

# Reasoning effort for models that support it
reentbotpro ./contracts --reasoning max
reentbotpro ./contracts --reasoning xhigh
reentbotpro ./contracts --reasoning high
reentbotpro ./contracts --reasoning medium
reentbotpro ./contracts --reasoning low
```

## Key Defaults

| Option | Default | Notes |
| --- | --- | --- |
| `--max-time` | `720` minutes | Wall-clock limit for audit/report/chat agent loops. |
| `--model` | `gpt-5.6-sol` | Model-specific context, output, and reasoning settings are inferred. |
| `--reasoning` | model default, currently `xhigh` for `gpt-5.6-sol` | Unsupported choices are adjusted for the selected model. |
| `--context-window` | model-specific | Advanced override for the model context window used to size budgets. |
| `--max-context` | auto | Advanced hard cap on retained history tokens; default auto-sizes per turn to the tools in use, reclaiming unused tool-schema space. |
| Minimum audit turns | `10000` | Internal guard before the audit agent may voluntarily stop before wrap-up. |
| `--verbosity` | `partial` | `off` shows tool headers only; `full` shows complete tool output. |
| `--output` | `./findings` | Each run creates a timestamped subdirectory. |
| `--image` | `reentbotpro-tools` | Docker image tag for the audit container. |

The first run builds the Docker image and can take several minutes. Later runs
reuse the cached image unless the architecture is wrong or the image is removed.

## Output

Each run writes a timestamped output directory, for example:

```text
findings/2026-04-30_14-30-00/
```

Typical contents:

- `report.md`: human-readable vulnerability report.
- `findings.json`: run metadata, artifact counts, submitted findings, and any
  final incomplete-readiness status.
- `campaign/`: saved campaign state, compact `trace.jsonl`, maps, controller
  branch dossiers, result logs, evidence reviews, and report reviews.
- `experiments/`: generated experiment and harness workspaces.

The audited source directory is bind-mounted at `/audit`, so files the agent
writes under the target tree persist on the host. Generated campaign and
experiment artifacts are copied out of the container with tar-stream extraction
at shutdown, preserving regular files as bytes. Interrupted or abnormal exits
also make a best-effort partial save before the container is removed; in that
case `findings.json` is marked with `partial` and `interrupted`.

## Audit Flow

ReentbotPro runs in three phases:

1. **Audit**: the agent explores code, models value flows, forms hypotheses,
   runs tools and experiments, and submits reviewed findings.
2. **Report**: the agent writes a markdown report from submitted findings and
   saved campaign context.
3. **Chat**: optional follow-up mode for questions or `keep-auditing`.

Internally, audits use one deterministic `attack_search` controller and
artifact-backed campaign state. The controller derives progress and
attack-surface coverage during synchronization. Controller synchronization is
the only scheduling and readiness path:

```text
State -> Map -> Plan -> Experiment -> Evidence -> Mutate or Report
```

A few properties keep the output honest:

- **Evidence gates.** Medium, high, and critical findings require a runnable
  proof-of-concept with objective evidence. A passing PoC proves only the
  mechanics, so the review gates separately classify production reachability,
  precondition provenance, measured funds at risk, and negative controls.
  Uncertain as-deployed exploitability is preserved as an explicit caveat rather
  than silently dropped or over-claimed.
- **Live targeting.** Live-reachability and inventory artifacts rank active
  proxies and configured/economic targets ahead of dormant
  implementation/template addresses, and queue transitive targets reached
  through proxy, provider, registry, asset, and oracle indirection.
- **Open scope.** Lexical profile signals rank attention but never exclude
  bland, infrastructure, proxy, provider, registry, or other parsed first-party
  profiles from the persisted scope manifest. Large manifests are mapped through
  controller-routed cumulative batches, so a per-call root/file bound cannot
  silently turn into a permanent scope exclusion.
- **Runnable scaffolds.** Generated experiment workspaces ship a small local
  Foundry config and a `forge-std/Test.sol` shim so a fresh workspace runs
  without first repairing remappings. Attack-graph candidates flow directly
  into sequence composition with embedded mechanism/state-model guidance. A
  `forge test` that executes no tests is recorded as blocked setup, not evidence.
- **Honest stops.** Voluntary and wall-clock stops run a fresh controller
  readiness check. Any nonterminal, non-parked branch blocks a clean stop;
  ordinary parked-only campaigns may finish. A controller-derived integrity
  limit (for example, omitted definitions at the hard map-retention bound)
  remains explicitly parked rather than rejected but can still block readiness.
  A failed final sync is treated as incomplete
  rather than trusting stale readiness state. When work remains, `findings.json` records
  `audit_status: incomplete_no_validated_findings` with a readiness snapshot
  instead of presenting a clean no-findings run.

For the full artifact contract, controller lifecycle, and guardrails, see
[docs/attack-campaign-engine.md](docs/attack-campaign-engine.md).

## Disclaimer

Use ReentbotPro only for authorized security testing, education, and CTF
work. It is not a replacement for a professional manual audit. Users are
responsible for ensuring they have authorization to test target contracts.

## License

MIT
