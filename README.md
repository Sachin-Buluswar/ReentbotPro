# ReentbotPro

ReentbotPro is an autonomous smart-contract audit harness. It runs an LLM agent
over a Solidity project in a Docker sandbox with Foundry, Slither, Echidna,
Medusa, Halmos, and standard shell tools. Optional Alchemy and Etherscan access
adds live-chain data and verified source.

The goal is evidence-backed vulnerabilities, not a list of static-analysis
warnings. The agent models the protocol, investigates suspicious state
transitions, runs validation experiments, and produces a report with
machine-readable findings.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Docker running locally
- A ChatGPT/Codex account or an OpenAI API key

## Install and run

```bash
git clone https://github.com/Sachin-Buluswar/ReentbotPro.git
cd ReentbotPro
uv tool install -e .
reentbotpro ./path/to/contracts
```

On the first interactive run, ReentbotPro opens a browser for ChatGPT/Codex
login unless `--api-key` or `OPENAI_API_KEY` is set. It also shows a setup wizard
for run settings and optional live-chain credentials. The first audit builds the
Docker image and can take several minutes; later runs reuse it.

If `reentbotpro` is not on your `PATH`, run `uv tool update-shell` and restart
your terminal.

For development, use the project environment instead of the installed tool:

```bash
uv sync
uv run reentbotpro ./path/to/contracts
```

## Optional live-chain access

ReentbotPro works without chain credentials and continues with source-only
analysis. For live state, traces, simulations, and verified-source lookups, set:

```bash
export ALCHEMY_API_KEY=<...>
export ETHERSCAN_API_KEY=<...>
```

You do not need to select a target chain at startup. The agent infers chain
bindings from deployment and scope metadata, then derives the appropriate
endpoint. It does not silently assume Ethereum mainnet when the chain is
unknown.

The interactive setup wizard can save these keys to
`~/.reentbotpro/config.json`. See
[Configuration](docs/configuration.md) for authentication, environment
variables, local config, and custom RPC endpoints.

## Common usage

```bash
# Basic audit
reentbotpro ./path/to/contracts

# Batch audit without the setup wizard or follow-up chat
reentbotpro ./contracts --no-chat

# Choose a model and wall-clock limit in minutes
reentbotpro ./contracts --model gpt-5.6-sol --max-time 30

# Change output verbosity and destination
reentbotpro ./contracts --verbosity full --output ./audit-results
```

Run `reentbotpro --help` for the complete option reference.

The default model is `gpt-5.6-sol` with model-appropriate `xhigh` reasoning.
The default wall-clock limit is 720 minutes, tool verbosity is `partial`, and
output is written below `./findings`. Model context and output settings are
inferred automatically unless advanced overrides are supplied.

## Output

Each run creates a timestamped directory such as:

```text
findings/2026-04-30_14-30-00/
```

Typical contents are:

- `report.md`: the human-readable vulnerability report.
- `findings.json`: run metadata, submitted findings, artifact counts, and any
  incomplete-readiness status.
- `campaign/`: durable campaign state, maps, result logs, and evidence reviews.
- `experiments/`: generated experiment and proof-of-concept workspaces.

The target source is bind-mounted into the audit container, so files the agent
writes under the target tree persist on the host. Interrupted or abnormal exits
make a best-effort partial save before cleanup and mark `findings.json`
accordingly.

## How the audit works

An audit has three phases:

1. **Audit:** explore the source, model value flows and invariants, investigate
   hypotheses, and run experiments.
2. **Report:** write a markdown report from reviewed findings and saved campaign
   context.
3. **Chat:** optionally answer follow-up questions or continue auditing.

The campaign follows one durable loop:

```text
State -> Map -> Plan -> Experiment -> Evidence -> Mutate or Report
```

Medium, high, and critical findings require runnable proof-of-concept evidence.
A passing experiment proves mechanics, so the review also considers production
reachability, the source of material preconditions, measured funds at risk, and
negative controls. Static analysis and live-chain probes can guide or corroborate
the investigation, but they do not replace a runnable proof.

Uncertain deployment context and unresolved branches are recorded as caveats or
readiness gaps rather than silently discarded. If the wall-clock limit arrives
before the campaign is ready, the output is marked incomplete instead of being
presented as a clean no-findings result.

For controller behavior, artifact contracts, and evidence guardrails, see the
[Attack Campaign Engine](docs/attack-campaign-engine.md).

## Disclaimer

Use ReentbotPro only for authorized security testing, education, and CTF work.
It is not a replacement for a professional manual audit. Users are responsible
for ensuring they have authorization to test target contracts.

## License

MIT
