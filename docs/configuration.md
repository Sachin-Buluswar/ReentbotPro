# Configuration

ReentbotPro needs access to an OpenAI model. Live-chain and verified-source
credentials are optional: without them, the audit continues with source and
local tooling.

## Interactive and non-interactive runs

In an interactive terminal, ReentbotPro shows its setup wizard unless
`--no-chat` is used. The wizard collects model, reasoning, time-limit, and
verbosity settings for the current run. It can also collect and save Alchemy and
Etherscan keys, but it does not ask for a target chain or RPC endpoint.

Piped, CI, and `--no-chat` runs do not prompt. They use CLI flags, environment
variables, local configuration, and built-in defaults.

## Model authentication

Without an API key, ReentbotPro uses ChatGPT/Codex OAuth. On the first
interactive run it opens a browser, then stores its login under
`${REENTBOTPRO_HOME:-~/.reentbotpro}/auth.json`. When available, it can reuse the
official Codex CLI login from `${CODEX_HOME:-~/.codex}/auth.json`.

Use an OpenAI API key instead with either form:

```bash
reentbotpro ./contracts --api-key <OPENAI_API_KEY>
export OPENAI_API_KEY=<OPENAI_API_KEY>
```

`--api-key` takes precedence over `OPENAI_API_KEY`. Use `--login` to force a
fresh ChatGPT/Codex browser login; `--login` and `--api-key` cannot be combined.
For an OpenAI-compatible API gateway, set `OPENAI_BASE_URL` together with API-key
authentication.

## Optional chain credentials

The normal live-chain setup is:

```bash
export ALCHEMY_API_KEY=<...>
export ETHERSCAN_API_KEY=<...>
```

`ALCHEMY_API_KEY` enables chain-aware RPC derivation and the host-side tools for
traces, call simulation, state changes, transfers, and pricing.
`ETHERSCAN_API_KEY` enables verified Solidity source, ABI, and proxy-to-
implementation lookups through the Etherscan V2 API.

No run-level target chain is required. The audit begins without a chain binding,
infers chains from deployment and scope metadata, and derives an Alchemy endpoint
for each resolved chain. A bare Alchemy key is never treated as permission to
query Ethereum mainnet when the target chain is unknown. If credentials or chain
context are unavailable, affected tools report the limitation and source-only
work continues.

## Local configuration

The setup wizard can save chain credentials to
`~/.reentbotpro/config.json`. Set `REENTBOTPRO_HOME` to use a different
application directory. The saved file is restricted to the current user.

The equivalent JSON is:

```json
{
  "alchemy_api_key": "<ALCHEMY_API_KEY>",
  "etherscan_api_key": "<ETHERSCAN_API_KEY>"
}
```

For Alchemy and Etherscan credentials, environment variables take precedence
over values in this file. `--model` takes precedence over
`REENTBOTPRO_MODEL`; otherwise the built-in model default is used.

## Explicit RPC overrides

Alchemy users normally do not need to configure an RPC URL. Use an explicit
override for local nodes, Tenderly or Anvil forks, non-Alchemy providers,
debugging, or networks unsupported by your Alchemy account.

For a run-wide override:

```bash
reentbotpro ./target --rpc-url http://127.0.0.1:8545
export ETH_RPC_URL=http://127.0.0.1:8545
```

`--rpc-url` takes precedence over `ETH_RPC_URL`, which takes precedence over
local config. A top-level config value supplies the same chain-agnostic
override:

```json
{
  "rpc_url": "http://127.0.0.1:8545"
}
```

To configure different endpoints by chain, use `rpc_urls`:

```json
{
  "alchemy_api_key": "<ALCHEMY_API_KEY>",
  "etherscan_api_key": "<ETHERSCAN_API_KEY>",
  "rpc_urls": {
    "base-mainnet": "https://custom-base.example",
    "42161": "https://custom-arbitrum.example"
  }
}
```

Per-chain keys may be an Alchemy network name, a friendly chain name, or a
decimal or hexadecimal chain ID. Explicit endpoints override a URL that would
otherwise be derived from the Alchemy key. They do not select or replace the
target chain recorded by the audit.

## Run settings

The most commonly adjusted settings are:

- `--model` and `--reasoning` for model selection and reasoning effort.
- `--max-time` for the wall-clock limit in minutes.
- `--verbosity` for `off`, `partial`, or `full` tool output.
- `--output` for the parent findings directory.
- `--image` for a custom audit-container image tag.

`--context-window` and `--max-context` are advanced overrides. ReentbotPro
normally infers the selected model's context window and sizes retained history
to the tool schemas used on each turn. Run `reentbotpro --help` for the complete
and current CLI option reference.

For the internal chain resolver, per-experiment RPC injection, and campaign
artifact contract, see [Attack Campaign Engine](attack-campaign-engine.md).
