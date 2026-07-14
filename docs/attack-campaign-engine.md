# Attack Campaign Engine

ReentbotPro should behave like a protocol exploit researcher, not a
vulnerability checklist runner. The LLM remains the principal investigator: it
chooses what looks suspicious, which assumptions to challenge, and which
experiments to run. The runtime constrains process quality and evidence flow,
not the security conclusions.

## Design Principle

The harness should encode the scientific method:

1. Model the protocol.
2. State assumptions and invariants.
3. Generate exploit hypotheses.
4. Convert hypotheses into executable experiments.
5. Interpret objective evidence.
6. Mutate or reject hypotheses.
7. Submit only evidence-backed findings.

Historical exploit patterns are useful examples and lenses, but the agent must
reason from the target protocol's actual value flows, trust boundaries, and live
deployment state. New features should help the model understand, test, reduce,
or prove a path. They should not become a parallel taxonomy of canned bug
classes.

## Runtime Loop

The current runtime is organized around one loop coordinated by the
deterministic `attack_search` controller:

```text
State -> Map -> Plan -> Experiment -> Evidence -> Mutate or Report
```

Responsibilities:

- **Attack search**: `attack_search` persists a branch queue, assigns a
  required next tool to each branch, schedules exploration by expected value vs
  proof cost (with explicit non-rejection parking for hard branches), records
  transitions, and prevents silent jumps from hypothesis to finding. It is the
  single authoritative scheduler for the campaign: every other planning tool
  (`plan_attack_campaign`, `review_campaign_progress`, `build_campaign_brief`,
  `review_attack_surface_coverage`) is advisory context and must not override
  `attack_search.next_action` without an explicit `action=advance` or
  `action=decision` transition.
- **State**: `read_campaign`, `update_campaign`, `review_campaign_progress`,
  and `build_campaign_brief` preserve the protocol model, value flows,
  assumptions, hypotheses, results, decisions, and process gaps. The advisory
  reviews surface gaps and suggestions but carry a `controller_note` deferring
  the required next action back to `attack_search`, so their signals never
  compete with the scheduler.
- **Map**: `inspect_scope`, `map_protocol_graph`, `map_action_space`,
  `extract_state_transition_model`, `map_live_reachability`,
  `inventory_live_targets`, `build_attack_graph`,
  `review_attack_surface_coverage`, `record_fork_context`,
  `estimate_amm_economics`, `estimate_flash_loan`, and
  `estimate_lending_health` describe source surfaces, live deployments,
  gates, dependencies, and economic assumptions.
  `extract_state_transition_model` is a generic, delexicalized modeling aid
  that reuses the same per-function units as `map_action_space`/`source_slice`
  to derive what state a contract tracks (mapping/aggregate/flag/enum/
  asset/external-dependency), who can change it, candidate **generic** invariant
  families (conservation, authorization binding, state-machine, external-call
  safety, rounding/bounds, batch/loop, liveness, replay), and experiments that
  could falsify them. It comes *before* any protocol-specific adapters: optional
  `vault_like`/`lending_like`/`queue_like` lenses are attached only when source
  evidence supports them, never default for unknown code, and never crowd out the
  generic invariants. It writes `stm-NNN.json` (see Artifact Contract) but no
  evidence — it is planning context the submission gates never consult, so it is
  in `_ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS` (cognitive surface, like
  `source_slice`/`synthesize_args`).
- **Plan**: `plan_attack_campaign` turns accumulated state, coverage, failed
  objectives, economics, fork context, and reviews into ranked research
  branches. It is advisory and does not decide that a finding exists, nor does
  it schedule work: its suggestions are returned under `candidate_next_steps`
  (not a `next_action`) alongside a `controller_note` that points back to
  `attack_search` for the authoritative next action and branch transitions.
- **Experiment**: `create_experiment`, `prepare_fork_exploit_workbench`,
  `compose_sequence_experiment`, `complete_sequence_experiment`,
  `compose_invariant_harness`, `synthesize_args`, `run_experiment`,
  `run_sequence_minimization`, `run_campaign_fuzz`, `diagnose_build`,
  `repair_experiment`, `extract_call_sequence`, and
  `mutate_hypothesis` create, run, reduce, and mutate validation work.
  `prepare_fork_exploit_workbench` infers a mechanism adapter (vault, lending,
  amm_oracle, bridge, queue_solver, staking, generic_execution) from explicit
  candidate metadata, an override, or candidate/fork-context text. When nothing
  matches it falls back to a `generic_state_transition` invariant/state-transition
  harness that makes no vault/share assumptions, instead of defaulting to vault,
  so novel non-economic bugs still get a proof scaffold. It also accepts an
  optional `state_transition_model` so a model-derived invariant drives the
  generic harness's objective, observation, and setup templates (see below).
  `complete_sequence_experiment` is the deterministic concretization step for a
  `needs_concretization` sequence scaffold: it reloads the workspace, applies
  target bindings, synthesized args, and minimal objective probes, then
  regenerates `sequence.json` and the `.t.sol` through the same generator so
  `scaffold_quality` stays consistent. It never marks the experiment validated.
  It materially applies a synthesized arg's per-parameter assignments: an inline
  expression goes straight into the call, a non-inline one
  (`vault.balanceOf(attacker)`, `address(vault)`, `type(uint256).max`,
  `block.timestamp + 1 hours`) is materialized through the parameter's scenario
  variable in `_configureScenario` and recorded under `scenario_assignments`.
  Materialization only happens when the expression is guaranteed to compile
  against the bound targets (referenced contract variables resolved, type
  matching); otherwise the parameter is held with a blocker rather than silently
  defaulted, and any seeding/minting setup requirement is surfaced as a remaining
  blocker.
  `synthesize_args` is a
  planning helper that reduces false negatives from complex ABI arguments: it
  proposes candidate Solidity argument expressions and setup requirements for a
  selected step/function (from action-space metadata, source-slice hints,
  parameter names/types, fork context, and common DeFi conventions). Each
  candidate call carries per-parameter `assignments` (name, expression, inline
  flag, setup requirements) so `complete_sequence_experiment` can materialize the
  non-inline expressions instead of collapsing them to a bare name. A genuine
  zero-parameter function (explicit empty `args`/`parameters`, or a `fn()`
  signature) is reported `observed` with an empty call. It proves
  nothing and never fabricates a signature/permit/proof/order/calldata payload —
  those return explicit blocker classes (`signature_required`, `permit_required`,
  `proof_required`, `order_struct_required`, `calldata_payload_required`,
  `route_required`, `array_shape_required`, `struct_shape_required`) so the agent
  completes them by hand. Results are written under
  `/workspace/campaign/arg-synthesis/arg-*.json`.
  `diagnose_build` runs or parses a build/test-list command and classifies
  Solidity project/harness blockers (missing import, pragma mismatch, compiler
  version, duplicate symbol, undeclared identifier, type error, wrong interface,
  missing dependency, test discovery, or unknown) with file/line, a repair hint,
  a `first_error`, and a `suggested_next` action so the agent repairs setup
  instead of re-reading raw logs. It is a diagnostic helper, not a detector: it
  writes only a build-diagnostic artifact under
  `/workspace/campaign/build-diagnostics/bdiag-*.json` (with a bounded `.log`
  carrying path/hash/line counts) and never mutates an experiment, so the
  submission gates still require a runnable PoC for high/critical findings.
  `repair_experiment` is the deterministic repair counterpart: given an
  experiment plus a diagnose_build reference (a `bdiag-*` id, artifact/log path,
  inline diagnostic, or raw log), it applies a small set of SAFE, surgical fixes
  to the agent's own `/workspace/experiments/` workspace — invalid checksum
  address literals (reusing the `run_experiment` checksum helper), a missing
  `forge-std/Test.sol` shim and its `foundry.toml` remapping, an undeclared
  generated scenario placeholder (declared by inferred type), and a stale
  `address(0)` target binding filled from `sequence.json` `target_addresses`. It
  also accepts an explicit `repairs` list (`{file, find, replace}` or
  `{file, line, before, after}`) applied verbatim only inside the workspace.
  Every applied repair is recorded as `{kind, file, line, before, after,
  reason}`, appended to `sequence.json` `repair_history`, and unsafe cases
  (signature/permit/proof/order/calldata payloads, arbitrary type mismatches,
  dependency installs, ambiguous overloads, interface-block regeneration) are
  returned as machine-readable `repair_suggestions` rather than patched —
  interface regeneration is delegated to `complete_sequence_experiment`. Like
  `run_experiment` against the local workspace, it is exempt from controller
  branch ordering (it can only touch the agent's own experiment), and it never
  marks an experiment validated: evidence review and the submission gates remain
  the source of truth.
- **Evidence and report**: `snapshot_state`, `compare_snapshots`,
  `evaluate_objective`, `summarize_trace`, `review_finding_evidence`,
  `review_report_quality`, and `submit_finding` keep findings tied to
  reproducible proof.

Tool exposure is progressive. The model starts with a compact core toolset for
scope inspection, file reads/searches, focused source slicing (`source_slice`
returns a compact contract/function/line slice with the function signature,
parameters, returns, modifiers, body, line hints, and related ranges instead of
a whole file — the parameter metadata is a typed input `synthesize_args` can
consume directly), shell/web access, campaign
state, controller sync, and planning. Specialized map, experiment, evidence, and
report helpers are exposed on demand: when the agent requests a toolset, when the
`attack_search` controller's selected next_action requires one (only the toolsets
that next_action needs, not the whole specialized surface), or when late wrap-up
requires submission tools.

The final report generation loop is intentionally narrower than the audit
loop. It can read campaign artifacts and write `/output/report.md`, but it
does not receive shell, mapping, experiment, web, evidence-review, or
submission tools. New audit work belongs in the campaign loop before report
generation starts.

## Artifact Contract

Campaign tools are artifact-first. Full protocol graphs, action spaces, source
slices (`source_slice` with `record_result`, under
`/workspace/campaign/source-slices/ss-*.json`), state-transition models
(`extract_state_transition_model`, under
`/workspace/campaign/state-transition-models/stm-*.json`), live reachability
maps, attack graphs, run logs, sequence payloads, minimization results, live
inventories, argument syntheses (`synthesize_args`, under
`/workspace/campaign/arg-synthesis/arg-*.json`), branch dossiers
(`attack_search`, under
`/workspace/campaign/branch-dossiers/<branch_id>.json`), and review artifacts
are written under `/workspace/campaign/` or
`/workspace/experiments/`. Live inventory artifacts
use `linv-*` ids to stay distinct from invariant `inv-*` ids. Tool responses
return compact ranked digests, counts, next actions, and artifact paths.
Campaign-controller and progress-review transitions also append compact JSONL
events to `/workspace/campaign/trace.jsonl`; the trace is for debugging audit
behavior without expanding model-visible context.

The chain/deployment registry (`inspect_scope`, written to
`/workspace/campaign/chain-registry/registry.json`, versioned by `chainreg-NNN`
id) records inferred networks, chain ids, deployed addresses, ambiguous
candidates, and notes. It is the durable input to tool-side RPC resolution and
is only written when real hints exist — the harness never fabricates a chain
binding.

The per-turn history budget is sized to the tools actually placed on the wire
that turn (`_turn_history_budget`). Demand-driven visibility means most turns
expose only a subset of `TOOLS`, so their schema overhead is smaller than the
conservative full-tool reserve; when the model context window is known, that
reclaimed headroom is handed back to conversation history instead of being left
unused. The budget shrinks as `attack_search`/`request_toolset` activate more
toolsets (more schemas on the wire) and widens again when the visible surface
narrows. The truncation/aging estimates discount that same visible subset, so a
turn is never measured against tools it did not send. An explicit `--max-context`
is a hard ceiling the per-turn budget never exceeds; without it the budget is
auto-derived (`max_context_is_user_cap` is False) and may legitimately exceed the
static full-tool reserve — that reserve is still what seeds the report/chat
phases and the recovery retries.

Long-run context compaction is designed to preserve audit state, not arbitrary
prefixes. When old turns are aged out or truncated, key campaign tool results
(`source_slice`, `synthesize_args`, `extract_state_transition_model`,
`compose_sequence_experiment`, `complete_sequence_experiment`, `diagnose_build`,
`run_experiment`, `attack_search`, and the two review gates) are replaced with
semantic summaries that keep the result's skeleton — status, readiness/runnable
flags, blockers, verdicts, objective markers, invariant kinds, and artifact
paths — while eliding bulky bodies and logs. On every `attack_search` save, the selected branch is also persisted as a
full-fidelity dossier under `branch-dossiers/`, and its `dossier_path` rides on
`next_action` and into the truncation note. So after a compaction the agent can
recover the current branch (hypothesis/objective, target actions, evidence,
required args, last blocker, next tool) with a single artifact read instead of
re-deriving it.

This contract exists to avoid context bloat. Broad Instascope-style workspaces
can contain many copied profiles, dependency trees, generated tests, prior
findings, and stale PoCs. The mapping tools use the ranked scope manifest for
broad scans, default to top ranked profile roots for `/audit` or `/audit/src`,
prune common third-party Solidity dependency trees from returned action
surfaces, and store live code probes as code presence, byte length, and short
hashes instead of raw bytecode. When a ranked or explicitly selected profile
root stores the protocol implementation under its own nested `lib` directory,
the mapping tools include those in-scope Solidity files while still pruning
top-level dependency trees, generated tests, and common third-party packages.

Action-space maps include duplicate-collapsed signature families, and
live-reachability maps include profile-family summaries and target-binding
signals. Active proxies, deployed configured contracts, and deployed contracts
with nonzero economic state are ranked ahead of unconfigured implementation or
template addresses. After live inventory runs, `attack_search` uses the latest
inventory matches as a soft branch re-ranker: active proxies and nonzero
economic state boost an existing branch, while no-code or
implementation/template bindings lower priority and add decision/mutation
blockers. Live inventory also records generic related targets discovered through
proxy slots, providers, registries, assets, or oracles. When a blocked address
points at a different deployed call target, the controller queues a related
live-target branch instead of repeating sibling source actions against the
blocked address. These transitive targets are audit targets; the runtime
records the original address, recommended call target, relation, and
normalization reason rather than silently replacing one address with another.
Attack graphs de-rank privileged, dormant, source-interface-only, and
setup-only ingress paths, and collapse repeated low-signal gated clones into
one candidate with similar targets recorded.

`build_attack_graph` runs in three modes. `reachability_aware` requires a
live-reachability map and ranks exposure-bound candidates as before.
`source_only` derives candidate skeletons from the action space alone — each
carries an explicit `source_only` exposure, a `needs_live_context` reachability
marker, live-context blockers (`live reachability not mapped`, `target address
not bound`), and a structural-label objective — so the downstream submission
gates still require live exposure and a runnable fork PoC before any
high/critical claim. Candidates are scored for attack structure, not visibility:
the non-view `state_changing_entrypoint` / `state_mutating_entrypoint` roll-ups,
public/external visibility, and first-party source score zero; only real call
boundaries, value movement, authorization, signed/cross-domain authority, and
per-claim/aggregate accounting lift a candidate (`score_reasons` records the
contributing labels). A candidate is capped at `high` unless a strong
boundary/value/signed/accounting signal is present, so a no-op like
`function ping() external {}` can never become a critical generic-invariant
candidate; bare entrypoints with no structural risk are diverted to the
`low_signal_entrypoints` frontier (preserved, never a top candidate, never
promoted to curiosity scheduling) while renamed/novel functions that actually
mutate state or cross a boundary still surface. `auto` (default) picks
`reachability_aware` only when a live map binds deployed or exposed context, and
falls back to `source_only` when live context is absent or an attempted live map
is empty (never erroring just because live context is absent). The model-visible
response stays compact (top
candidates capped by `max_candidates`, plus a `frontier_summary`); the artifact
preserves a richer novelty frontier so low-score, unlabeled/renamed, and
truncated branches are not silently dropped. The artifact records `mode`,
`all_candidate_count`, the top `candidate_chains`, and a `frontier` bucketed
into `omitted_by_score`, `omitted_by_truncation`, `low_signal_entrypoints`,
`source_only_needs_live_context`,
`low_score_state_mutators`, `unlabeled_state_mutators`,
`unusual_external_boundaries`, `generic_invariant_candidates`,
`pattern_candidates`, and `diversity_sample`
(reason buckets hold full entries; the rest hold compact references, bounded by
`frontier_max_items`). `low_signal_entrypoints` is a terminal reason bucket: it
preserves bare source-only entrypoints for the audit trail but is never reffed
into the semantic/novelty buckets, the diversity sample, or the scheduler.
Frontier entries are planning leads, not findings.
`attack_search` promotes a capped 1–3 of these frontier entries per run into
exploratory `attack_graph_frontier` branches (preferring the novelty-critical
unlabeled-state-mutator / unusual-external-boundary entries) so the curiosity /
diversity budget keeps an unusual lead or two visible — see the scheduling
section below.
Before live reachability exists, `attack_search` offers a source-only
`build_attack_graph` branch as a planning artifact while keeping
`map_live_reachability` the higher-priority next action when deployment/RPC
context is available. If a live-reachability artifact exists but binds no
deployed/exposed context, the scheduler treats it like missing live context for
planning: it may still request a source-only graph to preserve the frontier, but
it must not request a reachability-aware graph or fork-sequence work that depends
on target addresses.

`build_attack_graph` also accepts an optional `state_transition_model` (an
`stm-NNN` id or absolute path) so the generic invariants from
`extract_state_transition_model` become first-class attack-graph branches instead
of advisory artifacts the model must re-read. Each `candidate_invariant` becomes a
candidate keyed `stm:<model>:<invariant>` with `mechanism=generic_state_transition`,
a `Falsify invariant: …` objective, the invariant's falsification ideas and
candidate observations, and — where the invariant's function, an explicit target,
a referencing experiment prompt, or a model entrypoint resolves to an action-space
action — concrete action skeletons; an unmatched invariant keeps a
`no matched action-space entrypoint` blocker and a discounted score. These generic
candidates are scored only by invariant family and matched structural risk (a
`vault_like`/`lending_like` lens annotates them but never boosts the score),
compete for the top `candidate_chains`, and otherwise land in the
`generic_invariant_candidates` frontier bucket. The artifact and the compact
response both record a `state_transition_model` locator (`path`, `model_id`,
`candidate_count`). An invalid explicit `state_transition_model` ref errors
instead of being silently ignored.

`attack_search` schedules this generic-invariant workflow without forcing it.
Once a callable action space exists but no state-transition model has been
extracted, it adds a `missing_state_transition_model` branch
(`extract_state_transition_model`, `map` toolset) carrying the action-space arg
so generic invariants are built before the attack graph overfits to known
economic lenses; it gates strictly on the model artifact not existing, so a
`not_found`/empty extraction (which still writes a model artifact) cannot make
this loop. When a model with invariants exists alongside an action space and no
attack graph yet exists, the model path is threaded into the
`build_attack_graph` branch's `required_args`. When an attack graph already
exists but its recorded `state_transition_model` locator does not match the
latest model, it adds an `attack_graph_without_state_transition_model` branch
that rebuilds the graph with the model (`preserve_frontier=true`, `map` toolset)
so the generic invariants become scheduled branches; this fires only until a
model-aware graph exists, so it too cannot loop. The generic-invariant candidate
chains themselves surface as `attack_graph_state_model`-source branches that carry
their `invariant_id`, `invariant_kind`, `invariant_statement`, the
`state_transition_model` path, and the `generic_invariant` flag in the compact
branch, the `next_action`, and the durable branch dossier — planning context,
never finding evidence. Lacking live context, such a branch prefers
`map_live_reachability` (so its invariant binds to a deployed target); with live
reachability already mapped it may advance only when that artifact binds real
deployed/exposed context. If live reachability was attempted but returned no
deployed profiles, exposed actions, source-artifact actions, or target bindings,
the branch is preserved as `parked_needs_live_context` instead of falling through
to workbench or sequence composition. Strict claim/evidence branches
(`needs_evidence` and later) always outrank these mapping or parked branches.

`prepare_fork_exploit_workbench` consumes the same artifact. It loads an explicit
`state_transition_model` (an `stm-NNN` id or absolute path; an invalid explicit ref
errors) or, when absent, the candidate's own `source.state_transition_model`
(best-effort). It then matches an invariant to the selected candidate — by an
explicit invariant id (`candidate.invariant.id`, `candidate.invariant_id`, or
`candidate.source.invariant_id`), otherwise by target contract/function/action,
invariant kind, and referencing experiment prompts. When the workbench is
`generic_state_transition` and an invariant matches, it adds `model_guidance`
(model path, invariant id/kind/statement, falsification ideas, candidate
observations), prepends a `Falsify invariant: <statement>` objective with a
kind-specific note, derives setup tasks from the matched experiment prompts,
folds the invariant's candidate observations into the snapshot templates and
`compose_sequence_experiment_args` (with `mechanism=generic_state_transition`),
and surfaces the same context in the workbench README. A model `vault_like`/
`lending_like` lens only adds an annotation note; it never replaces the generic
invariant objective. When no invariant matches, the workbench records the model
locator but invents no invariant-specific guidance.

Duplicated deployed profile scopes should be triaged at the family level before
drilling into a specific address. Use explicit `files`, narrower `path`, or
`max_roots` only when a campaign needs to expand or contract the default scan.

At run completion, `_save_campaign_artifacts` copies:

- `/workspace/campaign` to `campaign/` in the run output directory.
- `/workspace/experiments` to `experiments/` in the run output directory.

The normal output directory also includes `report.md` and `findings.json`.
`findings.json` records run metadata, structured RPC provenance under `rpc`
(`provider` alchemy/explicit/none, target `network`/`chain_id`, `source`,
`override`, `assumed_default_mainnet`, plus a legacy redacted `rpc_url` prefix
kept for compatibility), saved artifact counts, submitted findings, and final
readiness status when the audit stops with unresolved high-signal work.
Interrupted or abnormal exits perform the same artifact copy best effort before
container cleanup and write a partial `findings.json` with `partial` and
`interrupted` markers when the normal report path did not finish.

Artifact copying uses a container-side tar stream and preserves regular files
as bytes, not UTF-8 text. Non-regular archive members are ignored during host
extraction. `/workspace` is mounted as a 1 GB tmpfs during the audit run, so
campaign and experiment artifacts must stay compact until they are copied out.
Current caveat: large raw analyzer dumps, especially Slither JSON, can still
fill the tmpfs or make local run outputs large. A follow-up implementation pass
should add size limits, compression, or skip metadata for large raw artifacts.

## Current Capabilities

The implementation currently supports:

- Scope inspection with Foundry profile ranking, source-root hints, deployed
  address extraction, generated-artifact warnings, and dependency pruning for
  broad workspaces.
- Source, action-space, live-reachability, live-inventory, and attack-graph
  mapping. These maps distinguish deployed entrypoints from imported
  interfaces, flattened dependencies, sibling source artifacts, privileged
  paths, dormant paths, source-only affordances, active proxies, configured
  deployed targets, and implementation/template addresses.
  Explicit action-space file requests are resolved against the active root and
  `/audit` so Instascope-style `src/...` paths do not become `/audit/src/src/...`.
  An action-space artifact that requested files but scanned none is marked
  `invalid_empty_source`, and `attack_search` requires a repaired
  `map_action_space` before live reachability, attack-graph, coverage, or
  harness work continues.
- Live on-chain investigation via host-side Alchemy enhanced APIs
  (`trace_onchain_tx`, `simulate_call`, `state_diff`, `enumerate_callers`,
  `get_asset_transfers`, `get_token_prices`, `get_token_info`,
  `simulate_asset_changes`, `simulate_execution`, `simulate_sequence`). These
  resolve the Alchemy key on the host, build per-network node URLs for any
  Alchemy-enabled EVM chain (Prices uses the REST host), and redact the key from
  every artifact and response. The agent selects the chain per call
  (`network`/`chain_id` accept an Alchemy subdomain, chain name, or chain id), or
  it is resolved at dispatch (`_prepare_host_tool_chain`) from an explicit fork
  context, an unambiguous chain-registry target binding, the latest
  `record_fork_context`, then the run-level default. A target the registry maps
  to several chains returns `chain_ambiguous`, and when no chain resolves the tool
  returns `chain_not_inferred` rather than silently querying Ethereum mainnet.
  Calls record lightweight CU telemetry and degrade capability cleanly
  when an API, tier, or chain is unavailable (account-level Alchemy usage limits
  govern spend). Each call writes its full result under
  `/workspace/campaign/probes/` and returns a compact digest. The results are
  corroboration only: they never relax
  `submit_finding`/`review_finding_evidence`, so a runnable forge PoC stays
  required for high/critical findings.
- Verified-source lookup via the host-side Etherscan tool
  (`get_contract_source`, Etherscan V2 multichain — one key + chainid). Returns
  verified Solidity source, ABI, and proxy→implementation for a deployed
  contract — the source-truth complement to Alchemy's runtime/state — written
  under `/workspace/campaign/probes/`. The key is resolved on the host and
  redacted; results are corroboration/context only. The chain id is resolved by
  the same dispatch precedence as the Alchemy tools (and returns
  `chain_not_inferred` rather than defaulting to chain id 1). Mainnet verified
  source is free; some L2s may require a paid Etherscan plan, and the tool
  degrades cleanly.
- Observed-transaction mining via the host-side `observed_tx_miner` tool (map
  toolset). For a deployed contract + target function/selector it composes the
  read-only Alchemy primitives — `trace_filter` to find real calls,
  `debug_traceTransaction` for in-call preconditions, `getAssetTransfers` for
  fund-flow context — and decodes each sample's calldata against a supplied ABI
  (a pure-Python keccak-256 derives the 4-byte selectors; a full
  `name(type,...)` signature also works without a separate ABI; selector-only
  falls back to a raw argument-word count). It returns representative samples
  (tx hash, actor, decoded args + arg shape, transfers, precondition hints, and
  fork `replay_hints`) plus `synthesize_args_hints`/`compose_sequence_hints` to
  seed `synthesize_args`, `record_fork_context`, and
  `compose_sequence_experiment`. This grounds setup/calldata/fork state in real
  usage so experiments avoid calldata/setup false negatives. The chain is
  selected per call or inferred at dispatch (fork context, chain-registry
  binding, latest `record_fork_context`, then run default; `chain_not_inferred`
  when none), the key is host-resolved and redacted, the full result is written under
  `/workspace/campaign/observed-txs/` (`otx-NNN`), and a compact digest is
  returned. It degrades cleanly to `unavailable` (no key, or trace APIs not on
  the key/chain) or `partial` (no matching txs, or enrichment unavailable) and is
  corroboration/context only — a runnable forge PoC stays required for findings.
- Chain/deployment inference and a single shared tool-side RPC resolver. The
  agent starts with no chain bound (no manual `--chain` for normal use):
  no-chain startup is the normal path, and source-only analysis proceeds until
  recon fixes a chain. `--chain`/`--chain-id` and config
  `default_chain`/`default_network`/`default_chain_id` are optional hints — not
  requirements and not single-chain constraints (a multi-chain scope overrides
  them per target, branch, or fork context). `ETH_RPC_URL` is an advanced
  explicit override and the env var injected into generated fork tests (see the
  fork-injection item below), never normal setup; host-side tools never silently
  fall back to mainnet.
  `inspect_scope` infers a chain/deployment registry from deployment files,
  Foundry `broadcast/<chainid>/` and Hardhat `deployments/<network>/` layouts,
  and block-explorer links, persisting it as a campaign artifact (above).
  Inference is conservative — only recognized aliases/subdomains/chain ids bind
  a chain, so a `localhost`/`hardhat`/`staging` directory never becomes one, and
  unresolved chain-grouped maps are kept as ambiguous candidates rather than
  dropped. A multi-chain scope is represented as multiple chain entries, never
  collapsed into one global default. The tool-side resolver
  (`_resolve_tool_rpc_endpoint`) derives an endpoint for a tool call in
  precedence order: explicit `rpc_url`; `network`/`chain_id` args; an explicit
  fork context; an unambiguous registry binding for the target; the latest
  recorded fork context; the run-level default
  (`REENTBOT_DEFAULT_NETWORK`/`REENTBOT_DEFAULT_CHAIN_ID` or config); the
  resolved chain via Alchemy/per-chain config; then a demoted, chain-agnostic
  `ETH_RPC_URL`; and nothing unless mainnet is explicitly allowed. A target the
  registry maps to several chains is never resolved arbitrarily — it returns
  `provider="none"`; `_resolve_tool_rpc_endpoints_for_chains` resolves one
  endpoint per explicitly named chain for multi-chain work. Resolution builds on
  the canonical `config.resolve_rpc_endpoint` and reuses the host-side
  Alchemy/Etherscan key handling, so a bare key plus a resolved chain is enough
  and no global chain is ever assumed. The host-side Alchemy/Etherscan tools use a
  sibling chain-only resolver (`_resolve_host_tool_chain`, applied at dispatch by
  `_prepare_host_tool_chain`) that yields a `(network, chain_id)` instead of a URL
  — they build their own per-chain request from the bare key — with the same
  precedence and the same `chain_not_inferred`/`chain_ambiguous` contract. The
  cast-driven state/economics tools
  (`record_fork_context`, `snapshot_state`, `estimate_amm_economics`,
  `estimate_flash_loan`) consume this resolver instead of cast's implicit
  default: manual inputs (reserves, liquidity) still need no RPC; an on-chain
  lookup derives a chain-specific endpoint from explicit args, a `fork_context`,
  or the target's deployment binding (binding across every probe/target of one
  artifact, so a snapshot belongs to one chain), and reports `rpc_not_configured`
  or `chain_ambiguous` (with candidate chains) rather than guessing. Each tool
  records a compact `rpc_endpoint` provenance summary (no raw URL) and redacts
  the resolved URL — which may carry an API key — from every stored cast command.
  The large live-probe tools (`map_live_reachability`, `inventory_live_targets`)
  extend the same precedence to many targets at once: a `_plan_live_probe_chains`
  planner groups targets/profiles by their resolved chain, derives a per-chain
  endpoint for each group, and probes each target against its own chain rather
  than a single global `ETH_RPC_URL`. A target the registry binds to several
  chains is left ambiguous (not probed); a resolved chain with no endpoint marks
  its probes `rpc_not_configured`; an explicit `network`/`chain_id` (or
  `fork_context`) filters out targets the registry binds to a different chain
  (`chain_mismatch`). Both the response and the artifact carry the chain grouping
  (`chains`/`chains_probed`/`targets_by_chain`) plus `ambiguous_targets` and
  `skipped_targets`, so a multi-chain scope is never collapsed into one
  chain-blind target list.
- Fork RPC injection for generated experiments. `run_experiment` (and
  `run_sequence_minimization`) no longer rely on a single global `ETH_RPC_URL`
  baked into the container at startup. Before executing a command they derive the
  chain-specific endpoint(s) the run needs and inject them as per-exec env vars,
  reusing the same precedence as `_resolve_tool_rpc_endpoint`: an explicit
  `rpc_url`/`network`/`chain_id`/`fork_context` arg; then the experiment's own
  sequence/workbench chain metadata — `primary_chain`, `required_chains`, a
  chain-bound `target_addresses` object form (`{address, network, chain_id}`,
  with the legacy plain-string form still supported), and the legacy `fork`
  block; then a deployment registry binding, the latest fork context, and run
  defaults. Metadata-declared chains are bound strictly (only recognized
  aliases/subdomains/chain ids), so a local-fork label like `local-mainnet-fork`
  never becomes a chain. A single primary chain sets `ETH_RPC_URL` (for the
  generated `vm.envString("ETH_RPC_URL")` fork tests) plus `RPC_URL_<chain_id>`
  and `RPC_URL_<NETWORK>` (e.g. `RPC_URL_8453`/`RPC_URL_BASE_MAINNET`); a
  multi-chain experiment additionally injects one `RPC_URL_<chain_id>` /
  `RPC_URL_<NETWORK>` per declared chain, with `ETH_RPC_URL` pointing only at the
  declared `primary_chain`. A run that intends to fork (chain args, declared
  chain metadata, or an RPC/fork marker in the command) but cannot derive an
  endpoint returns `rpc_not_configured`, and several declared chains with no
  primary returns `chain_ambiguous` — the command is not run against an implicit
  default. A command with no fork intent runs unchanged. The recorded result
  carries a URL-free `rpc_endpoints` (`primary`/`all`) provenance summary; the
  key-bearing URLs are injected only into the container exec, never stored.
- AST-backed action-space extraction. `map_action_space` first tries solc
  ground truth: it compiles the Foundry project with `forge build --ast`
  (forge resolves remappings and solc versions), reads each in-scope source's
  AST from the newest build-info, and derives exact visibility, mutability,
  modifiers, parameters, returns, contract kind, and inheritance — slicing
  function bodies via the AST `src` offsets to reuse the existing affordance and
  hint logic. Each entry is tagged `parse_source` (`ast` or `regex`) and the
  artifact records `source.parse_mode` (`ast`/`regex`/`mixed`). If compilation,
  build-info, or AST extraction is unavailable for a file, it falls back to the
  regex parser with no change in entry shape, so uncompilable targets keep
  working. The regex parser can truncate signature tails or invent phantom
  modifiers, so its reachability verdicts are trusted less than AST verdicts
  (below). Set `REENTBOTPRO_DISABLE_AST_MAP` to force the regex path.
  Follow-ups: AST-backed protocol-graph mapping and per-profile AST builds for
  Instascope one-profile-per-contract workspaces.
- Delexicalized structural affordances. Alongside the lexical
  `_action_affordances` (which keys off names/body substrings like
  deposit/withdraw/oracle/swap), `_structural_action_affordances` derives labels
  from source *shape* so renamed or adversarially-bland code still surfaces:
  `mapping_state_write`, `aggregate_state_update`, `state_mutating_entrypoint`,
  `external_boundary_crossing`, `unchecked_external_boundary`,
  `dynamic_call_target`, `external_call_with_value`,
  `arithmetic_rounding_or_division`, `batch_or_loop_surface`,
  `authorization_condition`, `lifecycle_state_change`,
  `user_claim_or_obligation_update`, and `emits_state_transition_event`. Both
  parsers (regex and AST) merge these into each action's affordances, and
  `_coverage_attention` weights them so a structurally risky lever crosses the
  high-attention threshold even with no known bug-class vocabulary. Detection is
  conservative regex/hint-based and the labels are prioritization/context only —
  the submission gates never consult them and no finding is derived from a
  structural affordance.
- Confidence-calibrated reachability. `_classify_action_reachability` marks a
  privileged-modifier (role-gated) verdict `high` confidence only when the
  action came from the AST; a regex (source-only) verdict is capped at `medium`.
  The attack-graph scorer fully buries a `gated` branch only for high-trust
  verdicts (AST modifiers or a live `authority.canCall` probe); an unverified
  regex gate gets a softened penalty so a parser misparse cannot silently drop a
  real high-value surface below the candidate score floor. Live-authority and
  AST confirmation both keep the full de-ranking for genuinely privileged paths.
- Mechanism-aware planning for deployed candidates, including vault/share
  accounting, lending, AMM/oracle, bridge/message, queue/solver, staking, and
  generic execution surfaces. These are experiment skeletons, not findings.
  `plan_attack_campaign` skips action-gap (coverage high-attention,
  hypothesized, open-gap) and protocol-graph hotspot levers whose action key is
  already decided (rejected/blocked/objective-failed/superseded), mirroring the
  `attack_search`/`review_campaign_progress` decided-key filter, so resolved
  branches are not regenerated on every plan call.
- Source/context review before harness work for coverage gaps. A coverage gap is
  an unreviewed surface, not an exploit hypothesis. The controller routes
  high-attention coverage gaps through focused source review, campaign-state
  updates, open questions, parking, or rejection until the branch has an
  attacker-controlled lever, target/action, value/right/invariant at risk,
  setup precondition, measurable objective, and any required deployment/fork
  binding. It must not jump directly from a coverage artifact to a sequence or
  invariant harness.
- Source review before harness work when live context is empty. After
  `map_live_reachability` has run and bound no deployed profiles, exposed
  actions, source-artifact actions, or target bindings, high-attention coverage
  gaps and existing source-only hypotheses stay in cognitive/core work: source
  slice, record a decision, mutate to a concretely bound branch, or park as
  `parked_needs_live_context`. The controller must not ask for sequence
  composition, invariant harness composition, workbench preparation, or
  experiment runs until deployment metadata, chain binding, or fork context
  exists.
- Audit-loop persistence guards: the agent may not voluntarily stop before
  10000 audit turns unless wrap-up was requested, and a later voluntary stop gets
  one final `attack_search` plus progress-review readiness check. The agent
  loop also parses the latest attack-search and progress-review artifacts and
  blocks voluntary stop only for clear unresolved high-signal work such as
  ready reviews/submissions, objective-evidence branches, runnable/reduction
  branches, economically significant live attack-graph branches, or unresolved
  high-attention coverage gaps that are not merely low-signal helper/mock/test/
  interface cleanup. During audit turns, the tool executor enforces
  the active `attack_search.next_action.tool` for state-creating and submission
  tools (compose/create/prepare experiments, non-diagnostic run_command,
  write_file, plan_attack_campaign, map/inventory tools, review_* and
  submit_finding, etc.). The required tool(s) are read from the next action's
  structured `expected_tools` list or ordered `pipeline` of `{"tool": ...}`
  steps when present, and otherwise from a scan of the free-text `tool` field.
  The controller is deliberately loose for learning/diagnosis and strict for
  claims/submission, so several exceptions exist so it cannot deadlock cognitive
  work the campaign authorised:
  1. An always-allowed cognitive-and-recording surface: `attack_search`,
     `request_toolset`, `read_campaign`, `review_campaign_progress`,
     `build_campaign_brief`, `inspect_scope`, `read_file`, `search_code`,
     `source_slice`, `list_files`, `fetch_url`, `web_search`,
     `update_campaign`, `mutate_hypothesis`, `synthesize_args`, and
     `diagnose_build` (plus the read-only host-side Alchemy/Etherscan
     investigation tools). These either read state, build derived views, record
     observations/pivots/decisions, classify build blockers, or propose
     candidate call arguments — they never invent evidence the submission gates
     rely on, so blocking them only creates deadlocks.
  2. `run_experiment` whose `command` references the agent's own workspace
     under `/workspace/experiments/`, and `repair_experiment` (which only ever
     edits that workspace), are always allowed, so the controller cannot block
     the agent from repairing or validating an experiment it has already
     concretized. Non-workspace `run_experiment` usage (cast probes, generic
     setup) still respects the controller.
  3. A clearly read-only diagnostic `run_command` — `forge build`/`config`/
     `inspect`, `forge test --list`, or `slither` (no shell chaining/expansion;
     a single redirect only into a `/workspace/` or `/output/` log) — is always
     allowed so the agent can compile, inspect, list tests, or run static
     analysis while a different branch is "first". Any other `run_command`
     (running stateful tests, installs, `cast send`, shell chains) still
     respects the controller.

  Progress counters in the run's explored state count successful outcomes, not
  attempted calls: a guard-blocked call, an invalid-arguments re-emit, or a tool
  error is tallied under `failed_tool_calls` by name instead of advancing the
  campaign counters, so the nudges and readiness checks key off real progress.

  These exceptions are branch-ordering permissions, not initial tool visibility.
  Tools outside the startup core remain hidden from the model until their
  toolset is active through `request_toolset`, `attack_search` activation, or
  wrap-up/report activation. `attack_search` activation is demand-driven: a
  successful sync reveals only the toolsets its selected next_action declares
  (`required_toolsets`) or pins (its `expected_tools`/`pipeline`/`tool`), so a
  single-tool next_action no longer unlocks the whole map+experiment+evidence
  surface. Activation accumulates and never revokes a toolset the agent already
  requested, so `request_toolset` stays a durable escape hatch. Because the
  always-allowed cognitive tools still respect this visibility (the guard only
  decides what is *blocked*, not what is *shown*), a tool the controller did not
  surface this turn is reached via `request_toolset`.

  Wrap-up or wall-clock stops that still have unresolved high-signal work
  record `audit_status: incomplete_no_validated_findings` plus
  `final_readiness` in `findings.json`.
- Fork workbench, sequence, invariant, fuzz, minimization, route-composition,
  and run-capture helpers. `attack_search` keeps branches out of the run queue
  until target bindings, typed calls, live/manual blockers, and measurable
  objectives are sufficiently concrete. Sequence workspaces are self-contained
  Foundry workspaces with a local config and minimal `forge-std/Test.sol` shim
  so fresh generated experiments do not require dependency repair before the
  first run. A sequence scaffold is `needs_concretization` (not `needs_run`)
  when it is not yet runnable or still lacks an executable objective assertion;
  the intentional placeholder TODO comments no longer count against it on their
  own. Native-ETH paths are first class: a payable action with a supported value
  literal (`0.5 ether`, `1 gwei`, an integer, or a declared constant) is emitted
  as a typed `target.fn{value: ...}(args)` call — and the matching generated
  interface function is rendered `payable` (even when manual-interface or
  action-space mutability is missing/stale) so the emitted call compiles — and
  `receive`/`fallback`
  entrypoints are emitted as low-level `address(target).call{value: ...}(data)`
  calls (empty calldata for `receive`; a supported `hex"..."`/`bytes("...")`
  payload for `fallback`) — so they count as `executable`, not as a harness
  limit. `scaffold_quality` carries a tri-state `proof_readiness`: `ready` (every
  step executable plus an objective assertion), `partial` (a plausible branch
  held back only by current harness limits — an unsupported `msg.value` or
  fallback-calldata expression, complex args/routes, or missing
  interface metadata, surfaced per step as machine-readable `blocker_classes`
  and aggregated in `harness_limit_blockers`), or `blocked` (no useful core
  call, or a live blocker that would make even a partial probe misleading). A
  sequence that is missing target, deployment, chain, or source context is
  routed as `needs_context`, not `needs_concretization`: the next step is
  source/deployment/fork lookup or a parking/rejection decision, not
  `complete_sequence_experiment`. A blocked generated PoC/run with a repairable
  compile, target-binding, fork/setup, revert, assertion, or timeout diagnosis is
  routed as `needs_poc_repair`: the next step is a focused diagnosis/repair and a
  rerun of the same experiment, or an explicit decision/mutation if the same
  blocker remains or the run proves a failed protocol assumption. A `partial`
  scaffold should be completed (via
  `complete_sequence_experiment`,
  which `attack_search` recommends as the `needs_concretization` next action in
  place of a hand-written `write_file`) or handed to future
  concretization/synthesis tools, not treated as rejection evidence; a `blocked`
  one needs a recorded blocker or an evidence-backed mutate/reject. Completion
  adds a `completion_history` entry and an `objective_probe` summary to
  `sequence.json`; in `mode=partial_probe` it captures before/after snapshots but
  withholds the objective assertion (keeping the scaffold non-runnable on
  purpose), and it never emits a meaningless `assertTrue(true)`. The
  `objective_probe` summary carries a `strength` field (`generic_probe` for an
  auto-generated delta guard, `none` when no assertion was emitted) so the
  evidence/review gates can refuse to treat a generic accounting/balance delta as
  final, exact-invariant proof.
- Expected-value / proof-cost branch scheduling. `attack_search` orders its
  branch queue in tiers. The claim/evidence-adjacent statuses (`ready_to_submit`,
  `needs_report_review`, `needs_finding_review`, `needs_evidence`,
  `needs_reduction`) keep strict status-rank precedence — they are never
  reordered by a heuristic, so a finding close to submission always wins. The
  exploratory / proof-construction statuses are scheduled by a conservative
  `scheduling_score = expected_value_score - proof_cost_score - blocker_penalty +
  next_step_value + diversity_bonus`, so cheap, high-value branches rise and
  expensive, repeatedly-stalled ones sink instead of the loop over-focusing one
  hard-to-prove branch while lower-cost high-EV branches wait. Expected value
  leans on the already-reranked `priority_score` (which folds in the
  live-inventory rerank), plus severity, live exposure / deployed target,
  value-moving affordances, and objective clarity. Proof cost reflects the
  current status's distance to bankable evidence, inventory hard/missing
  blockers, `harness_limit_blockers`/`partial`/`blocked` `proof_readiness`, and
  calldata/signature/callback synthesis. The blocker penalty grows with repeated
  failed/blocked/parked history. The scores are stamped on each branch and
  surfaced in the compact `active_branches` and `next_action`; the sort key
  recomputes them, so ordering and the stamped values never disagree.
  `next_action.selection_rationale` records the selected branch's tier/scores and
  the top alternatives with a compact reason each was not selected, so a resumed
  agent can see whether the controller chose evidence work, a repairable PoC, an
  exploratory branch, or a pinned selected branch. Scoring is read-only ranking
  signal — the submission gates remain the sole source of truth for finding
  integrity.
- Curiosity / diversity budget. To stop the scheduler over-focusing the
  familiar, easy-to-prove DeFi patterns, a small `diversity_bonus` (a capped
  `novelty_score`, max `_ATTACK_SEARCH_DIVERSITY_BONUS_CAP`) lifts unusual,
  low-label branches — but only inside the exploratory tier. It is strictly
  subordinate to evidence ordering: the bonus never applies to the strict
  (claim/evidence) tier or to parked/terminal branches, so it can shuffle which
  exploratory branch leads but can never reorder `ready_to_submit`,
  `needs_report_review`, `needs_finding_review`, `needs_evidence`, or
  `needs_reduction`, and a parked branch still sinks below all active work.
  `novelty_score` rewards `attack_graph_frontier` branches, `source_only`
  exposure, generic (`generic_state_transition`/`generic_execution`) mechanisms,
  structural state-mutation/external-boundary affordances that carry no
  recognized DeFi label, open coverage gaps, and state-changing actions with no
  lexical pattern match; it discounts repeatedly failed/parked branches and
  branches with no concrete call or source reference. Generic source-only model
  candidates are capped below critical priority until live target binding or
  objective evidence exists, so novelty can preserve them without turning
  unbound invariants into proof work. The branch records
  `novelty_score`, `diversity_bonus`, `curiosity_budget_eligible`,
  `diversity_reason`, `frontier_source`, and `scheduling_notes`, surfaced (only
  when actually novel) in the compact branch, `next_action`, and dossier. To
  feed the budget, `attack_search` promotes a capped 1–3 branches per run from
  the latest attack-graph `frontier` (source `attack_graph_frontier`,
  medium/low priority, status by blocker — usually `needs_mapping` when live
  context is still unmapped, and `parked_needs_live_context` after an empty live
  reachability artifact). Frontier branches are exploratory leads, never
  findings: their required evidence and stop condition demand a concrete
  hypothesis, decision, or live-context parking record, and the submission gates
  still require a runnable fork PoC plus live exposure before any high/critical
  claim.
- Partial probes and parking. When a `partial` scaffold already has
  an executable subset (`proof_readiness=partial` with `executable_sequence_calls
  > 0`), `attack_search` surfaces it as `needs_partial_probe` and recommends
  `complete_sequence_experiment mode=partial_probe`, which renders a
  `test_partial_probe_*` test over the known steps. A partial probe is a setup
  run kind (`run_kind=partial_probe`): it exercises preconditions and preserves
  research momentum but never satisfies an experiment, and
  `review_finding_evidence` records a caveat for any medium/high/critical
  finding whose only execution evidence is a partial probe. A parallel caveat
  covers any medium/high/critical finding whose only execution evidence is a
  `generic_probe` run (an auto-generated `after != before`/`> before` delta
  guard, recorded as `probe_strength` on the run classification):
  `generic_probe` is setup/context evidence, not objective impact proof, so a
  stronger artifact — a linked `objective_evaluation`, a preserved sequence
  minimization, or a non-generic execution run — is needed for confidence. These
  caveats do not block readiness by themselves; they keep the weakness visible
  without suppressing a mechanically validated candidate. For a
  plausible-but-hard branch the controller offers non-rejection outlets. A
  `needs_poc_repair` branch is active repair work, not a finding and not a
  rejection: it preserves a mechanically useful PoC long enough to repair the
  first concrete blocker before the agent pivots. A `parked_*` status is
  non-terminal,
  sorts below all active proof work as its own tier, is preserved across `sync`
  until the agent un-parks it, and creates no decision and supersedes no sibling.
  Parking usually comes from `action=advance`, which requires `notes`; the
  controller may also derive `parked_needs_live_context` for source-only/generic
  attack-graph branches after live reachability was attempted but still did not
  bind a deployed target, chain, or fork context. The park family names why a
  branch waits: `parked_harness_limit` (harness cannot express it yet),
  `parked_low_roi` (expected value too low for current budget),
  `parked_needs_dependency` (blocked on an unbuilt tool/dependency), and
  `parked_needs_live_context` (needs live target/fork context not yet available).
  Each park records a `parking_reason` and an optional `recommended_budget`. The
  `unproven_due_to_harness_limit` decision status is the terminal-ish sibling
  (terminal for the pass, never superseding siblings and never summarized as a
  rejection). The harness-limit outlets name the future tool/evidence that would
  reopen the branch, so a hard branch is preserved without pretending it was
  falsified.
- Scaffold route filter. `compose_sequence_experiment` runs a single
  conservative check on the agent's `objective`/`success_condition`/action
  notes: if they read as clearly non-economic (access-control, reentrancy,
  message-replay terms) AND contain no economic terms (flash/loan/swap/
  oracle/liquidation/etc.), the rendered `ReentbotProSequence.t.sol` drops
  every matched route's TODO checklist (`amm_or_valuation`, `oracle_window`,
  `flash_loan`, `liquidation_credit`) and replaces them with a one-line
  suppression note that tells the agent how to re-enable specific routes.
  Word-boundary matching is used so contract or function names like
  ``uniswapV3MintCallback`` do not by themselves count as ``swap``/``callback``
  economic signals. Any ambiguity (e.g. ``"must revert"`` plus ``"flash loan"``)
  falls back to the legacy "keep every matched route" behaviour — we err
  strongly toward keeping routes because the cost of dropping a relevant
  route silently is higher than the cost of an extra TODO block. The full
  route plan is still preserved in `sequence.json` and the experiment's
  `README.md`, so the audit trail is intact and the agent can review any
  suppressed routes manually. When the classifier guessed wrong, the agent
  passes `force_route_kinds=["flash_loan_route", ...]` on
  `compose_sequence_experiment` to re-include specific route prompts; there
  is intentionally no parallel intent-override surface.
- Callback-attacker harness. Many real exploits need the attacker to BE a
  contract that receives a callback (ERC777/ERC721/ERC1155 receiver hooks, AMM
  swap callbacks, flash-loan callbacks, or a generic `receive`/`fallback`
  reentry) rather than an EOA. `compose_sequence_experiment` records a
  `callback_attacker_plan` (`enabled`, `kinds`, `attacker_contract`,
  `entrypoints`, `routed_steps`, `blockers`, `notes`) in `sequence.json` and,
  when enabled, generates a configurable `CallbackAttacker` contract in
  `ReentbotProSequence.t.sol` with only the detected hooks. The plan enables
  when an action carries explicit `callback_kind`/`use_attacker_contract`
  metadata, when matched action-space `callback_surfaces` hints (or a
  protocol-graph callback edge) show the target invokes a callback, or when a
  step routes through the attacker contract (actor `callbackAttacker`/
  `attackerContract` or `use_attacker_contract=true`). Routed steps prank as
  `address(callbackAttacker)` instead of the attacker EOA, and the contract is
  instantiated in `setUp` with `vm.deal(address(callbackAttacker), 100 ether)`.
  The reentry payload is never fabricated: the contract exposes
  `configureReentry(target, data, maxCalls)` plus configuration fields. A routed
  *reentry step* is either a callback entry (receive/fallback or a recognized
  callback function) OR a normal entrypoint that declares explicit
  callback/reentry intent — the common `callbackAttacker` calls
  `target.withdraw`, the target calls back, the attacker re-enters shape. Intent
  is declared via `callback_kind`, a named payload field
  (`callback_payload`/`reentry_calldata`/`callback_data`/...), a named reentry
  target (`reentry_target`/`callback_target`), an `attacker_contract` carrying a
  known kind, or `use_attacker_contract` plus callback-surface metadata. When a
  routed reentry step supplies a safe payload literal (`hex"..."`/`bytes("...")`)
  AND a resolvable reentry target (or the step's own contract, with optional
  `reentry_max_calls`), completion emits the concrete
  `configureReentry(address(...), hex"...", n)` call in `_configureScenario` and
  the step is `executable`. A routed reentry step that still lacks a renderable
  config stays `partial` with the `callback_payload_required` blocker class —
  readiness and the generated code always agree, so a hook is configured iff its
  step is executable; a plain routed call with no callback metadata is never held
  back. The `callback_attacker_plan` blocker is conditional and explains the
  missing part with a stable class: `callback_payload_required` (no payload),
  `unsupported_calldata` (payload present but unsafe/dynamic), or
  `callback_target_required` (safe payload but unresolved target). It is present
  only when a routed reentry step actually lacks a renderable config, not merely
  because a plan is enabled. `complete_sequence_experiment` recomputes the
  `callback_attacker_plan` from the final actions/targets after applying patches
  (so an action or target patch that introduces or resolves reentry intent is
  reflected, never reusing a stale plan); a caller may pin a plan explicitly via
  `callback_attacker_plan` to skip the recompute. The scaffold's presence is
  harness support, not full-exploit
  evidence, so a runnable forge PoC with state deltas is still required for any
  high/critical finding. `force_callback_kinds=[...]` forces specific hooks in
  when detection misses them.
- Sequence call-context plan. Every `compose_sequence_experiment` and
  `complete_sequence_experiment` run records a general `call_context_plan` in
  `sequence.json` and the generated README. It is mechanism-agnostic: each step
  records the call mode, external target binding, `msg.sender`, execution/state
  context, token/right holder, spender, beneficiary, allowance sensitivity,
  third-party-state sensitivity, architecture notes, and validation prompts.
  Completion recomputes this plan after action or target patches, so PoC repair
  sees the latest caller/state/spender facts instead of stale compose-time
  assumptions. The plan is a repair and classification aid, not a new scheduler
  and not a proof gate; it helps the agent distinguish "wrong context, update
  the PoC" from "mechanics worked but production reachability is synthetic,
  unknown, or architecture-incompatible."
- Run capture treats successful `forge test` invocations that execute no tests
  as blocked results. They remain useful setup evidence, but they do not satisfy
  experiment execution or create objective-evidence branches.
- Snapshot, comparison, objective-evaluation, trace-summary, evidence-review,
  and report-review artifacts. Snapshot comparisons include exact-key objective
  suggestions so objective evaluation can bind to the observed deltas without
  fuzzy matching. Evidence review accepts source evidence references such as
  `/audit/src/Vault.sol:42`, can infer affected code only from target source
  roots, and does not treat generated experiment PoCs as affected source. A
  passing PoC is treated as mechanics proof only: for medium/high/critical
  candidates, evidence review also classifies explicit exploit preconditions,
  provenance for each material precondition, production reachability, measured
  funds at risk, and negative controls. Synthetic PoC-only setup, unknown
  production state, architecture-incompatible call context, or zero measured
  funds at risk for high/critical claims lowers exploitability confidence and
  adds caveats instead of blocking readiness by itself. Report review can
  inherit affected-code references from a ready evidence review when the final
  report draft omits them, but the report still needs to carry the
  exploitability checklist so the writeup distinguishes PoC setup from
  as-deployed exposure.
- Repo-local generated PoCs used for target build compatibility are mirrored
  under `/workspace/experiments/generated-pocs/<result-id>/` when
  `run_experiment` can read the referenced target-local test path. Target-tree
  test paths remain contamination, but a clean generated-PoC mirror can keep
  them as supplemental traceability instead of invalidating otherwise passing
  evidence.
- Hard submission gates for medium, high, and critical findings:
  `submit_finding` requires ready evidence and report reviews plus passing
  replay/PoC output. The as-deployed exploitability checklist (`preconditions`,
  `precondition_provenance`, `production_reachability`, `funds_at_risk`, and
  `negative_controls`) is persisted as classification and caveats rather than a
  recall-cutting hard blocker. Objective-evaluation absence, attack-graph live
  context gaps, route-composition gaps, partial/generic-probe-only evidence,
  trusted-role ambiguity, minimized-variant references, and report
  presentation/completeness gaps are also persisted as warnings or confidence
  caveats rather than hard readiness blockers. Evidence review still blocks
  genuinely missing root-cause/impact/source/reproduction/evidence structure,
  failed or empty validation output without objective evidence, failed
  minimization evidence, and unvalidated high/critical claims.
  The `test_output` heuristic is Foundry-aware (`_parse_forge_test_summary`):
  it consumes `Test result: ok. N passed; M failed` lines and `[PASS]`/`[FAIL]`
  per-test markers, so a passing suite using `vm.expectRevert` is never
  classified as a failure on the basis of substring keywords. A non-empty
  `objective_evaluation` reference downgrades the `test_output` heuristic
  warning from blocker to warning at every gate site (`_finding_review_gap_summary`,
  `_review_report_quality`, `_submission_review_blockers`, and the
  `_submit_finding` contradiction check), consistent with
  `_high_impact_objective_warnings`, which treats absent objective artifacts as
  a confidence caveat for high/critical findings. The warning still appears in
  the finding's `system_note` so reviewers can inspect.
- Submission caveat preservation. Because many exploitability and proof-strength
  gaps are warnings rather than hard blockers, `submit_finding` copies linked
  evidence-review and report-review warnings into the final finding as
  `review_caveats`, `review_warnings`, and `review_warning_categories`. The
  categories are broad (`exploitability`, `proof_strength`, `live_context`,
  `route_context`, `privilege_context`, `evidence_integrity`, `report_quality`,
  `other`) so they preserve reviewer signal without encoding a protocol-specific
  detector. This keeps recall high while making uncertainty visible in
  `findings.json`.
- Gap and caveat strings produced by `_finding_review_gap_summary` and
  `_high_impact_objective_warnings` carry inline recovery hints after an em-dash
  (e.g. `missing affected code references — pass affected_code=[{...}]`). The
  short key phrase before the em-dash is preserved so existing assertions
  remain valid; the hint tells the agent the exact field name, expected shape,
  and example value so weaker models do not have to guess.

These artifacts are planning and validation instruments. They are not bug
classifiers and should not be treated as proof of exploitability by themselves.

## Known Gaps

Highest-value improvements:

1. **Attack-graph fork-test completion**
   Generated attack-graph-to-workbench-to-sequence materialization now records
   whether the scaffold can execute and whether objective assertions are still
   missing, but workspaces still need stronger live precondition resolution,
   calldata inference, and protocol-specific objective assertions.

2. **Live precondition resolution**
   Target binding now distinguishes active proxies, deployed configured or
   economic contracts, no-code targets, and implementation/template-like
   addresses, and it follows generic provider/registry indirection without
   discarding the original target. Continue improving generic probes for
   blockers that create false positives: `owner()`, `paused()`, `hasRole`,
   allowlists, compliance modules, manager/executor roles, token balances,
   oracle freshness, vault assets, signature-domain state, and deployment
   liveness.

3. **Earlier branch rejection**
   De-rank or close branches when a path is privileged-only, dormant,
   cross-domain gated without a spoof path, missing an objective delta, or only
   works with unrealistic mocks/setup. Same-target child branches are
   superseded when a parent attack-graph economic branch has already decided the
   same action path, and target-level invalidity decisions such as no code,
   dormant or uninitialized implementation, wrong proxy, or empty/no-economic
   live market state supersede
   sibling branches on the same exact target. Same-target mechanism decisions
   also record compact action-family coverage so semantic variants such as
   direct, self, and on-behalf reward claim wrappers do not consume turns after
   source and live probes disprove the shared authorization or accounting
   mechanism. Mechanism-level decisions can also suppress branches from the
   same live clone/code family, while target-level invalidity remains scoped to
   the exact target so unrelated live deployments are not over-pruned. Related
   live targets remain separate branches.

4. **Regression campaigns**
   Keep a small suite of saved protocol scopes and expected agent behaviors:
   bounded context growth, controller selects mapping before setup-only
   experiments, live reachability is used before findings, and false positives
   are rejected with evidence.

5. **Implementation decomposition**
   `tools.py` is being split into the modules below. `tool_schemas.py` and
   `host_tools.py` are extracted; the remaining campaign core is a
   tightly-coupled component that needs staged, cycle-aware extraction. The
   working plan, measured dependency structure, and ordering live in
   `docs/tools-split-plan.md`.

## Implementation Cleanup Plan

Do not remove the campaign loop, `attack_search`, live reachability, attack
graphs, sequence experiments, minimization, evidence reviews, report reviews,
or hard submission gates. Those are the intended architecture.

Module split (status and ordering tracked in `docs/tools-split-plan.md`):

- `tool_schemas.py`: OpenAI function schemas, toolset definitions, schema
  compaction. **Extracted** (clean leaf; imports nothing internal).
- `host_tools.py`: host-side Alchemy + Etherscan investigation tools, key
  redaction, and runtime state. **Extracted** (self-contained sink; lazy-imports
  the few core helpers it reuses, and tests patch it directly).
- `dispatcher.py`: tool dispatch and parallel-safety metadata. Keep `execute_tool`
  in the `tools.py` facade until the impl modules land.
- `campaign_state.py`: state file loading, saving, ids, summaries, and the
  state-only coverage/progress/brief helpers. **Extracted** as a foundation leaf
  (imports only `AuditContainer` + stdlib); cross-controller orchestrators
  (`_review_campaign_progress`, `_build_campaign_brief`, trace writers) stay in
  core.
- `attack_search.py`: deterministic branch queue and next-action logic.
- `source_mapping.py`: scope inspection, source roots, protocol graphs, action
  spaces, and coverage review.
- `live_reachability.py`: deployed profile binding, RPC probes, profile
  families, and attack graph input.
- `economics.py`: fork context, AMM, flash-loan, and lending-health estimates.
- `experiments.py`: experiment creation, sequence/invariant scaffolds,
  execution capture, fuzz capture, sequence extraction, and minimization.
- `evidence_review.py`: snapshots, comparisons, objective evaluation, trace
  summaries, evidence review, report review, and finding submission gates.
- `workspace_tools.py`: list/read/write/run shell tools plus host web
  search/fetch helpers. **Base primitives extracted** (a stdlib +
  `AuditContainer` base layer re-exported from the `tools.py` facade);
  `_search_code` and `_inspect_scope` stay in core until the `source_mapping`
  split, since they depend on its action-source-path helpers.

Additional cleanup:

- Add shared helpers for model-supplied argument coercion:
  bounded integers, booleans, list shape validation, dict shape validation, and
  safe path normalization.
- Split `tests/test_tools.py` along the same module boundaries.
- Keep README user-facing and short. Keep this document as the architecture
  source of truth.
- Delete local generated `findings-*` run outputs, logs, caches, and virtualenvs
  before committing. `.gitignore` already excludes the common generated paths.
- Prefer enriching an existing artifact over inventing a new one. Add fields
  only when a planner, scaffold, evidence gate, or report gate consumes them.

## Architecture Guardrails

New work should stay inside the same loop instead of becoming a parallel
framework:

- Every feature must feed State, Map, Plan, Experiment, Evidence, mutation, or
  reporting.
- Treat generated route, fork, and source hints as prompts for the LLM, not as
  exploit claims.
- Treat Alchemy enhanced-API results (traces, simulations, transfers, prices,
  observed transactions) as corroborating evidence the LLM interprets, never as
  a substitute for a runnable forge PoC; they must not relax `submit_finding` or
  `review_finding_evidence`.
- Promote a prompt into executable helper code only when the assumption is
  protocol-agnostic and objectively checkable.
- Before adding a detector, ask whether a better campaign brief, graph edge,
  action affordance, route context, or evidence gate would let the LLM discover
  and test the issue itself.
- Prefer consolidation over expansion once a capability exists: remove duplicate
  prompt text, share helper logic, and tighten evidence flow before creating
  another artifact or planner branch.

## Settled Defaults

- Keep campaign state in one JSON file until artifact size or concurrency makes
  section-level files clearly necessary.
- Generate experiments under `/workspace/experiments` unless the target build
  requires repo-local tests.
- Keep terminal/report output as the primary interface for now.
- Prefer protocol models, invariants, action maps, planner briefs, and
  experiments over hard-coded exploit taxonomies.
