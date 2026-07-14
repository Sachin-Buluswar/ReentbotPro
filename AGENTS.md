# ReentbotPro Agent Guide

This is the stable, repo-level contract for any agent or engineer changing
ReentbotPro. It states the mission, the non-negotiable principles, where the
current truth lives, how to make a change safely, and how to verify it.

It is deliberately **not** a mirror of the current implementation. Exact tool
lists, controller statuses, toolset contents, artifact paths, helper names,
default values, and line counts live in the code, tests, and architecture docs
and change often. Read those for current behavior; read this for the rules that
do not change as the harness evolves.

`AGENTS.md` and `CLAUDE.md` are the same document and must stay byte-identical
(`tests/test_docs.py` enforces this). Edit both together, or neither.

## Purpose

ReentbotPro is an autonomous smart-contract audit harness. An LLM agent
researches a Solidity target inside a sandbox, runs analysis and validation
tools, preserves campaign state, and produces a report plus machine-readable
findings. The product is **validated, evidence-backed vulnerabilities** —
especially unprivileged loss-of-funds and permanent fund-locking issues — not a
list of suspicions.

What this harness is, and is not:

- It is **not** a checklist scanner.
- It is **not** a taxonomy of canned bug detectors.
- It preserves **generic state/invariant reasoning**, frontier exploration, and
  evidence-backed experimentation as the primary methodology.
- Known vulnerability classes are **lenses, not rails**: useful for focusing
  attention, never a substitute for reasoning about state, rights, and
  invariants from the actual code.

The LLM is the researcher and code-synthesis engine. Deterministic runtime code
exists to improve process quality — preserve state, force the next required
action, keep artifacts compact, and block the jump from hunch to finding
without evidence — not to replace the agent's judgment with a detector.

## Non-Negotiable Principles

These hold across implementations. Changing any of them is a product decision,
not a refactor.

- **One authoritative controller.** `attack_search` owns campaign scheduling
  and the required next action. Every other planning, briefing, or modeling
  tool is **advisory** unless the controller explicitly routes through it. Do
  not add a second scheduler or a parallel planning workflow.
- **Preserve the core loop:**
  `State -> Map -> Plan -> Experiment -> Evidence -> Mutate or Report`.
  Every substantial feature must feed one stage of this loop. Fold useful
  signal back into state, maps, experiments, evidence review, or reporting
  rather than spawning a standalone detector or duplicate planner.
- **Do not weaken the evidence gates.** Medium, high, and critical findings
  require objective, runnable evidence reviewed through the project's
  evidence-review path before submission. The submission gates are the source
  of truth for finding integrity.
- **PoC mechanics are not deployed exploitability.** Medium, high, and critical
  findings must separately assess and classify production reachability,
  material precondition provenance, measured funds at risk, and negative
  controls. Recall comes first: synthetic setup, architecture-incompatible call
  context, unknown live state, zero exposure, route/live-context gaps,
  partial/generic-probe-only evidence, trusted-role ambiguity, and report polish
  issues should become explicit caveats and confidence/severity qualifiers, not
  silent suppression of a mechanically validated candidate.
- **Probes and models are not proof.** Partial probes, generic probes,
  source-only hypotheses, static-analysis output, hosted simulations, and
  chain-query results are corroboration and planning context — never final
  proof and never a substitute for a runnable PoC.
- **Known bug classes are lenses, not rails.** Keep generic state-transition
  and invariant reasoning and frontier exploration first-class. Do not
  deprioritize a target merely because its names are bland or it does not match
  a familiar class.
- **Do not silently drop plausible branches.** When the current harness cannot
  express a branch, record the blocker, harness limit, or parking decision —
  "rejected" and "cannot validate yet" are different states.
- **Durable state over conversation memory.** Prefer recorded campaign
  artifacts and state over relying on chat history. Keep model-visible
  responses compact; write bulk detail to artifact files.
- **Treat stale inputs as contamination.** Generated artifacts, prior
  findings, old PoCs, old tests, and copied audit outputs are contamination
  unless the user explicitly asks for regression comparison.
- **Transitive targets are in scope.** Deployed contracts reached through
  proxy/provider/registry, asset, oracle, or authority indirection are valid
  audit targets. Preserve the original binding and normalization reason; never
  silently swap addresses.
- **The cognitive surface stays open; side effects stay sequenced.** The agent
  must always be able to read, search, inspect, reason, and record campaign
  state, even while the controller is forcing a next action on another branch.
  The controller sequences **side-effecting** tools; it does not gate thinking,
  reading, or recording. Validation of the agent's own generated experiments
  must always be allowed — the downstream gates still verify the resulting
  evidence.
- **Keep the registry coherent.** Tool schemas, dispatch, toolset membership,
  prompt behavior, and tests must stay synchronized. A tool must be visible,
  routed, and tested as a set.
- **Do not broaden side-effecting permissions or relax gates without tests.**
  Any change to what a side-effecting tool may do, or to an evidence/report
  gate, lands with tests that pin the new boundary.
- **PoCs are for disclosure.** PoC scaffolds exist to validate findings for
  responsible disclosure, not to become reusable offensive tooling.
- **Degrade cleanly offline.** When live RPC, Docker, auth, or target
  dependencies are unavailable, report the limitation and preserve
  offline/unit-test behavior. Never fake live-audit validation with
  unit-test-only evidence.

This section intentionally does not enumerate the exact always-allowed tool
set, controller statuses, toolset contents, or artifact directories. Those are
implementation details — see the references below.

## Current Architecture References

This guide does **not** enumerate every current tool, status, path, default, or
helper. For exact current behavior, read the source of truth.

**Design and roadmap**
- `docs/attack-campaign-engine.md` — the campaign loop, `attack_search`
  lifecycle, evidence lifecycle, artifact contract, guardrails, and defaults.
  This is the architecture source of truth.
- `docs/tools-split-plan.md` — the current `tools.py` module-split plan and its
  measured dependency graph.
- `README.md` — user-facing install, auth, usage, and output.

**Code (category-based source map)**
- `src/reentbotpro/agent.py` — audit/report/chat loops, controller guard,
  tool visibility, context budgeting/truncation, recovery, runtime nudges.
- `src/reentbotpro/tool_schemas.py` — current tool registry: schemas,
  toolset definitions, `request_toolset` behavior, and schema compaction.
- `src/reentbotpro/tools.py` — tool implementations and workflow mechanics;
  also the public facade that re-exports the extracted modules.
- `src/reentbotpro/campaign_state.py` — durable campaign-state model.
- `src/reentbotpro/host_tools.py` — host-side, read-only investigation tools
  (live chain / verified source) with key redaction.
- `src/reentbotpro/workspace_tools.py` — base file/shell/web primitives
  (stdlib + container), re-exported from the `tools.py` facade.
- `src/reentbotpro/prompt.py` — the system and report prompt contract.
- `src/reentbotpro/llm.py` — model/auth/context/reasoning and API conversion.
- `src/reentbotpro/cli.py` — CLI, setup, Docker lifecycle, output persistence.
- `src/reentbotpro/docker.py` — image lifecycle and minimal source init.
- `src/reentbotpro/config.py` — app-local config and RPC precedence.
- `src/reentbotpro/display.py` — Rich terminal rendering of the audit run.

**Tests (executable contracts)**
- `tests/test_tool_registry.py` — schemas / dispatch / toolsets / facade
  agreement.
- `tests/test_prompt.py` — prompt behavior contract.
- `tests/test_agent.py` — controller guard, context/truncation, runtime behavior.
- `tests/test_tools.py` — tool and workflow behavior.
- `tests/test_campaign_flow.py` — end-to-end campaign/evidence lineage.
- `tests/test_docs.py` — `AGENTS.md`/`CLAUDE.md` equality and archive hygiene.

**Conflict resolution.** If this guide conflicts with code, tests, or
architecture docs:
1. Prefer **tests and code** for exact current behavior.
2. Prefer **architecture docs** for current design intent.
3. Update this guide only when a stable operating principle or workflow
   actually changed.
4. Do not preserve a stale implementation detail merely because it appears
   here — delete it and point at the source of truth instead.

## Before Changing Code

- Identify the subsystem you are touching (use the source map above).
- Read the relevant architecture docs and the nearest existing tests first.
- Prefer small, behavior-preserving patches over opportunistic refactors,
  renames, or formatting churn.
- Add or update tests for every behavior change — especially around campaign
  state, prompt text, artifact contracts, schemas, and evidence gates.
- Do not broaden side-effecting tool permissions without tests.
- Do not change evidence-review or report-review gate boundaries without tests
  that pin the new boundary.
- Keep public tool names, schemas, dispatch, toolset membership, JSON keys,
  artifact paths, campaign-id shapes, and output file names stable unless the
  task explicitly requires migration. When one changes, change schema +
  dispatch + toolset + tests together.
- For prompt changes, update the prompt tests in the same patch.
- For architecture changes, update `docs/attack-campaign-engine.md` rather than
  expanding this guide with volatile detail, and re-check `prompt.py` for tool,
  toolset, controller, gate, or default references that the change made stale.
- For model-supplied tool args, validate shape and bounds defensively; prefer
  shared coercion helpers over ad hoc parsing.
- Do not add protocol-specific dependency guessing to container source init —
  report what failed and let the agent diagnose the target.
- When a default changes (model, timeouts, paths, image, auth), update code,
  tests, `README.md`, and the architecture doc together. This guide does not
  track default values.
- The project targets Python 3.11+ and is managed with `uv`. Do not hand-edit
  `uv.lock`; prefer the standard library or existing dependencies, and ask
  before adding a runtime dependency.
- Keep generated output, caches, virtualenvs, local findings, and logs out of
  commits. Docs describe current behavior, not change history.

## Verification Matrix

Use `uv` for everything. Run the narrowest meaningful tests first, then broaden
when a change crosses module boundaries. If Docker, network, auth, RPC, or a
target project is unavailable, state that limitation instead of faking results.

**General (broad or cross-module changes)**
- `uv run ruff check .`
- `uv run pytest -q`

**Tool schemas / toolsets / dispatch / facade / `request_toolset`**
- `uv run pytest tests/test_tool_registry.py tests/test_agent.py -q`

**Prompt or runtime-nudge changes**
- `uv run pytest tests/test_prompt.py tests/test_agent.py -q`

**Controller, `attack_search`, campaign scheduling, context/truncation**
- `uv run pytest tests/test_agent.py tests/test_tools.py -q`

**Tool implementation changes**
- `uv run pytest tests/test_tools.py -q`
- add `tests/test_tool_registry.py` if schemas/dispatch/toolsets changed.

**Campaign state / artifact / evidence-lineage behavior**
- `uv run pytest tests/test_campaign_flow.py tests/test_tools.py -q`

**Prompt + tool-visibility behavior together**
- `uv run pytest tests/test_prompt.py tests/test_agent.py tests/test_tool_registry.py -q`

**Other subsystems**
- `cli.py` / output persistence: `uv run pytest tests/test_cli.py -q`
- `config.py` / RPC config: `uv run pytest tests/test_config.py tests/test_cli.py -q`
- `docker.py` / container init: `uv run pytest tests/test_docker.py -q`
- `llm.py` / model/auth/conversion: `uv run pytest tests/test_llm.py -q`

**Docs, equality, and archive hygiene**
- `uv run pytest tests/test_docs.py -q`

Do not add brittle line-number references or stale line counts to this matrix.

## Prompt and Tooling Rules

- Prompt text is product behavior. Small edits can materially change audit
  behavior, so every prompt change ships with prompt tests.
- The prompt must preserve `attack_search` authority, generic
  source/state/invariant reasoning, narrow toolset use, and strict evidence
  gates. Known bug classes stay lenses, not rails.
- Tool descriptions must match actual behavior in `tool_schemas.py`.
- Do not encourage broad `request_toolset("all")` as the default. Prefer the
  narrowest toolset the controller's next action requires; keep `all` as a
  wrap-up/debugging escape hatch.
- Keep side-effecting tools clearly distinct from cognitive, read-only, and
  modeling tools, in both schema descriptions and the prompt.
- Do not bake permanent, per-mechanism playbooks into the prompt when
  branch-specific tool outputs and docs can carry that guidance. Mechanism
  detail belongs in branch/tool surfaces, not an always-on prompt taxonomy.

## Architecture Staleness Policy

This guide is intentionally **not** an architecture mirror, and it must not be
allowed to become one. When the architecture changes, update the place that is
the source of truth for it — the architecture docs under `docs/`, the tool
schemas, the code comments near the implementation, and the executable tests —
and re-sync the surfaces that *describe* that architecture to the agent, above
all the system prompt (`prompt.py`).
Update **this** guide only when a stable operating principle, source-of-truth
pointer, verification workflow, or done criterion actually changes.

Do **not** add exact current lists of tools, controller statuses, toolset
contents, artifact paths, scoring weights, default values, line numbers, or
helper-function names to this file. Those rot the moment the implementation
moves; they belong in code, tests, and architecture docs, which this guide
points at instead. If you find such a detail here, treat it as a bug: delete it
and replace it with a pointer to the source of truth.

## Clean Handoff Archives

Handoff ZIPs have repeatedly shipped broken because they were zipped from a
working tree and included environment or cache junk (`.venv`, `.git`,
`.pytest_cache`, `.ruff_cache`, `__MACOSX`, `.DS_Store`, `__pycache__`,
`*.pyc`) or generated run outputs. Extracting those can shadow a clean install
and break `uv run`.

- Do **not** zip the working directory directly.
- Do **not** include `.venv`, `.git`, `.pytest_cache`, `.ruff_cache`,
  `__MACOSX`, `.DS_Store`, `__pycache__`, `*.pyc`, or generated run outputs
  (findings, logs, caches).
- Prefer a source-only archive from a clean tree:
  `git archive --format=zip --output dist/ReentbotPro-clean.zip HEAD`
  (`dist/` is gitignored, so the archive is never committed).
- Validate any archive before sending it with
  `python scripts/check_clean_archive.py <archive.zip>`; it exits non-zero and
  lists offenders when forbidden entries are present. `tests/test_docs.py`
  exercises this checker.

## Done Criteria

A change is not done until:

- the relevant tests from the verification matrix were run, or skipped with a
  stated reason (e.g. Docker/RPC unavailable);
- `uv run ruff check .` and `uv run pytest -q` pass for broad Python changes,
  unless a skip is explicitly documented;
- prompt, tool, schema, dispatch, and toolset changes have matching tests;
- docs were updated where they are the source of stable design intent
  (`docs/attack-campaign-engine.md` for architecture; this guide only when a
  stable principle or workflow changed);
- `AGENTS.md` and `CLAUDE.md` are byte-identical;
- no generated or local artifacts are included in handoff archives;
- the final response names the files changed and the verification performed.
