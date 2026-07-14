# `tools.py` Split Plan

This is the working plan for decomposing `src/reentbotpro/tools.py` into the
modules named in `CLAUDE.md` (cleanup priority #1) and
`docs/attack-campaign-engine.md`. It records the **actual** dependency structure
of the file (measured, not assumed), what has already been extracted, and the
staged, cycle-aware order for the rest.

Keep this in sync with the code as modules land.

## Status

| Module | State | Lines moved | Notes |
| --- | --- | --- | --- |
| `tool_schemas.py` | **done** | ~4.3k | Clean leaf: `TOOLS`, toolset defs, `_compact_*`, `expand/tool_names/tools_for_toolsets`. Imports nothing internal. |
| `host_tools.py` | **done** | ~2.0k | Alchemy + Etherscan + redaction + runtime. Self-contained sink; lazy-imports the 5 core helpers it reuses. |
| `dispatcher.py` | pending | — | `execute_tool` references ~55 impl symbols; keep in the `tools.py` facade until the impl modules land. |
| `campaign_state.py` | **done** | ~1.3k | Foundation leaf: state load/save, ids, entry helpers, derived summaries, coverage/progress/brief helpers that depend only on the state file. True leaf (imports only `AuditContainer` + stdlib). 8 cross-controller orchestrators (`_review_campaign_progress`, `_build_campaign_brief`, `_append_campaign_trace`, `_compact_trace_value`, and 4 progress/coverage fns that reach into the controller/experiments) stay in core. |
| `economics.py` | pending | ~1.8k | **Not a clean leaf** — cyclic with `attack_search`/`experiments`. Needs cycle-breaking. |
| `source_mapping.py` | pending | ~2k+ | AST extraction, parsed-file model, protocol graphs, action spaces. Untested low-level helpers. |
| `live_reachability.py` | pending | ~1.3k | Reachability classify, profile binding, attack-graph input. Cyclic with `attack_search`. |
| `experiments.py` | pending | ~7.7k | Largest sub-mass. Scaffolds, run capture, fuzz, minimization, mutation. Cyclic with `attack_search`/`campaign_state`. |
| `evidence_review.py` | pending | ~1.8k | Gates: finding/report review, submit. Depends on `experiments`/`source_mapping` loaders. |
| `workspace_tools.py` | **done (base primitives)** | ~0.2k | 7 file/shell/web primitives (`_truncate`, `_read_file`, `_write_file`, `_list_files`, `_run_command`, `_web_search`, `_fetch_url`) + the `_FIND_PRUNE_*` prune constants extracted as a base layer (imports only stdlib + `AuditContainer`, re-exported from the facade). `_search_code` and `_inspect_scope` deferred: they pull the action-source-path / `source_mapping` helpers, which belong with that split. |

Despite the completed extractions, `tools.py` is currently **~43.5k lines** — it
has *grown* well past its pre-split size because substantial tooling landed after
the split paused (host-side Alchemy/Etherscan investigation, observed-tx mining,
economics estimators, and richer experiment scaffolds). Four extractions have
moved ~7.8k lines out (`tool_schemas` ~4.3k, `host_tools` ~2.0k, `campaign_state`
~1.3k, and the `workspace_tools` base primitives ~0.2k). What remains in the
single file is the tightly-coupled campaign core (`attack_search`, `economics`,
`source_mapping`, `live_reachability`, `experiments`, `evidence_review`, plus the
`dispatcher` and the `_search_code`/`_inspect_scope` remainder of
`workspace_tools`) described below.

## The dependency reality (important)

The earlier review assumed a clean leaf→root DAG. The code is not that. A
top-level-symbol reference graph (every top-level def/const → the other
top-level symbols its body references) shows the proposed "core" modules form a
**strongly-connected component**. Measured bidirectional edges include:

- `attack_search` ↔ `campaign_state`
- `experiments` ↔ `attack_search`
- `experiments` ↔ `campaign_state`
- `economics` ↔ `attack_search`
- `economics` ↔ `experiments`
- `live_reachability` ↔ `attack_search`
- `evidence_review` → `attack_search` (and shared loaders in `experiments`)

And the workspace primitives (`_read_file`, `_run_command`, …) are called *by*
core logic (experiment runners, etc.), so they are a **base dependency**, not a
leaf that depends on core.

Consequence: the remaining modules **cannot be split by moving code alone** — a
naive move produces import cycles that fail at load time. Each remaining module
needs one of the cycle-breaking techniques below. This is why only the two
genuinely-acyclic pieces (`tool_schemas`, `host_tools`) were extracted as
mechanical moves; the rest is staged with explicit dependency surgery.

### What makes a piece "cleanly extractable today"

A symbol set `S` is a safe mechanical move when **no non-`S` core symbol
references into `S`** (a sink) or **`S` references no core symbol** (a leaf), and
its test coupling is understood. `tool_schemas` is a pure leaf; `host_tools` is a
sink whose only inbound edge is `execute_tool` and whose only outbound edges are
5 low-level helpers (made lazy). Everything else currently fails this test.

## Cycle-breaking techniques (in order of preference)

1. **Lazy (function-local) imports at the few back-edge call sites.** Used for
   `host_tools` (5 sites). Best when the cross-module references are few and at
   call time, not module load time. Keeps the module importable in any order.
2. **A `campaign_state` foundation module imported by everyone.** Most cycles
   route through campaign-state load/save/id/trace helpers. Extracting
   `campaign_state` *first* (it only needs `AuditContainer` + stdlib) collapses a
   large share of the cross-module edges into a one-directional
   `everything → campaign_state` shape.
3. **Move a shared low-level helper down into a base** (e.g. `_truncate`, the
   arg-coercion helpers, artifact-dir constants) so two siblings depend on the
   base instead of each other.
4. **Keep the dispatcher in the facade.** `execute_tool`'s match references every
   impl symbol; do not move it until the impl modules exist, or convert it to a
   name→handler registry at that point.

Avoid a deferred in-function import used only to dodge a cycle that *should* have
been broken by layering — that signals the module boundary is wrong. (The
`host_tools` lazy imports are fine: they are genuine optional reuse of unrelated
helpers, not a hidden structural cycle.)

## The facade contract (how nothing breaks)

`tools.py` stays the public module. The rest of the codebase and the tests
import ~60 public **and private** names from `reentbotpro.tools`
(`agent.py`, `cli.py`, `tests/`). Each extracted module is re-exported from
`tools.py` so every `from reentbotpro.tools import X` keeps working.

`tests/test_tool_registry.py` pins this contract:

- `ToolsFacadeContractTests` scans every `from reentbotpro.tools import …` in
  the repo and asserts each name still resolves on the facade — so a move that
  forgets a re-export fails immediately.
- `ToolRegistryConsistencyTests` pins that `TOOLS`, `TOOLSET_DEFINITIONS`,
  `PARALLEL_SAFE`, and the `execute_tool` dispatch arms stay in agreement.

### Patch sites

Tests patch module attributes with `mock.patch.object(<module>, name)`. Because
patching rebinds the name on the *patched* module's namespace, the patch must
target the module where the **callee looks the name up**, not the facade. When a
patched function moves, repoint its patch sites in lockstep (done for the 24
`_alchemy_http_post` / `_etherscan_http_get` sites → `host_tools`, plus the
`_ALCHEMY_USAGE` state reads). Run the suite with the patch active and assert the
mock was called so a silent no-op patch fails loudly.

## Pre-move characterization tests (do before each risky module)

The integration suite masks drift in low-level helpers. Before moving
`source_mapping` / `attack_search`, add direct tests for the currently-untested
helpers a move could silently break:

- AST offset/slicing: `_ast_byte_to_char` (multibyte UTF-8), `_ast_type_string`
  (array/mapping/struct), `_action_stable_uid`, `_action_logical_key`.
- Branch identity/ordering/dedup: `_attack_search_branch_sort_key`,
  `_attack_search_branch_action_key_set`, `_candidate_clone_fingerprint`,
  `_attack_search_new_id`.

These govern branch supersession and AST keying and have no direct coverage
today; a behavior-preserving move must keep them byte-identical.

## Recommended remaining order

1. **`campaign_state.py`** (foundation) — **done**. The closed leaf subset was
   computed by fixpoint (drop any section symbol that references outside the
   set, repeat) and extracted per-symbol since it is non-contiguous. The 8
   cross-controller orchestrators that reach into the controller/experiments
   (`_review_campaign_progress`, `_build_campaign_brief`, `_append_campaign_trace`,
   `_compact_trace_value`, and the progress/coverage fns that query controller
   state) stay in core and re-import the leaf. Note: a few action/coverage
   constants physically grouped in the original "Attack campaign state" section
   moved with it (faithful to the original grouping).
2. **`economics.py`** — after `campaign_state`. Lazy-import the few
   `attack_search`/`experiments` back-edges; the rest of its deps become
   `→ campaign_state`.
3. **`source_mapping.py`** + **`live_reachability.py`** — after the AST/identity
   characterization tests land. `live_reachability` stays a mandatory map input;
   only its file location moves.
4. **`experiments.py`** — largest mass. Externalize the forge-std `Test.sol`
   shim and `foundry.toml` into `reentbotpro/templates/` via
   `importlib.resources`, and add the templates dir to package-data, or the
   installed tool loses the shim.
5. **`attack_search.py`** — extract last among prod modules (most hidden
   coupling); the branch sort-key/id characterization tests are the safety net.
6. **`evidence_review.py`** — after `experiments`/`source_mapping` (the gates
   call evidence loaders that live there). The three submission gates and their
   severity/id coupling do not change — only file location.
7. **`workspace_tools.py`** — **done for the raw primitives** (true base:
   `_truncate`, `_read_file`, `_run_command`, `_write_file`, `_list_files`,
   `_web_search`, `_fetch_url`, plus the `_FIND_PRUNE_*` constants), extracted to
   a base layer the core imports and re-exports. Still deferred: `_search_code`
   (depends on `_normalize_action_source_path` / `_default_source_scan_roots`) and
   `_inspect_scope` (needs scope-manifest / `source_mapping`) — both move with the
   `source_mapping` split, not before it.
8. **`dispatcher.py`** — last. `execute_tool` + `_request_toolset`. Either keep
   `execute_tool` in the facade or convert to a name→handler registry once the
   impl modules exist.
9. **Split `tests/test_tools.py`** to mirror the module boundaries
   (behavior-preserving moves). Keep all imports on the facade; leave
   `tests/test_campaign_flow.py` untouched as the cross-module lineage alarm.
   Guard the carve with a `--collect-only` test-count before/after.

## Verification per step

Run after every module lands:

```bash
uv run pytest tests/test_tools.py tests/test_tool_registry.py tests/test_campaign_flow.py -q
uv run pytest tests/test_agent.py -q      # facade imports used by the loop
uv run ruff check .
```

Each artifact-path / campaign-id assertion in the suite is its own regression
alarm. Keep tool names, JSON keys, artifact paths, campaign-id shapes, and
output file names stable across every move.
