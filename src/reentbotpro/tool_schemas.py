"""Tool schemas (OpenAI function-calling format), toolset definitions, and the
on-the-wire schema compaction used by ``tools_for_toolsets``.

Extracted from ``tools.py`` as the first, dependency-free leaf of the module
split. It imports nothing from its siblings; the rest of the package imports
the schema surface from here, and ``tools.py`` re-exports it for the public
``reentbotpro.tools`` facade.
"""


REQUEST_TOOLSET_NAME = "request_toolset"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "inspect_scope",
            "description": (
                "Build a concise audit-scope manifest from the workspace. "
                "Use this first to identify real source roots, Foundry "
                "profiles, deployed addresses, high-value contracts, and "
                "generated artifact directories to ignore. Also infers a "
                "lightweight chain/deployment registry (networks, chain ids, "
                "deployed addresses) from deployment files, Foundry broadcast "
                "and Hardhat deployment layouts, and explorer links, recording "
                "it as a campaign artifact so later tools resolve the right "
                "chain without a manual default. Read-only/context tool."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Workspace root to inspect (default: /audit)",
                        "default": "/audit",
                    },
                    "max_profiles": {
                        "type": "integer",
                        "description": (
                            "Maximum ranked Foundry profiles in the compact response "
                            "(default: 40, max: 120). The persisted manifest always "
                            "retains every parsed profile."
                        ),
                        "default": 40,
                    },
                    "include_low_priority": {
                        "type": "boolean",
                        "description": (
                            "Deprecated compatibility no-op. Infrastructure, bland, "
                            "and low-attention profiles are always retained in scope."
                        ),
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "List files and directories at a path in the audit workspace. "
                "Returns names with / suffix for directories. Use depth > 1 to "
                "see nested directory structure. Generated artifacts, prior "
                "findings, dependency trees, and stale PoC folders are pruned "
                "by default; set include_artifacts=true only when you "
                "intentionally need them."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to list (default: /audit)",
                        "default": "/audit",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum directory depth to recurse into (default: 10, max: 10)",
                        "default": 10,
                    },
                    "include_artifacts": {
                        "type": "boolean",
                        "description": "Include generated/cache/prior-finding/PoC artifact directories",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file in the audit workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to read",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line number to start reading from (1-based)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return (default: 500)",
                        "default": 500,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": (
                "Search for a regex pattern across files in the workspace. "
                "Returns matching lines with file paths and line numbers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search in (default: /audit)",
                        "default": "/audit",
                    },
                    "glob": {
                        "type": "string",
                        "description": 'File pattern to filter (e.g., "*.sol")',
                    },
                    "include_artifacts": {
                        "type": "boolean",
                        "description": "Search generated/cache/prior-finding/PoC artifact directories too",
                        "default": False,
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "source_slice",
            "description": (
                "Return a compact Solidity source slice for a "
                "contract/function/line range, including modifiers, entrypoint "
                "body, local hints, and related line ranges. Use this instead "
                "of reading whole files when focusing an exploit hypothesis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Specific .sol file or root to scan (default: /audit)",
                        "default": "/audit",
                    },
                    "contract": {
                        "type": "string",
                        "description": "Contract name to disambiguate the target function",
                    },
                    "function": {
                        "type": "string",
                        "description": "Function name to slice (resolved uniquely or with contract/line)",
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number; selects the function whose body contains it",
                    },
                    "include": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "body",
                                "modifiers",
                                "state_hints",
                                "external_calls",
                                "events",
                                "authorization",
                                "value_flows",
                                "oracle_reads",
                                "callback_surfaces",
                            ],
                        },
                        "description": "Sections to return; defaults to all when omitted",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Source lines of context around the function (default: 20, max: 120)",
                        "default": 20,
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum body characters before truncation (default: 12000, max: 50000)",
                        "default": 12000,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Persist the slice as a campaign artifact + result",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file in the workspace. Use this to create "
                "exploit PoCs, test files, config files, etc. Parent directories "
                "are created automatically."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to write to (must be under /audit, /workspace, or /output)",
                    },
                    "content": {
                        "type": "string",
                        "description": "File content to write",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_campaign",
            "description": (
                "Read the persistent attack-campaign state from "
                "/workspace/campaign/state.json. Use this to recover the "
                "protocol model, assumptions, invariants, hypotheses, "
                "experiments, results, decisions, and open questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": [
                            "all",
                            "protocol_model",
                            "trust_boundary",
                            "value_flow",
                            "invariant",
                            "hypothesis",
                            "experiment",
                            "result",
                            "decision",
                            "open_question",
                        ],
                        "description": "Campaign section to read (default: all)",
                        "default": "all",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_campaign",
            "description": (
                "Add or update a structured attack-campaign artifact. Use this "
                "instead of freeform scratchpad notes for protocol models, "
                "trust boundaries, value flows, invariants, hypotheses, "
                "experiments, results, decisions, and open questions. The tool "
                "persists state to /workspace/campaign/state.json."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": [
                            "protocol_model",
                            "trust_boundary",
                            "value_flow",
                            "invariant",
                            "hypothesis",
                            "experiment",
                            "result",
                            "decision",
                            "open_question",
                        ],
                        "description": "The campaign section to modify",
                    },
                    "action": {
                        "type": "string",
                        "enum": ["add", "update"],
                        "description": "Add a new artifact or update an existing one",
                        "default": "add",
                    },
                    "id": {
                        "type": "string",
                        "description": "Required when action=update. Existing artifact id.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short artifact title",
                    },
                    "content": {
                        "type": "string",
                        "description": (
                            "Detailed artifact content. For hypotheses include "
                            "the suspected attacker-controlled lever, target "
                            "invariant, and proposed test. For experiments "
                            "include setup, transaction sequence, expected "
                            "observation, and success/failure condition."
                        ),
                    },
                    "status": {
                        "type": "string",
                        "enum": [
                            "open",
                            "testing",
                            "observed",
                            "validated",
                            "rejected",
                            "blocked",
                            "inconclusive",
                            "superseded",
                        ],
                        "description": "Artifact status",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Investigation priority",
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Concrete evidence: file paths, line numbers, command "
                            "outputs, trace observations, balance deltas, URLs, "
                            "or reasons a branch was rejected."
                        ),
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Related campaign artifact ids, such as hypothesis "
                            "ids linked to experiments or results."
                        ),
                    },
                    "action_keys": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional exact Contract::signature/action identities. "
                            "Use these to hand a reviewed coverage branch to a "
                            "hypothesis, experiment, result, or decision without "
                            "lexical matching."
                        ),
                    },
                    "coverage_keys": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional exact Contract::signature@source-file "
                            "definition identities supplied by attack_search. "
                            "Preserve these with action_keys so same-named "
                            "definitions in different files are not conflated."
                        ),
                    },
                    "hypothesis_card": {
                        "type": "object",
                        "description": (
                            "For section=hypothesis, structured experiment-admission "
                            "facts. Partial cards are preserved as context work; all "
                            "seven fields plus evidence are required before the "
                            "controller schedules a harness."
                        ),
                        "properties": {
                            "attacker_control": {"type": "string"},
                            "state_path": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "invariant_at_risk": {"type": "string"},
                            "impact_sink": {"type": "string"},
                            "material_preconditions": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "falsifier": {"type": "string"},
                            "objective": {"type": "string"},
                        },
                    },
                },
                "required": ["section", "title", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": REQUEST_TOOLSET_NAME,
            "description": (
                "Request a specialized toolset for the next turn. Use this when "
                "core tools are not enough for mapping, experiments, evidence "
                "review, or finding/report submission."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "toolset": {
                        "type": "string",
                        "enum": ["map", "experiment", "evidence", "report", "all"],
                        "description": "Specialized toolset to make available.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Concrete reason this toolset is needed now.",
                    },
                },
                "required": ["toolset", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_campaign_brief",
            "description": (
                "Build a compact resume brief for long attack campaigns and "
                "context truncation. The brief summarizes current campaign "
                "state, latest map/plan/evidence artifacts, open work, ready "
                "reviews, and the next process action. It is a continuity "
                "artifact for the LLM, not a separate scheduler or finding "
                "decision."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short brief title",
                    },
                    "focus": {
                        "type": "string",
                        "description": "Optional focus such as oracle path, withdrawals, bridge messages, or resume after truncation",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum items per brief section (default: 8, max: 30)",
                        "default": 8,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to also record a redundant campaign result artifact",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attack_search",
            "description": (
                "Synchronize the deterministic attack-search controller. This "
                "persists a branch queue, assigns each branch a required next "
                "tool, and prevents the audit from drifting into passive notes. "
                "Call action=sync after material campaign changes and follow "
                "the returned next_action before reporting."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "sync", "status", "select", "advance", "decision"],
                        "description": "Controller action to perform (default: sync)",
                        "default": "sync",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["discover", "validate", "exploit_hypothesis"],
                        "description": "Search mode for a new controller run",
                        "default": "discover",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short title for a new or refreshed search",
                    },
                    "focus": {
                        "type": "string",
                        "description": "Optional subsystem, invariant, or asset focus",
                    },
                    "branch_id": {
                        "type": "string",
                        "description": "Branch id for select or advance actions",
                    },
                    "status": {
                        "type": "string",
                        "description": (
                            "New action=advance status: needs_context, needs_harness, "
                            "needs_run, needs_poc_repair (not exploit evidence), "
                            "needs_evidence, parked_*. An attack-graph branch may "
                            "advance to needs_harness only when its complete "
                            "hypothesis_card is already recorded or supplied with "
                            "concrete evidence in the same call."
                        ),
                    },
                    "hypothesis_card": {
                        "type": "object",
                        "description": (
                            "Complete seven-field admission card for action=advance "
                            "on an attack-graph/STM/economic branch currently blocked "
                            "only on structured hypothesis context. Supply it with "
                            "status=needs_harness and evidence; partial cards are "
                            "rejected and never unlock sequence composition."
                        ),
                        "properties": {
                            "attacker_control": {"type": "string"},
                            "state_path": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "invariant_at_risk": {"type": "string"},
                            "impact_sink": {"type": "string"},
                            "material_preconditions": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "falsifier": {"type": "string"},
                            "objective": {"type": "string"},
                        },
                        "required": [
                            "attacker_control",
                            "state_path",
                            "invariant_at_risk",
                            "impact_sink",
                            "material_preconditions",
                            "falsifier",
                            "objective",
                        ],
                    },
                    "decision_status": {
                        "type": "string",
                        "enum": [
                            "rejected",
                            "blocked",
                            "blocked_setup",
                            "blocked_compile",
                            "blocked_revert",
                            "objective_failed",
                            "unproven_due_to_harness_limit",
                            "superseded",
                        ],
                        "description": (
                            "Terminal or blocking branch outcome for action=decision. "
                            "Use rejected/blocked/objective_failed when evidence "
                            "falsifies a branch and there is no adjacent mutation. "
                            "Use unproven_due_to_harness_limit when the branch is "
                            "NOT falsified but proof is blocked by harness "
                            "expressiveness; it is not summarized as a rejection and "
                            "does not supersede sibling branches. For it, the "
                            "decision/notes MUST name the exact harness limit and "
                            "what future tool or evidence would reopen the branch."
                        ),
                    },
                    "decision": {
                        "type": "string",
                        "description": "Concrete branch decision and why it follows from evidence",
                    },
                    "decision_scope": {
                        "type": "string",
                        "enum": [
                            "branch",
                            "action_family",
                            "clone_family",
                            "target",
                        ],
                        "description": (
                            "How far an evidence-backed decision may propagate "
                            "(default: branch). action_family/clone_family must be "
                            "chosen explicitly. target propagation is honored only "
                            "for deterministic inventory or binding hard blockers."
                        ),
                        "default": "branch",
                    },
                    "failed_assumption": {
                        "type": "string",
                        "description": "Assumption invalidated by the evidence, if any",
                    },
                    "impact_assessment": {
                        "type": "string",
                        "description": "Why the branch is or is not reportable as loss/lock/profit impact",
                    },
                    "next_focus": {
                        "type": "string",
                        "description": "Optional adjacent subsystem or hypothesis to investigate next",
                    },
                    "update_related": {
                        "type": "boolean",
                        "description": (
                            "Whether to update the branch's controller-owned "
                            "hypothesis/experiment status targets (default: true). "
                            "Generic related_ids are provenance only and are never "
                            "status-mutated."
                        ),
                        "default": True,
                    },
                    "notes": {
                        "type": "string",
                        "description": (
                            "Short transition note or controller rationale. "
                            "Required when action=advance parks a branch (a "
                            "parked_* status): name the blocker and what evidence "
                            "or tool would un-park it."
                        ),
                    },
                    "parking_reason": {
                        "type": "string",
                        "description": (
                            "Optional explicit reason for parking a branch "
                            "(action=advance with a parked_* status). Defaults to "
                            "notes. Recorded on the branch and surfaced in the "
                            "compact response; cleared when the branch is "
                            "un-parked."
                        ),
                    },
                    "recommended_budget": {
                        "type": "string",
                        "description": (
                            "Optional budget hint for a parked branch (e.g. "
                            "'revisit after live fork context' or an effort "
                            "estimate). Recorded for later scheduling; does not "
                            "gate anything."
                        ),
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Evidence paths or artifact ids for a branch transition",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids for a branch transition",
                    },
                    "reset": {
                        "type": "boolean",
                        "description": "Start a fresh controller even if one exists",
                        "default": False,
                    },
                    "max_branches": {
                        "type": "integer",
                        "description": "Maximum active branches to return (default: 12, max: 40)",
                        "default": 12,
                    },
                    "include_terminal": {
                        "type": "boolean",
                        "description": "Include compact terminal branches in sync/status responses (default: false for sync)",
                        "default": False,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to also record a redundant campaign result artifact",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_protocol_graph",
            "description": (
                "Extract a lightweight value-flow and trust-boundary graph from "
                "Solidity source. Use this during orientation or before "
                "planning complex attack campaigns to map contracts, "
                "entrypoints, asset/accounting hints, external dependencies, "
                "authorization/valuation/callback boundaries, and bounded "
                "same-contract state read/write/call dependencies. This is "
                "source-derived context for LLM reasoning, not a vulnerability "
                "taxonomy or proof of a bug."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Source root to scan (default: /audit)",
                        "default": "/audit",
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional explicit Solidity files to scan. If "
                            "provided, path is used only for metadata."
                        ),
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional completed cumulative action-space id/path. "
                            "Its retained file inventory replaces an independent "
                            "first-page root scan, and definitions beyond the "
                            "bounded source graph are projected explicitly."
                        ),
                    },
                    "include_tests": {
                        "type": "boolean",
                        "description": "Include test/script Solidity files (default: false)",
                        "default": False,
                    },
                    "max_files": {
                        "type": "integer",
                        "description": (
                            "Maximum Solidity files to scan into the persisted graph "
                            "(default: 160, max: 500). Tool return remains compact."
                        ),
                        "default": 160,
                    },
                    "max_roots": {
                        "type": "integer",
                        "description": (
                            "Fallback ranked-profile-root scan bound when no "
                            "cumulative action_space inventory is supplied "
                            "(default: 12, max: 100)."
                        ),
                        "default": 12,
                    },
                    "max_items": {
                        "type": "integer",
                        "description": (
                            "Maximum graph items per persisted section "
                            "(default: 2000, max: 10000). The artifact and "
                            "response report exact retained/omitted counts."
                        ),
                        "default": 2000,
                    },
                    "response_items": {
                        "type": "integer",
                        "description": "Maximum hotspots/nodes/edges to include in the tool response (default: 6, max: 50)",
                        "default": 6,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional campaign artifact ids this graph supports",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to record a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_experiment",
            "description": (
                "Run an experiment command in the audit container and optionally "
                "record the command output as a campaign result. Use this for "
                "Foundry tests, fork simulations, fuzz harnesses, trace commands, "
                "or other evidence-producing experiment runs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run",
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Working directory (default: /audit)",
                        "default": "/audit",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": (
                            "Timeout in seconds. Adaptive default when omitted: "
                            "600 for builds, 300 for forge test / static analyzers, "
                            "900 for echidna/medusa, 120 for cast reads, 90 for "
                            "ad-hoc scripts, 180 otherwise; max: 1800"
                        ),
                    },
                    "title": {
                        "type": "string",
                        "description": "Short result title",
                    },
                    "experiment_id": {
                        "type": "string",
                        "description": "Related campaign experiment id",
                    },
                    "hypothesis_id": {
                        "type": "string",
                        "description": "Related campaign hypothesis id",
                    },
                    "interpretation": {
                        "type": "string",
                        "description": (
                            "Optional expected observation or early interpretation. "
                            "The raw command result is still recorded."
                        ),
                    },
                    "run_kind": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "build",
                            "static_analysis",
                            "inventory",
                            "setup_probe",
                            "partial_probe",
                            "live_config_probe",
                            "harness_run",
                            "poc_run",
                            "fuzz_run",
                        ],
                        "description": (
                            "Classify the command. Build/static/inventory/setup/"
                            "partial-probe runs are recorded as setup evidence and "
                            "do not satisfy an exploit experiment. Use partial_probe "
                            "for a generated test_partial_probe_* run that exercises "
                            "preconditions/executable subset only: it guides "
                            "mutation but cannot validate impact. Harness, PoC, and "
                            "fuzz runs are objective-capable and require "
                            "objective reduction before reporting."
                        ),
                        "default": "auto",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                    "auto_repair": {
                        "type": "boolean",
                        "description": (
                            "For Foundry commands, automatically repair common "
                            "generated-harness checksum address literals and "
                            "rerun once (default: true)."
                        ),
                        "default": True,
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Advanced explicit RPC URL override. If omitted, "
                            "run_experiment derives chain-specific Alchemy "
                            "endpoints from network/chain_id, fork_context, "
                            "experiment metadata, chain registry, latest fork "
                            "context, and injects ETH_RPC_URL "
                            "(plus RPC_URL_<chain_id>/RPC_URL_<NETWORK>) per chain."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain (name/subdomain/id) for the fork endpoint; "
                            "derives a per-chain endpoint when no rpc_url override "
                            "is given."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id for the fork endpoint when no "
                            "rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the fork chain when no explicit chain is given."
                        ),
                    },
                    "chain_registry": {
                        "type": "string",
                        "description": (
                            "Chain-registry id/path used to bind targets to "
                            "chains; defaults to the latest recorded registry."
                        ),
                    },
                    "primary_chain": {
                        "description": (
                            "Optional primary chain ({\"network\":..., "
                            "\"chain_id\":...} or a name/id) for a multi-chain "
                            "experiment: it selects which declared chain backs "
                            "ETH_RPC_URL while every required chain still gets its "
                            "own RPC_URL_<chain_id> endpoint."
                        ),
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sequence_minimization",
            "description": (
                "Run a baseline sequence replay and explicit minimization variant "
                "commands, then save a structured artifact showing which variants "
                "preserve the same objective/evidence marker. Use this after a "
                "sequence experiment has a replay validation plan; the LLM still "
                "edits or chooses the concrete variant commands."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sequence": {
                        "type": "string",
                        "description": (
                            "Sequence experiment id such as exp-001, an experiment "
                            "directory under /workspace/experiments, or an absolute "
                            "path to sequence.json"
                        ),
                    },
                    "baseline": {
                        "type": "object",
                        "description": (
                            "Baseline run: command, optional working_dir/timeout, "
                            "and expected_markers proving the objective evidence"
                        ),
                    },
                    "variants": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Variant runs. Each entry needs variant_id/id, command, "
                            "and expected_markers. variant_id should match an id in "
                            "sequence_minimization_plan when possible."
                        ),
                    },
                    "setup_checks": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Optional setup-reduction checks. Each entry is a "
                            "command that changes one setup assumption, includes "
                            "expected_markers, and records whether the objective "
                            "survives with that setup reduced."
                        ),
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Default working directory for commands (default: /audit)",
                        "default": "/audit",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Default timeout per command in seconds (default: 600, max: 1800)",
                        "default": 600,
                    },
                    "title": {
                        "type": "string",
                        "description": "Short minimization artifact title",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related hypothesis, experiment, result, comparison, or evaluation ids",
                    },
                    "run_variants_if_baseline_fails": {
                        "type": "boolean",
                        "description": "Run variants even if the baseline does not preserve the expected markers",
                        "default": False,
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Advanced explicit RPC URL override applied to every "
                            "replay command; else chain-specific endpoints are "
                            "derived from the sequence's chain metadata, "
                            "network/chain_id, or fork_context (same "
                            "resolution as run_experiment)."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain (name/subdomain/id) for the fork endpoint when "
                            "no rpc_url override is given."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id for the fork endpoint when no "
                            "rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the fork chain when no explicit chain is given."
                        ),
                    },
                    "primary_chain": {
                        "description": (
                            "Optional primary chain ({\"network\":..., "
                            "\"chain_id\":...} or a name/id) selecting which "
                            "declared chain backs ETH_RPC_URL for a multi-chain "
                            "sequence replay."
                        ),
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["sequence", "baseline"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_campaign_fuzz",
            "description": (
                "Run a fuzz, invariant, symbolic, or property-test campaign "
                "command and save a structured campaign artifact with the full "
                "log, outcome classification, failure snippets, and recommended "
                "next evidence tools. The LLM still chooses the harness and "
                "command; this only preserves and triages the run output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run, such as forge test --match-contract ReentbotProInvariant -vvv",
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Working directory (default: /audit)",
                        "default": "/audit",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 900, max: 1800)",
                        "default": 900,
                    },
                    "title": {
                        "type": "string",
                        "description": "Short fuzz or invariant campaign title",
                    },
                    "experiment_id": {
                        "type": "string",
                        "description": "Related campaign experiment id",
                    },
                    "hypothesis_id": {
                        "type": "string",
                        "description": "Related campaign hypothesis id",
                    },
                    "invariant_id": {
                        "type": "string",
                        "description": "Related campaign invariant id",
                    },
                    "max_snippets": {
                        "type": "integer",
                        "description": "Maximum failure snippets to save (default: 8, max: 25)",
                        "default": 8,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "diagnose_build",
            "description": (
                "Run or parse a build/test-list command and classify Solidity "
                "project/harness blockers. Use before manual repair or after a "
                "failed run_experiment. Returns structured diagnostics (missing "
                "import, pragma/compiler mismatch, duplicate symbol, undeclared "
                "identifier, type error, wrong interface, missing dependency, "
                "test discovery, or unknown) with file/line, a repair hint, and "
                "a suggested next action instead of a raw log. Does not mutate "
                "experiment source or definitions; besides ordinary compiler "
                "artifacts, it writes a campaign diagnostic artifact."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project/workspace root to build or detect (default: /audit)",
                        "default": "/audit",
                    },
                    "command": {
                        "type": "string",
                        "description": (
                            "Explicit single diagnostic command to run instead of "
                            "the auto-chosen one: forge build/config/inspect, forge "
                            "test --list, or slither. Shell chains and arbitrary "
                            "write/path overrides are rejected; FOUNDRY_PROFILE is "
                            "the only allowed leading environment assignment."
                        ),
                    },
                    "profile": {
                        "type": "string",
                        "description": "Foundry profile to build with (runs FOUNDRY_PROFILE=<profile> forge build)",
                    },
                    "log": {
                        "type": "string",
                        "description": "Raw build/test-list log text to classify without running a command",
                    },
                    "log_path": {
                        "type": "string",
                        "description": "Path to a saved build log to parse (under /workspace, /audit, or /output)",
                    },
                    "experiment": {
                        "type": "string",
                        "description": (
                            "Experiment id like exp-001, an experiment directory, or a "
                            "sequence.json path; builds that workspace with forge build"
                        ),
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds when running a command (default: 120, max: 600)",
                        "default": 120,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "snapshot_state",
            "description": (
                "Capture a structured on-chain or local-RPC state snapshot for "
                "an experiment. Use this before and after a transaction "
                "sequence to measure ETH balances, ERC20 balances, storage "
                "slots, and arbitrary view calls. Snapshots are saved under "
                "/workspace/campaign/snapshots/ and can be compared with "
                "compare_snapshots."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short snapshot title",
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Explicit RPC URL override; else derived per-chain "
                            "from network/chain_id, fork_context, registry, or the "
                            "latest recorded fork context."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain name (mainnet, base, arbitrum) used to derive "
                            "a per-chain endpoint when no rpc_url override is given."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id used to derive a per-chain endpoint "
                            "when no rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the chain for endpoint derivation."
                        ),
                    },
                    "eth_balances": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string"},
                                "address": {"type": "string"},
                            },
                            "required": ["address"],
                        },
                        "description": "ETH/native balances to query",
                    },
                    "erc20_balances": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "token": {"type": "string"},
                                "token_label": {"type": "string"},
                                "account": {"type": "string"},
                                "account_label": {"type": "string"},
                            },
                            "required": ["token", "account"],
                        },
                        "description": "ERC20 balances to query via balanceOf",
                    },
                    "storage_slots": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string"},
                                "contract": {"type": "string"},
                                "slot": {"type": "string"},
                            },
                            "required": ["contract", "slot"],
                        },
                        "description": "Raw storage slots to query with cast storage",
                    },
                    "calls": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string"},
                                "target": {"type": "string"},
                                "signature": {"type": "string"},
                                "args": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["target", "signature"],
                        },
                        "description": (
                            "Arbitrary view calls, e.g. totalAssets()(uint256), "
                            "getReserves()(uint112,uint112,uint32), or debt(address)(uint256)."
                        ),
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related experiment, hypothesis, or invariant ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_snapshots",
            "description": (
                "Compare two state snapshots created by snapshot_state. The "
                "tool reports changed probe values, numeric deltas when values "
                "are parseable integers, and stores the comparison under "
                "/workspace/campaign/comparisons/. It also returns exact-key "
                "objective suggestions for evaluate_objective."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "before": {
                        "type": "string",
                        "description": (
                            "Before snapshot id like snap-001 or path to a "
                            "snapshot JSON file"
                        ),
                    },
                    "after": {
                        "type": "string",
                        "description": (
                            "After snapshot id like snap-002 or path to a "
                            "snapshot JSON file"
                        ),
                    },
                    "title": {
                        "type": "string",
                        "description": "Short comparison title",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related experiment, hypothesis, result, or invariant ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["before", "after"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "evaluate_objective",
            "description": (
                "Evaluate a snapshot comparison against LLM-specified "
                "objectives such as attacker profit, protocol asset loss, debt "
                "increase, share drift, or an unchanged invariant. Computes raw "
                "and decimal deltas, optional USD estimates, records whether "
                "every objective was achieved, and preserves comparison/run "
                "lineage in a campaign evidence artifact."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "comparison": {
                        "type": "string",
                        "description": (
                            "Comparison id like cmp-001 or path under "
                            "/workspace/campaign/comparisons/"
                        ),
                    },
                    "objectives": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Expected deltas to evaluate. Each objective may "
                            "include label, key or match substring, direction "
                            "(increase/decrease/nonzero/unchanged/any), "
                            "min_delta, decimals, unit, price_usd, and role."
                        ),
                    },
                    "title": {
                        "type": "string",
                        "description": "Short evaluation title",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related experiment, hypothesis, result, or invariant ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["comparison", "objectives"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_fork_context",
            "description": (
                "Record concrete fork/on-chain context for an attack campaign: "
                "network, fork block, target contracts, tokens, pools, routers, "
                "actors, oracles, flash-loan providers, assumptions, and optional cast "
                "validation probes. Use this before composing fork experiments "
                "so target addresses and environment assumptions survive."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short context title",
                    },
                    "network": {
                        "type": "string",
                        "description": "Network name, e.g. mainnet, arbitrum, base",
                    },
                    "chain_id": {
                        "description": "Expected chain id if known",
                    },
                    "fork_block": {
                        "description": "Fork block number or tag if known",
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Explicit RPC URL override for validation; else "
                            "derived per-chain from network/chain_id, registry, "
                            "or the latest recorded fork context."
                        ),
                    },
                    "contracts": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Target contracts: label, address, kind, notes",
                    },
                    "tokens": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Relevant tokens: label/symbol, address, decimals, price_usd, notes",
                    },
                    "pools": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Relevant pools/markets: label, address/pair, kind, token0, token1, notes",
                    },
                    "routers": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Routers/aggregators: label, address, kind, supported tokens, notes",
                    },
                    "oracles": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Oracle/feed dependencies: label, address, source, notes",
                    },
                    "flash_loan_providers": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Flash-loan providers: label, address/provider, fee assumptions, notes",
                    },
                    "actors": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Actors to use in simulations: label, address, role, notes",
                    },
                    "assumptions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Environment, market, fork, liquidity, and role assumptions",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Additional context or uncertainty",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids",
                    },
                    "validate": {
                        "type": "boolean",
                        "description": "Run cast probes for chain/block, code presence, token metadata, and actor balances",
                        "default": False,
                    },
                    "probe_token_metadata": {
                        "type": "boolean",
                        "description": "When validate=true, probe token decimals and symbol",
                        "default": True,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to record a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "estimate_amm_economics",
            "description": (
                "Estimate constant-product AMM swap/path economics from "
                "manual reserves or UniswapV2-style on-chain getReserves() "
                "lookups. Use this to reason about capital, liquidity depth, "
                "price impact, slippage, and value assumptions for a proposed "
                "attack sequence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short economics estimate title",
                    },
                    "pools": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Ordered pool legs. Each leg may include label, "
                            "pair, token_in_index, reserve_in, reserve_out, "
                            "amount_in or amount_in_decimal, fee_bps, token "
                            "decimals/symbols, price_usd assumptions, and "
                            "target_price_decrease_bps."
                        ),
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Explicit RPC URL override for on-chain reserve "
                            "lookups; else derived per-chain from "
                            "network/chain_id, fork_context, registry, or "
                            "the latest recorded fork context."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain name (mainnet, base, arbitrum) used to derive "
                            "a per-chain endpoint when no rpc_url override is given."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id used to derive a per-chain endpoint "
                            "when no rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the chain for endpoint derivation."
                        ),
                    },
                    "sensitivity_multipliers": {
                        "type": "array",
                        "items": {"type": ["number", "string"]},
                        "description": (
                            "Optional positive multipliers for first amount_in "
                            "route sensitivity. Defaults to 0.25, 0.5, 1, and 2."
                        ),
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related hypothesis, experiment, action-space, or result ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["pools"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "estimate_flash_loan",
            "description": (
                "Estimate flash-loan capital availability, fees, repayment, "
                "and optional USD cost for assets the LLM wants to use in an "
                "experiment. Can use manual liquidity assumptions or query "
                "provider ERC20/native balances with cast."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short flash-loan estimate title",
                    },
                    "assets": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Assets to borrow. Each object may include symbol, "
                            "asset token address, provider address, kind "
                            "(erc20/native), amount or amount_decimal, decimals, "
                            "fee_bps, available_liquidity or "
                            "available_liquidity_decimal, and price_usd."
                        ),
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Explicit RPC URL override for provider liquidity "
                            "lookups; else derived per-chain from "
                            "network/chain_id, fork_context, registry, or "
                            "the latest recorded fork context."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain name (mainnet, base, arbitrum) used to derive "
                            "a per-chain endpoint when no rpc_url override is given."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id used to derive a per-chain endpoint "
                            "when no rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the chain for endpoint derivation."
                        ),
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related hypothesis, experiment, economics, or result ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["assets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "estimate_lending_health",
            "description": (
                "Estimate lending position health factors, liquidation threshold "
                "distance, shortfall, and rough liquidation bonus under explicit "
                "collateral/debt price assumptions. Use this for borrow, collateral, "
                "oracle, and liquidation hypotheses before writing a fork PoC."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short lending economics estimate title",
                    },
                    "positions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Positions to model. Each object may include label, "
                            "collateral_amount or collateral_amount_decimal, "
                            "collateral_decimals, collateral_price_usd or "
                            "collateral_value_usd, liquidation_threshold_bps or "
                            "collateral_factor_bps, debt_amount or "
                            "debt_amount_decimal, debt_decimals, debt_price_usd or "
                            "debt_value_usd, liquidation_bonus_bps, and optional "
                            "collateral_price_shift_bps/debt_price_shift_bps."
                        ),
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related hypothesis, experiment, economics, or result ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["positions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_trace",
            "description": (
                "Summarize a Foundry or experiment log into compact trace "
                "evidence: top calls, notable value-flow functions, events, "
                "reverts, failures, and warnings. Use this after run_experiment "
                "produces a verbose forge/anvil/cast log."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the log file to summarize",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short summary title",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum items per summary list (default: 25, max: 100)",
                        "default": 25,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related experiment, hypothesis, result, or finding ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_call_sequence",
            "description": (
                "Extract an ordered protocol call sequence from a verbose trace "
                "or experiment log and save it as a campaign artifact. Use this "
                "after invariant/fuzz/trace output reveals an interesting path, "
                "then turn the extracted sequence into a focused PoC experiment."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Trace or experiment log path under /workspace, /audit, or /output",
                    },
                    "fuzz_run": {
                        "type": "string",
                        "description": (
                            "Optional fuzz-run id like fuzz-001 or path under "
                            "/workspace/campaign/fuzz-runs/. If path is omitted, "
                            "the extractor reads the fuzz run's saved log_path."
                        ),
                    },
                    "title": {
                        "type": "string",
                        "description": "Short sequence title",
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional action-space id/path. When provided, calls "
                            "are matched to known protocol actions and observations."
                        ),
                    },
                    "include_unmatched": {
                        "type": "boolean",
                        "description": "Include calls not present in the action space",
                        "default": False,
                    },
                    "max_steps": {
                        "type": "integer",
                        "description": "Maximum extracted steps (default: 50, max: 200)",
                        "default": 50,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to record a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_action_space",
            "description": (
                "Build a protocol-specific action map from Solidity source: "
                "public/external entrypoints, read-only observation functions, "
                "modifiers, role-gating hints, token/native value-flow hints, "
                "events, external calls, and compact state read/write/call-order "
                "facts. Broad manifest-backed scopes are processed in explicit "
                "cumulative profile-root batches so bounded scans never silently "
                "drop later profiles. Use this to choose multi-step attack "
                "grammars from the target's actual callable surface."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Root path to scan for Solidity files",
                        "default": "/audit",
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Specific Solidity files to scan. Relative paths "
                            "are resolved under /audit."
                        ),
                    },
                    "include_tests": {
                        "type": "boolean",
                        "description": "Whether to include test and script files",
                        "default": False,
                    },
                    "max_files": {
                        "type": "integer",
                        "description": (
                            "Maximum Solidity files to scan in one batch/file page "
                            "(default: 160, max: 500). Cumulative snapshots retain "
                            "prior pages; the tool return remains compact."
                        ),
                        "default": 160,
                    },
                    "max_roots": {
                        "type": "integer",
                        "description": (
                            "Profile-root batch size for broad /audit or /audit/src "
                            "mappings (default: 12, max: 100). The response's "
                            "scope_batch supplies exact root/file cursors when more "
                            "source remains."
                        ),
                        "default": 12,
                    },
                    "profile_cursor": {
                        "type": "integer",
                        "minimum": 0,
                        "description": (
                            "Zero-based retained-profile-root cursor (default: 0). "
                            "For continuation use exactly scope_batch.next_cursor."
                        ),
                        "default": 0,
                    },
                    "source_file_cursor": {
                        "type": "integer",
                        "minimum": 0,
                        "description": (
                            "Zero-based file cursor within the selected profile-root "
                            "batch (default: 0). For continuation use exactly "
                            "scope_batch.next_file_cursor; this prevents max_files "
                            "from skipping a large root."
                        ),
                        "default": 0,
                    },
                    "previous_action_space": {
                        "type": "string",
                        "description": (
                            "Required when either continuation cursor is nonzero: "
                            "the preceding "
                            "cumulative action-space id/path whose scope_batch "
                            "continues at this cursor."
                        ),
                    },
                    "max_items": {
                        "type": "integer",
                        "description": (
                            "Maximum actions, observations, or graph items to persist in the "
                            "artifact (default: 2000, max: 10000). Exact omission "
                            "counts are persisted; attack_search remaps at a larger "
                            "limit before downstream work. Tool return remains compact."
                        ),
                        "default": 2000,
                    },
                    "response_items": {
                        "type": "integer",
                        "description": "Maximum ranked actions/observations to include in the tool response (default: 6, max: 50)",
                        "default": 6,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_state_transition_model",
            "description": (
                "Extract a generic state-transition and invariant model from "
                "Solidity source (optionally cross-referenced with "
                "action-space/protocol-graph artifacts): what state a contract "
                "tracks, who can change it, which generic invariants might hold "
                "(conservation, authorization binding, state-machine, "
                "external-call safety, rounding/bounds, batch/loop, liveness, "
                "replay), and experiments to falsify them. Optional "
                "vault/lending/queue lenses appear only when source evidence "
                "supports them. Planning context to guide hypotheses and "
                "experiments; not vulnerability evidence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Optional short model title",
                    },
                    "path": {
                        "type": "string",
                        "description": "Source root to scan (default: /audit)",
                        "default": "/audit",
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional explicit Solidity files to scan. If "
                            "provided, path is used only for metadata."
                        ),
                    },
                    "contract": {
                        "type": "string",
                        "description": "Optional contract name to focus the model on",
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional action-space id like as-001 or path to "
                            "reuse the cumulative source inventory and prefer its "
                            "mapped facts for matching callable definitions"
                        ),
                    },
                    "protocol_graph": {
                        "type": "string",
                        "description": (
                            "Optional protocol-graph id like pg-001 or path for "
                            "external-dependency context"
                        ),
                    },
                    "source_slice": {
                        "type": ["object", "string"],
                        "description": (
                            "Optional scoping hint: an object (path/contract/"
                            "function) or a 'Contract.function'/signature string"
                        ),
                    },
                    "focus": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "generic",
                            "accounting",
                            "authorization",
                            "state_machine",
                            "external_boundary",
                        ],
                        "description": (
                            "Bias which invariant families are retained first. "
                            "The artifact records exact total/retained/omitted "
                            "counts plus a bounded omitted-family/source frontier "
                            "when max_items cannot retain every candidate."
                        ),
                        "default": "auto",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": (
                            "Maximum retained modeled items per section (default: "
                            "50, max: 200); tracked-state, entrypoint, and "
                            "candidate-invariant omissions are recorded "
                            "explicitly, never treated as coverage"
                        ),
                        "default": 50,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to persist the model artifact and a campaign result",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "map_live_reachability",
            "description": (
                "Map deployed/live reachability for scoped contracts and action "
                "spaces. This records code/proxy/admin probes, source-derived "
                "entrypoint gates, and whether actions appear public, role-gated, "
                "signature-gated, cross-domain-gated, dormant, or unknown. "
                "Profile network/chain_id bindings are retained on every action "
                "exposure. Profiles are grouped by chain and probed against a per-chain "
                "endpoint in explicit cumulative batches; multi-chain, unbound, "
                "and later profiles are reported rather than guessed or silently "
                "dropped. It is generic live context for planning, not a "
                "vulnerability claim."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short reachability map title",
                    },
                    "scope_manifest": {
                        "type": "string",
                        "description": (
                            "Scope manifest id/path; defaults to "
                            "/workspace/campaign/scope-manifest.json"
                        ),
                        "default": "/workspace/campaign/scope-manifest.json",
                    },
                    "action_space": {
                        "type": "string",
                        "description": "Optional action-space id/path to classify entrypoints",
                    },
                    "focus_contracts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional contract names to include",
                    },
                    "execute_probes": {
                        "type": "boolean",
                        "description": (
                            "Run read-only cast probes against the per-chain "
                            "endpoint resolved for each profile (default: true)."
                        ),
                        "default": True,
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Advanced explicit RPC override for every profile; "
                            "else endpoints are derived per chain."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain (name/subdomain/id) applied to profiles; "
                            "profiles the registry binds elsewhere are skipped."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id applied to profiles when no "
                            "rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the chain when no explicit chain is given."
                        ),
                    },
                    "chain_registry": {
                        "type": "string",
                        "description": (
                            "Chain-registry id/path used to bind profiles to "
                            "chains; defaults to the latest recorded registry."
                        ),
                    },
                    "max_profiles": {
                        "type": "integer",
                        "description": (
                            "Addressed-profile batch size (default: 25, max: 100). "
                            "The response's scope_batch supplies the next cursor "
                            "when more profiles remain."
                        ),
                        "default": 25,
                    },
                    "profile_cursor": {
                        "type": "integer",
                        "minimum": 0,
                        "description": (
                            "Zero-based addressed-profile cursor (default: 0). "
                            "For continuation use exactly scope_batch.next_cursor."
                        ),
                        "default": 0,
                    },
                    "previous_live_reachability": {
                        "type": "string",
                        "description": (
                            "Required with profile_cursor > 0: the preceding "
                            "cumulative live-reachability id/path whose "
                            "scope_batch continues at this cursor."
                        ),
                    },
                    "response_items": {
                        "type": "integer",
                        "description": "Maximum profile/action exposure samples to include in the tool response (default: 8, max: 50)",
                        "default": 8,
                    },
                    "probe_concurrency": {
                        "type": "integer",
                        "description": (
                            "Maximum concurrent read-only RPC probe jobs when execute_probes=true "
                            "(default: 6, max: 20)."
                        ),
                        "default": 6,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inventory_live_targets",
            "description": (
                "Run bounded read-only RPC inventory probes for exact deployed "
                "targets. Use this before fork PoCs to capture code presence, "
                "proxy slots, common admin/authority/paused state, token metadata, "
                "vault asset/underlying, lending-market accounting, and generic "
                "provider/registry indirection. Targets are grouped by chain and "
                "probed against a per-chain endpoint; multi-chain or unbound "
                "targets are reported, never guessed. Related deployed targets are "
                "planning evidence for transitive audit branches, not exploit proof."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short inventory title",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Targets to probe. Each item should include address "
                            "and optional label, contract, kind, selectors, "
                            "network, or chain_id; equal addresses on distinct "
                            "chains remain distinct targets."
                        ),
                    },
                    "execute_probes": {
                        "type": "boolean",
                        "description": (
                            "Run read-only cast probes against the per-chain "
                            "endpoint resolved for each target (default: true)."
                        ),
                        "default": True,
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": (
                            "Advanced explicit RPC override for every target; "
                            "else endpoints are derived per chain."
                        ),
                    },
                    "network": {
                        "type": "string",
                        "description": (
                            "Chain (name/subdomain/id) applied to targets; targets "
                            "the registry binds elsewhere are skipped."
                        ),
                    },
                    "chain_id": {
                        "description": (
                            "Numeric chain id applied to targets when no "
                            "rpc_url/network is given."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Fork-context id (fc-001) whose network/chain_id binds "
                            "the chain when no explicit chain is given."
                        ),
                    },
                    "chain_registry": {
                        "type": "string",
                        "description": (
                            "Chain-registry id/path used to bind targets to "
                            "chains; defaults to the latest recorded registry."
                        ),
                    },
                    "probe_concurrency": {
                        "type": "integer",
                        "description": "Maximum concurrent probe jobs (default: 4, max: 12)",
                        "default": 4,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related hypothesis, workbench, attack graph, or experiment ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_attack_graph",
            "description": (
                "Build an attack graph from source actions and optional live "
                "reachability. It links entrypoints, gates, dependencies, and "
                "value affordances into experiment skeletons, including bounded "
                "two- or three-action causal paths within one contract or across "
                "unambiguous direct same-file inheritance. reachability_aware "
                "requires a live map; source_only keeps live-binding blockers; "
                "auto chooses from context. The compact response returns top "
                "candidates; the artifact retains the bounded frontier and "
                "compatible causal paths omitted by the result cap."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short attack graph title",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["auto", "reachability_aware", "source_only"],
                        "description": (
                            "auto (default): reachability-aware only when a live "
                            "map contains deployed context, else source-only. "
                            "reachability_aware: require a live-reachability "
                            "artifact; auto selects it only when that artifact "
                            "contains deployed context. source_only: build "
                            "source-derived skeletons without live context (still "
                            "need live binding before high/critical claims)."
                        ),
                        "default": "auto",
                    },
                    "action_space": {
                        "type": "string",
                        "description": "Action-space id/path; defaults to latest known action space",
                    },
                    "live_reachability": {
                        "type": "string",
                        "description": (
                            "Live reachability id/path; defaults to latest known "
                            "map. Required only when mode=reachability_aware."
                        ),
                    },
                    "protocol_graph": {
                        "type": "string",
                        "description": "Optional protocol graph id/path for linked source context",
                    },
                    "state_transition_model": {
                        "type": "string",
                        "description": (
                            "Optional state-transition-model id/path; build generic "
                            "invariant candidates from its candidate_invariants."
                        ),
                    },
                    "focus": {
                        "type": "string",
                        "description": "Optional subsystem, asset, or invariant focus",
                    },
                    "max_candidates": {
                        "type": "integer",
                        "description": "Maximum candidate chains returned in the response top list (default: 12, max: 50)",
                        "default": 12,
                    },
                    "preserve_frontier": {
                        "type": "boolean",
                        "description": (
                            "Write a richer low-score/unlabeled/omitted branch "
                            "frontier, including compatible capped causal paths, "
                            "to the artifact for novelty discovery "
                            "(default: true). The response only returns a summary."
                        ),
                        "default": True,
                    },
                    "frontier_max_items": {
                        "type": "integer",
                        "description": "Maximum distinct frontier branches preserved in the artifact (default: 50, max: 250)",
                        "default": 50,
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Related campaign artifact ids",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to add a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compose_sequence_experiment",
            "description": (
                "Create a multi-step experiment scaffold from an LLM-selected "
                "action sequence and observation plan. Use this after "
                "map_action_space when you have chosen a concrete action "
                "grammar to test against an invariant or hypothesis. Set an "
                "action's use_attacker_contract=true (or actor "
                "'callbackAttacker') plus callback_kind to route it through a "
                "generated CallbackAttacker contract for ERC777/ERC721/ERC1155 "
                "receiver, flash-loan, or AMM-callback flows. sequence.json "
                "also records call_context_plan for caller/state/allowance repair."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short experiment title",
                    },
                    "objective": {
                        "type": "string",
                        "description": (
                            "Invariant, assumption, or attack-campaign question "
                            "this sequence tests"
                        ),
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional action-space id like as-001 or path under "
                            "/workspace/campaign/action-spaces/"
                        ),
                    },
                    "protocol_graph": {
                        "type": "string",
                        "description": (
                            "Optional protocol-graph id like pg-001 or path "
                            "under /workspace/campaign/protocol-graphs/. "
                            "Matched graph context is copied into the scaffold "
                            "as setup/evidence prompts."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Optional fork-context id like fc-001 or path under "
                            "/workspace/campaign/fork-contexts/. Target addresses "
                            "from this context are merged into the generated scaffold. "
                            "Required when an attack-graph candidate has missing or "
                            "ambiguous live-chain metadata; the composer never guesses "
                            "mainnet from an address alone."
                        ),
                    },
                    "call_sequence": {
                        "type": "string",
                        "description": (
                            "Optional extracted call-sequence id like seq-001 or "
                            "path under /workspace/campaign/sequences/. If "
                            "actions are omitted, steps from this sequence become "
                            "the experiment actions."
                        ),
                    },
                    "fuzz_run": {
                        "type": "string",
                        "description": (
                            "Optional fuzz-run id like fuzz-001 or path under "
                            "/workspace/campaign/fuzz-runs/. Candidate failure "
                            "snippets are copied into the scaffold as reduction "
                            "context."
                        ),
                    },
                    "attack_graph": {
                        "type": "string",
                        "description": (
                            "Optional attack-graph id like ag-001 or path under "
                            "/workspace/campaign/attack-graphs/. If provided, "
                            "compose_sequence_experiment can materialize the "
                            "selected candidate directly instead of requiring the "
                            "LLM to copy action skeletons by hand."
                        ),
                    },
                    "candidate_id": {
                        "type": "string",
                        "description": (
                            "Candidate id, attack_key, action_key, or title from "
                            "the attack_graph. If omitted with attack_graph, the "
                            "top ranked candidate is used."
                        ),
                    },
                    "mechanism": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "vault",
                            "lending",
                            "amm_oracle",
                            "bridge",
                            "queue_solver",
                            "staking",
                            "generic_execution",
                            "generic_state_transition",
                        ],
                        "description": (
                            "Optional mechanism override for an attack-graph "
                            "candidate. The composer embeds setup, blocker, "
                            "snapshot, and objective guidance directly."
                        ),
                        "default": "auto",
                    },
                    "state_transition_model": {
                        "type": "string",
                        "description": (
                            "Optional state-transition-model id/path used to "
                            "enrich an attack-graph sequence with a matching "
                            "invariant and observation guidance."
                        ),
                    },
                    "fork_block": {
                        "description": (
                            "Optional fork block to use when materializing an "
                            "attack-graph candidate without an explicit fork_context. "
                            "The candidate or its referenced live-reachability profile "
                            "must still bind one unambiguous chain."
                        ),
                    },
                    "actions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Ordered steps selected by the LLM. Each object may "
                            "include actor, contract, function, target, args, "
                            "value, notes, expected_effect, call_mode, "
                            "state_context, token_holder, token_spender, and "
                            "beneficiary."
                        ),
                    },
                    "observations": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Read calls, balance snapshots, trace checks, or "
                            "assertions to evaluate before/after the sequence."
                        ),
                    },
                    "setup": {
                        "type": "string",
                        "description": "Actors, balances, mocks, fork block, and target bindings",
                    },
                    "target_addresses": {
                        "type": "object",
                        "description": (
                            "Optional mapping from contract names or target "
                            "labels to deployed addresses or Solidity address "
                            "expressions for the generated scaffold."
                        ),
                    },
                    "success_condition": {
                        "type": "string",
                        "description": "Observable condition that validates or falsifies the hypothesis",
                    },
                    "hypothesis_id": {
                        "type": "string",
                        "description": "Related campaign hypothesis id",
                    },
                    "invariant_id": {
                        "type": "string",
                        "description": "Related campaign invariant id",
                    },
                    "target_dir": {
                        "type": "string",
                        "description": (
                            "Directory for experiment files. Default is "
                            "/workspace/experiments."
                        ),
                        "default": "/workspace/experiments",
                    },
                    "solidity_pragma": {
                        "type": "string",
                        "description": (
                            "Solidity pragma constraint for generated scaffold "
                            "contracts, default '>=0.8.0 <0.9.0'."
                        ),
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Investigation priority",
                    },
                    "force_route_kinds": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "amm_or_valuation_route",
                                "oracle_window_route",
                                "flash_loan_route",
                                "liquidation_credit_route",
                            ],
                        },
                        "description": (
                            "Optional list of route kinds that must appear in the "
                            "scaffold even when the objective reads as "
                            "non-economic (access control / reentrancy / "
                            "replay). Use this when the objective is "
                            "access-control-flavoured but actually needs a "
                            "specific economic route — e.g., a callback test "
                            "that DOES involve a flash loan."
                        ),
                    },
                    "force_callback_kinds": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "generic_receive_fallback",
                                "erc721_receiver",
                                "erc1155_receiver",
                                "erc777_recipient",
                                "uniswap_v2_callback",
                                "uniswap_v3_callback",
                                "flash_loan_callback",
                            ],
                        },
                        "description": (
                            "Optional callback hooks to force into the generated "
                            "CallbackAttacker even when none are auto-detected."
                        ),
                    },
                },
                "required": ["title", "objective"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "complete_sequence_experiment",
            "description": (
                "Complete an existing sequence experiment by applying target "
                "bindings, synthesized args, callback/attacker setup, and "
                "objective probe scaffolding. Use this when "
                "scaffold_quality.proof_readiness is partial or "
                "scaffold_quality.runnable=false. It reloads the workspace, "
                "rewrites sequence.json and ReentbotProSequence.t.sol through "
                "the same generator (so scaffold_quality stays consistent), and "
                "records a fresh completion in campaign state without marking the "
                "experiment validated."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sequence": {
                        "type": "string",
                        "description": (
                            "Experiment id like exp-001, an experiment "
                            "directory, or an absolute sequence.json path."
                        ),
                    },
                    "target_addresses": {
                        "type": "object",
                        "description": (
                            "Optional mapping from contract names/labels to "
                            "deployed addresses; merged into the scaffold's "
                            "target bindings."
                        ),
                    },
                    "arg_synthesis": {
                        "type": ["string", "object"],
                        "description": (
                            "Optional arg-synthesis artifact id like arg-001, an "
                            "absolute path, or an inline artifact. The top "
                            "candidate call's resolvable args are applied to the "
                            "matching step; held blockers are never fabricated."
                        ),
                    },
                    "actions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Optional replacement action list. Stale interface "
                            "matches are dropped and re-derived."
                        ),
                    },
                    "observations": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Optional replacement observation list (read/view "
                            "calls used for before/after objective probes)."
                        ),
                    },
                    "success_condition": {
                        "type": "string",
                        "description": (
                            "Optional measurable success condition for the "
                            "objective assertion."
                        ),
                    },
                    "objective_probe_strategy": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "log_only",
                            "balance_delta",
                            "accounting_delta",
                            "custom_placeholders",
                        ],
                        "description": (
                            "How to scaffold before/after objective probes. "
                            "Default auto picks accounting_delta from bound "
                            "observation views, else balance_delta from fork "
                            "tokens, else log_only."
                        ),
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["full", "partial_probe"],
                        "description": (
                            "full emits an objective assertion when safe; "
                            "partial_probe captures snapshots but withholds the "
                            "assertion. Default full."
                        ),
                    },
                    "run_build": {
                        "type": "boolean",
                        "description": (
                            "Run a safe compile-only build (forge build) in the "
                            "workspace and capture the log. Default false."
                        ),
                        "default": False,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Record a campaign result for the completion. Default true.",
                        "default": True,
                    },
                    "callback_attacker_plan": {
                        "type": "object",
                        "description": (
                            "Optional pinned callback/attacker plan. When "
                            "omitted, the plan is recomputed from the final "
                            "actions/targets so callback/reentry intent stays in "
                            "sync; supply this only to override that recompute."
                        ),
                    },
                },
                "required": ["sequence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "repair_experiment",
            "description": (
                "Apply narrow repairs to a generated experiment workspace after "
                "build/setup diagnostics. Use for missing imports, undeclared "
                "generated identifiers, checksum literals, interface mismatch "
                "hints, and obvious scaffold placeholders. Returns remaining "
                "blockers. Only edits the agent's own /workspace/experiments/ "
                "workspace and never relaxes the submission gates. Unsafe cases "
                "(signatures/proofs/orders, type mismatches, dependency installs, "
                "interface regeneration) come back as machine-readable "
                "repair_suggestions, not patches."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "experiment": {
                        "type": "string",
                        "description": (
                            "Experiment id like exp-001, an experiment "
                            "directory, or an absolute sequence.json path under "
                            "/workspace/experiments/."
                        ),
                    },
                    "diagnostic": {
                        "type": ["string", "object"],
                        "description": (
                            "Optional diagnose_build reference: a bdiag-NNN id, an "
                            "absolute artifact/log path, or an inline diagnostic "
                            "object/list. Drives which repair classes apply."
                        ),
                    },
                    "log": {
                        "type": "string",
                        "description": (
                            "Optional raw build/test log text to classify and "
                            "repair from when no diagnostic reference is given."
                        ),
                    },
                    "repairs": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Optional explicit repairs, each {file, find, replace} "
                            "or {file, line, before, after} with a reason. Applied "
                            "verbatim only inside the experiment workspace."
                        ),
                    },
                    "auto": {
                        "type": "boolean",
                        "description": (
                            "Apply the supported automatic repair classes "
                            "(checksum, forge-std shim/remapping, undeclared "
                            "placeholder, stale target binding). Default true."
                        ),
                        "default": True,
                    },
                    "run_build": {
                        "type": "boolean",
                        "description": (
                            "Run diagnose_build in the workspace after repair and "
                            "include the result. Default false."
                        ),
                        "default": False,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Record a campaign result for the repair. Default true.",
                        "default": True,
                    },
                },
                "required": ["experiment"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compose_invariant_harness",
            "description": (
                "Advanced manual escape hatch: create a Foundry invariant/handler scaffold from a selected "
                "action grammar and stated invariant. Use this when a "
                "hypothesis needs breadth across action orderings, actors, and "
                "parameters rather than a single sequence. The controller does "
                "not recommend or auto-complete this scaffold."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short harness title",
                    },
                    "invariant": {
                        "type": "string",
                        "description": "Property that should hold across generated action sequences",
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional action-space id like as-001 or path under "
                            "/workspace/campaign/action-spaces/"
                        ),
                    },
                    "protocol_graph": {
                        "type": "string",
                        "description": (
                            "Optional protocol-graph id like pg-001 or path "
                            "under /workspace/campaign/protocol-graphs/. "
                            "Matched graph context is copied into the harness "
                            "as setup/evidence prompts."
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Optional fork-context id like fc-001 or path under "
                            "/workspace/campaign/fork-contexts/. Target addresses "
                            "from this context are merged into the generated handler."
                        ),
                    },
                    "actions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Handler actions selected by the LLM. Each object "
                            "must include a concrete actor, contract, function, "
                            "bounds or args, and expected_effect. Do not call "
                            "this tool with an empty actions list."
                        ),
                    },
                    "observations": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "State reads or assertions used by the invariant",
                    },
                    "actors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Actor labels to model in the handler",
                    },
                    "setup": {
                        "type": "string",
                        "description": "Target bindings, mocks, fork state, seeds, and assumptions",
                    },
                    "target_addresses": {
                        "type": "object",
                        "description": (
                            "Optional mapping from contract names or target "
                            "labels to deployed addresses or Solidity address "
                            "expressions for the generated handler."
                        ),
                    },
                    "hypothesis_id": {
                        "type": "string",
                        "description": "Related campaign hypothesis id",
                    },
                    "invariant_id": {
                        "type": "string",
                        "description": "Related campaign invariant id",
                    },
                    "target_dir": {
                        "type": "string",
                        "description": "Directory for experiment files",
                        "default": "/workspace/experiments",
                    },
                    "solidity_pragma": {
                        "type": "string",
                        "description": (
                            "Solidity pragma constraint for generated scaffold "
                            "contracts, default '>=0.8.0 <0.9.0'."
                        ),
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Investigation priority",
                    },
                },
                "required": ["title", "invariant", "actions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "synthesize_args",
            "description": (
                "Generate candidate Solidity argument expressions and setup "
                "requirements for a selected sequence step/function. Use this "
                "before completing a non-runnable sequence scaffold with complex "
                "args. It does not prove a vulnerability: it proposes candidate "
                "values from action-space metadata, source-slice hints, "
                "parameter names/types, fork context, and common DeFi "
                "conventions, and returns explicit blockers (never a fabricated "
                "signature/permit/proof/order/calldata payload)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short arg-synthesis title",
                    },
                    "action": {
                        "type": "object",
                        "description": (
                            "A single action/step to synthesize args for: "
                            "contract, function, args, value, expected_effect. "
                            "Use this or sequence + step_index."
                        ),
                    },
                    "sequence": {
                        "type": "string",
                        "description": (
                            "Sequence experiment id like exp-001, an experiment "
                            "directory, or an absolute sequence.json path. "
                            "Requires step_index."
                        ),
                    },
                    "step_index": {
                        "type": "integer",
                        "description": "1-based step index into the sequence's actions",
                    },
                    "action_space": {
                        "type": "string",
                        "description": (
                            "Optional action-space id like as-001 or path under "
                            "/workspace/campaign/action-spaces/ to enrich "
                            "parameter metadata"
                        ),
                    },
                    "fork_context": {
                        "type": "string",
                        "description": (
                            "Optional fork-context id like fc-001 or path under "
                            "/workspace/campaign/fork-contexts/ for target "
                            "addresses, tokens, and actors"
                        ),
                    },
                    "source_slice": {
                        "type": ["object", "string"],
                        "description": (
                            "Optional source-slice hint: an object with a "
                            "signature/parameters, or a raw function signature "
                            "string to parse parameter names/types from"
                        ),
                    },
                    "target_addresses": {
                        "type": "object",
                        "description": (
                            "Optional mapping from contract names/labels to "
                            "deployed addresses for spender/target candidates"
                        ),
                    },
                    "objective": {
                        "type": "string",
                        "description": (
                            "Optional objective; routes role candidates "
                            "(e.g. attacker vs victim) and amount conventions"
                        ),
                    },
                    "max_candidates": {
                        "type": "integer",
                        "description": "Maximum candidate calls to return (default: 5, max: 20)",
                        "default": 5,
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Persist the synthesis artifact + a campaign result",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mutate_hypothesis",
            "description": (
                "Record a disciplined hypothesis mutation after an experiment, "
                "trace, objective evaluation, or economics estimate invalidates "
                "or weakens an assumption. The LLM supplies the interpretation "
                "and adjacent hypotheses; this tool links evidence, updates the "
                "source hypothesis status, and creates adjacent hypothesis, "
                "decision, and open-question artifacts. It never creates a "
                "placeholder experiment workspace."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_hypothesis_id": {
                        "type": "string",
                        "description": "Hypothesis id being mutated, such as hyp-001",
                    },
                    "failed_assumption": {
                        "type": "string",
                        "description": "The assumption that failed, weakened, or changed",
                    },
                    "interpretation": {
                        "type": "string",
                        "description": "What the evidence means and why mutation is warranted",
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Result, trace, comparison, evaluation, economics, or file evidence",
                    },
                    "related_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional related campaign ids",
                    },
                    "source_status": {
                        "type": "string",
                        "enum": [
                            "rejected",
                            "blocked",
                            "inconclusive",
                            "superseded",
                        ],
                        "description": "Status to set on the source hypothesis",
                        "default": "inconclusive",
                    },
                    "mutations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "hypothesis": {"type": "string"},
                                "rationale": {"type": "string"},
                                "experiment": {
                                    "type": "string",
                                    "description": "Proposed falsification test; planning text, not an experiment artifact.",
                                },
                                "hypothesis_card": {
                                    "type": "object",
                                    "properties": {
                                        "attacker_control": {"type": "string"},
                                        "state_path": {"type": "array", "items": {"type": "string"}},
                                        "invariant_at_risk": {"type": "string"},
                                        "impact_sink": {"type": "string"},
                                        "material_preconditions": {"type": "array", "items": {"type": "string"}},
                                        "falsifier": {"type": "string"},
                                        "objective": {"type": "string"},
                                    },
                                },
                            },
                            "required": ["title", "hypothesis", "rationale", "experiment"],
                        },
                        "description": (
                            "Adjacent hypotheses selected by the LLM. Each item "
                            "requires title, hypothesis, rationale, and "
                            "experiment. Optional priority and evidence fields "
                            "are preserved."
                        ),
                    },
                    "open_questions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Optional unresolved questions that block or guide "
                            "the next experiment. Each item may include title, "
                            "question, priority, and evidence."
                        ),
                    },
                    "update_source": {
                        "type": "boolean",
                        "description": "Whether to update the source hypothesis status",
                        "default": True,
                    },
                    "record_decision": {
                        "type": "boolean",
                        "description": "Whether to create a decision artifact for the mutation rationale",
                        "default": True,
                    },
                },
                "required": [
                    "source_hypothesis_id",
                    "failed_assumption",
                    "interpretation",
                    "mutations",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "Execute a shell command inside the audit container. Use this to "
                "run tools (forge, slither, echidna, medusa, halmos), compile code, "
                "run tests, or inspect the environment. Commands run from /audit by default."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Working directory (default: /audit)",
                        "default": "/audit",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 600, max: 1800)",
                        "default": 600,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the web for information. Use this to find documentation "
                "about protocols and dependencies, known vulnerabilities in libraries, "
                "details about deployed contracts, flash loan provider APIs, DEX pool "
                "information, and any other context that helps you understand and "
                "exploit the target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 5)",
                        "default": 5,
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": (
                "Fetch the content of a web page. Use this to read documentation, "
                "audit reports, Etherscan contract source, or any other web resource. "
                "Returns the page content as plain text (HTML tags stripped)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default: 60)",
                        "default": 60,
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "review_finding_evidence",
            "description": (
                "Review a candidate finding before submit_finding. This checks "
                "reproduction, unprivileged assumptions, precondition provenance, "
                "production reachability, funds at risk, validation output, impact, "
                "linked campaign evidence, and route proof for composed attacks. "
                "Exploitability uncertainty, missing objective evidence, route/live "
                "gaps, probe-only evidence, and trusted-role ambiguity are warnings/"
                "status, not suppressors for a mechanically validated candidate. "
                "It records the review under "
                "/workspace/campaign/finding-reviews/."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Candidate finding title",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Candidate severity",
                    },
                    "root_cause": {
                        "type": "string",
                        "description": "Root cause and mechanism",
                    },
                    "impact": {
                        "type": "string",
                        "description": "Economic impact, capital, profit/loss, and affected funds",
                    },
                    "affected_code": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": (
                            "Specific code locations with file and lines/function. "
                            "May be empty only when evidence includes concrete "
                            "/audit/src/*.sol:line or /audit/contracts/*.sol:line refs."
                        ),
                    },
                    "reproduction_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete transaction or test steps",
                    },
                    "campaign_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Linked campaign ids: hypotheses, experiments, results, evaluations",
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Evidence paths or ids: logs, traces, comparisons, "
                            "evaluations, sequence.json artifacts, PoCs, and "
                            "source refs such as /audit/src/Vault.sol:42"
                        ),
                    },
                    "test_output": {
                        "type": "string",
                        "description": "Validation output, usually forge test output",
                    },
                    "proof_of_concept": {
                        "type": "string",
                        "description": "PoC code or path summary",
                    },
                    "validated": {
                        "type": "boolean",
                        "description": "Whether the candidate has a passing validation run",
                        "default": False,
                    },
                    "objective_evaluation": {
                        "type": "string",
                        "description": (
                            "Passing eval-NNN id or direct campaign evaluation "
                            "path. It clears proof-strength caveats only when the "
                            "artifact, comparison, links, and successful result/"
                            "experiment lineage validate."
                        ),
                    },
                    "sequence_minimization": {
                        "type": "string",
                        "description": (
                            "Sequence minimization id or path, if a reduced "
                            "variant was used to support the finding"
                        ),
                    },
                    "capital_required": {
                        "type": "string",
                        "description": "Upfront capital and flash-loan assumptions",
                    },
                    "preconditions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Material setup conditions the exploit depends on, "
                            "or an explicit statement that no special victim/"
                            "protocol state is required"
                        ),
                    },
                    "precondition_provenance": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "precondition": {"type": "string"},
                                "provenance": {
                                    "type": "string",
                                    "enum": [
                                        "attacker_controlled",
                                        "normal_protocol_flow",
                                        "observed_onchain",
                                        "user_created_measured",
                                        "synthetic_modeling_only",
                                        "incompatible_with_deployed_architecture",
                                        "unknown",
                                    ],
                                },
                                "evidence": {"type": "string"},
                            },
                        },
                        "description": (
                            "For each material precondition, classify whether "
                            "it is attacker-controlled, produced by normal "
                            "protocol flow, observed/measured live, synthetic "
                            "PoC-only setup, incompatible with deployed "
                            "architecture, or unknown"
                        ),
                    },
                    "production_reachability": {
                        "type": "string",
                        "description": (
                            "As-deployed reachability proof: deployed call path, "
                            "chain/fork binding, caller/spender/proxy identity, "
                            "sequence call_context_plan, and why the PoC path is "
                            "reachable in production"
                        ),
                    },
                    "funds_at_risk": {
                        "type": "string",
                        "description": (
                            "Measured live exposure or concrete amount/user set "
                            "at risk; zero or unknown exposure is classified as "
                            "a caveat rather than a submission blocker"
                        ),
                    },
                    "negative_controls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Baselines or falsification checks, such as wrong "
                            "spender/caller, no synthetic victim setup, paused "
                            "state, no-liquidity case, or expected failure"
                        ),
                    },
                    "trusted_role_required": {
                        "type": "boolean",
                        "description": "True if exploit requires owner/admin/governance/malicious trusted role",
                    },
                    "privileged_role_notes": {
                        "type": "string",
                        "description": "Explanation of role assumptions",
                    },
                    "known_limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Remaining caveats, blocked validation, or scope assumptions",
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to record a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [
                    "title",
                    "severity",
                    "root_cause",
                    "impact",
                    "affected_code",
                    "reproduction_steps",
                    "campaign_ids",
                    "evidence",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "review_report_quality",
            "description": (
                "Review the final report draft before submit_finding. Checks "
                "attack narrative, root cause, impact, reproduction, validation, "
                "precondition provenance, production reachability, funds at risk, "
                "negative controls, assumptions, limitations, remediation, linked "
                "evidence review, and route evidence. Exploitability uncertainty, "
                "route/live gaps, objective gaps, minimized-variant references, "
                "and presentation issues are report caveats. If affected_code is "
                "omitted, a linked ready evidence review can supply code refs. "
                "It records the review under /workspace/campaign/report-reviews/."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Report finding title",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Report severity",
                    },
                    "summary": {
                        "type": "string",
                        "description": "Short bug-bounty-ready summary",
                    },
                    "root_cause": {
                        "type": "string",
                        "description": "Precise implementation mistake and why it matters",
                    },
                    "impact": {
                        "type": "string",
                        "description": "Economic/security impact and affected funds or users",
                    },
                    "attack_path": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Ordered exploit or transaction sequence",
                    },
                    "affected_code": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Specific code locations with file and lines/functions",
                    },
                    "reproduction_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete commands or steps a triager can run",
                    },
                    "proof_of_concept": {
                        "type": "string",
                        "description": "PoC code path or concise description",
                    },
                    "validation": {
                        "type": "string",
                        "description": "Validation summary, including exact observed result",
                    },
                    "test_output": {
                        "type": "string",
                        "description": "Passing test output, usually forge test output",
                    },
                    "economic_analysis": {
                        "type": "string",
                        "description": (
                            "Capital required, profit/loss estimate, fees, "
                            "or explicit non-economic state-transition proof "
                            "and assumptions"
                        ),
                    },
                    "assumptions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Explicit exploit preconditions and environment assumptions",
                    },
                    "limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Known limitations, caveats, or 'none identified'",
                    },
                    "preconditions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Material exploit preconditions and setup assumptions",
                    },
                    "precondition_provenance": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "precondition": {"type": "string"},
                                "provenance": {
                                    "type": "string",
                                    "enum": [
                                        "attacker_controlled",
                                        "normal_protocol_flow",
                                        "observed_onchain",
                                        "user_created_measured",
                                        "synthetic_modeling_only",
                                        "incompatible_with_deployed_architecture",
                                        "unknown",
                                    ],
                                },
                                "evidence": {"type": "string"},
                            },
                        },
                        "description": (
                            "Report-ready provenance classification for each "
                            "material precondition"
                        ),
                    },
                    "production_reachability": {
                        "type": "string",
                        "description": (
                            "Deployed call path, chain/fork binding, and caller/"
                            "spender/proxy identity, including any sequence "
                            "call_context_plan caveats, proving the PoC path is "
                            "reachable as deployed"
                        ),
                    },
                    "funds_at_risk": {
                        "type": "string",
                        "description": "Measured live exposure or concrete amount/user set at risk",
                    },
                    "negative_controls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Baselines or falsification checks included in the report",
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Specific fix guidance",
                    },
                    "campaign_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Linked campaign ids",
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Evidence paths or ids referenced by the report",
                    },
                    "evidence_review": {
                        "type": "string",
                        "description": "Finding evidence review id or path from review_finding_evidence",
                    },
                    "objective_evaluation": {
                        "type": "string",
                        "description": (
                            "Passing eval-NNN id or direct campaign evaluation "
                            "path; include its id/path and executed result lineage "
                            "in campaign_ids/evidence."
                        ),
                    },
                    "sequence_minimization": {
                        "type": "string",
                        "description": (
                            "Sequence minimization id or path, if a reduced "
                            "variant supports the final report"
                        ),
                    },
                    "record_result": {
                        "type": "boolean",
                        "description": "Whether to record a campaign result artifact",
                        "default": True,
                    },
                },
                "required": [
                    "title",
                    "severity",
                    "summary",
                    "root_cause",
                    "impact",
                    "attack_path",
                    "reproduction_steps",
                    "campaign_ids",
                    "evidence",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_finding",
            "description": (
                "Submit a vulnerability finding. Call this for each distinct "
                "vulnerability you discover. Include proof-of-concept code and "
                "test results whenever possible. Medium/high/critical submissions "
                "are blocked unless evidence_review and report_review both point "
                "to ready review artifacts. Precondition provenance, production "
                "reachability, funds at risk, negative controls, route/live "
                "context, probe strength, and report polish issues are preserved "
                "as classification and caveats, not recall-cutting blockers; "
                "linked review warnings are copied into the finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Concise description of the vulnerability",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Vulnerability severity",
                    },
                    "description": {
                        "type": "string",
                        "description": "Root cause, mechanism, and exploit scenario",
                    },
                    "impact": {
                        "type": "string",
                        "description": (
                            "What an attacker can achieve, estimated economic impact. "
                            "MUST include: upfront capital required, whether a flash loan "
                            "is needed, estimated net profit in USD after gas costs."
                        ),
                    },
                    "affected_code": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "lines": {"type": "string"},
                            },
                            "required": ["file", "lines"],
                        },
                        "description": "Specific code locations",
                    },
                    "proof_of_concept": {
                        "type": "string",
                        "description": "Exploit code or test code",
                    },
                    "validated": {
                        "type": "boolean",
                        "description": "True if PoC was tested and passed",
                        "default": False,
                    },
                    "test_output": {
                        "type": "string",
                        "description": "forge test output or similar",
                    },
                    "campaign_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Related campaign artifact ids: hypotheses, "
                            "experiments, results, action spaces, evaluations."
                        ),
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Evidence file paths such as campaign logs, traces, "
                            "snapshot comparisons, evaluations, or PoC files."
                        ),
                    },
                    "reproduction_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete transaction or test steps that reproduce the issue",
                    },
                    "objective_evaluation": {
                        "type": "string",
                        "description": (
                            "Passing objective evaluation id or path, if used to "
                            "quantify impact. The submission gate reloads it and "
                            "checks comparison, review, and executed-run lineage."
                        ),
                    },
                    "preconditions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Material exploit preconditions and setup assumptions",
                    },
                    "precondition_provenance": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "precondition": {"type": "string"},
                                "provenance": {
                                    "type": "string",
                                    "enum": [
                                        "attacker_controlled",
                                        "normal_protocol_flow",
                                        "observed_onchain",
                                        "user_created_measured",
                                        "synthetic_modeling_only",
                                        "incompatible_with_deployed_architecture",
                                        "unknown",
                                    ],
                                },
                                "evidence": {"type": "string"},
                            },
                        },
                        "description": (
                            "As-deployed provenance classification for every "
                            "material precondition"
                        ),
                    },
                    "production_reachability": {
                        "type": "string",
                        "description": (
                            "Deployed call path, chain/fork binding, and caller/"
                            "spender/proxy identity proving production reachability"
                        ),
                    },
                    "funds_at_risk": {
                        "type": "string",
                        "description": "Measured live exposure or concrete amount/user set at risk",
                    },
                    "negative_controls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Baselines or falsification checks",
                    },
                    "evidence_review": {
                        "type": "string",
                        "description": (
                            "Related finding evidence review id or path from "
                            "review_finding_evidence"
                        ),
                    },
                    "report_review": {
                        "type": "string",
                        "description": (
                            "Related report quality review id or path from "
                            "review_report_quality"
                        ),
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Suggested fix",
                    },
                },
                "required": ["title", "severity", "description", "impact", "affected_code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_onchain_tx",
            "description": (
                "Fetch the full call trace of a historical transaction via Alchemy "
                "debug_traceTransaction (callTracer or prestateTracer)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tx_hash": {"type": "string", "description": "0x 32-byte transaction hash."},
                    "tracer": {
                        "type": "string",
                        "description": "callTracer (default) or prestateTracer.",
                        "default": "callTracer",
                    },
                    "network": {
                        "type": "string",
                        "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred.",
                    },
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["tx_hash"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "simulate_call",
            "description": (
                "Cheaply simulate one call at a block via Alchemy debug_traceCall "
                "(callTracer, optional state overrides). ~40 CU."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Target contract address (0x, 20 bytes)."},
                    "data": {"type": "string", "description": "0x calldata (default 0x)."},
                    "from": {"type": "string", "description": "Optional caller address."},
                    "value": {"type": "string", "description": "Optional 0x wei value."},
                    "gas": {"type": "string", "description": "Optional 0x gas limit."},
                    "block": {"type": "string", "description": "Block tag/number (default latest)."},
                    "tracer": {"type": "string", "description": "callTracer (default) or prestateTracer."},
                    "state_overrides": {
                        "type": "object",
                        "description": "Optional eth state overrides keyed by address (stateDiff/balance/code).",
                    },
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["to"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "state_diff",
            "description": (
                "Replay a historical tx via Alchemy trace_replayTransaction and summarize "
                "exact per-address storage/balance/nonce diffs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tx_hash": {"type": "string", "description": "0x 32-byte transaction hash."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["tx_hash"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_callers",
            "description": (
                "List callers and selectors hitting an address over a bounded block range "
                "via Alchemy trace_filter (attack-surface mapping)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address to filter (0x, 20 bytes)."},
                    "from_block": {"type": "string", "description": "Required start block (tag/hex/decimal)."},
                    "to_block": {"type": "string", "description": "End block (default latest)."},
                    "direction": {"type": "string", "description": "'to' (callers of address, default) or 'from' (calls it makes)."},
                    "count": {"type": "integer", "description": "Max traces (1-1000, default 100).", "default": 100},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["address", "from_block"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_asset_transfers",
            "description": (
                "Historical fund flows to/from an address via Alchemy getAssetTransfers; "
                "finds counterparties and transitive deployed targets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address whose transfers to fetch (use with direction)."},
                    "direction": {"type": "string", "description": "in, out, or both (default both)."},
                    "from_address": {"type": "string", "description": "Explicit sender filter (overrides address)."},
                    "to_address": {"type": "string", "description": "Explicit recipient filter (overrides address)."},
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "external, internal, erc20, erc721, erc1155, specialnft.",
                    },
                    "contract_addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Restrict to these token contracts.",
                    },
                    "from_block": {"type": "string", "description": "Start block (default 0x0)."},
                    "to_block": {"type": "string", "description": "End block (default latest)."},
                    "max_count": {"type": "integer", "description": "Max transfers per side (1-1000, default 100).", "default": 100},
                    "order": {"type": "string", "description": "asc or desc (default desc)."},
                    "page_key": {"type": "string", "description": "Pagination key from a prior call."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_token_prices",
            "description": (
                "Current USD prices for token contract addresses via the Alchemy Prices "
                "API; feed results into the estimate_* economics tools."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Token contract addresses (resolved on the network field).",
                    },
                    "tokens": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "network": {"type": "string"},
                                "address": {"type": "string"},
                            },
                        },
                        "description": "Explicit [{network, address}] pairs (overrides addresses).",
                    },
                    "network": {"type": "string", "description": "Optional shared chain for addresses[] (subdomain/name/id); per-token networks override; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional shared chain id for addresses[] (e.g. 8453); alternative to network."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_token_info",
            "description": "Token metadata (name/symbol/decimals/logo) for a contract via Alchemy getTokenMetadata.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Token contract address (0x, 20 bytes)."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "simulate_asset_changes",
            "description": (
                "Simulate a tx and decode net asset changes (who gains/loses what) via "
                "Alchemy simulateAssetChanges. ~2500 CU."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Sender address (0x, 20 bytes)."},
                    "to": {"type": "string", "description": "Target address (0x, 20 bytes)."},
                    "value": {"type": "string", "description": "Optional 0x wei value (default 0x0)."},
                    "data": {"type": "string", "description": "Optional 0x calldata (default 0x)."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["from", "to"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "simulate_execution",
            "description": (
                "Simulate a tx and return its decoded nested execution trace via Alchemy "
                "simulateExecution. ~2500 CU."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Sender address (0x, 20 bytes)."},
                    "to": {"type": "string", "description": "Target address (0x, 20 bytes)."},
                    "value": {"type": "string", "description": "Optional 0x wei value (default 0x0)."},
                    "data": {"type": "string", "description": "Optional 0x calldata (default 0x)."},
                    "block": {"type": "string", "description": "Block tag/number (default latest)."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["from", "to"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "simulate_sequence",
            "description": (
                "Simulate an ordered sequence of txs (bundle) for asset changes or execution "
                "traces via Alchemy bundle simulation. ~2500 CU/tx."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "transactions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from": {"type": "string"},
                                "to": {"type": "string"},
                                "value": {"type": "string"},
                                "data": {"type": "string"},
                            },
                        },
                        "description": "Ordered txs, each {from, to, value, data}.",
                    },
                    "mode": {"type": "string", "description": "asset_changes (default) or execution."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                },
                "required": ["transactions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_contract_source",
            "description": (
                "Fetch a deployed contract's verified Solidity source, ABI, and "
                "proxy->implementation via Etherscan; auto-follows proxies."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Deployed contract address (0x, 20 bytes)."},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                    "follow_proxy": {"type": "boolean", "description": "If a proxy, also fetch the implementation's source (default true).", "default": True},
                },
                "required": ["address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "observed_tx_miner",
            "description": (
                "Find and summarize representative successful on-chain transactions for a "
                "contract/function selector, including decoded argument shapes, actors, "
                "transfers, preconditions, and replay hints. Mines real calls via Alchemy "
                "trace_filter/traces/transfers to ground setup, calldata, and fork state so "
                "experiments avoid calldata/setup false negatives. Corroboration/context only "
                "(never a finding by itself); degrades cleanly with no key or matching txs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short miner run title."},
                    "address": {"type": "string", "description": "Deployed contract to mine calls to (0x, 20 bytes)."},
                    "function": {"type": "string", "description": "Target function: a name (needs abi), a full signature name(uint256,address), or a 4-byte selector."},
                    "selector": {"type": "string", "description": "Target 4-byte selector (0x + 8 hex); overrides function."},
                    "abi": {
                        "type": "array",
                        "items": {"type": ["object", "string"]},
                        "description": "Optional ABI (entry objects or signature strings) to match selectors and decode args.",
                    },
                    "action_space": {"type": "string", "description": "Optional action-space id/path recorded for correlation."},
                    "from_block": {"description": "Start block (tag/hex/decimal). Default: a recent window below the chain head."},
                    "to_block": {"description": "End block (tag/hex/decimal, default latest)."},
                    "max_transactions": {"type": "integer", "description": "Max sample transactions (1-20, default 5).", "default": 5},
                    "include_traces": {"type": "boolean", "description": "Enrich each sample with its call trace for precondition hints (default true).", "default": True},
                    "include_transfers": {"type": "boolean", "description": "Attach asset-transfer context per sample (default true).", "default": True},
                    "network": {"type": "string", "description": "Optional chain (subdomain/name/id). If omitted, inferred from fork/registry/default; else chain_not_inferred."},
                    "chain_id": {"type": "integer", "description": "Optional target chain id (e.g. 8453); alternative to network."},
                    "record_result": {"type": "boolean", "description": "Write the full result under /workspace/campaign/observed-txs (default true).", "default": True},
                },
                "required": ["address"],
            },
        },
    },
]


# Model-facing workflow hops retired in favor of attack_search and concrete
# sequence composition. Keep the names as a regression contract; no schemas or
# toolset memberships exist for them.
RETIRED_MODEL_TOOLS = frozenset({
    "create_experiment",
    "plan_attack_campaign",
    "prepare_fork_exploit_workbench",
    "review_attack_surface_coverage",
    "review_campaign_progress",
})


TOOLSET_DEFINITIONS: dict[str, tuple[str, ...]] = {
    "core": (
        "inspect_scope",
        "list_files",
        "read_file",
        "search_code",
        "source_slice",
        "write_file",
        "run_command",
        "web_search",
        "fetch_url",
        "read_campaign",
        "update_campaign",
        "build_campaign_brief",
        "attack_search",
        REQUEST_TOOLSET_NAME,
    ),
    "map": (
        "map_protocol_graph",
        "map_action_space",
        "extract_state_transition_model",
        "map_live_reachability",
        "inventory_live_targets",
        "build_attack_graph",
        "record_fork_context",
        "estimate_amm_economics",
        "estimate_flash_loan",
        "estimate_lending_health",
        "trace_onchain_tx",
        "enumerate_callers",
        "get_asset_transfers",
        "get_token_prices",
        "get_token_info",
        "get_contract_source",
        "observed_tx_miner",
    ),
    "experiment": (
        "compose_sequence_experiment",
        "complete_sequence_experiment",
        "compose_invariant_harness",
        "synthesize_args",
        "run_experiment",
        "run_sequence_minimization",
        "run_campaign_fuzz",
        "diagnose_build",
        "repair_experiment",
        "extract_call_sequence",
        "mutate_hypothesis",
    ),
    "evidence": (
        "snapshot_state",
        "compare_snapshots",
        "evaluate_objective",
        "summarize_trace",
        "simulate_call",
        "state_diff",
        "simulate_asset_changes",
        "simulate_execution",
        "simulate_sequence",
    ),
    "report": (
        "review_finding_evidence",
        "review_report_quality",
        "submit_finding",
    ),
}
DEFAULT_TOOLSETS = frozenset({"core"})
REQUESTABLE_TOOLSETS = tuple(name for name in TOOLSET_DEFINITIONS if name != "core")
TOOL_BY_NAME = {
    tool["function"]["name"]: tool
    for tool in TOOLS
    if isinstance(tool, dict) and isinstance(tool.get("function"), dict)
}
# Parameter-level descriptions stay compact; tool-level descriptions get a
# generous budget. A tool's own description is the model's primary signal for
# choosing among the ~50-tool surface, so clipping it mid-sentence costs far
# more (wrong-tool / mis-arg turns) than the handful of tokens it saves. The
# full TOOLS schema is already what _TOOLS_TOKEN_OVERHEAD reserves against, so
# widening the on-the-wire description does not change the context budget.
_SCHEMA_DESCRIPTION_LIMIT = 120
_TOOL_DESCRIPTION_LIMIT = 600
_PARAMETER_SUBTREE_KEYS = ("parameters", "properties", "items")
# Tools whose description is a bounded, auto-derived navigation map (not free
# prose) and is therefore never clipped — clipping it would hide part of the map.
_NAVIGATION_TOOL_NAMES = frozenset({REQUEST_TOOLSET_NAME})


def _compact_schema_text(value: str, *, limit: int = _SCHEMA_DESCRIPTION_LIMIT) -> str:
    compact = " ".join(str(value).split())
    if len(compact) <= limit:
        return compact
    return compact[:limit - 3].rstrip() + "..."


def _compact_tool_schema(value, *, in_parameters: bool = False):
    if isinstance(value, dict):
        unclipped_description = (
            not in_parameters and value.get("name") in _NAVIGATION_TOOL_NAMES
        )
        compacted = {}
        for key, item in value.items():
            if key == "description" and isinstance(item, str):
                if unclipped_description:
                    compacted[key] = " ".join(item.split())
                else:
                    limit = (
                        _SCHEMA_DESCRIPTION_LIMIT if in_parameters
                        else _TOOL_DESCRIPTION_LIMIT
                    )
                    compacted[key] = _compact_schema_text(item, limit=limit)
            else:
                compacted[key] = _compact_tool_schema(
                    item,
                    in_parameters=in_parameters or key in _PARAMETER_SUBTREE_KEYS,
                )
        return compacted
    if isinstance(value, list):
        return [_compact_tool_schema(item, in_parameters=in_parameters) for item in value]
    return value


def expand_toolsets(toolsets: set[str] | frozenset[str] | tuple[str, ...]) -> set[str]:
    requested = {str(item).strip().lower() for item in toolsets if str(item).strip()}
    if "all" in requested:
        return set(TOOLSET_DEFINITIONS)
    expanded = {"core"}
    expanded.update(name for name in requested if name in TOOLSET_DEFINITIONS)
    return expanded


def tool_names_for_toolsets(toolsets: set[str] | frozenset[str] | tuple[str, ...]) -> list[str]:
    names = []
    seen = set()
    for toolset in ("core", "map", "experiment", "evidence", "report"):
        if toolset not in expand_toolsets(toolsets):
            continue
        for name in TOOLSET_DEFINITIONS[toolset]:
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
    return names


def tools_for_toolsets(toolsets: set[str] | frozenset[str] | tuple[str, ...]) -> list[dict]:
    names = set(tool_names_for_toolsets(toolsets))
    return [
        _compact_tool_schema(tool) for tool in TOOLS
        if tool.get("function", {}).get("name") in names
    ]


# Reverse index: tool name -> the toolsets that expose it. Derived from
# TOOLSET_DEFINITIONS at import time so it cannot drift. Every specialized tool
# lives in exactly one toolset (pinned by test_every_tool_in_exactly_one_toolset),
# but a set is kept per name so a future multi-toolset member would resolve to all
# of its owners rather than silently picking one.
_TOOLSETS_BY_TOOL_NAME: dict[str, frozenset[str]] = {
    name: frozenset(
        toolset for toolset, members in TOOLSET_DEFINITIONS.items()
        if name in members
    )
    for name in TOOL_BY_NAME
}


def toolsets_for_tool_names(
    tool_names: set[str] | frozenset[str] | tuple[str, ...] | list[str],
) -> set[str]:
    """Map tool names to the minimal specialized toolsets that expose them.

    Returns the set of toolset names whose activation makes every resolvable name
    in ``tool_names`` visible. A name already in ``core`` (always visible) or one
    that is not a known tool contributes nothing, so the result is the smallest
    specialized cover needed for demand-driven activation — empty when every name
    is core/unknown.
    """
    needed: set[str] = set()
    for raw in tool_names:
        owners = _TOOLSETS_BY_TOOL_NAME.get(str(raw).strip())
        if not owners or "core" in owners:
            # Unknown tool, or already always-visible via core — no activation.
            continue
        needed.update(owners)
    return needed


def _toolset_overview_text() -> str:
    """A compact `toolset -> members` map derived from TOOLSET_DEFINITIONS."""
    return " | ".join(
        f"{toolset} -> {', '.join(TOOLSET_DEFINITIONS[toolset])}"
        for toolset in REQUESTABLE_TOOLSETS
    )


def _augment_request_toolset_description() -> None:
    """Fold the live toolset map + activation rules into request_toolset.

    The model only sees a tool's description before it decides to call it, and
    the toolset partition is not obvious (e.g. simulate_* is in `evidence`,
    trace_onchain_tx/get_* are in `map`, mutate_hypothesis is in `experiment`).
    Without this, the model guesses the wrong toolset and burns a full turn on a
    reveal. Derived from TOOLSET_DEFINITIONS at import time so it cannot drift.
    """
    tool = TOOL_BY_NAME.get(REQUEST_TOOLSET_NAME)
    if not tool:
        return
    function = tool["function"]
    description = function.get("description", "")
    if "Tools by toolset" in description:
        return
    function["description"] = (
        description.rstrip()
        + " Requested toolsets become visible on the NEXT turn, not the current"
        + " one. Prefer the narrowest toolset the current"
        + " attack_search.next_action requires. Request 'all' only for late"
        + " wrap-up, debugging tool visibility, or when a controller action"
        + " explicitly needs multiple specialized toolsets. Tools by toolset — "
        + _toolset_overview_text()
        + "."
    )


_augment_request_toolset_description()
