"""Campaign state model: load/save, ids, entry helpers, derived summaries,
and the compact-brief/coverage/progress helpers that depend only on the state
file.

Extracted from tools.py as a foundation leaf: it imports only AuditContainer +
stdlib and references no sibling module, so it breaks the cross-module cycles
that route through campaign state. Trace writing and the cross-controller
progress/brief orchestrators stay in tools.py (they reach into the controller
and experiments).
"""
import json
import posixpath
import re
from datetime import datetime, timezone

from reentbotpro.docker import AuditContainer


_CAMPAIGN_STATE_PATH = "/workspace/campaign/state.json"


_CAMPAIGN_TRACE_PATH = "/workspace/campaign/trace.jsonl"


_CAMPAIGN_TRACE_MAX_EVENTS = 600


_CAMPAIGN_SECTIONS = (
    "protocol_model",
    "trust_boundary",
    "value_flow",
    "invariant",
    "hypothesis",
    "experiment",
    "result",
    "decision",
    "open_question",
)


_CAMPAIGN_ID_PREFIXES = {
    "protocol_model": "pm",
    "trust_boundary": "tb",
    "value_flow": "vf",
    "invariant": "inv",
    "hypothesis": "hyp",
    "experiment": "exp",
    "result": "res",
    "decision": "dec",
    "open_question": "oq",
    "snapshot": "snap",
    "comparison": "cmp",
    "trace": "trace",
    "call_sequence": "seq",
    "action_space": "as",
    "source_slice": "ss",
    "evaluation": "eval",
    "fork_context": "fc",
    "economics": "econ",
    "flash_loan": "flash",
    "mutation": "mut",
    "finding_review": "fr",
    "report_review": "rr",
    "protocol_graph": "pg",
    "campaign_brief": "brief",
    "fuzz_run": "fuzz",
    "sequence_minimization": "min",
    "live_reachability": "lr",
    "live_inventory": "linv",
    "attack_graph": "ag",
    "arg_synthesis": "arg",
    "build_diagnostic": "bdiag",
    "observed_tx": "otx",
    "state_transition_model": "stm",
    "chain_registry": "chainreg",
}


# Read-only recognition for artifacts created before the model-facing workflow
# consolidation. These prefixes are deliberately absent from allocation above.
_LEGACY_CAMPAIGN_ID_PREFIXES = {
    "progress_review": "prg",
    "coverage_review": "cov",
    "campaign_plan": "plan",
    "fork_workbench": "fw",
}


_CAMPAIGN_STATUSES = {
    "open",
    "testing",
    "observed",
    "validated",
    "rejected",
    "blocked",
    "inconclusive",
    "superseded",
}


_CAMPAIGN_PRIORITIES = {"critical", "high", "medium", "low"}


_HYPOTHESIS_CARD_FIELDS = (
    "attacker_control",
    "state_path",
    "invariant_at_risk",
    "impact_sink",
    "material_preconditions",
    "falsifier",
    "objective",
)


_FINDING_REVIEW_DIR = "/workspace/campaign/finding-reviews"


def _finding_review_reference_id(value: object) -> str:
    """Return the canonical id for an exact finding-review reference.

    Review ids and their absolute artifact paths are two spellings of the same
    identity.  Other paths (including nested paths) and generic campaign text
    are deliberately not treated as review references.
    """
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if re.fullmatch(r"fr-\d{3,}", text):
        return text
    if not text.startswith("/"):
        return ""
    normalized = posixpath.normpath(text)
    if posixpath.dirname(normalized) != _FINDING_REVIEW_DIR:
        return ""
    name = posixpath.basename(normalized)
    if not name.endswith(".json"):
        return ""
    review_id = name[:-5]
    return review_id if re.fullmatch(r"fr-\d{3,}", review_id) else ""


def _normalize_hypothesis_card(value: object) -> dict:
    if value in (None, {}):
        return {}
    if not isinstance(value, dict):
        raise ValueError("hypothesis_card must be an object")
    card = {}
    for field in _HYPOTHESIS_CARD_FIELDS:
        raw = value.get(field)
        if field in {"state_path", "material_preconditions"}:
            if raw is None:
                continue
            if not isinstance(raw, list):
                raise ValueError(f"hypothesis_card.{field} must be an array")
            if any(
                not isinstance(item, str) or not item.strip()
                for item in raw
            ):
                raise ValueError(
                    f"hypothesis_card.{field} items must be nonempty strings"
                )
            items = [item.strip() for item in raw]
            if items:
                card[field] = items[:12]
            continue
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError(f"hypothesis_card.{field} must be a string")
        text = raw.strip()
        if text:
            card[field] = text
    return card


_EXPERIMENT_RUN_KINDS = {
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
}


# partial_probe is setup-grade: a partial probe exercises preconditions and the
# executable subset of a not-yet-materializable sequence. It guides mutation but
# never satisfies an exploit experiment or proves impact, so it lives with the
# other setup kinds and the evidence gates refuse to accept it as PoC proof.
_EXPERIMENT_SETUP_RUN_KINDS = {
    "build",
    "static_analysis",
    "inventory",
    "setup_probe",
    "partial_probe",
    "live_config_probe",
}


_EXPERIMENT_OBJECTIVE_RUN_KINDS = {"harness_run", "poc_run", "fuzz_run"}


_TRACE_ALLOWED_PREFIXES = (
    "/workspace/campaign/results/",
    "/workspace/campaign/fuzz-runs/",
    "/workspace/experiments/",
    "/audit/",
    "/output/",
)


_TRACE_MAX_BYTES = 300_000


_FUZZ_FAILURE_MARKERS = (
    "Failing tests",
    "Failed invariant",
    "counterexample",
    "falsified",
    "Falsifying example",
    "invariant broken",
    "Invariant violation",
    "FAIL. Reason",
    "[FAIL",
    "Suite result: FAILED",
    "Test result: FAILED",
    "minimal reproduction",
    "Call sequence",
    "Sequence:",
    "calldata=",
    "panic:",
)


_ACTION_SOURCE_ALLOWED_PREFIXES = ("/audit/", "/workspace/experiments/")


_LIVE_INVENTORY_MAX_TARGETS = 50


_ACTION_SOURCE_PRUNE_PARTS = (
    "/.git/",
    "/.context/",
    "/node_modules/",
    "/lib/",
    "/out/",
    "/artifacts/",
    "/cache/",
    "/coverage/",
    "/broadcast/",
    "/findings/",
    "/tmp/",
    "/typechain/",
    "/typechain-types/",
)


_TOP_LEVEL_ARTIFACT_DIRS = {
    ".git",
    ".context",
    "artifacts",
    "broadcast",
    "build",
    "cache",
    "coverage",
    "dist",
    "findings",
    "logs",
    "minitest",
    "node_modules",
    "out",
    "poc-tests",
    "ssrtest",
    "tmp",
    "typechain",
    "typechain-types",
}


_ACTION_TEST_PARTS = ("/test/", "/tests/", "/script/", "/scripts/")


_ACTION_TEST_SUFFIXES = (".t.sol", ".s.sol")


_ACTION_MAX_FILE_CHARS = 400_000


_COVERAGE_EVIDENCE_PREFIXES = (
    "/workspace/campaign/",
    "/workspace/experiments/",
)


_COVERAGE_META_EVIDENCE_PREFIXES = (
    "/workspace/campaign/protocol-graphs/",
    "/workspace/campaign/action-spaces/",
    "/workspace/campaign/attack-graphs/",
    "/workspace/campaign/attack-search/",
    "/workspace/campaign/branch-dossiers/",
    "/workspace/campaign/state-transition-models/",
    "/workspace/campaign/source-slices/",
    "/workspace/campaign/fork-contexts/",
    "/workspace/campaign/live-reachability/",
    "/workspace/campaign/live-inventory/",
    "/workspace/campaign/finding-reviews/",
    "/workspace/campaign/report-reviews/",
    "/workspace/campaign/brief.json",
    "/workspace/campaign/brief.md",
    # Legacy planning artifacts remain readable for state migration, but they
    # never establish action coverage and are not worth loading on every sync.
    "/workspace/campaign/coverage-reviews/",
    "/workspace/campaign/progress-reviews/",
    "/workspace/campaign/fork-workbenches/",
)


_COVERAGE_EVIDENCE_MAX_FILES = 75


_COVERAGE_EVIDENCE_MAX_CHARS = 20_000


def _empty_campaign_state() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1,
        "created_at": now,
        "updated_at": now,
        "path": _CAMPAIGN_STATE_PATH,
        "process": [
            "model the protocol and value flows",
            "state assumptions and invariants",
            "generate exploit hypotheses",
            "design and run experiments",
            "interpret results and mutate hypotheses",
            "submit only evidence-backed findings",
        ],
        "counters": {section: 0 for section in _CAMPAIGN_SECTIONS},
        "sections": {section: [] for section in _CAMPAIGN_SECTIONS},
    }


async def _load_campaign_state(container: AuditContainer) -> dict:
    try:
        raw = await container.read_file(_CAMPAIGN_STATE_PATH)
    except FileNotFoundError:
        return _empty_campaign_state()

    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        state = _empty_campaign_state()
        state["recovered_from_invalid_json"] = True
        return state

    state.setdefault("schema_version", 1)
    state.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    state.setdefault("path", _CAMPAIGN_STATE_PATH)
    state.setdefault("process", _empty_campaign_state()["process"])
    state.setdefault("counters", {})
    state.setdefault("sections", {})
    for section in _CAMPAIGN_SECTIONS:
        state["counters"].setdefault(section, 0)
        state["sections"].setdefault(section, [])
    return state


async def _save_campaign_state(container: AuditContainer, state: dict) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    content = json.dumps(state, indent=2, sort_keys=True)
    await container.write_file(_CAMPAIGN_STATE_PATH, content + "\n")


def _next_campaign_id(state: dict, section: str) -> str:
    state.setdefault("counters", {})
    state["counters"].setdefault(section, 0)
    state["counters"][section] = int(state["counters"].get(section, 0)) + 1
    prefix = _CAMPAIGN_ID_PREFIXES[section]
    return f"{prefix}-{state['counters'][section]:03d}"


def _summarize_campaign_state(state: dict, section: str = "all") -> str:
    if section != "all":
        entries = state["sections"].get(section)
        if entries is None:
            return f"Error: unknown campaign section '{section}'"
        payload = {
            "path": _CAMPAIGN_STATE_PATH,
            "section": section,
            "updated_at": state.get("updated_at"),
            "entries": entries,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    counts = {
        name: len(state["sections"].get(name, []))
        for name in _CAMPAIGN_SECTIONS
    }
    active = []
    for name in ("hypothesis", "experiment", "open_question"):
        for entry in state["sections"].get(name, []):
            status = entry.get("status", "open")
            if status in ("open", "testing", "blocked"):
                active.append({
                    "id": entry.get("id"),
                    "section": name,
                    "title": entry.get("title"),
                    "status": status,
                    "priority": entry.get("priority"),
                })

    payload = {
        "path": _CAMPAIGN_STATE_PATH,
        "updated_at": state.get("updated_at"),
        "counts": counts,
        "active_work": active[-20:],
        "sections": state["sections"],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


async def _read_campaign(container: AuditContainer, args: dict) -> str:
    section = args.get("section", "all")
    if section != "all" and section not in _CAMPAIGN_SECTIONS:
        return f"Error: unknown campaign section '{section}'"

    state = await _load_campaign_state(container)
    if not state["sections"].get("protocol_model") and section == "all":
        await _save_campaign_state(container, state)
        return (
            "No campaign artifacts have been recorded yet. Initialized empty "
            f"campaign state at {_CAMPAIGN_STATE_PATH}.\n\n"
            + _summarize_campaign_state(state, section)
        )
    return _summarize_campaign_state(state, section)


async def _update_campaign(container: AuditContainer, args: dict) -> str:
    section = args.get("section", "")
    if section not in _CAMPAIGN_SECTIONS:
        return f"Error: unknown campaign section '{section}'"

    action = args.get("action", "add")
    if action not in ("add", "update"):
        return "Error: action must be 'add' or 'update'"

    title = args.get("title", "").strip()
    content = args.get("content", "").strip()
    if not title:
        return "Error: 'title' is required"
    if not content:
        return "Error: 'content' is required"

    state = await _load_campaign_state(container)
    now = datetime.now(timezone.utc).isoformat()
    evidence = args.get("evidence") or []
    related_ids = args.get("related_ids") or []
    action_keys = args.get("action_keys")
    coverage_keys = args.get("coverage_keys")
    if not isinstance(evidence, list):
        return "Error: evidence must be a list of strings"
    if any(not isinstance(item, str) for item in evidence):
        return "Error: evidence must be a list of strings"
    if not isinstance(related_ids, list):
        return "Error: related_ids must be a list of strings"
    if action_keys is not None and not isinstance(action_keys, list):
        return "Error: action_keys must be a list of strings"
    if coverage_keys is not None and not isinstance(coverage_keys, list):
        return "Error: coverage_keys must be a list of strings"
    if isinstance(action_keys, list) and any(
        not isinstance(item, str) for item in action_keys
    ):
        return "Error: action_keys must be a list of strings"
    if isinstance(coverage_keys, list) and any(
        not isinstance(item, str) for item in coverage_keys
    ):
        return "Error: coverage_keys must be a list of strings"
    status = args.get("status", "open")
    if status not in _CAMPAIGN_STATUSES:
        return f"Error: unknown campaign status '{status}'"
    priority = args.get("priority")
    if priority is not None and priority not in _CAMPAIGN_PRIORITIES:
        return f"Error: unknown campaign priority '{priority}'"

    try:
        hypothesis_card = (
            _normalize_hypothesis_card(args.get("hypothesis_card"))
            if section == "hypothesis" and "hypothesis_card" in args
            else None
        )
    except ValueError as exc:
        return f"Error: {exc}"

    payload = {
        "title": title,
        "content": content,
        "status": status,
        "priority": priority,
        "evidence": [item.strip() for item in evidence if item.strip()],
        "related_ids": [str(item) for item in related_ids],
        "updated_at": now,
    }
    if hypothesis_card is not None:
        payload["hypothesis_card"] = hypothesis_card
    if action_keys is not None:
        payload["action_keys"] = [
            str(item).strip() for item in action_keys if str(item).strip()
        ]
    if coverage_keys is not None:
        payload["coverage_keys"] = [
            str(item).strip() for item in coverage_keys if str(item).strip()
        ]

    if action == "add":
        artifact_id = _next_campaign_id(state, section)
        entry = {
            "id": artifact_id,
            "created_at": now,
            **payload,
        }
        state["sections"][section].append(entry)
        await _save_campaign_state(container, state)
        return (
            f"Added campaign artifact {artifact_id} in section "
            f"'{section}': {title}"
        )

    artifact_id = args.get("id", "").strip()
    if not artifact_id:
        return "Error: 'id' is required when action=update"

    for entry in state["sections"][section]:
        if entry.get("id") == artifact_id:
            entry.update(payload)
            await _save_campaign_state(container, state)
            return (
                f"Updated campaign artifact {artifact_id} in section "
                f"'{section}': {title}"
            )

    return f"Error: no artifact with id '{artifact_id}' in section '{section}'"


def _entry_related_ids(entry: dict) -> list[str]:
    return [str(item) for item in entry.get("related_ids") or []]


def _entry_evidence(entry: dict) -> list[str]:
    return [str(item) for item in entry.get("evidence") or []]


def _entry_references_id(entry: dict, artifact_id: str) -> bool:
    if artifact_id in _entry_related_ids(entry):
        return True
    haystack = "\n".join([
        str(entry.get("title") or ""),
        str(entry.get("content") or ""),
        *(_entry_evidence(entry)),
    ])
    return artifact_id in haystack


def _entries_referencing(
    state: dict,
    section: str,
    artifact_id: str,
) -> list[dict]:
    return [
        entry for entry in state["sections"].get(section, [])
        if _entry_references_id(entry, artifact_id)
    ]


def _entry_summary(entry: dict, *, section: str | None = None) -> dict:
    summary = {
        "id": entry.get("id"),
        "title": entry.get("title"),
        "status": entry.get("status"),
        "priority": entry.get("priority"),
    }
    if section:
        summary["section"] = section
    return summary


async def _load_campaign_json_if_exists(
    container: AuditContainer,
    path: str,
) -> dict | None:
    if not path.startswith("/workspace/campaign/"):
        return None
    try:
        raw = await container.read_file(posixpath.normpath(path))
    except FileNotFoundError:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _progress_evidence_paths(state: dict, prefix: str) -> list[str]:
    paths = []
    seen = set()
    for entry in state["sections"].get("result", []):
        for evidence in _entry_evidence(entry):
            if evidence.startswith(prefix) and evidence not in seen:
                seen.add(evidence)
                paths.append(evidence)
    return paths


async def _progress_evaluations(container: AuditContainer, state: dict) -> list[dict]:
    evaluations = []
    for path in _progress_evidence_paths(
        state,
        "/workspace/campaign/evaluations/",
    ):
        payload = await _load_campaign_json_if_exists(container, path)
        if not payload:
            continue
        summary = payload.get("summary") or {}
        failed = int(summary.get("failed", 0) or 0)
        unmatched = int(summary.get("unmatched", 0) or 0)
        passed = int(summary.get("passed", 0) or 0)
        objectives = int(summary.get("objectives", 0) or 0)
        if failed or unmatched or (objectives and passed == 0):
            evaluations.append({
                "id": payload.get("id"),
                "title": payload.get("title"),
                "path": path,
                "summary": summary,
                "related_ids": payload.get("related_ids") or [],
                "suggested_action": "interpret the failed objective and call mutate_hypothesis or record a rejection decision",
            })
    return evaluations


async def _progress_ready_reviews(
    container: AuditContainer,
    state: dict,
    *,
    prefix: str,
    kind: str,
) -> list[dict]:
    reviews = []
    for path in _progress_evidence_paths(state, prefix):
        payload = await _load_campaign_json_if_exists(container, path)
        if not payload or not payload.get("ready"):
            continue
        candidate = payload.get("candidate") or {}
        if not isinstance(candidate, dict):
            candidate = {}
        reviews.append({
            "id": payload.get("id"),
            "kind": kind,
            "title": payload.get("title"),
            "severity": payload.get("severity"),
            "path": path,
            "campaign_ids": [
                str(item)
                for item in candidate.get("campaign_ids") or []
                if str(item).strip()
            ],
            "evidence_review_id": _finding_review_reference_id(
                candidate.get("evidence_review")
            ),
        })
    return reviews


def _review_route_blocking_gaps(payload: dict) -> list[str]:
    gaps = [
        str(item)
        for item in payload.get("blocking_gaps") or []
        if str(item).strip()
    ]
    if not gaps:
        return []
    route_kinds = {
        str(route.get("kind") or "").lower()
        for summary in payload.get("route_compositions") or []
        if isinstance(summary, dict)
        for route in summary.get("routes") or []
        if isinstance(route, dict)
    }
    markers = (
        "route composition",
        "route evidence",
        "amm/oracle",
        "flash",
        "liquidation",
        "unwind",
        "repayment",
    )
    route_gaps = []
    for gap in gaps:
        lowered = gap.lower()
        if any(marker in lowered for marker in markers) or any(
            kind and kind in lowered for kind in route_kinds
        ):
            route_gaps.append(gap)
    return route_gaps


async def _progress_blocked_reviews(
    container: AuditContainer,
    state: dict,
    *,
    prefix: str,
    kind: str,
) -> list[dict]:
    reviews = []
    for path in _progress_evidence_paths(state, prefix):
        payload = await _load_campaign_json_if_exists(container, path)
        if not payload or payload.get("ready"):
            continue
        route_gaps = _review_route_blocking_gaps(payload)
        if not route_gaps:
            continue
        reviews.append({
            "id": payload.get("id"),
            "kind": kind,
            "title": payload.get("title"),
            "severity": payload.get("severity"),
            "path": path,
            "blocking_gaps": payload.get("blocking_gaps") or [],
            "route_blocking_gaps": route_gaps,
            "candidate": payload.get("candidate") or {},
            "route_compositions": payload.get("route_compositions") or [],
            "sequence_minimizations": payload.get("sequence_minimizations") or [],
        })
    return reviews




async def _progress_candidate_fuzz_runs(
    container: AuditContainer,
    state: dict,
) -> list[dict]:
    candidates = []
    for path in _progress_evidence_paths(
        state,
        "/workspace/campaign/fuzz-runs/",
    ):
        payload = await _load_campaign_json_if_exists(container, path)
        if not payload:
            continue
        summary = payload.get("summary") or {}
        if not summary.get("candidate_failure"):
            continue
        fuzz_id = str(payload.get("id") or "")
        processed = False
        if fuzz_id:
            for result in _entries_referencing(state, "result", fuzz_id):
                evidence = _entry_evidence(result)
                if any(
                    item.startswith((
                        "/workspace/campaign/traces/",
                        "/workspace/campaign/sequences/",
                        "/workspace/campaign/evaluations/",
                        "/workspace/campaign/comparisons/",
                    ))
                    for item in evidence
                ):
                    processed = True
                    break
        if processed:
            continue
        candidates.append({
            "id": payload.get("id"),
            "title": payload.get("title"),
            "path": path,
            "log_path": payload.get("log_path"),
            "created_at": payload.get("created_at"),
            "summary": summary,
            "related_ids": payload.get("related_ids") or [],
            "snippet_count": len(payload.get("failure_snippets") or []),
            "suggested_action": (
                "summarize the log or extract the failing sequence, then turn "
                "it into objective state deltas before treating it as a finding"
            ),
        })
    return sorted(
        candidates,
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )


def _reviewed_sequence_minimization_keys(review_payload: dict) -> set[str]:
    keys = set()
    for summary in review_payload.get("sequence_minimizations") or []:
        if not isinstance(summary, dict):
            continue
        for field in ("id", "path"):
            value = str(summary.get(field) or "").strip()
            if value:
                keys.add(value)
    candidate = review_payload.get("candidate") or {}
    for item in candidate.get("campaign_ids") or []:
        text = str(item).strip()
        if re.fullmatch(r"min-\d{3,}", text):
            keys.add(text)
    for item in candidate.get("evidence") or []:
        text = str(item).strip()
        if text.startswith("/workspace/campaign/minimizations/"):
            keys.add(posixpath.normpath(text))
    return keys


def _progress_missing_foundation(state: dict) -> list[dict]:
    missing: list[dict] = []
    if not state["sections"].get("protocol_model"):
        missing.append({
            "section": "protocol_model",
            "suggested_action": "model protocol components and lifecycle",
        })
    if (
        not state["sections"].get("value_flow")
        and not state["sections"].get("trust_boundary")
    ):
        missing.append({
            "section": "value_flow",
            "suggested_action": (
                "record where value enters, sits, moves, and exits, or record "
                "the trust boundary that controls that flow"
            ),
        })
    if (
        not state["sections"].get("invariant")
        and not state["sections"].get("open_question")
    ):
        missing.append({
            "section": "invariant",
            "suggested_action": (
                "state one solvency/authorization/accounting invariant or an "
                "open question that must be answered before one can be tested"
            ),
        })
    return missing




def _hypothesis_experiment_readiness(hypothesis: dict) -> dict:
    invalid_card = ""
    try:
        card = _normalize_hypothesis_card(hypothesis.get("hypothesis_card"))
    except ValueError as exc:
        # Old or hand-edited campaign state is durable input. Treat malformed
        # cards as context work instead of crashing the authoritative sync.
        card = {}
        invalid_card = str(exc)
    raw_evidence = hypothesis.get("evidence")
    evidence = (
        [
            item.strip()
            for item in raw_evidence
            if isinstance(item, str) and item.strip()
        ]
        if isinstance(raw_evidence, list)
        else []
    )
    labels = {
        "attacker_control": "hypothesis_card.attacker_control",
        "state_path": "hypothesis_card.state_path",
        "invariant_at_risk": "hypothesis_card.invariant_at_risk",
        "impact_sink": "hypothesis_card.impact_sink",
        "material_preconditions": "hypothesis_card.material_preconditions",
        "falsifier": "hypothesis_card.falsifier",
        "objective": "hypothesis_card.objective",
    }
    missing = [labels[field] for field in _HYPOTHESIS_CARD_FIELDS if not card.get(field)]
    if invalid_card:
        missing.insert(0, invalid_card)
    if not evidence:
        missing.append("source, deployment, or probe evidence")
    return {
        "ready": not missing,
        "missing": missing,
        "hypothesis_card": card,
        "invalid_card": invalid_card or None,
    }


def _progress_hypotheses_without_experiments(state: dict) -> list[dict]:
    items = []
    for hypothesis in state["sections"].get("hypothesis", []):
        if hypothesis.get("status", "open") not in {"open", "testing", "inconclusive"}:
            continue
        hypothesis_id = str(hypothesis.get("id") or "")
        experiments = [
            entry
            for entry in _entries_referencing(state, "experiment", hypothesis_id)
            if not entry.get("manual_only")
            and "Template: fork_workbench" not in str(entry.get("content") or "")
        ]
        results = _entries_referencing(state, "result", hypothesis_id)
        if experiments or results or hypothesis.get("mutation_children"):
            continue
        readiness = _hypothesis_experiment_readiness(hypothesis)
        if readiness["ready"]:
            suggested_action = (
                "compose a sequence experiment or reject the branch "
                "with a decision"
            )
        else:
            suggested_action = (
                "source-review or deployment-bind this hypothesis before "
                "harness work; record missing setup as an open_question, mutate "
                "to a concrete hypothesis, or reject it"
            )
        items.append({
            **_entry_summary(hypothesis, section="hypothesis"),
            "suggested_action": suggested_action,
            "readiness": readiness,
        })
    return items


async def _progress_blocked_results(
    container: AuditContainer,
    state: dict,
) -> list[dict]:
    items = []
    for result in state["sections"].get("result", []):
        if result.get("status") not in {"blocked", "inconclusive"}:
            continue
        result_id = str(result.get("id") or "")
        decisions = _entries_referencing(state, "decision", result_id)
        has_mutation = any(
            item.startswith("mut-")
            for item in _entry_related_ids(result)
        )
        if decisions or has_mutation:
            continue
        evidence = _entry_evidence(result)
        failure_diagnosis = None
        for path in evidence:
            if not path.endswith(".followup.json"):
                continue
            payload = await _load_campaign_json_if_exists(container, path)
            diagnosis = (payload or {}).get("failure_diagnosis")
            if isinstance(diagnosis, dict):
                failure_diagnosis = diagnosis
                break
        suggested_action = "record why it is blocked, fix/run again, or mutate the linked hypothesis"
        if failure_diagnosis:
            repairs = failure_diagnosis.get("suggested_repairs") or []
            if repairs:
                suggested_action = str(repairs[0])
            else:
                suggested_action = str(failure_diagnosis.get("summary") or suggested_action)
        items.append({
            **_entry_summary(result, section="result"),
            "evidence": evidence,
            "related_ids": _entry_related_ids(result),
            "failure_diagnosis": failure_diagnosis,
            "suggested_action": suggested_action,
        })
    return items




def _brief_text(value: object, *, max_chars: int = 220) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _brief_entry(entry: dict, *, section: str, max_evidence: int = 4) -> dict:
    item = _entry_summary(entry, section=section)
    content = _brief_text(entry.get("content"), max_chars=220)
    if content:
        item["content_preview"] = content
    evidence = _entry_evidence(entry)[:max_evidence]
    if evidence:
        item["evidence"] = evidence
    related_ids = _entry_related_ids(entry)[:8]
    if related_ids:
        item["related_ids"] = related_ids
    updated_at = entry.get("updated_at") or entry.get("created_at")
    if updated_at:
        item["updated_at"] = updated_at
    return item


def _brief_state_entries(
    state: dict,
    section: str,
    *,
    statuses: set[str] | None = None,
    max_items: int,
) -> list[dict]:
    entries = []
    for entry in reversed(state["sections"].get(section, [])):
        status = str(entry.get("status") or "open")
        if statuses is not None and status not in statuses:
            continue
        entries.append(_brief_entry(entry, section=section))
        if len(entries) >= max_items:
            break
    return entries


def _brief_artifact_summary(path: str, payload: dict) -> dict:
    summary = {
        "id": payload.get("id"),
        "title": payload.get("title"),
        "path": path,
        "created_at": payload.get("created_at"),
        "summary": payload.get("summary") or {},
    }
    if payload.get("next_actions"):
        summary["next_actions"] = payload.get("next_actions")[:3]
    branches = payload.get("branches") or []
    if branches:
        top_branch = branches[0]
        summary["top_branch"] = {
            "id": top_branch.get("id"),
            "title": top_branch.get("title"),
            "priority": top_branch.get("priority"),
            "recommended_next_tool": top_branch.get("recommended_next_tool"),
            "blockers": (top_branch.get("blockers") or [])[:5],
        }
    high_gaps = payload.get("high_attention_gaps") or []
    if high_gaps:
        summary["top_high_attention_gaps"] = [
            {
                "key": item.get("key"),
                "attention_score": item.get("attention_score"),
                "affordances": item.get("affordances") or [],
            }
            for item in high_gaps[:5]
        ]
    return summary


async def _brief_latest_artifacts(
    container: AuditContainer,
    state: dict,
    directory: str,
    *,
    max_items: int,
) -> list[dict]:
    artifacts = []
    for path in _progress_evidence_paths(state, directory):
        payload = await _load_campaign_json_if_exists(container, path)
        if payload:
            artifacts.append(_brief_artifact_summary(path, payload))
    artifacts.sort(
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )
    return artifacts[:max_items]




def _brief_markdown(brief: dict) -> str:
    lines = [
        f"# {brief['title']}",
        "",
        f"Brief id: `{brief['id']}`",
        f"Created: {brief['created_at']}",
    ]
    if brief.get("focus"):
        lines.append(f"Focus: {brief['focus']}")
    lines.extend(["", "## Counts"])
    counts = brief.get("counts") or {}
    for section in _CAMPAIGN_SECTIONS:
        lines.append(f"- {section}: {counts.get(section, 0)}")

    suggestion = brief.get("suggested_next") or {}
    lines.extend([
        "",
        "## Controller Next Action",
        "- Exact projection: attack_search is authoritative for this next_action "
        "and all branch transitions.",
        f"- Status: `{suggestion.get('status', 'unknown')}`",
        f"- Tool: `{suggestion.get('tool') or 'none'}`",
        f"- Instructions: {suggestion.get('instructions', '')}",
    ])

    active = brief.get("active_work") or {}
    lines.extend(["", "## Open Work"])
    controller_branches = active.get("attack_search_branches") or []
    lines.append(f"- attack_search_branches: {len(controller_branches)}")
    for item in controller_branches[:5]:
        lines.append(
            f"  - {item.get('id')}: {item.get('title')} "
            f"[{item.get('status')}; {item.get('next_tool')}]"
        )
    latest = brief.get("latest_artifacts") or {}
    lines.extend(["", "## Latest Context"])
    for key in (
        "protocol_graphs",
        "action_spaces",
        "state_transition_models",
        "live_reachability",
        "live_inventory",
        "attack_graphs",
        "fuzz_runs",
        "sequence_minimizations",
        "fork_contexts",
        "economics",
        "finding_reviews",
        "report_reviews",
    ):
        items = latest.get(key) or []
        lines.append(f"- {key}: {len(items)}")
        for item in items[:2]:
            label = item.get("title") or item.get("id") or item.get("path")
            lines.append(f"  - {label} ({item.get('path')})")

    foundations = brief.get("foundations") or {}
    if any(foundations.values()):
        lines.extend(["", "## Recent State"])
        for key, items in foundations.items():
            if not items:
                continue
            lines.append(f"- {key}:")
            for item in items[:3]:
                label = item.get("title") or item.get("id")
                lines.append(f"  - {item.get('id')}: {label}")

    return "\n".join(lines).rstrip() + "\n"
