"""Agent loop — streaming LLM + tool execution."""

import asyncio
import json
import re
import shlex
import signal
import time

from reentbotpro.display import Display
from reentbotpro.docker import AuditContainer
from reentbotpro.llm import (
    ResponsesLLMClient,
    estimate_responses_request_tokens,
    get_model_settings,
)
from reentbotpro.prompt import REPORT_INSTRUCTION
from reentbotpro.tools import (
    DEFAULT_TOOLSETS,
    PARALLEL_SAFE,
    REQUEST_TOOLSET_NAME,
    REQUESTABLE_TOOLSETS,
    TOOL_BY_NAME,
    TOOLS,
    execute_tool,
    expand_toolsets,
    tools_for_toolsets,
    toolsets_for_tool_names,
)


# ── Context window defaults ────────────────────────────────────────────

DEFAULT_CONTEXT_WINDOW = 272_000
DEFAULT_MAX_TIME_MINUTES = 720
DEFAULT_MAX_TIME_SECONDS = DEFAULT_MAX_TIME_MINUTES * 60
_OUTPUT_RESERVE = 16_384  # max_output_tokens target for audit turns
_SAFETY_MARGIN = 2_500


def _tools_token_overhead(tools: list[dict] | None = None) -> int:
    """Estimate the token overhead of the tool definitions sent with every call.

    Tool schemas ride along on every API call but are not part of the message
    history, so the context budget reserves space for them separately. ``tools``
    defaults to the full ``TOOLS`` set (the conservative reserve used by the
    public budget); pass the currently visible subset to size the reserve to what
    is actually placed on the wire for a turn.
    """
    return len(json.dumps(tools if tools is not None else TOOLS, default=str)) // 4


_TOOLS_TOKEN_OVERHEAD = _tools_token_overhead(TOOLS)

# Hard ceiling per API call. GPT-5.4 supports up to 128k output tokens.
_MAX_OUTPUT_TOKENS = 128_000
_CONTEXT_RETRY_FACTORS = (0.70, 0.50, 0.30)
_RECENT_FULL_TOOL_TURNS = 3
_AGED_TOOL_OUTPUT_COMPRESS_THRESHOLD = 2_000
# Below this fraction of the context budget, leave the conversation append-only
# (no reasoning strip, no tool-output compaction) so the provider's prompt-cache
# prefix stays byte-stable across turns. Aging/compaction only kicks in once the
# history approaches the budget and we actually need to reclaim space.
_APPEND_ONLY_BUDGET_FRACTION = 0.7

# When the model's output is cut off mid-tool-call (finish_reason="length"),
# we nudge it to retry with shorter reasoning. The wall-clock limit is the
# runaway guard for repeated truncations.

# Prevents premature termination when the model gives up after a single error
# (e.g. failed compilation) instead of diagnosing and recovering.
_MIN_AUDIT_TURNS = 10000
_CAMPAIGN_STATE_REQUIRED_BY_TURN = 5
_ATTACK_SEARCH_REQUIRED_BY_TURN = 3
_CAMPAIGN_STATE_PATH = "/workspace/campaign/state.json"
_ATTACK_SEARCH_CURRENT_PATH = "/workspace/campaign/attack-search/current.json"
_PROGRESS_REVIEW_DIR = "/workspace/campaign/progress-reviews"
_ATTACK_SEARCH_TERMINAL_STATUSES = {"validated", "rejected", "superseded"}
_STOP_BLOCKING_STATUSES = {
    "ready_to_submit",
    "needs_report_review",
    "needs_finding_review",
    "needs_evidence",
    "needs_reduction",
    "needs_concretization",
    "needs_run",
    "running",
}
_STOP_LIVE_BRANCH_STATUSES = {"needs_inventory", "needs_harness", "blocked_revert"}
_STOP_READY_PROGRESS_KEYS = (
    "ready_report_reviews",
    "ready_finding_reviews",
    "sequence_minimizations_without_review",
    "candidate_fuzz_failures",
)

_CAMPAIGN_SUMMARY_COUNTERS = (
    ("toolset_requests", "Toolset requests"),
    ("campaign_updates", "Campaign artifacts recorded"),
    ("action_spaces_mapped", "Action-space maps built"),
    ("protocol_graphs", "Protocol graphs built"),
    ("progress_reviews", "Campaign progress reviews recorded"),
    ("campaign_briefs", "Campaign resume briefs recorded"),
    ("coverage_reviews", "Attack-surface coverage reviews recorded"),
    ("campaign_plans", "Attack campaign plans recorded"),
    ("attack_search_runs", "Attack-search controller syncs"),
    ("sequence_experiments", "Sequence experiments composed"),
    ("sequence_completions", "Sequence experiments completed"),
    ("sequence_minimizations", "Sequence minimizations recorded"),
    ("fuzz_runs", "Fuzz/invariant runs recorded"),
    ("build_diagnostics", "Build diagnostics recorded"),
    ("experiment_repairs", "Experiment repairs applied"),
    ("objective_evaluations", "Objective evaluations recorded"),
    ("fork_contexts", "Fork contexts recorded"),
    ("economics_estimates", "Economics estimates recorded"),
    ("lending_health_estimates", "Lending health estimates recorded"),
    ("invariant_harnesses", "Invariant harnesses composed"),
    ("call_sequences", "Call sequences extracted"),
    ("flash_loan_estimates", "Flash-loan estimates recorded"),
    ("finding_reviews", "Finding evidence reviews recorded"),
    ("report_reviews", "Report quality reviews recorded"),
    ("hypothesis_mutations", "Hypothesis mutations recorded"),
)

_CAMPAIGN_TOOL_TRACKING = {
    "read_campaign": (("campaign_reads",), ()),
    "update_campaign": (("campaign_updates",), ()),
    "review_campaign_progress": (("campaign_updates", "progress_reviews"), ("result",)),
    "build_campaign_brief": (("campaign_updates", "campaign_briefs"), ("result",)),
    "attack_search": (("campaign_updates", "attack_search_runs"), ("result",)),
    "map_protocol_graph": (("campaign_updates", "protocol_graphs"), ("result",)),
    "review_attack_surface_coverage": (
        ("campaign_updates", "coverage_reviews"),
        ("result",),
    ),
    "plan_attack_campaign": (("campaign_updates", "campaign_plans"), ("result",)),
    "create_experiment": (
        ("campaign_updates", "experiments_created"),
        ("experiment",),
    ),
    "run_experiment": (("campaign_updates", "experiments_run"), ("result",)),
    "run_sequence_minimization": (
        ("campaign_updates", "experiments_run", "sequence_minimizations"),
        ("result",),
    ),
    "run_campaign_fuzz": (
        ("campaign_updates", "experiments_run", "fuzz_runs"),
        ("result",),
    ),
    "diagnose_build": (
        ("campaign_updates", "build_diagnostics"),
        ("result",),
    ),
    "repair_experiment": (
        ("campaign_updates", "experiment_repairs"),
        ("experiment", "result"),
    ),
    "snapshot_state": (("campaign_updates", "state_snapshots"), ("result",)),
    "compare_snapshots": (
        ("campaign_updates", "snapshot_comparisons"),
        ("result",),
    ),
    "evaluate_objective": (
        ("campaign_updates", "objective_evaluations"),
        ("result",),
    ),
    "record_fork_context": (("campaign_updates", "fork_contexts"), ("result",)),
    "estimate_amm_economics": (
        ("campaign_updates", "economics_estimates"),
        ("result",),
    ),
    "estimate_flash_loan": (
        ("campaign_updates", "economics_estimates", "flash_loan_estimates"),
        ("result",),
    ),
    "estimate_lending_health": (
        ("campaign_updates", "economics_estimates", "lending_health_estimates"),
        ("result",),
    ),
    "review_finding_evidence": (
        ("campaign_updates", "finding_reviews"),
        ("result",),
    ),
    "review_report_quality": (("campaign_updates", "report_reviews"), ("result",)),
    "summarize_trace": (("campaign_updates", "trace_summaries"), ("result",)),
    "extract_call_sequence": (("campaign_updates", "call_sequences"), ("result",)),
    "map_action_space": (
        ("campaign_updates", "action_spaces_mapped"),
        ("result",),
    ),
    "compose_sequence_experiment": (
        ("campaign_updates", "experiments_created", "sequence_experiments"),
        ("experiment",),
    ),
    "complete_sequence_experiment": (
        ("campaign_updates", "sequence_completions"),
        ("experiment", "result"),
    ),
    "compose_invariant_harness": (
        ("campaign_updates", "experiments_created", "invariant_harnesses"),
        ("experiment",),
    ),
    "mutate_hypothesis": (
        ("campaign_updates", "hypothesis_mutations"),
        ("hypothesis", "experiment", "decision", "open_question"),
    ),
}
_CAMPAIGN_COUNTER_KEYS = tuple(dict.fromkeys(
    key
    for counters, _sections in _CAMPAIGN_TOOL_TRACKING.values()
    for key in counters
))


def get_model_max_output_tokens(model: str | None) -> int:
    """Return the effective max output tokens for the selected model."""
    return min(get_model_settings(model).max_output_tokens, _MAX_OUTPUT_TOKENS)


def calculate_max_context(
    context_window: int,
    output_reserve: int = _OUTPUT_RESERVE,
    *,
    tools: list[dict] | None = None,
) -> int:
    """Calculate how many tokens of conversation history to retain.

    Subtracts space reserved for the model's response, a safety margin, and
    the token overhead of tool definitions (sent with every API call but not
    counted in message tokens) from the model's context window.
    Floors at 10k to prevent negative or unusably small values.

    ``tools`` defaults to ``None``, which reserves the full ``TOOLS`` overhead —
    the conservative, byte-stable budget the loop relies on. Pass the currently
    visible toolset to size the reserve to what a turn actually sends; the
    visible subset is smaller than the full set whenever specialized toolsets are
    still inactive.
    """
    overhead = (
        _TOOLS_TOKEN_OVERHEAD if tools is None else _tools_token_overhead(tools)
    )
    return max(
        context_window - output_reserve - _SAFETY_MARGIN - overhead,
        10_000,
    )


def _turn_history_budget(
    max_context: int,
    *,
    context_window: int | None,
    visible_tools: list[dict],
    max_context_is_user_cap: bool,
) -> int:
    """Size one turn's conversation-history budget to the tools it actually sends.

    Demand-driven visibility means a turn usually places far fewer than the full
    ``TOOLS`` set on the wire, so its schema overhead is smaller and more of the
    model window can hold history. When ``context_window`` is known we recompute
    the budget against ``visible_tools``:

    - No user cap: use the visible-tool budget directly, even when it exceeds the
      conservative full-tool ``max_context``. Reclaiming that headroom is the
      whole point — the old ``min(max_context, …)`` clamp threw it away because
      the static ``max_context`` already reserved the full tool set.
    - User cap: the user's explicit ``max_context`` is a hard ceiling, so clamp
      the visible-tool budget down to it (never above), while still shrinking
      below it when the window cannot hold that much.

    When ``context_window`` is unavailable, fall back to the static ``max_context``
    unchanged — the legacy behaviour for callers that do not thread the window
    through.
    """
    if context_window is None:
        return max_context
    visible_budget = calculate_max_context(context_window, tools=visible_tools)
    if max_context_is_user_cap:
        return min(max_context, visible_budget)
    return visible_budget


# ── Helpers ──────────────────────────────────────────────────────────────


def _estimate_tokens(messages: list[dict]) -> int:
    """Rough token estimate: 4 chars ≈ 1 token."""
    return len(json.dumps(messages, default=str)) // 4


def _estimate_context_tokens(
    messages: list[dict], tools: list[dict] | None = None
) -> int:
    """Estimate conversation tokens using the actual Responses request shape.

    The full request estimate includes the tool schemas, so we subtract their
    overhead to leave a message-only estimate — the unit the per-turn history
    budget is expressed in. ``tools`` defaults to ``None``, which discounts the
    full ``TOOLS`` set (the conservative legacy behaviour). When a demand-driven
    turn only places the visible subset on the wire, pass that subset so the
    estimate adds and subtracts the same tools instead of globally discounting
    the whole set for a request that never carried it.
    """
    tool_set = TOOLS if tools is None else tools
    overhead = (
        _TOOLS_TOKEN_OVERHEAD if tools is None else _tools_token_overhead(tools)
    )
    request_tokens = estimate_responses_request_tokens(messages, tool_set)
    return max(1, request_tokens - overhead)


def _group_into_turns(messages: list[dict]) -> list[list[dict]]:
    """Group messages into logical turns for pair-aware truncation.

    A turn is one of:
    - A standalone message (system, user, or assistant without tool_calls)
    - An assistant message with tool_calls + all its consecutive tool result
      messages

    This ensures tool_call/tool_result pairs are never split, which would
    produce a malformed conversation that the API may reject.
    """
    turns: list[list[dict]] = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            # Group this assistant message with all following tool results
            turn = [msg]
            i += 1
            while i < len(messages) and messages[i].get("role") == "tool":
                turn.append(messages[i])
                i += 1
            turns.append(turn)
        else:
            turns.append([msg])
            i += 1
    return turns


def _build_findings_summary(findings: list[dict]) -> str:
    """Format findings as a compact summary for injection into truncation note."""
    if not findings:
        return ""
    lines = []
    for f in findings:
        title = f.get("title", "Untitled")
        if len(title) > 120:
            title = title[:117] + "..."
        severity = f.get("severity", "info").upper()
        validated = "validated" if f.get("validated") else "unvalidated"
        lines.append(f"  - {f['id']} [{severity}] {title} — {validated}")
    return "\n".join(lines)


def _active_toolsets(explored: dict | None) -> set[str]:
    if not explored:
        return set(DEFAULT_TOOLSETS)
    active = explored.setdefault("active_toolsets", set(DEFAULT_TOOLSETS))
    if not isinstance(active, set):
        active = set(active or DEFAULT_TOOLSETS)
        explored["active_toolsets"] = active
    expanded = expand_toolsets(active)
    explored["active_toolsets"] = expanded
    return expanded


def _visible_tools(explored: dict | None) -> list[dict]:
    return tools_for_toolsets(_active_toolsets(explored))


_REPORT_PHASE_TOOL_NAMES = {
    "list_files",
    "read_file",
    "write_file",
    "read_campaign",
}


def _report_visible_tools() -> list[dict]:
    return [
        tool for tool in tools_for_toolsets({"core"})
        if tool.get("function", {}).get("name") in _REPORT_PHASE_TOOL_NAMES
    ]


def _requested_toolsets_from_calls(tool_calls: list[dict]) -> list[str]:
    requested = []
    valid = {*REQUESTABLE_TOOLSETS, "all"}
    for tc in tool_calls:
        if tc.get("function", {}).get("name") != REQUEST_TOOLSET_NAME:
            continue
        try:
            args = json.loads(tc["function"].get("arguments") or "{}")
        except (json.JSONDecodeError, KeyError, AttributeError):
            continue
        toolset = str(args.get("toolset") or "").strip().lower()
        if toolset in valid:
            requested.append(toolset)
    return requested


def _activate_toolsets(explored: dict, requested: list[str] | set[str]) -> set[str]:
    if not requested:
        return set()
    active = _active_toolsets(explored)
    before = set(active)
    for toolset in requested:
        active.update(expand_toolsets({toolset}))
    explored["active_toolsets"] = active
    explored.setdefault("requested_toolsets", set()).update(requested)
    return active - before


def _activate_requested_toolsets(tool_calls: list[dict], explored: dict) -> set[str]:
    return _activate_toolsets(explored, _requested_toolsets_from_calls(tool_calls))


def _toolset_activation_note(activated: set[str], *, reason: str) -> dict | None:
    if not activated:
        return None
    return {
        "role": "user",
        "content": (
            f"Toolsets now available ({reason}): "
            + ", ".join(sorted(activated))
            + ". Continue with the next concrete campaign action."
        ),
    }


def _build_explored_summary(explored: dict) -> str:
    """Format explored state as a compact summary for the truncation note."""
    parts = []
    files = explored.get("files_read", set())
    tools = explored.get("tools_run", set())

    if files:
        sorted_files = sorted(files)
        if len(sorted_files) > 20:
            parts.append(
                f"Files analyzed ({len(files)} total, showing first 20): "
                + ", ".join(sorted_files[:20])
            )
        else:
            parts.append(f"Files analyzed: {', '.join(sorted_files)}")

    if tools:
        parts.append(f"Tools used: {', '.join(sorted(tools))}")

    active_toolsets = explored.get("active_toolsets", set())
    if active_toolsets:
        parts.append(f"Active toolsets: {', '.join(sorted(active_toolsets))}")
    requested_toolsets = explored.get("requested_toolsets", set())
    if requested_toolsets:
        parts.append(f"Requested toolsets: {', '.join(sorted(requested_toolsets))}")
    if explored.get("scope_inspections"):
        parts.append(f"Scope inspections: {explored['scope_inspections']}")

    for key, label in _CAMPAIGN_SUMMARY_COUNTERS:
        count = explored.get(key, 0)
        if count:
            parts.append(f"{label}: {count}")

    failed = explored.get("failed_tool_calls")
    if failed:
        rendered = ", ".join(
            f"{name} ({count})" for name, count in sorted(failed.items())
        )
        parts.append(f"Failed or blocked tool calls: {rendered}")

    return "\n".join(parts)


def _preview_lines(lines: list[str], max_lines: int, max_chars: int = 800) -> str:
    preview = "\n".join(lines[:max_lines])
    if len(preview) <= max_chars:
        return preview
    return preview[:max_chars] + "\n..."


def _keep_fields(src: dict, keys) -> dict:
    """Copy fields that carry information.

    Drops ``None``/``""``/``[]``/``{}`` so a skeleton stays compact, but keeps
    ``0`` and ``False`` because they are load-bearing audit facts (e.g.
    ``runnable: false``, ``executable_sequence_calls: 0``).
    """
    return {
        key: src[key]
        for key in keys
        if src.get(key) not in (None, "", [], {})
    }


def _summarize_json_result(content: str, builder, *, elided: str) -> str:
    """Shared scaffold for the JSON-returning semantic tool summaries.

    Implements the json.loads-first contract: parse ``content``, run ``builder``
    to keep only the audit-relevant skeleton, and elide bulky fields. Falls back
    to the generic first-300-chars preview when the content is not a JSON object
    (e.g. a plain ``Error: ...`` string), so the caller never loses its existing
    fallback behaviour.
    """
    char_count = len(content)
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return f"{content[:300]}\n[... {char_count} chars — compressed]"
    if not isinstance(data, dict):
        return f"{content[:300]}\n[... {char_count} chars — compressed]"
    kept = builder(data)
    return (
        f"{json.dumps(kept, sort_keys=True)}\n"
        f"[{elided}, {char_count} chars raw — compressed]"
    )


def _source_slice_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "status", "path", "contract", "function", "line_range",
        "signature", "modifiers", "returns",
    ))
    # Parameter names/types are small but load-bearing for follow-up synthesis;
    # keep them compactly (the "type name" raw form) while the bulky body is
    # elided below.
    parameters = data.get("parameters")
    if isinstance(parameters, list) and parameters:
        kept["parameters"] = [
            str(param.get("raw") or param.get("name") or "")
            for param in parameters
            if isinstance(param, dict)
        ][:12]

    hints = data.get("hints")
    if isinstance(hints, dict):
        hint_digest: dict = {}
        for group, items in hints.items():
            if not isinstance(items, list) or not items:
                continue
            first = items[0] if isinstance(items[0], dict) else {}
            text = first.get("text")
            hint_digest[group] = {
                "count": len(items),
                "first": text[:160] if isinstance(text, str) else None,
            }
        if hint_digest:
            kept["hints"] = hint_digest

    body = data.get("body")
    if isinstance(body, str):
        kept["body_chars"] = len(body)
    if isinstance(data.get("candidates"), list) and data["candidates"]:
        kept["candidate_count"] = data.get("candidate_count", len(data["candidates"]))
    return kept


def _summarize_source_slice(content: str) -> str:
    """Compress a source_slice result while keeping its semantic skeleton.

    Unlike the generic first-300-chars fallback, this preserves the slice's
    locator + signature metadata and a digest of the top line hints (dropping
    only the bulky body text) so a compressed turn still tells the agent which
    function it sliced and what flowed through it.
    """
    return _summarize_json_result(
        content, _source_slice_skeleton, elided="source_slice — body elided",
    )


def _synthesize_args_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "arg_synthesis_id", "path", "status", "contract", "function", "signature",
    ))
    plan = data.get("parameter_plan")
    if isinstance(plan, list):
        kept["parameters"] = len(plan)
    calls = data.get("candidate_calls")
    if isinstance(calls, list):
        kept["candidate_calls"] = len(calls)
        top = calls[0] if calls and isinstance(calls[0], dict) else {}
        if isinstance(top.get("args"), list):
            kept["top_call_args"] = top["args"]
        if top.get("confidence") is not None:
            kept["top_call_confidence"] = top["confidence"]
    blockers = data.get("blockers")
    if isinstance(blockers, list) and blockers:
        kept["blocker_classes"] = sorted({
            str(item.get("class"))
            for item in blockers
            if isinstance(item, dict) and item.get("class")
        })
    return kept


def _summarize_synthesize_args(content: str) -> str:
    """Compress a synthesize_args result while keeping its planning skeleton.

    Keeps the locator (id/path), the target signature + status, the candidate
    counts, the top candidate call, and any blocker classes, while eliding the
    bulky per-parameter plan/candidate list. A compressed turn still tells the
    agent what it synthesized and what is still blocked.
    """
    return _summarize_json_result(
        content,
        _synthesize_args_skeleton,
        elided="synthesize_args — plan/candidates elided",
    )


def _compose_sequence_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, ("experiment_id", "workspace"))
    quality = data.get("scaffold_quality")
    if isinstance(quality, dict):
        kept.update(_keep_fields(quality, (
            "proof_readiness", "runnable",
            "executable_sequence_calls", "partial_sequence_calls",
            "blocked_sequence_calls",
        )))
        blockers = [
            *(quality.get("harness_limit_blockers") or []),
            *(quality.get("source_blockers") or []),
        ]
        if blockers:
            kept["blockers"] = blockers[:8]
    steps = data.get("steps")
    if isinstance(steps, list) and steps:
        kept["steps"] = len(steps)
    unmatched = data.get("unmatched_actions")
    if isinstance(unmatched, list) and unmatched:
        kept["unmatched_actions"] = len(unmatched)
    return kept


def _summarize_compose_sequence_experiment(content: str) -> str:
    """Compress a compose_sequence_experiment result to its proof-readiness gist.

    Preserves the experiment locator (id/workspace) and the scaffold's
    runnable/proof_readiness/executable/partial/blocker signals while eliding the
    rendered steps and graph context, so a compressed turn still tells the agent
    whether the scaffold is runnable and what is holding it back.
    """
    return _summarize_json_result(
        content,
        _compose_sequence_skeleton,
        elided="compose_sequence_experiment — scaffold/steps elided",
    )


def _complete_sequence_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "experiment_id", "workspace", "sequence_path", "contract_path",
        "mode", "validated",
    ))
    steps = data.get("steps")
    if isinstance(steps, list):
        kept["steps"] = len(steps)
    quality = data.get("scaffold_quality")
    if isinstance(quality, dict):
        kept.update(_keep_fields(quality, (
            "proof_readiness", "runnable",
            "executable_sequence_calls", "partial_sequence_calls",
        )))
    applied = data.get("applied_changes")
    if isinstance(applied, list):
        kept["applied_changes"] = len(applied)
    remaining = data.get("remaining_blockers")
    if isinstance(remaining, list) and remaining:
        kept["remaining_blockers"] = [str(item) for item in remaining][:8]
    build = data.get("build")
    if isinstance(build, dict):
        build_kept = _keep_fields(build, ("command", "exit_code"))
        build_blockers = build.get("blockers")
        if isinstance(build_blockers, list) and build_blockers:
            build_kept["blockers"] = [str(item) for item in build_blockers][:5]
        if build_kept:
            kept["build"] = build_kept
    return kept


def _summarize_complete_sequence_experiment(content: str) -> str:
    """Compress a complete_sequence_experiment result to its concretization gist.

    Preserves the sequence locator, runnable/proof_readiness, applied-change and
    remaining-blocker counts, and the build outcome, while eliding the rendered
    probe/steps so a compressed turn still tells the agent how far the scaffold
    got and what blockers remain.
    """
    return _summarize_json_result(
        content,
        _complete_sequence_skeleton,
        elided="complete_sequence_experiment — scaffold/probe elided",
    )


def _diagnose_build_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "build_diagnostic_id", "status", "build_system",
        "suggested_next", "exit_code", "path", "log_path",
    ))
    first_error = data.get("first_error")
    if isinstance(first_error, dict) and first_error:
        compact = _keep_fields(first_error, ("kind", "file", "line"))
        message = str(first_error.get("message") or "").strip()
        if message:
            compact["message"] = message[:200]
        if compact:
            kept["first_error"] = compact
    diagnostics = data.get("diagnostics")
    if isinstance(diagnostics, list) and diagnostics:
        kept["diagnostic_count"] = len(diagnostics)
        kinds = sorted({
            str(item.get("kind"))
            for item in diagnostics
            if isinstance(item, dict) and item.get("kind")
        })
        if kinds:
            kept["diagnostic_kinds"] = kinds
    return kept


def _summarize_diagnose_build(content: str) -> str:
    """Compress a diagnose_build result to its classified-blocker gist.

    Preserves status/build_system, the first error's kind+message, the set of
    diagnostic kinds, and suggested_next while eliding the raw log, so a
    compressed turn still tells the agent what failed and what to do next.
    """
    return _summarize_json_result(
        content,
        _diagnose_build_skeleton,
        elided="diagnose_build — diagnostics/log elided",
    )


def _attack_search_result_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, ("search_id", "action", "focus"))
    next_action = data.get("next_action")
    if isinstance(next_action, dict):
        compact = _keep_fields(next_action, (
            "branch_id", "branch_title", "status", "tool", "source", "dossier_path",
        ))
        required_args = next_action.get("required_args")
        if isinstance(required_args, dict) and required_args:
            compact["required_args_keys"] = sorted(required_args.keys())
        required_evidence = next_action.get("required_evidence")
        if isinstance(required_evidence, list) and required_evidence:
            compact["required_evidence"] = [str(item) for item in required_evidence][:5]
        if compact:
            kept["next_action"] = compact
    summary = data.get("summary")
    if isinstance(summary, dict):
        summary_kept = _keep_fields(summary, ("branches", "active", "terminal"))
        if summary_kept:
            kept["summary"] = summary_kept
    active = data.get("active_branches")
    if isinstance(active, list) and active:
        kept["active_branches"] = [
            _keep_fields(branch, ("id", "title", "status", "next_tool", "priority"))
            for branch in active[:6]
            if isinstance(branch, dict)
        ]
    return kept


def _summarize_attack_search(content: str) -> str:
    """Compress an attack_search result to its controller state.

    Preserves the next_action (branch_id/status/tool/source/dossier_path and the
    required-args keys) plus the top active branches, while eliding the full
    per-branch detail. The dossier_path lets the agent recover the selected
    branch with one artifact read even after the turn is compacted.
    """
    return _summarize_json_result(
        content,
        _attack_search_result_skeleton,
        elided="attack_search — branch detail elided",
    )


def _review_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, ("review_id", "path", "ready", "evidence_review_ready"))
    blocking = data.get("blocking_gaps")
    if isinstance(blocking, list) and blocking:
        kept["blocking_gaps"] = [str(item) for item in blocking][:10]
    missing = data.get("missing_evidence_paths")
    if isinstance(missing, list) and missing:
        kept["missing_evidence_paths"] = [str(item) for item in missing][:10]
    warnings = data.get("warnings")
    if isinstance(warnings, list) and warnings:
        kept["warnings"] = len(warnings)
    return kept


def _summarize_review(content: str, *, label: str) -> str:
    """Compress an evidence/report review to its verdict + missing evidence.

    Both review tools share a shape: a ready/blocking verdict plus the missing
    evidence paths. Preserving exactly those lets a compressed turn still tell
    the agent whether a submission gate would pass and what is still missing.
    """
    return _summarize_json_result(
        content, _review_skeleton, elided=f"{label} — review detail elided",
    )


# run_experiment returns plain text (raw command output + a recorded-result
# footer), not JSON, so its summary parses markers out of the text instead of
# going through _summarize_json_result.
_RUN_EXPERIMENT_MARKER_RE = re.compile(
    r"(suite result:|test result:|ran \d+ test|\[pass\]|\[fail\]|"
    r"\d+ passed|\d+ failed|revert|panic|objective|assert|"
    r"counterexample|invariant|timed out)",
    re.IGNORECASE,
)
_RUN_EXPERIMENT_FOOTER_PREFIXES = (
    "Recorded campaign result:",
    "Run classification:",
    "Full log:",
    "Mirrored generated PoC:",
    "Replay follow-up:",
    "Experiment follow-up:",
    "Suggested next tools:",
)


def _summarize_run_experiment(content: str) -> str:
    """Compress a run_experiment result while keeping its objective markers.

    The raw forge/echidna/medusa output is bulky but the audit-relevant facts
    are small: the recorded result id + status, exit/timeout, run classification,
    the follow-up/log artifact paths, and a handful of objective marker lines
    (pass/fail/revert/invariant). Preserving those lets a compressed turn still
    tell the agent whether the experiment produced evidence and where the full
    log lives.
    """
    char_count = len(content)
    kept: dict = {}

    recorded = re.search(r"Recorded campaign result:\s*(\S+)\s*\(([^)]+)\)", content)
    if recorded:
        kept["result_id"] = recorded.group(1)
        kept["status"] = recorded.group(2).strip()
    classification = re.search(
        r"Run classification:\s*(\S+)\s*/\s*(\S+)\s*"
        r"\(satisfies_experiment_run=(\w+)\)",
        content,
    )
    if classification:
        kept["run_kind"] = classification.group(1)
        kept["evidence_grade"] = classification.group(2)
        kept["satisfies_experiment_run"] = classification.group(3).lower() == "true"
    log_match = re.search(r"Full log:\s*(\S+)", content)
    if log_match:
        kept["log_path"] = log_match.group(1)
    followup = re.search(r"(?:Replay|Experiment) follow-up:\s*(\S+)", content)
    if followup:
        kept["followup_path"] = followup.group(1)
    mirrored = re.search(r"Mirrored generated PoC:\s*(.+)", content)
    if mirrored:
        kept["mirrored_pocs"] = [
            part.strip() for part in mirrored.group(1).split(",") if part.strip()
        ]

    exit_match = re.search(r"\[exit code:\s*(-?\d+)\]", content)
    if exit_match:
        kept["exit_code"] = int(exit_match.group(1))
    elif "timed out after" in content:
        kept["exit_code"] = "timeout"
    elif kept.get("status") == "observed":
        kept["exit_code"] = 0

    markers: list[str] = []
    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith(_RUN_EXPERIMENT_FOOTER_PREFIXES):
            continue
        if _RUN_EXPERIMENT_MARKER_RE.search(stripped):
            markers.append(stripped[:200])
        if len(markers) >= 8:
            break
    if markers:
        kept["objective_markers"] = markers

    if not kept:
        return f"{content[:300]}\n[... {char_count} chars — compressed]"
    return (
        f"{json.dumps(kept, sort_keys=True)}\n"
        f"[run_experiment — raw output elided, {char_count} chars raw — compressed]"
    )


def _observed_tx_miner_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "observed_tx_miner_id", "path", "status", "target", "selector",
        "network", "from_block", "to_block",
    ))
    samples = data.get("samples")
    if isinstance(samples, list) and samples:
        kept["sample_count"] = len(samples)
        # Preserve each sample's tx hash + decoded argument shape: those are the
        # load-bearing facts a later turn needs to replay the call or synthesize
        # args; the bulky transfers/calldata/trace are elided into the artifact.
        compact = [
            _keep_fields(sample, (
                "tx_hash", "from", "selector", "function", "success", "arg_shape",
            ))
            for sample in samples[:8]
            if isinstance(sample, dict)
        ]
        if compact:
            kept["samples"] = compact
    hints = data.get("synthesize_args_hints")
    if isinstance(hints, dict) and hints.get("primary_selector"):
        kept["primary_selector"] = hints.get("primary_selector")
    blockers = data.get("blockers")
    if isinstance(blockers, list) and blockers:
        kept["blockers"] = blockers[:4]
    return kept


def _summarize_observed_tx_miner(content: str) -> str:
    """Compress an observed_tx_miner result while keeping its replay skeleton.

    Keeps the artifact locator (id/path), status/target/selector, and a compact
    per-sample view that preserves each tx hash + decoded argument shape, while
    eliding the bulky transfers, full calldata, and per-tx traces.
    """
    return _summarize_json_result(
        content, _observed_tx_miner_skeleton,
        elided="observed_tx_miner — transfers/calldata/hints elided",
    )


def _state_transition_model_skeleton(data: dict) -> dict:
    kept = _keep_fields(data, (
        "state_transition_model_id", "path", "status", "focus",
    ))
    scope = data.get("scope")
    if isinstance(scope, dict):
        kept_scope = _keep_fields(scope, ("path", "contract", "files_scanned"))
        if kept_scope:
            kept["scope"] = kept_scope
    summary = data.get("summary")
    if isinstance(summary, dict):
        kept_summary = _keep_fields(summary, (
            "tracked_state", "entrypoints", "candidate_invariants", "contracts",
        ))
        if kept_summary:
            kept["summary"] = kept_summary
    invariants = data.get("candidate_invariants")
    if isinstance(invariants, list) and invariants:
        # The invariant KINDS are the load-bearing planning signal; keep them
        # (and the top entrypoints below) while eliding the bulky statements,
        # falsification ideas, tracked_state, and experiment prompts.
        kept["invariant_kinds"] = sorted({
            str(item.get("kind"))
            for item in invariants
            if isinstance(item, dict) and item.get("kind")
        })
        kept["candidate_invariants"] = len(invariants)
    entrypoints = data.get("entrypoints")
    if isinstance(entrypoints, list) and entrypoints:
        kept["entrypoints"] = [
            _keep_fields(item, ("contract", "function", "line"))
            for item in entrypoints[:6]
            if isinstance(item, dict)
        ]
    lenses = data.get("lenses")
    if isinstance(lenses, dict) and lenses:
        kept["lenses"] = sorted(lenses.keys())
    blockers = data.get("blockers")
    if isinstance(blockers, list) and blockers:
        kept["blockers"] = blockers[:4]
    return kept


def _summarize_state_transition_model(content: str) -> str:
    """Compress an extract_state_transition_model result, keeping its planning
    skeleton: the artifact locator (id/path), status/focus/scope, the invariant
    KINDS + count, the top entrypoints, present lens names, and blockers, while
    eliding the bulky statements, tracked_state, and experiment prompts."""
    return _summarize_json_result(
        content,
        _state_transition_model_skeleton,
        elided=(
            "extract_state_transition_model — "
            "tracked_state/invariants/prompts elided"
        ),
    )


def _summarize_tool_result(tool_name: str, content: str) -> str:
    """Create a compact summary of a tool result for compressed context."""
    lines = content.strip().split("\n")
    line_count = len(lines)
    char_count = len(content)

    match tool_name:
        case "read_file":
            preview = _preview_lines(lines, 5)
            return f"{preview}\n[... {line_count} lines, {char_count} chars — compressed]"
        case "run_command":
            if line_count > 10:
                preview = _preview_lines(lines[:3] + ["..."] + lines[-3:], 7)
            else:
                preview = _preview_lines(lines, 5)
            return f"{preview}\n[... {line_count} lines — compressed]"
        case "search_code":
            preview = _preview_lines(lines, 5)
            return f"{preview}\n[... {line_count} result lines — compressed]"
        case "source_slice":
            return _summarize_source_slice(content)
        case "synthesize_args":
            return _summarize_synthesize_args(content)
        case "compose_sequence_experiment":
            return _summarize_compose_sequence_experiment(content)
        case "complete_sequence_experiment":
            return _summarize_complete_sequence_experiment(content)
        case "diagnose_build":
            return _summarize_diagnose_build(content)
        case "run_experiment":
            return _summarize_run_experiment(content)
        case "attack_search":
            return _summarize_attack_search(content)
        case "observed_tx_miner":
            return _summarize_observed_tx_miner(content)
        case "extract_state_transition_model":
            return _summarize_state_transition_model(content)
        case "review_finding_evidence":
            return _summarize_review(content, label="review_finding_evidence")
        case "review_report_quality":
            return _summarize_review(content, label="review_report_quality")
        case "fetch_url":
            return f"{content[:300]}\n[... {char_count} chars — compressed]"
        case _:
            return f"{content[:300]}\n[... {char_count} chars — compressed]"


def _compress_turn(turn: list[dict], min_content_chars: int = 500) -> list[dict]:
    """Compress bulky tool results in a turn, keeping replay-critical items intact.

    For turns with tool calls, replaces large tool result content with compact
    summaries while preserving the assistant message's tool calls and encrypted
    response items. This lets the agent retain tool continuity without the raw
    data payload.
    """
    if len(turn) < 2:
        return turn  # standalone message, nothing to compress

    assistant_msg = turn[0]
    if assistant_msg.get("role") != "assistant" or not assistant_msg.get("tool_calls"):
        return turn  # not a tool-call turn

    # Map tool_call_id → tool name for better summaries
    tc_names = {}
    for tc in assistant_msg.get("tool_calls", []):
        tc_names[tc["id"]] = tc["function"]["name"]

    # Strip display-only reasoning text from compressed turns to reclaim context
    # space. Keep response_items: encrypted reasoning is replay-critical for
    # stateless Responses API tool loops.
    stripped_assistant = {
        k: v for k, v in assistant_msg.items()
        if k not in ("reasoning", "reasoning_details")
    }
    compressed = [stripped_assistant]
    for msg in turn[1:]:
        content = msg.get("content", "")
        if msg["role"] == "tool" and len(content) > min_content_chars:
            tool_name = tc_names.get(msg.get("tool_call_id"), "unknown")
            summary = _summarize_tool_result(tool_name, content)
            compressed.append({**msg, "content": summary})
        else:
            compressed.append(msg)
    return compressed


def _strip_old_reasoning(messages: list[dict]) -> None:
    """Remove display-only reasoning while preserving replay-critical items.

    The Responses API recommends carrying reasoning items, function calls, and
    tool outputs since the last user message when manually managing state. Raw
    reasoning text is only for local display and can be stripped aggressively,
    but encrypted response_items after the latest user message must remain.
    """
    last_assistant_idx = None
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            last_assistant_idx = i
            break

    if last_assistant_idx is None:
        return

    last_user_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "user":
            last_user_idx = i
            break

    for i in range(len(messages)):
        msg = messages[i]
        if msg.get("role") != "assistant":
            continue

        drop_keys = set()
        if i != last_assistant_idx:
            drop_keys.update(("reasoning", "reasoning_details"))
        if i < last_user_idx:
            drop_keys.add("response_items")

        if drop_keys and any(k in msg for k in drop_keys):
            messages[i] = {k: v for k, v in msg.items() if k not in drop_keys}


def _attack_branch_recovery_line(explored: dict | None) -> str:
    """One-line summary of the currently selected attack_search branch.

    Built from the locator that ``_record_attack_search_branch`` stashed on the
    last successful attack_search call. Returns "" when no branch is known, so
    the truncation note simply omits the line.
    """
    branch = (explored or {}).get("attack_branch")
    if not isinstance(branch, dict) or not branch.get("branch_id"):
        return ""
    head = f"Current attack_search branch: {branch['branch_id']}"
    title = branch.get("branch_title")
    if title:
        head += f" — {title}"
    detail = []
    if branch.get("status"):
        detail.append(f"status={branch['status']}")
    if branch.get("tool"):
        detail.append(f"next tool={branch['tool']}")
    if branch.get("source"):
        detail.append(f"source={branch['source']}")
    if detail:
        head += " (" + ", ".join(detail) + ")"
    return head


def _attack_branch_dossier_path(explored: dict | None) -> str:
    branch = (explored or {}).get("attack_branch")
    if isinstance(branch, dict):
        return str(branch.get("dossier_path") or "")
    return ""


def _build_truncation_note(
    findings: list[dict] | None = None,
    explored: dict | None = None,
    *,
    emergency: bool = False,
) -> dict:
    """Build the synthetic user note inserted when history is compacted.

    Carries forward what survives compaction: submitted findings, the explored
    summary, and — when an attack_search branch is currently selected — that
    branch's id/status/next-tool plus its dossier path, so the agent can resume
    the branch with a single artifact read instead of re-deriving it.
    """
    findings_summary = _build_findings_summary(findings or [])
    explored_summary = _build_explored_summary(explored) if explored else ""
    branch_line = _attack_branch_recovery_line(explored)
    dossier_path = _attack_branch_dossier_path(explored)

    opening = (
        "[System: Earlier conversation was aggressively truncated to recover "
        "from a context-window error."
        if emergency
        else "[System: Earlier conversation was truncated to fit context window."
    )
    note_parts = [opening]
    if findings_summary:
        note_parts.append(f"Your findings so far:\n{findings_summary}")
    else:
        note_parts.append("No findings submitted yet.")
    if explored_summary:
        note_parts.append(explored_summary)
    if branch_line:
        note_parts.append(branch_line)

    recover = (
        "Call read_campaign now to recover /workspace/campaign/state.json "
        "before taking any other audit action."
    )
    if findings_summary or explored_summary:
        closing = (
            "Continue your analysis. Do not re-investigate submitted findings "
            f"unless you have new information. {recover}"
        )
    else:
        closing = f"Continue your analysis. {recover}"
    if dossier_path:
        closing += (
            f" Then read {dossier_path} to resume the current attack_search "
            "branch."
        )
    note_parts.append(closing + "]")
    return {"role": "user", "content": "\n".join(note_parts)}


def _is_tool_call_turn(turn: list[dict]) -> bool:
    return bool(
        turn
        and turn[0].get("role") == "assistant"
        and turn[0].get("tool_calls")
    )


def _age_tool_outputs(
    messages: list[dict],
    *,
    max_context: int | None = None,
    full_fidelity_recent_tool_turns: int = _RECENT_FULL_TOOL_TURNS,
    min_content_chars: int = _AGED_TOOL_OUTPUT_COMPRESS_THRESHOLD,
    tools: list[dict] | None = None,
) -> list[dict]:
    """Compress old tool outputs while keeping recent tool turns unchanged.

    When ``max_context`` is given and the history is still comfortably under
    budget, return it untouched so the prompt-cache prefix stays byte-stable;
    only compress once the conversation approaches the budget. ``tools`` is the
    visible subset placed on the wire this turn, so the budget check discounts
    exactly those schemas rather than the full set.
    """
    if (
        max_context is not None
        and _estimate_context_tokens(messages, tools)
        <= int(max_context * _APPEND_ONLY_BUDGET_FRACTION)
    ):
        return messages
    _strip_old_reasoning(messages)
    turns = _group_into_turns(messages)
    tool_turn_indexes = [
        i for i, turn in enumerate(turns)
        if _is_tool_call_turn(turn)
    ]
    keep_full = (
        set(tool_turn_indexes[-full_fidelity_recent_tool_turns:])
        if full_fidelity_recent_tool_turns > 0
        else set()
    )

    aged: list[dict] = []
    for i, turn in enumerate(turns):
        kept_turn = (
            turn if i in keep_full
            else _compress_turn(turn, min_content_chars=min_content_chars)
        )
        aged.extend(kept_turn)

    _strip_old_reasoning(aged)
    return aged


def _tool_result_failed(content: object) -> bool:
    """Return True when a tool result indicates the call did not make progress.

    Counts as a failure: the executor's argument-validation re-emit
    (``invalid_tool_arguments_json`` / ``invalid_tool_arguments_shape``), the
    controller guard block (``attack_search_next_action_required``), the generic
    dispatch failure envelope (``tool_failed``), any other tool returning a
    structured ``{"error": ...}`` payload, or a plain ``"Error: ..."`` string.
    Everything else (including useful read_file/search_code output) is treated as
    a successful outcome so progress counters reflect what actually ran.
    """
    text = content if isinstance(content, str) else str(content or "")
    text = text.strip()
    if not text:
        return False
    if text.startswith("Error:"):
        return True
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return False
        if isinstance(data, dict):
            error_code = data.get("error")
            return isinstance(error_code, str) and bool(error_code.strip())
    return False


def _attack_search_result_next_action(content: str) -> dict | None:
    """Parse an attack_search tool result, returning its ``next_action`` dict.

    Returns ``None`` for a non-JSON result, a non-dict payload, or a payload with
    no dict ``next_action`` (e.g. a guard error envelope), so callers can treat
    "no usable next_action" uniformly. The result is the compact, model-visible
    payload, so it carries the controller's ``required_toolsets`` / ``expected_tools``
    / ``pipeline`` / ``tool`` fields that drive demand-driven activation.
    """
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    next_action = data.get("next_action")
    return next_action if isinstance(next_action, dict) else None


def _record_attack_search_branch(explored: dict, next_action: dict | None) -> None:
    """Record the controller's latest selected branch from an attack_search result.

    Stores the compact next_action locator (branch id/title/status/next tool/
    source) plus the dossier path under ``explored["attack_branch"]`` so the
    truncation note can name the current branch and point at its dossier. A
    branchless next_action (e.g. a completed search) is ignored, leaving any
    previously recorded branch in place.
    """
    if not isinstance(next_action, dict):
        return
    branch = {
        key: next_action.get(key)
        for key in ("branch_id", "branch_title", "status", "tool", "source", "dossier_path")
        if next_action.get(key) not in (None, "", [], {})
    }
    if branch.get("branch_id"):
        explored["attack_branch"] = branch


def _update_explored(
    tool_calls: list[dict],
    explored: dict,
    results: list[dict] | None = None,
):
    """Update explored state based on executed tool calls.

    When ``results`` (the tool-result messages returned by
    ``_execute_tool_calls``) is provided, only calls whose result indicates a
    successful outcome contribute to progress counters; calls that were
    guard-blocked, rejected for invalid arguments, or returned a tool error are
    tallied under ``explored["failed_tool_calls"]`` by name instead of inflating
    progress. When ``results`` is omitted the legacy behaviour (count every
    well-formed call) is preserved for backward compatibility.
    """
    result_by_id: dict[str, str] = {}
    for item in results or []:
        call_id = item.get("tool_call_id")
        if call_id is not None:
            result_by_id[call_id] = item.get("content", "")

    for tc in tool_calls:
        try:
            name = tc["function"]["name"]
        except (KeyError, TypeError):
            continue

        if results is not None and _tool_result_failed(
            result_by_id.get(tc.get("id"), "")
        ):
            failed = explored.setdefault("failed_tool_calls", {})
            failed[name] = failed.get(name, 0) + 1
            continue

        try:
            args = json.loads(tc["function"]["arguments"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        if name == "inspect_scope":
            explored["scope_inspections"] = explored.get("scope_inspections", 0) + 1
        elif name == "read_file":
            path = args.get("path", "")
            if path:
                explored["files_read"].add(path)
        elif name == "run_command":
            cmd = args.get("command", "")
            for tool in ("slither", "forge", "echidna", "medusa", "halmos"):
                if tool in cmd:
                    explored["tools_run"].add(tool)
                    break
        elif name == REQUEST_TOOLSET_NAME:
            explored["toolset_requests"] = explored.get("toolset_requests", 0) + 1
            toolset = str(args.get("toolset") or "").strip().lower()
            if toolset in {*REQUESTABLE_TOOLSETS, "all"}:
                explored.setdefault("requested_toolsets", set()).add(toolset)
        elif name in _CAMPAIGN_TOOL_TRACKING:
            counters, sections = _CAMPAIGN_TOOL_TRACKING[name]
            for key in counters:
                explored[key] = explored.get(key, 0) + 1
            if name == "update_campaign":
                section = args.get("section", "")
                if section:
                    explored.setdefault("campaign_sections", set()).add(section)
            elif name == "attack_search":
                if sections:
                    explored.setdefault("campaign_sections", set()).update(sections)
                # Demand-driven toolset activation: reveal only the toolsets the
                # controller's selected next_action actually needs, instead of
                # unlocking the whole specialized surface (map+experiment+evidence)
                # on every successful sync. The agent can still pull any other
                # toolset on demand via request_toolset. Reading the next_action
                # requires the result payload, so this only fires when results are
                # provided (and only successful calls reach here).
                if results is not None:
                    next_action = _attack_search_result_next_action(
                        result_by_id.get(tc.get("id"), "")
                    )
                    # Remember the controller's latest next_action (branch +
                    # dossier) so the truncation note can point a recovering agent
                    # straight at the current branch.
                    _record_attack_search_branch(explored, next_action)
                    # Activate only what this next_action needs. An empty result
                    # leaves the active toolsets unchanged (rely on request_toolset).
                    _activate_toolsets(
                        explored,
                        _toolsets_from_attack_search_next_action(next_action),
                    )
            elif sections:
                explored.setdefault("campaign_sections", set()).update(sections)


async def _read_container_json(container: AuditContainer, path: str) -> dict | None:
    try:
        raw = await container.read_file(path)
    except (FileNotFoundError, AttributeError):
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


_ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS = {
    # Controller verbs the agent must always be able to use to drive or escape
    # the campaign loop. Blocking these creates deadlocks.
    "attack_search",
    REQUEST_TOOLSET_NAME,
    # State and scope introspection. These read campaign artifacts or build
    # derived views; they never invent evidence the submission gates rely on.
    "read_campaign",
    "review_campaign_progress",
    "build_campaign_brief",
    "inspect_scope",
    # Read-only cognitive surface. A security researcher needs to read source,
    # search patterns, list files, slice functions, and pull external context
    # throughout a campaign; the controller's branch ordering must not block these.
    "read_file",
    "search_code",
    "source_slice",
    "list_files",
    "fetch_url",
    "web_search",
    # State recording. The agent must always be able to record observations,
    # pivot hypotheses, or reject branches via mutate_hypothesis, even while
    # the controller has a must-follow next action on a different branch.
    "update_campaign",
    "mutate_hypothesis",
    # Argument synthesis is a cognitive planning tool: it proposes candidate
    # call args + setup/blockers for a step's complex ABI. It writes an
    # arg-synthesis artifact but invents no evidence the submission gates rely
    # on, so the controller's branch ordering must not block it (same class as
    # update_campaign/mutate_hypothesis).
    "synthesize_args",
    # Build diagnosis is a diagnostic/cognitive tool: it runs or parses a
    # build/test-list command and classifies blockers (missing import, pragma,
    # compiler, interface, dependency, ...) so the agent can repair setup
    # instead of re-reading raw logs. It writes only a build-diagnostic artifact
    # and never mutates an experiment, so branch ordering must not block it.
    "diagnose_build",
    # Generic state-transition / invariant modeling is a cognitive planning
    # tool: it reads source (and optionally action-space/protocol-graph
    # artifacts) and derives a delexicalized model of tracked state, who can
    # change it, candidate generic invariants, and falsification experiments. It
    # writes only a planning artifact and explicitly produces no evidence the
    # submission gates rely on (same class as source_slice/synthesize_args), so
    # the controller's branch ordering must not block it.
    "extract_state_transition_model",
    # Live on-chain investigation (host-side Alchemy enhanced APIs). These are
    # read-only — they query chain history/state and run hosted simulations,
    # never mutating campaign artifacts beyond writing their own probe evidence.
    # Like read_file/fetch_url/web_search they are cognitive surface, so branch
    # ordering must not block them. They degrade cleanly when no key is set.
    "trace_onchain_tx",
    "simulate_call",
    "state_diff",
    "enumerate_callers",
    "get_asset_transfers",
    "get_token_prices",
    "get_token_info",
    "simulate_asset_changes",
    "simulate_execution",
    "simulate_sequence",
    # Mines representative real on-chain calls (composes the read-only Alchemy
    # trace/transfer primitives) for calldata shapes, actors, and replay hints.
    # Same read-only cognitive-surface category; degrades cleanly without a key.
    "observed_tx_miner",
    # Verified-source lookup (host-side Etherscan). Read-only context, same
    # cognitive-surface category as the Alchemy investigation tools above.
    "get_contract_source",
}

# Regex used by the run_experiment workspace exception. Validation of the
# agent's own experiments must not be gated by branch ordering; the workspace
# under /workspace/experiments/ is created exclusively by tools the campaign
# already authorised (compose_sequence_experiment, compose_invariant_harness,
# create_experiment), so allowing run_experiment against it is a clean bypass
# of the controller without weakening evidence integrity.
_LOCAL_EXPERIMENT_WORKSPACE_PATTERN = re.compile(r"/workspace/experiments/")


def _run_experiment_targets_local_workspace(tool_args: dict | None) -> bool:
    """Return True if a run_experiment call targets the agent's own workspace.

    The agent's experiments live under ``/workspace/experiments/exp-NNN-...``.
    Running validation tests against them must always be allowed so the
    deterministic controller cannot block the agent from validating work it
    has already produced. Commands targeting other paths fall through to the
    normal guard logic.
    """
    if not isinstance(tool_args, dict):
        return False
    command = tool_args.get("command")
    if not isinstance(command, str) or not command:
        return False
    return bool(_LOCAL_EXPERIMENT_WORKSPACE_PATTERN.search(command))


def _attack_search_expected_tool_names(next_tool: object) -> set[str]:
    text = str(next_tool or "").strip()
    if not text:
        return set()
    return {
        name for name in TOOL_BY_NAME
        if re.search(rf"\b{re.escape(name)}\b", text)
    }


def _attack_search_expected_tools(next_action: dict | None) -> set[str]:
    """Resolve the tools a next_action requires, preferring structured fields.

    The controller may carry an explicit ``expected_tools`` list or an ordered
    ``pipeline`` of ``{"tool": ...}`` steps. When either is present we trust those
    exact names instead of scanning the free-text ``tool`` field for substrings,
    which removes the ambiguity of a description that mentions several tools.
    Falls back to the regex scan of ``tool`` only when no structured field
    resolves to a known tool.
    """
    if not isinstance(next_action, dict):
        return _attack_search_expected_tool_names(next_action)

    structured: set[str] = set()
    expected = next_action.get("expected_tools")
    if isinstance(expected, list):
        for item in expected:
            name = str(item or "").strip()
            if name in TOOL_BY_NAME:
                structured.add(name)
    pipeline = next_action.get("pipeline")
    if isinstance(pipeline, list):
        for step in pipeline:
            if isinstance(step, dict):
                name = str(step.get("tool") or "").strip()
            else:
                name = str(step or "").strip()
            if name in TOOL_BY_NAME:
                structured.add(name)
    if structured:
        return structured
    return _attack_search_expected_tool_names(next_action.get("tool"))


def _toolsets_from_attack_search_next_action(next_action: dict | None) -> set[str]:
    """Resolve the specialized toolsets a controller next_action needs activated.

    Demand-driven activation: after a successful attack_search the audit loop
    reveals only the toolsets needed to execute the selected branch, not the whole
    specialized surface. Resolution order, most to least authoritative:

    1. ``next_action["required_toolsets"]`` — the controller's own declaration.
       Honored whenever it names at least one known toolset (an all-``core``
       declaration legitimately resolves to "activate nothing specialized").
    2. Otherwise the tools the branch pins via ``expected_tools`` / ``pipeline`` /
       the free-text ``tool`` field (resolved by ``_attack_search_expected_tools``,
       the same resolver the controller guard uses), mapped back to their owning
       toolsets so the required tool is guaranteed visible.

    ``core`` is always active, so it is never returned. Returns an empty set when
    nothing resolves (or the search is complete), so the caller leaves the active
    toolsets unchanged and the agent falls back to request_toolset.
    """
    if not isinstance(next_action, dict):
        return set()
    if next_action.get("status") == "complete":
        return set()

    specialized = set(REQUESTABLE_TOOLSETS)
    known = specialized | {"core"}
    declared = next_action.get("required_toolsets")
    if isinstance(declared, (list, tuple, set)):
        tokens = {
            str(item).strip().lower() for item in declared if str(item).strip()
        }
        if tokens & known:
            # The controller named at least one known toolset — authoritative.
            return tokens & specialized

    return toolsets_for_tool_names(_attack_search_expected_tools(next_action))


# Leading "VAR=value" environment assignments are configuration, not execution,
# so they are ignored when matching a diagnostic command shape (e.g. the
# common FOUNDRY_PROFILE=ci prefix).
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=[^\s]*$")

# Shell syntax that can chain, background, substitute, or append output — any of
# these can smuggle a state-changing or file-writing command past an otherwise
# read-only prefix, so their presence disqualifies a command from the diagnostic
# fast-path. (A single ">" stdout/stderr redirect is handled separately and only
# allowed into a campaign/output log root.)
_NON_DIAGNOSTIC_SHELL_TOKENS = (";", "|", "&", "`", "$", ">>", "<", "(", ")", "\n")

# A single redirect is allowed only into these roots so static-analysis output
# can be captured as campaign evidence; anything else is treated as a write
# target outside the agent's scratch space and disqualifies the command.
_DIAGNOSTIC_REDIRECT_ROOTS = ("/workspace/", "/output/")

# Read-only diagnostic command shapes the controller must not block: the agent
# needs to compile, inspect config/artifacts, list tests, or run static analysis
# while pursuing an unrelated required next action. These never send
# transactions, install dependencies, or run stateful generated tests.
_DIAGNOSTIC_COMMAND_PREFIXES = (
    ("forge", "build"),
    ("forge", "config"),
    ("forge", "inspect"),
)


def _diagnostic_redirect_target_allowed(target: str) -> bool:
    return any(target.startswith(root) for root in _DIAGNOSTIC_REDIRECT_ROOTS)


def _diagnostic_command_core(tokens: list[str]) -> list[str] | None:
    """Strip validated redirects from a token list, returning the base command.

    Returns ``None`` if a redirect points outside the allowed log roots or uses
    an unexpected file-descriptor form, so the caller treats the command as
    non-diagnostic.
    """
    base: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if ">" in tok:
            fd, _, attached = tok.partition(">")
            if fd not in ("", "1", "2"):
                return None
            if attached:
                target = attached
            else:
                i += 1
                if i >= n:
                    return None
                target = tokens[i]
            if not _diagnostic_redirect_target_allowed(target):
                return None
            i += 1
            continue
        base.append(tok)
        i += 1
    return base


def _run_command_is_diagnostic(tool_args: dict | None) -> bool:
    """Return True for clearly read-only run_command diagnostics.

    Conservative by design: anything with shell chaining/expansion, a redirect
    outside a campaign/output log, or a command outside the small static
    allowlist (``forge build``/``config``/``inspect``, ``forge test --list``,
    ``slither``) is rejected so it still respects the controller's branch
    ordering. read_file/search_code/source_slice cover ordinary reads; this only
    unblocks build/inspect/static-analysis runs the agent needs for diagnosis.
    """
    if not isinstance(tool_args, dict):
        return False
    command = tool_args.get("command")
    if not isinstance(command, str):
        return False
    command = command.strip()
    if not command:
        return False
    if any(meta in command for meta in _NON_DIAGNOSTIC_SHELL_TOKENS):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    base = _diagnostic_command_core(tokens)
    if base is None:
        return False
    while base and _ENV_ASSIGNMENT_RE.match(base[0]):
        base = base[1:]
    if not base:
        return False
    if tuple(base[:2]) in _DIAGNOSTIC_COMMAND_PREFIXES:
        return True
    if base[:2] == ["forge", "test"] and "--list" in base:
        return True
    if base[0] == "slither":
        return True
    return False


async def _attack_search_tool_guard(
    container: AuditContainer,
    *,
    tool_name: str,
    turn_tool_names: set[str],
    tool_args: dict | None = None,
) -> str | None:
    if tool_name in _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS:
        return None
    if (
        tool_name == "run_experiment"
        and _run_experiment_targets_local_workspace(tool_args)
    ):
        return None
    if tool_name == "repair_experiment":
        # repair_experiment only ever edits the agent's own experiment workspace
        # under /workspace/experiments/ (it errors on any other target). Like the
        # run_experiment local-workspace exception, repairing an agent-created
        # experiment so it can be validated must not be gated by branch ordering;
        # the submission gates still verify the resulting evidence.
        return None
    if tool_name == "run_command" and _run_command_is_diagnostic(tool_args):
        # Read-only build/inspect/static-analysis diagnostics are cognitive
        # surface: the agent must be able to compile, list tests, or run slither
        # while a different branch is "first". Non-diagnostic run_command usage
        # still respects the controller below.
        return None
    search = await _read_container_json(container, _ATTACK_SEARCH_CURRENT_PATH)
    if not search:
        return None
    next_action = search.get("next_action") or {}
    if next_action.get("status") == "complete":
        return None
    expected_tools = _attack_search_expected_tools(next_action)
    if not expected_tools:
        return None
    if tool_name in expected_tools:
        return None
    if tool_name in PARALLEL_SAFE and expected_tools.intersection(turn_tool_names):
        return None
    return json.dumps({
        "error": "attack_search_next_action_required",
        "blocked_tool": tool_name,
        "required_tools": sorted(expected_tools),
        "next_action": {
            "branch_id": next_action.get("branch_id"),
            "status": next_action.get("status"),
            "tool": next_action.get("tool"),
            "source": next_action.get("source"),
        },
        "message": (
            "The deterministic attack-search controller has an active "
            "must-follow next action. Execute the required tool, or call "
            "attack_search with action=decision/advance if that branch is no "
            "longer viable."
        ),
    }, indent=2, sort_keys=True)


def _campaign_branch_terminal(branch: dict) -> bool:
    return (
        branch.get("status") in _ATTACK_SEARCH_TERMINAL_STATUSES
        or bool(branch.get("terminal_decision"))
    )


def _campaign_branch_score(branch: dict) -> int:
    try:
        return int(branch.get("priority_score", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _campaign_branch_has_economic_signal(branch: dict) -> bool:
    binding = branch.get("target_binding") or {}
    if binding.get("economically_significant_hint"):
        return True
    if str(binding.get("kind") or "") in {
        "active_proxy",
        "deployed_economic_contract",
        "deployed_configured_contract",
    }:
        return True
    if (branch.get("inventory_context") or {}).get("economically_significant_targets"):
        return True
    labels = {
        str(label)
        for action in branch.get("target_actions") or []
        if isinstance(action, dict)
        for label in action.get("affordances") or []
    }
    return bool(labels.intersection({
        "value_out_or_burn",
        "credit_or_liquidation",
        "valuation_dependency",
        "market_or_router",
        "callback_or_flashloan_surface",
        "cross_domain_or_message",
        "generic_execution",
        "delegatecall",
    }))


_LOW_SIGNAL_COVERAGE_TERMS = (
    "mock",
    "test",
    "fixture",
    "certora",
    "interface",
    "script",
    "helper",
    "library",
)


def _campaign_branch_is_low_signal_coverage_cleanup(branch: dict) -> bool:
    if str(branch.get("source") or "") != "coverage_high_attention_gap":
        return False
    if str(branch.get("status") or "") != "needs_context":
        return False
    if _campaign_branch_has_economic_signal(branch):
        return False
    score = _campaign_branch_score(branch)
    text_parts = [
        str(branch.get("title") or ""),
        str(branch.get("key") or ""),
        str(branch.get("instructions") or ""),
        " ".join(str(item) for item in branch.get("action_keys") or []),
    ]
    for action in branch.get("target_actions") or []:
        if isinstance(action, dict):
            text_parts.extend([
                str(action.get("contract") or ""),
                str(action.get("function") or ""),
                str(action.get("file") or ""),
            ])
    text = " ".join(text_parts).lower()
    return score < 18 and any(term in text for term in _LOW_SIGNAL_COVERAGE_TERMS)


def _campaign_stop_branch_blocker(branch: dict) -> dict | None:
    if _campaign_branch_terminal(branch):
        return None
    if _campaign_branch_is_low_signal_coverage_cleanup(branch):
        return None
    status = str(branch.get("status") or "")
    source = str(branch.get("source") or "")
    priority = str(branch.get("priority") or "").lower()
    score = _campaign_branch_score(branch)
    high_signal = (
        priority in {"critical", "high"}
        or score >= 18
        or _campaign_branch_has_economic_signal(branch)
    )
    must_block = (
        status in _STOP_BLOCKING_STATUSES
        or source in {
            "ready_report_review",
            "ready_finding_review",
            "result_without_objective",
            "candidate_fuzz_failure",
            "unreviewed_sequence_minimization",
        }
        or (
            source == "attack_graph_candidate"
            and status in _STOP_LIVE_BRANCH_STATUSES
            and high_signal
        )
        or (
            source == "coverage_high_attention_gap"
            and high_signal
        )
    )
    if not must_block:
        return None
    return {
        "branch_id": branch.get("id"),
        "status": status,
        "source": source,
        "priority": priority,
        "priority_score": score,
        "next_tool": branch.get("next_tool"),
        "title": str(branch.get("title") or "")[:180],
    }


async def _campaign_stop_readiness(container: AuditContainer) -> dict:
    blockers = []
    search = await _read_container_json(container, _ATTACK_SEARCH_CURRENT_PATH)
    if search:
        active = [
            branch for branch in search.get("branches") or []
            if isinstance(branch, dict) and not _campaign_branch_terminal(branch)
        ]
        for branch in active:
            blocker = _campaign_stop_branch_blocker(branch)
            if blocker:
                blockers.append({"kind": "active_attack_search_branch", **blocker})

    state = await _read_container_json(container, _CAMPAIGN_STATE_PATH)
    latest_progress = None
    if state:
        try:
            progress_count = int(
                ((state.get("counters") or {}).get("progress_review") or 0)
            )
        except (TypeError, ValueError):
            progress_count = 0
        if progress_count > 0:
            latest_progress = await _read_container_json(
                container,
                f"{_PROGRESS_REVIEW_DIR}/prg-{progress_count:03d}.json",
            )

    if latest_progress:
        summary = latest_progress.get("summary") or {}
        for key in _STOP_READY_PROGRESS_KEYS:
            try:
                count = int(summary.get(key, 0) or 0)
            except (TypeError, ValueError):
                count = 0
            if count > 0:
                blockers.append({
                    "kind": "progress_gap",
                    "gap": key,
                    "count": count,
                    "path": latest_progress.get("path")
                    or f"{_PROGRESS_REVIEW_DIR}/{latest_progress.get('id')}.json",
                })
        coverage_gaps = latest_progress.get("coverage_high_attention_gaps") or []
        unresolved_high_coverage = []
        for item in coverage_gaps:
            try:
                high_gaps = int(
                    (item.get("summary") or {}).get("high_attention_gaps", 0) or 0
                )
            except (AttributeError, TypeError, ValueError):
                high_gaps = 0
            if high_gaps > 0:
                unresolved_high_coverage.append(item)
        if unresolved_high_coverage:
            blockers.append({
                "kind": "progress_gap",
                "gap": "coverage_high_attention_gaps",
                "count": len(unresolved_high_coverage),
                "path": latest_progress.get("path")
                or f"{_PROGRESS_REVIEW_DIR}/{latest_progress.get('id')}.json",
            })

    return {
        "ready": not blockers,
        "blockers": blockers[:8],
        "omitted_blockers": max(0, len(blockers) - 8),
        "checked": {
            "attack_search": bool(search),
            "progress_review": bool(latest_progress),
        },
    }


async def _record_final_readiness(
    container: AuditContainer,
    explored: dict,
    *,
    reason: str,
) -> dict:
    readiness = await _campaign_stop_readiness(container)
    explored["final_readiness"] = readiness
    if not readiness["ready"]:
        explored["audit_status"] = "incomplete_no_validated_findings"
        explored["audit_status_reason"] = reason
    return readiness


def _truncate_messages(
    messages: list[dict],
    findings: list[dict] | None = None,
    explored: dict | None = None,
    max_estimated_tokens: int = 100_000,
    *,
    force: bool = False,
    tools: list[dict] | None = None,
) -> list[dict]:
    """Keep system prompt, early turns, and recent turns within context limit.

    ``tools`` is the visible subset placed on the wire this turn; the budget
    estimates discount exactly those schemas so a demand-driven turn is not
    measured against the full tool set it never sends.

    Uses turn-based grouping so that assistant tool_call messages and their
    tool result messages are always kept or dropped together — never split.

    Reasoning content from old assistant messages is always stripped
    proactively (keeping only the most recent for tool-call continuity),
    since it can be very large and serves no purpose once the model has
    moved on.

    Truncation strategy (two-phase, only when over budget after stripping):
    1. Recent turns are kept at full fidelity (most recent first).
    2. Older turns that don't fit at full size are compressed — bulky tool
       results are replaced with short summaries while assistant content and
       tool calls are preserved. Compressed turns fill whatever budget remains.

    A truncation note is injected with a summary of findings and explored
    state so the agent retains knowledge of what it has discovered and
    analyzed even when the original conversation turns are gone.

    Turn costs are precomputed once to avoid repeated JSON serialization.
    """
    # Under budget and not forced: leave the history byte-identical so the
    # provider prompt cache keeps hitting the stable prefix. Stripping/compacting
    # here would reclaim space we don't need yet at the cost of a cache miss.
    if not force and _estimate_context_tokens(messages, tools) <= max_estimated_tokens:
        return messages

    # Over budget (or forced): reclaim space. Drop replayed reasoning first —
    # it's large and only the most recent assistant message needs it for
    # tool-call continuity — and that alone may bring us back under budget.
    _strip_old_reasoning(messages)

    original_estimate = _estimate_context_tokens(messages, tools)
    if not force and original_estimate <= max_estimated_tokens:
        return messages
    if force and original_estimate <= max_estimated_tokens:
        max_estimated_tokens = max(1_000, int(original_estimate * 0.80))

    turns = _group_into_turns(messages)

    # Precompute per-turn token costs (avoids repeated serialization)
    turn_costs = [_estimate_tokens(turn) for turn in turns]

    # Always keep: system prompt (turn 0), first 2 turns for initial context
    system_turns = turns[:1]
    early_turns = turns[1:3]
    remaining_turns = turns[3:]
    remaining_costs = turn_costs[3:]

    truncation_note = [_build_truncation_note(findings, explored, emergency=force)]

    # Calculate base costs using precomputed values
    base_cost = sum(turn_costs[:min(3, len(turn_costs))])
    note_cost = _estimate_tokens(truncation_note)
    remaining_budget = max_estimated_tokens - base_cost - note_cost - 500

    # Phase 1: Fill recent turns (full fidelity) from the end
    recent_turns: list[list[dict]] = []
    for i in range(len(remaining_turns) - 1, -1, -1):
        cost = remaining_costs[i]
        if remaining_budget - cost < 0:
            break
        recent_turns.insert(0, remaining_turns[i])
        remaining_budget -= cost

    # Phase 2: Compress and fit dropped middle turns
    dropped_count = len(remaining_turns) - len(recent_turns)
    middle_turns = remaining_turns[:dropped_count]

    compressed_kept: list[list[dict]] = []
    if middle_turns:
        for turn in reversed(middle_turns):
            compressed = _compress_turn(turn)
            cost = _estimate_tokens(compressed)
            if remaining_budget - cost < 0:
                break
            compressed_kept.insert(0, compressed)
            remaining_budget -= cost

    # Assemble: system + early + truncation note + compressed middle + recent
    result = [msg for turn in system_turns + early_turns for msg in turn]
    result.extend(truncation_note)
    for turn in compressed_kept:
        result.extend(turn)
    for turn in recent_turns:
        result.extend(turn)

    # Strip reasoning from all but the most recent assistant message to
    # reclaim context space (_compress_turn already strips compressed turns;
    # this catches surviving recent turns that aren't the latest).
    _strip_old_reasoning(result)

    if _estimate_context_tokens(result, tools) > max_estimated_tokens:
        return _emergency_truncate_messages(
            messages,
            findings,
            explored,
            max_estimated_tokens,
            tools=tools,
        )

    return result


def _emergency_truncate_messages(
    messages: list[dict],
    findings: list[dict] | None,
    explored: dict | None,
    max_estimated_tokens: int,
    *,
    tools: list[dict] | None = None,
) -> list[dict]:
    """Last-resort compaction used after a context-window error."""
    _strip_old_reasoning(messages)
    turns = _group_into_turns(messages)
    system_turns = turns[:1] if turns and turns[0][0].get("role") == "system" else []
    candidate_turns = turns[1:] if system_turns else turns
    note = [_build_truncation_note(findings, explored, emergency=True)]

    base = [msg for turn in system_turns for msg in turn] + note
    if _estimate_context_tokens(base, tools) > max_estimated_tokens and system_turns:
        system_msg = dict(system_turns[0][0])
        content = system_msg.get("content", "")
        if len(content) > 8_000:
            system_msg["content"] = (
                content[:8_000]
                + "\n[... system prompt truncated during context recovery]"
            )
        base = [system_msg] + note
    if _estimate_context_tokens(base, tools) > max_estimated_tokens:
        base = note

    kept_turns: list[list[dict]] = []
    for turn in reversed(candidate_turns):
        compressed = _compress_turn(turn)
        trial_turns = [compressed] + kept_turns
        trial = base + [msg for kept in trial_turns for msg in kept]
        if _estimate_context_tokens(trial, tools) <= max_estimated_tokens:
            kept_turns = trial_turns

    result = base + [msg for turn in kept_turns for msg in turn]
    _strip_old_reasoning(result)
    return result


# ── Main audit loop ─────────────────────────────────────────────────────


async def run_audit(
    client: ResponsesLLMClient,
    model: str,
    system_prompt: str,
    container: AuditContainer,
    display: Display,
    max_time_seconds: int = DEFAULT_MAX_TIME_SECONDS,
    prior_findings: list[dict] | None = None,
    max_context: int = calculate_max_context(DEFAULT_CONTEXT_WINDOW),
    reasoning_config: dict | None = None,
    init_report: str | None = None,
    initial_toolsets: set[str] | None = None,
    context_window: int | None = None,
    max_context_is_user_cap: bool = False,
) -> tuple[list[dict], list[dict], dict]:
    """
    Run the audit agent loop.
    Returns (findings, messages, explored) — findings list, conversation
    history, and explored state (files read, tools run).

    If init_report is provided, it is injected as the first user message
    so the agent starts with full visibility into container setup status.

    If prior_findings is provided (e.g. from a previous audit via keep-auditing),
    a summary is injected at the start so the agent knows what was already
    discovered and can focus on unexplored areas.

    max_context is the conversation-history token budget. When the user did not
    set an explicit cap it is the conservative full-TOOLS reserve from
    calculate_max_context(); when they did (--max-context), it is that hard cap
    and max_context_is_user_cap is True.

    context_window, when provided, sizes the per-turn history budget to the tools
    actually placed on the wire that turn: a turn that exposes only the core
    toolset reserves less schema overhead than the conservative full-TOOLS
    budget, so more of the window is left for history. Without a user cap the
    per-turn budget is that reclaimed visible-tool budget (it may legitimately
    exceed the static full-tool max_context); with a user cap it is clamped to
    max_context so the user's ceiling is always respected. When context_window is
    None (the default for existing callers), the static max_context is used
    unchanged on every turn. See _turn_history_budget().
    """
    messages = [{"role": "system", "content": system_prompt}]

    # Inject container initialization report so the agent starts with
    # full visibility into what succeeded/failed during setup.
    if init_report:
        messages.append({
            "role": "user",
            "content": (
                "[Container initialization report]\n" + init_report
            ),
        })

    # On resumed audits, tell the agent what was already found
    if prior_findings:
        summary = _build_findings_summary(prior_findings)
        messages.append({
            "role": "user",
            "content": (
                "This is a resumed audit. The following findings were already "
                "submitted in a prior session — do not re-investigate these. "
                "Focus on unexplored areas and contracts.\n\n"
                f"Prior findings:\n{summary}"
            ),
        })

    findings: list[dict] = []
    explored: dict = {
        "files_read": set(),
        "tools_run": set(),
        "active_toolsets": expand_toolsets(initial_toolsets or DEFAULT_TOOLSETS),
    }
    reasoning_tokens_used = 0
    start_time = time.time()
    turn = 0
    time_warned_90 = False
    time_warned_95 = False
    wrap_up_requested = False
    wrap_up_injected = False  # ensures wrap-up message is only injected once
    consecutive_truncations = 0
    early_stop_nudges = 0
    campaign_state_nudged = False
    attack_search_nudged = False
    final_readiness_nudges = 0
    final_readiness_required = None

    # Signal handling for graceful shutdown
    shutdown_count = 0

    def _signal_handler(sig, frame):
        nonlocal shutdown_count, wrap_up_requested
        shutdown_count += 1
        if shutdown_count == 1:
            display.status("\nCtrl+C received — asking agent to wrap up...")
            wrap_up_requested = True
        else:
            display.status("\nForce quit — saving findings...")
            raise KeyboardInterrupt

    old_handler = signal.signal(signal.SIGINT, _signal_handler)

    try:
        while True:
            elapsed = time.time() - start_time
            time_fraction = (
                elapsed / max_time_seconds if max_time_seconds > 0 else 0
            )

            # Wall-clock limit reached — allow one final wrap-up turn.
            if elapsed >= max_time_seconds:
                if not wrap_up_requested:
                    note = _toolset_activation_note(
                        _activate_toolsets(explored, {"report"}),
                        reason="wrap-up",
                    )
                    if note:
                        messages.append(note)
                    messages.append({
                        "role": "user",
                        "content": (
                            "Wall-clock limit reached. Submit any remaining findings NOW "
                            "using submit_finding, then stop."
                        ),
                    })
                    wrap_up_requested = True
                    wrap_up_injected = True
                else:
                    readiness = await _record_final_readiness(
                        container,
                        explored,
                        reason="wall_clock_limit_reached_with_active_campaign_work",
                    )
                    if not readiness["ready"]:
                        display.error(
                            "Wall-clock limit reached with unresolved "
                            "campaign work; marking audit incomplete."
                        )
                    break

            # Soft signals — at most one per turn, never duplicated
            elif wrap_up_requested and turn > 0 and not wrap_up_injected:
                # Ctrl+C wrap-up — inject once
                wrap_up_injected = True
                note = _toolset_activation_note(
                    _activate_toolsets(explored, {"report"}),
                    reason="wrap-up",
                )
                if note:
                    messages.append(note)
                messages.append({
                    "role": "user",
                    "content": (
                        "Wrap up now. Submit your strongest findings using "
                        "submit_finding and stop."
                    ),
                })
            elif time_fraction >= 0.95 and not time_warned_95:
                time_warned_95 = True
                note = _toolset_activation_note(
                    _activate_toolsets(explored, {"report"}),
                    reason="late-audit submission window",
                )
                if note:
                    messages.append(note)
                messages.append({
                    "role": "user",
                    "content": (
                        "The wall-clock limit is nearly exhausted. Submit any "
                        "remaining findings now."
                    ),
                })
            elif time_fraction >= 0.90 and not time_warned_90:
                time_warned_90 = True
                note = _toolset_activation_note(
                    _activate_toolsets(explored, {"report"}),
                    reason="late-audit submission window",
                )
                if note:
                    messages.append(note)
                messages.append({
                    "role": "user",
                    "content": (
                        "You have used 90% of your wall-clock limit. Start wrapping up. "
                        "Focus on validating your strongest findings and submitting them."
                    ),
                })

            turn += 1

            if (
                turn > _ATTACK_SEARCH_REQUIRED_BY_TURN
                and not attack_search_nudged
                and not wrap_up_requested
                and explored.get("attack_search_runs", 0) == 0
            ):
                attack_search_nudged = True
                messages.append({
                    "role": "user",
                    "content": (
                        "Initialize the deterministic attack-search controller "
                        "now: call attack_search with action=sync, then follow "
                        "its next_action.tool before continuing broad analysis."
                    ),
                })

            if (
                turn > _CAMPAIGN_STATE_REQUIRED_BY_TURN
                and not campaign_state_nudged
                and not wrap_up_requested
                and explored.get("campaign_updates", 0) == 0
            ):
                campaign_state_nudged = True
                messages.append({
                    "role": "user",
                    "content": (
                        "You have not recorded any structured campaign state yet. "
                        "Before continuing broad analysis, use update_campaign to "
                        "record the current protocol model, at least one value "
                        "flow or trust boundary, and one invariant or open "
                        "question. Record a hypothesis only if it is concrete "
                        "and evidence-backed. Add an experiment only if a branch "
                        "is already concrete; otherwise record the missing "
                        "precondition as an open_question or blocked hypothesis "
                        "instead of inventing a placeholder experiment."
                    ),
                })

            # Show progress every 5 turns
            if turn % 5 == 0 or turn == 1:
                display.progress_status(
                    elapsed, max_time_seconds,
                    turn,
                    reasoning_tokens=reasoning_tokens_used,
                )

            # Size the per-turn history budget to the tools actually sent this
            # turn. Demand-driven visibility means a turn often exposes far fewer
            # than the full TOOLS set, so its schema overhead is smaller; when a
            # context_window is known we reclaim that headroom for history (unless
            # the user pinned an explicit max_context cap, which is then honored).
            visible_tools = _visible_tools(explored)
            turn_max_context = _turn_history_budget(
                max_context,
                context_window=context_window,
                visible_tools=visible_tools,
                max_context_is_user_cap=max_context_is_user_cap,
            )

            # Context window management
            messages = _truncate_messages(
                messages, findings, explored, turn_max_context, tools=visible_tools
            )

            # Call LLM (streaming)
            try:
                (
                    response_message,
                    _,
                    r_tokens,
                    finish_reason,
                    messages,
                ) = await _stream_turn_with_recovery(
                    client,
                    model,
                    messages,
                    display,
                    findings=findings,
                    explored=explored,
                    max_context=turn_max_context,
                    tools=visible_tools,
                    reasoning_config=reasoning_config,
                )
            except Exception as e:
                display.error(f"LLM call failed after recovery attempts: {e}")
                explored["llm_error"] = str(e)
                break

            reasoning_tokens_used += r_tokens
            messages.append(response_message)

            # If no tool calls, check whether it was intentional or truncation
            if not response_message.get("tool_calls"):
                if finish_reason == "length":
                    # Response was truncated by max_output_tokens; the model
                    # likely started tool calls but they were cut off.
                    consecutive_truncations += 1
                    display.error(
                        f"Response truncated, retrying ({consecutive_truncations})..."
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your last response was cut off (hit the output "
                            "token limit) before you could include tool calls. "
                            "Keep your reasoning very brief and emit your next "
                            "tool call immediately."
                        ),
                    })
                    continue
                # Early-termination guard: reject premature stops
                if (turn < _MIN_AUDIT_TURNS
                        and not wrap_up_requested):
                    early_stop_nudges += 1
                    display.error(
                        f"Agent tried to stop at turn {turn}/{_MIN_AUDIT_TURNS} "
                        f"(nudge {early_stop_nudges})"
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "The audit has barely started — do not stop. "
                            "If compilation or test discovery failed, call "
                            "diagnose_build first to classify the blocker before "
                            "any manual dependency repair. If the failure is in a "
                            "generated experiment workspace, use repair_experiment "
                            "for narrow scaffold repairs. Only spend manual "
                            "run_command turns on dependency repair after diagnosis "
                            "says the blocker is external dependency/setup and you "
                            "have time-boxed it. "
                            "If the project cannot compile after a few diagnosed "
                            "attempts, switch to manual source review with "
                            "source_slice, read_file, and search_code, record the "
                            "blocker in campaign state with update_campaign, and "
                            "continue through attack_search. "
                            "If action-space mapping exists but the branch space is "
                            "unclear, use extract_state_transition_model and "
                            "build_attack_graph to preserve generic invariant/"
                            "frontier branches before narrowing into "
                            "mechanism-specific lenses. "
                            "Continue with protocol modeling, value-flow mapping, "
                            "open questions, concrete hypotheses when supported, "
                            "and experiments only when branches are ready."
                        ),
                    })
                    continue
                final_readiness_complete = (
                    final_readiness_required is not None
                    and explored.get("attack_search_runs", 0)
                    > final_readiness_required.get("attack_search_runs", 0)
                    and explored.get("progress_reviews", 0)
                    > final_readiness_required.get("progress_reviews", 0)
                )
                if not wrap_up_requested and not final_readiness_complete:
                    if final_readiness_required is None:
                        final_readiness_required = {
                            "attack_search_runs": explored.get("attack_search_runs", 0),
                            "progress_reviews": explored.get("progress_reviews", 0),
                        }
                    final_readiness_nudges += 1
                    display.error(
                        "Agent tried to stop without a final campaign readiness sync "
                        f"(nudge {final_readiness_nudges})"
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "Before stopping, perform one final campaign readiness "
                            "check: call attack_search with action=sync, then call "
                            "review_campaign_progress. If either tool reports active "
                            "branches, process gaps, ready reviews, or economically "
                            "significant live/deployed targets that still need "
                            "inventory, harnessing, objective evidence, mutation, or "
                            "submission, follow that next action instead of stopping. "
                            "Stop only after that readiness check supports no viable "
                            "high/critical live economic finding path, or after "
                            "submitting any ready findings."
                        ),
                    })
                    continue
                readiness = await _campaign_stop_readiness(container)
                if wrap_up_requested:
                    explored["final_readiness"] = readiness
                    if not readiness["ready"]:
                        explored["audit_status"] = "incomplete_no_validated_findings"
                        explored["audit_status_reason"] = "wrap_up_requested"
                        display.error(
                            "Stopping during wrap-up with unresolved campaign "
                            "work; marking audit incomplete."
                        )
                else:
                    if not readiness["ready"]:
                        display.error(
                            "Deterministic readiness check found unresolved "
                            "campaign work"
                        )
                        messages.append({
                            "role": "user",
                            "content": (
                                "Do not stop yet. The deterministic campaign "
                                "readiness check found unresolved high-signal "
                                "work:\n"
                                + json.dumps(readiness, indent=2, sort_keys=True)
                                + "\nFollow the relevant attack_search next action, "
                                "run the needed inventory/harness/evidence/review "
                                "step, submit ready findings, or record an explicit "
                                "attack_search decision if the branch is not viable."
                            ),
                        })
                        continue
                display.agent_done()
                break
            else:
                consecutive_truncations = 0  # reset on successful tool call
                early_stop_nudges = 0

            # Execute tool calls
            tool_results = await _execute_tool_calls(
                response_message["tool_calls"],
                container, findings, display,
            )
            messages.extend(tool_results)
            messages = _age_tool_outputs(
                messages, max_context=turn_max_context, tools=visible_tools
            )

            # Track explored state (success-based: failed/blocked calls are
            # tallied separately, not counted as campaign progress)
            _update_explored(response_message["tool_calls"], explored, tool_results)
            note = _toolset_activation_note(
                _activate_requested_toolsets(response_message["tool_calls"], explored),
                reason="request_toolset",
            )
            if note:
                messages.append(note)

    finally:
        signal.signal(signal.SIGINT, old_handler)

    return findings, messages, explored


async def _stream_turn(
    client: ResponsesLLMClient,
    model: str,
    messages: list[dict],
    display: Display,
    tools: list[dict] | None = None,
    max_output_tokens: int | None = _OUTPUT_RESERVE,
    reasoning_config: dict | None = None,
) -> tuple[dict, int, int, str | None]:
    """Make one streaming LLM call.

    Returns (assistant_message, total_token_count, reasoning_token_count,
    finish_reason).  finish_reason is "stop", "length", "tool_calls", or
    None if the API didn't report it.
    """
    if max_output_tokens is None:
        adjusted_max = get_model_max_output_tokens(model)
    else:
        adjusted_max = min(max_output_tokens, get_model_max_output_tokens(model))
    return await client.stream_turn(
        model=model,
        messages=messages,
        tools=tools if tools is not None else tools_for_toolsets(DEFAULT_TOOLSETS),
        display=display,
        max_output_tokens=adjusted_max,
        reasoning_config=reasoning_config,
    )


def _is_context_window_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(fragment in message for fragment in (
        "context window",
        "context length",
        "context_length_exceeded",
        "input exceeds",
        "too many tokens",
        "maximum context",
    ))


async def _stream_turn_with_recovery(
    client: ResponsesLLMClient,
    model: str,
    messages: list[dict],
    display: Display,
    *,
    findings: list[dict] | None = None,
    explored: dict | None = None,
    max_context: int,
    tools: list[dict] | None = None,
    max_output_tokens: int | None = _OUTPUT_RESERVE,
    reasoning_config: dict | None = None,
) -> tuple[dict, int, int, str | None, list[dict]]:
    """Stream one turn, shrinking only the retry payload after context errors."""
    transient_attempts = 0
    context_attempts = 0

    while True:
        try:
            response, total, reasoning, finish_reason = await _stream_turn(
                client,
                model,
                messages,
                display,
                tools=tools,
                max_output_tokens=max_output_tokens,
                reasoning_config=reasoning_config,
            )
            return response, total, reasoning, finish_reason, messages
        except Exception as exc:
            if _is_context_window_error(exc):
                if context_attempts >= len(_CONTEXT_RETRY_FACTORS):
                    raise
                factor = _CONTEXT_RETRY_FACTORS[context_attempts]
                context_attempts += 1
                retry_budget = max(int(max_context * factor), 10_000)
                display.error(
                    "LLM input exceeded the context window; retrying with "
                    f"a smaller one-call context budget ({retry_budget:,} "
                    "estimated tokens)..."
                )
                messages = _truncate_messages(
                    messages,
                    findings,
                    explored,
                    retry_budget,
                    force=True,
                    tools=tools,
                )
                transient_attempts = 0
                continue

            if transient_attempts >= 3:
                raise
            transient_attempts += 1
            display.error(
                f"LLM call failed ({exc}), retrying ({transient_attempts}/3)..."
            )
            await asyncio.sleep(2 ** (transient_attempts - 1))


async def _execute_tool_calls(
    tool_calls: list[dict],
    container: AuditContainer,
    findings: list[dict],
    display: Display,
    *,
    enforce_attack_search: bool = True,
) -> list[dict]:
    """Execute tool calls, batching adjacent read-only calls where safe.

    Result messages are returned in the same order as the model's tool calls.
    Side-effecting tools form ordering barriers so reads cannot run before an
    earlier write/command/finding submission that the model placed first.
    """
    results: list[dict] = []
    turn_tool_names = {
        str(tc.get("function", {}).get("name") or "")
        for tc in tool_calls
        if tc.get("function", {}).get("name")
    }

    async def _exec_one(tc: dict) -> dict:
        display.tool_start(tc)
        name = tc["function"]["name"]

        def _reemit(message: str, *, error: str) -> dict:
            payload = json.dumps(
                {"error": error, "tool": name, "message": message},
                indent=2, sort_keys=True,
            )
            display.tool_result(tc, payload)
            return {"role": "tool", "tool_call_id": tc["id"], "content": payload}

        raw_arguments = tc["function"].get("arguments") or ""
        if raw_arguments.strip() == "":
            args = {}  # no-argument tools may send "" / omit arguments
        else:
            try:
                args = json.loads(raw_arguments)
            except json.JSONDecodeError as exc:
                # Don't silently run the tool with empty args — that hides the
                # mistake and produces a confusing downstream failure. Ask the
                # model to re-emit valid JSON.
                return _reemit(
                    f"Arguments were not valid JSON ({exc}). Re-emit this tool "
                    "call with a valid JSON object as arguments.",
                    error="invalid_tool_arguments_json",
                )
            if not isinstance(args, dict):
                return _reemit(
                    "Tool arguments must be a JSON object (for no-argument tools "
                    "use {}). Re-emit this tool call with an object.",
                    error="invalid_tool_arguments_shape",
                )
        if enforce_attack_search:
            guarded = await _attack_search_tool_guard(
                container,
                tool_name=name,
                tool_args=args,
                turn_tool_names=turn_tool_names,
            )
            if guarded is not None:
                display.tool_result(tc, guarded)
                return {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": guarded,
                }
        result = await execute_tool(
            name, args, container, findings, display
        )
        display.tool_result(tc, result)
        return {
            "role": "tool",
            "tool_call_id": tc["id"],
            "content": result,
        }

    async def _flush_parallel(batch: list[dict]) -> None:
        if not batch:
            return
        results.extend(await asyncio.gather(*[_exec_one(tc) for tc in batch]))

    parallel_batch: list[dict] = []
    for tc in tool_calls:
        name = tc["function"]["name"]
        if name in PARALLEL_SAFE:
            parallel_batch.append(tc)
            continue
        await _flush_parallel(parallel_batch)
        parallel_batch = []
        results.append(await _exec_one(tc))

    await _flush_parallel(parallel_batch)

    return results


# ── Report generation ────────────────────────────────────────────────────


async def run_report(
    client: ResponsesLLMClient,
    model: str,
    messages: list[dict],
    container: AuditContainer,
    display: Display,
    findings: list[dict],
    explored: dict | None = None,
    max_time_seconds: int = DEFAULT_MAX_TIME_SECONDS,
    max_context: int = calculate_max_context(DEFAULT_CONTEXT_WINDOW),
    reasoning_config: dict | None = None,
) -> str | None:
    """Generate the vulnerability report. Returns report content or None.

    Injects the full structured findings data alongside the report instruction
    so the agent has authoritative data regardless of what conversation history
    was truncated during the audit phase.

    Uses the selected model's maximum output instead of the audit-turn output
    reserve so long reports are not cut short by a smaller local cap.
    """
    display.phase("Report Phase")

    # Inject report instruction with full findings data so the agent doesn't
    # depend on truncated conversation history for finding details
    if findings:
        findings_json = json.dumps(findings, indent=2, default=str)
        report_msg = (
            REPORT_INSTRUCTION
            + "\n\nAUTHORITATIVE_SUBMITTED_FINDINGS_JSON:\n\n"
            + findings_json
        )
    else:
        report_msg = (
            REPORT_INSTRUCTION
            + "\n\nNo findings were submitted during the audit. "
            "Note this in the report and document what was analyzed."
        )
    if explored and explored.get("audit_status"):
        report_msg += (
            "\n\nFinal audit status: "
            + str(explored.get("audit_status"))
            + ". The deterministic campaign readiness snapshot was:\n\n"
            + json.dumps(
                explored.get("final_readiness") or {},
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
    messages.append({"role": "user", "content": report_msg})

    # Let the agent keep writing until complete or the wall-clock limit is hit.
    # The report phase only ever sends the read/write subset, so the budget
    # estimates discount exactly those schemas (not the full TOOLS set).
    report_started_at = time.time()
    report_tools = _report_visible_tools()
    while True:
        if time.time() - report_started_at >= max_time_seconds:
            display.status("Report wall-clock limit reached.")
            break
        messages = _truncate_messages(
            messages, findings, explored, max_context, tools=report_tools
        )
        try:
            (
                response_message,
                _,
                _,
                finish_reason,
                messages,
            ) = await _stream_turn_with_recovery(
                client,
                model,
                messages,
                display,
                findings=findings,
                explored=explored,
                max_context=max_context,
                tools=report_tools,
                max_output_tokens=None,
                reasoning_config=reasoning_config,
            )
        except Exception as e:
            display.error(f"Report generation failed: {e}")
            return None

        messages.append(response_message)

        if not response_message.get("tool_calls"):
            if finish_reason == "length":
                messages.append({
                    "role": "user",
                    "content": (
                        "Continue the report from exactly where it was cut off. "
                        "Keep writing to /output/report.md if you are using tools."
                    ),
                })
                continue
            break

        tool_results = await _execute_tool_calls(
            response_message["tool_calls"],
            container, findings, display,
            enforce_attack_search=False,
        )
        messages.extend(tool_results)
        messages = _age_tool_outputs(
            messages, max_context=max_context, tools=report_tools
        )
        if explored is not None:
            _update_explored(response_message["tool_calls"], explored, tool_results)

    # Try to read the report from the container
    try:
        report = await container.read_file("/output/report.md")
        return report
    except Exception:
        try:
            report = await container.read_file("/audit/report.md")
            return report
        except Exception:
            pass

    # Fallback: the model may have included the report in response text instead
    # of using write_file. Stitch substantial assistant chunks together so a
    # continued report is not reduced to only the final chunk.
    report_chunks = [
        msg.get("content", "")
        for msg in messages
        if msg.get("role") == "assistant" and len(msg.get("content", "")) > 500
    ]
    if report_chunks:
        return "\n\n".join(report_chunks)

    display.error("Could not read generated report from container")
    return None


# ── Interactive chat ─────────────────────────────────────────────────────


async def chat_loop(
    client: ResponsesLLMClient,
    model: str,
    messages: list[dict],
    container: AuditContainer,
    display: Display,
    findings: list[dict],
    explored: dict | None = None,
    max_time_seconds: int = DEFAULT_MAX_TIME_SECONDS,
    max_context: int = calculate_max_context(DEFAULT_CONTEXT_WINDOW),
    reasoning_config: dict | None = None,
    context_window: int | None = None,
    max_context_is_user_cap: bool = False,
):
    """Interactive chat after audit.

    context_window and max_context_is_user_cap are forwarded to run_audit when
    the user types ``keep-auditing`` so a resumed audit reclaims per-turn
    visible-tool budget the same way the initial audit does.
    """
    display.chat_start()

    while True:
        try:
            user_input = await asyncio.to_thread(input, "\n[reentbotpro] > ")
        except (EOFError, KeyboardInterrupt):
            break

        user_input = user_input.strip()
        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            break
        if user_input.lower() == "keep-auditing":
            display.resuming_audit()
            new_findings, messages, new_explored = await run_audit(
                client, model,
                messages[0]["content"],  # system prompt
                container, display,
                max_time_seconds=max_time_seconds,
                prior_findings=findings,
                max_context=max_context,
                reasoning_config=reasoning_config,
                initial_toolsets=(_active_toolsets(explored) if explored else None),
                context_window=context_window,
                max_context_is_user_cap=max_context_is_user_cap,
            )
            findings.extend(new_findings)
            # Merge explored state
            if explored is not None and new_explored:
                explored["files_read"].update(new_explored.get("files_read", set()))
                explored["tools_run"].update(new_explored.get("tools_run", set()))
                for key in ("toolset_requests", *_CAMPAIGN_COUNTER_KEYS):
                    explored[key] = explored.get(key, 0) + new_explored.get(key, 0)
                explored.setdefault("campaign_sections", set()).update(
                    new_explored.get("campaign_sections", set())
                )
                explored.setdefault("active_toolsets", set(DEFAULT_TOOLSETS)).update(
                    new_explored.get("active_toolsets", set())
                )
                explored.setdefault("requested_toolsets", set()).update(
                    new_explored.get("requested_toolsets", set())
                )
                merged_failed = explored.setdefault("failed_tool_calls", {})
                for name, count in new_explored.get("failed_tool_calls", {}).items():
                    merged_failed[name] = merged_failed.get(name, 0) + count
            continue

        messages.append({"role": "user", "content": user_input})

        # Run agent turns until no more tool calls, bounded only by wall clock.
        chat_started_at = time.time()
        while True:
            if time.time() - chat_started_at >= max_time_seconds:
                display.status("Chat wall-clock limit reached.")
                break
            # Size the budget to the tools this chat turn actually sends (the
            # active toolsets can grow mid-chat via request_toolset).
            visible_tools = _visible_tools(explored)
            messages = _truncate_messages(
                messages, findings, explored, max_context, tools=visible_tools
            )
            try:
                (
                    response_message,
                    _,
                    _,
                    _,
                    messages,
                ) = await _stream_turn_with_recovery(
                    client,
                    model,
                    messages,
                    display,
                    findings=findings,
                    explored=explored,
                    max_context=max_context,
                    tools=visible_tools,
                    max_output_tokens=None,
                    reasoning_config=reasoning_config,
                )
            except Exception as e:
                display.error(f"LLM call failed: {e}")
                break

            messages.append(response_message)

            if not response_message.get("tool_calls"):
                break

            tool_results = await _execute_tool_calls(
                response_message["tool_calls"],
                container, findings, display,
                enforce_attack_search=False,
            )
            messages.extend(tool_results)
            messages = _age_tool_outputs(
                messages, max_context=max_context, tools=visible_tools
            )

            # Track explored state from chat interactions
            if explored is not None:
                _update_explored(response_message["tool_calls"], explored, tool_results)
                note = _toolset_activation_note(
                    _activate_requested_toolsets(response_message["tool_calls"], explored),
                    reason="request_toolset",
                )
                if note:
                    messages.append(note)
