"""Host-side Alchemy + Etherscan on-chain investigation tools.

These call Alchemy's enhanced JSON-RPC / Prices REST APIs and the Etherscan V2
verified-source API directly from the host (like fetch_url/web_search), not via
the in-container cast probes. They resolve their keys on the host, redact them
from every artifact/response, degrade cleanly without a key, and write results
only as corroborating evidence under /workspace/campaign/ (probes/, plus
observed-txs/ for observed_tx_miner) -- they never relax the submission gates.

Extracted from tools.py as a clean dependency *sink*: nothing in the core calls
these except the execute_tool dispatch, which imports them at the bottom of
tools.py. The few low-level helpers these reuse from the core module
(``_coerce_*_arg``, campaign-state loaders/trace writers) are imported lazily
inside the handful of functions that need them, so this module imports cleanly
on its own regardless of import order.
"""
import hashlib
import json
import re
from datetime import datetime, timezone

from reentbotpro.config import (
    ETHERSCAN_V2_API_URL,
    alchemy_node_url,
    alchemy_prices_url,
    resolve_alchemy_network,
    resolve_chain_id,
)


_ALCHEMY_PROBE_DIR = "/workspace/campaign/probes"
_ALCHEMY_HTTP_TIMEOUT_SECONDS = 45

# Billing compute-unit cost per method (verified against Alchemy's compute-unit
# costs reference, June 2026). Used only for the per-run budget guard/telemetry.
_ALCHEMY_CU_COSTS = {
    "eth_call": 26,
    "eth_getCode": 20,
    "eth_getStorageAt": 20,
    "eth_getBalance": 20,
    "eth_getLogs": 60,
    "eth_chainId": 0,
    "trace_transaction": 40,
    "trace_call": 40,
    "trace_filter": 40,
    "trace_block": 20,
    "trace_replayTransaction": 80,
    "debug_traceTransaction": 40,
    "debug_traceCall": 40,
    "debug_traceBlockByNumber": 40,
    "alchemy_getAssetTransfers": 120,
    "alchemy_getTokenBalances": 20,
    "alchemy_getTokenMetadata": 10,
    "alchemy_simulateAssetChanges": 2500,
    "alchemy_simulateExecution": 2500,
    "alchemy_simulateAssetChangesBundle": 2500,
    "alchemy_simulateExecutionBundle": 2500,
    "prices_by_address": 100,
    "prices_historical": 100,
}
_ALCHEMY_DEFAULT_CU_COST = 50

# Method -> capability family. A tier/feature/chain rejection for any method in
# a family marks the whole family unavailable for that network so the agent
# stops retrying and falls back.
_ALCHEMY_METHOD_FAMILY = {
    "trace_transaction": "trace_debug",
    "trace_call": "trace_debug",
    "trace_filter": "trace_debug",
    "trace_block": "trace_debug",
    "trace_replayTransaction": "trace_debug",
    "debug_traceTransaction": "trace_debug",
    "debug_traceCall": "trace_debug",
    "debug_traceBlockByNumber": "trace_debug",
    "alchemy_getAssetTransfers": "transfers",
    "alchemy_getTokenBalances": "token",
    "alchemy_getTokenMetadata": "token",
    "alchemy_simulateAssetChanges": "simulation",
    "alchemy_simulateExecution": "simulation",
    "alchemy_simulateAssetChangesBundle": "simulation",
    "alchemy_simulateExecutionBundle": "simulation",
    "prices_by_address": "prices",
    "prices_historical": "prices",
}

# Error-message substrings that indicate the API/tier/feature/chain is not
# available on this key (vs. a transient or argument error). These trigger
# capability degradation rather than a plain error.
_ALCHEMY_UNAVAILABLE_MARKERS = (
    "not available",
    "not enabled",
    "not supported",
    "unsupported",
    "upgrade",
    "tier",
    "not allowed",
    "not authorized",
    "unauthorized",
    "forbidden",
    "no access",
    "method not found",
)

# Module-level runtime state, set once per run by the CLI and reset by tests.
_ALCHEMY_RUNTIME = {
    "api_key": None,
}
_ALCHEMY_USAGE = {"cu": 0, "calls": 0}
_ALCHEMY_CAPABILITY: dict = {}

# Returned (by Alchemy/Etherscan host tools) when no target chain can be
# inferred from explicit args, a fork context, or a chain-registry binding. The
# host tools never silently query Ethereum mainnet instead.
_CHAIN_NOT_INFERRED_MESSAGE = (
    "No target chain was inferred. Pass network/chain_id, record a fork_context, "
    "or rely on a chain-registry target binding."
)


def set_alchemy_runtime(api_key) -> None:
    """Configure the host-side Alchemy credential for this run."""
    _ALCHEMY_RUNTIME["api_key"] = api_key or None


def reset_alchemy_runtime() -> None:
    """Reset all host-side Alchemy state (test helper)."""
    _ALCHEMY_RUNTIME["api_key"] = None
    _ALCHEMY_USAGE["cu"] = 0
    _ALCHEMY_USAGE["calls"] = 0
    _ALCHEMY_CAPABILITY.clear()


def alchemy_key_configured() -> bool:
    """True when an Alchemy API key is configured for this run."""
    return bool(_ALCHEMY_RUNTIME.get("api_key"))


def _alchemy_settings() -> str | None:
    """Return the runtime Alchemy API key without reading local config."""
    return _ALCHEMY_RUNTIME.get("api_key") or None


async def _alchemy_fork_context_network(container) -> str | None:
    """Resolve the chain from the agent's most recent record_fork_context, or
    None. Reads the latest fork-context artifact(s) and maps network/chain_id to
    an Alchemy subdomain. Best-effort and never raises."""
    from reentbotpro.tools import _CAMPAIGN_ID_PREFIXES, _load_campaign_state
    if container is None:
        return None
    try:
        state = await _load_campaign_state(container)
        count = int((state.get("counters") or {}).get("fork_context", 0) or 0)
    except Exception:
        return None
    prefix = _CAMPAIGN_ID_PREFIXES.get("fork_context")
    if not prefix or count <= 0:
        return None
    for n in range(count, max(0, count - 10), -1):
        path = f"/workspace/campaign/fork-contexts/{prefix}-{n:03d}.json"
        try:
            fork_context = json.loads(await container.read_file(path))
        except (FileNotFoundError, json.JSONDecodeError, ValueError, AttributeError, TypeError):
            continue
        if not isinstance(fork_context, dict):
            continue
        resolved = resolve_alchemy_network(
            fork_context.get("network"), fork_context.get("chain_id")
        )
        if resolved:
            return resolved
    return None


async def _alchemy_context_network(container) -> str | None:
    """The chain to use when a tool call omits `network`, or None.

    Resolves the agent's most recent recorded fork-context chain. It never falls
    back to a run-level or Ethereum-mainnet default. In the normal dispatch path
    the chain is already resolved and injected before the tool runs; this remains
    the in-tool safety net for direct call sites.
    """
    return await _alchemy_fork_context_network(container)


def _redact_alchemy(value, api_key):
    """Recursively replace the api key (and any node URL embedding it) with a
    placeholder. Defense-in-depth: results normally never carry the key, but
    everything written or returned passes through here first."""
    if not api_key:
        return value
    if isinstance(value, str):
        return value.replace(api_key, "<alchemy-key>")
    if isinstance(value, dict):
        return {k: _redact_alchemy(v, api_key) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_alchemy(item, api_key) for item in value]
    return value


def _alchemy_cu_cost(method) -> int:
    return _ALCHEMY_CU_COSTS.get(method, _ALCHEMY_DEFAULT_CU_COST)


def _alchemy_account_usage(method) -> None:
    _ALCHEMY_USAGE["cu"] = int(_ALCHEMY_USAGE["cu"]) + _alchemy_cu_cost(method)
    _ALCHEMY_USAGE["calls"] = int(_ALCHEMY_USAGE["calls"]) + 1


def _alchemy_family(method) -> str:
    return _ALCHEMY_METHOD_FAMILY.get(method, "node")


def _alchemy_capability_blocked(network, method):
    entry = _ALCHEMY_CAPABILITY.get((network, _alchemy_family(method)))
    if entry and entry.get("available") is False:
        return entry.get("reason") or "API unavailable on this key for this network"
    return None


def _alchemy_mark_unavailable(network, method, reason) -> None:
    _ALCHEMY_CAPABILITY[(network, _alchemy_family(method))] = {
        "available": False,
        "reason": reason,
    }


def _alchemy_looks_unavailable(message) -> bool:
    low = str(message or "").lower()
    return any(marker in low for marker in _ALCHEMY_UNAVAILABLE_MARKERS)


async def _alchemy_http_post(url, payload, *, timeout):
    """POST JSON to an Alchemy endpoint. Returns (status_code, parsed_body).

    The single network seam — tests patch this. parsed_body is a dict on JSON
    success, otherwise the raw response text.
    """
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            url,
            json=payload,
            headers={
                "User-Agent": "ReentbotPro/0.1",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return resp.status_code, body


async def _alchemy_rpc(method, params, *, network=None, cu_method=None, container=None) -> dict:
    """Call an Alchemy JSON-RPC method. Returns a normalized dict and never
    raises for network/HTTP/RPC errors; never leaks the key.

    The target chain is the agent-supplied `network` (Alchemy subdomain, chain
    name, or chain id); when omitted it resolves the chain recorded in the latest
    record_fork_context. If no chain can be inferred it returns
    ``chain_not_inferred`` rather than silently querying Ethereum mainnet."""
    key = _alchemy_settings()
    billing_method = cu_method or method
    if not key:
        return {"network": network, "method": method, "ok": False,
                "error": "alchemy_not_configured", "message": "No Alchemy API key configured."}
    if network is None or str(network).strip() == "":
        net = await _alchemy_context_network(container) if container is not None else None
        if not net:
            return {"network": None, "method": method, "ok": False,
                    "error": "chain_not_inferred", "message": _CHAIN_NOT_INFERRED_MESSAGE}
    else:
        net = resolve_alchemy_network(network)
        if not net:
            return {"network": network, "method": method, "ok": False, "error": "invalid_network",
                    "message": (f"unrecognized network '{network}'; pass an Alchemy subdomain "
                                "(base-mainnet), a chain name (base), or a chain id (8453)")}
    base = {"network": net, "method": method}
    blocked = _alchemy_capability_blocked(net, method)
    if blocked:
        return {**base, "ok": False, "error": "unavailable", "degraded": True, "message": blocked}
    cost = _alchemy_cu_cost(billing_method)
    try:
        url = alchemy_node_url(net, key)
    except ValueError as exc:
        return {**base, "ok": False, "error": "invalid_network", "message": str(exc)}
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        status, body = await _alchemy_http_post(url, payload, timeout=_ALCHEMY_HTTP_TIMEOUT_SECONDS)
    except Exception as exc:
        return {**base, "ok": False, "error": "request_failed", "message": _redact_alchemy(str(exc), key)}
    _alchemy_account_usage(billing_method)
    if status in (401, 403):
        reason = f"{_alchemy_family(method)} API returned HTTP {status} for {net}; not enabled on this key."
        _alchemy_mark_unavailable(net, method, reason)
        return {**base, "ok": False, "error": "unavailable", "degraded": True,
                "http_status": status, "message": reason}
    if not isinstance(body, dict):
        return {**base, "ok": False, "error": "non_json_response", "http_status": status,
                "message": _redact_alchemy(str(body), key)[:500]}
    if isinstance(body.get("error"), dict):
        err = body["error"]
        msg = _redact_alchemy(str(err.get("message") or ""), key)
        if _alchemy_looks_unavailable(msg) or status == 404:
            _alchemy_mark_unavailable(net, method, msg or "API unavailable on this key")
            return {**base, "ok": False, "error": "unavailable", "degraded": True,
                    "http_status": status, "rpc_code": err.get("code"), "message": msg}
        return {**base, "ok": False, "error": "rpc_error", "http_status": status,
                "rpc_code": err.get("code"), "message": msg}
    return {**base, "ok": True, "result": _redact_alchemy(body.get("result"), key),
            "http_status": status, "cu": cost, "cu_total": int(_ALCHEMY_USAGE["cu"])}


async def _alchemy_prices_call(payload, *, endpoint="tokens/by-address", cu_method="prices_by_address") -> dict:
    """Call the Alchemy Prices REST API (different host, bare key)."""
    key = _alchemy_settings()
    base = {"network": "prices", "method": cu_method}
    if not key:
        return {**base, "ok": False, "error": "alchemy_not_configured",
                "message": "No Alchemy API key configured."}
    blocked = _alchemy_capability_blocked("prices", cu_method)
    if blocked:
        return {**base, "ok": False, "error": "unavailable", "degraded": True, "message": blocked}
    cost = _alchemy_cu_cost(cu_method)
    try:
        url = alchemy_prices_url(key, endpoint=endpoint)
    except ValueError as exc:
        return {**base, "ok": False, "error": "invalid_endpoint", "message": str(exc)}
    try:
        status, body = await _alchemy_http_post(url, payload, timeout=_ALCHEMY_HTTP_TIMEOUT_SECONDS)
    except Exception as exc:
        return {**base, "ok": False, "error": "request_failed", "message": _redact_alchemy(str(exc), key)}
    _alchemy_account_usage(cu_method)
    if status in (401, 403):
        reason = f"Prices API returned HTTP {status}; not enabled on this key."
        _alchemy_mark_unavailable("prices", cu_method, reason)
        return {**base, "ok": False, "error": "unavailable", "degraded": True,
                "http_status": status, "message": reason}
    if not isinstance(body, dict):
        return {**base, "ok": False, "error": "non_json_response", "http_status": status,
                "message": _redact_alchemy(str(body), key)[:500]}
    return {**base, "ok": True, "result": _redact_alchemy(body, key),
            "http_status": status, "cu": cost, "cu_total": int(_ALCHEMY_USAGE["cu"])}


async def _write_alchemy_artifact(container, slug, payload) -> str:
    """Persist a redacted probe payload under the campaign probes dir, return
    its path (a valid /workspace/campaign/ evidence path)."""
    key = _alchemy_settings()
    redacted = _redact_alchemy(payload, key)
    content = json.dumps(redacted, indent=2, sort_keys=True, default=str)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha1(content.encode("utf-8", "replace")).hexdigest()[:8]
    safe_slug = re.sub(r"[^a-z0-9]+", "-", str(slug).lower()).strip("-") or "probe"
    path = f"{_ALCHEMY_PROBE_DIR}/{safe_slug}-{stamp}-{digest}.json"
    await container.write_file(path, content + "\n")
    return path


async def _alchemy_trace_event(container, *, tool, call) -> None:
    from reentbotpro.tools import _append_campaign_trace
    try:
        await _append_campaign_trace(container, {
            "event": "alchemy_probe",
            "tool": tool,
            "network": call.get("network"),
            "method": call.get("method"),
            "ok": bool(call.get("ok")),
            "error": None if call.get("ok") else call.get("error"),
            "cu_total": int(_ALCHEMY_USAGE["cu"]),
        })
    except Exception:
        pass  # tracing is best-effort and must never fail a tool


def _alchemy_bad_args(tool, exc) -> str:
    return json.dumps(
        {"tool": tool, "ok": False, "error": "bad_arguments", "message": str(exc)},
        indent=2, sort_keys=True,
    )


def _alchemy_error_digest(tool, call) -> str:
    out = {"tool": tool, "ok": False, "error": call.get("error"), "message": call.get("message")}
    for field in ("network", "method", "http_status", "rpc_code", "cu_total"):
        if call.get(field) is not None:
            out[field] = call.get(field)
    err = call.get("error")
    if call.get("degraded"):
        out["degraded"] = True
        out["fallback"] = (
            "This Alchemy API is unavailable on the current key/chain. Use a "
            "forge/cast anvil fork instead; this does not block findings."
        )
    elif err == "alchemy_not_configured":
        out["fallback"] = (
            "Set ALCHEMY_API_KEY or api_keys.alchemy to enable Alchemy tools; "
            "forge/cast remain fully available."
        )
    return json.dumps(out, indent=2, sort_keys=True, default=str)


async def _alchemy_finish(container, *, tool, slug, call, summarize=None) -> str:
    """Shared completion: trace the call; on failure return a compact error
    digest; on success write the full redacted result as an evidence artifact
    and return a compact summary digest with the artifact path."""
    await _alchemy_trace_event(container, tool=tool, call=call)
    if not call.get("ok"):
        return _alchemy_error_digest(tool, call)
    result = call.get("result")
    summary = {}
    if summarize is not None:
        try:
            summary = summarize(result) or {}
        except Exception as exc:  # never let summarization break a successful call
            summary = {"summary_error": str(exc)[:200]}
    artifact = await _write_alchemy_artifact(container, slug, {
        "tool": tool, "method": call.get("method"), "network": call.get("network"),
        "cu": call.get("cu"), "cu_total": call.get("cu_total"), "result": result,
    })
    digest = {
        "tool": tool, "ok": True, "network": call.get("network"),
        "method": call.get("method"), "artifact": artifact,
        "cu": call.get("cu"), "cu_total": call.get("cu_total"),
        "note": "Corroboration only — a runnable forge PoC is still required for findings.",
    }
    digest.update(summary)
    return json.dumps(digest, indent=2, sort_keys=True, default=str)


# ── Argument coercion for on-chain identifiers ───────────────────────────

_HEX_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX_TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_HEX_DATA_RE = re.compile(r"0x[0-9a-fA-F]*")
_BLOCK_TAGS = ("latest", "earliest", "pending", "safe", "finalized")


def _coerce_str_arg(value, name, *, default=None, required=False):
    if value is None:
        if required:
            raise ValueError(f"{name} is required")
        return default
    text = str(value).strip()
    if not text:
        if required:
            raise ValueError(f"{name} is required")
        return default
    return text


def _coerce_address_arg(value, name, *, required=True):
    text = _coerce_str_arg(value, name, required=required)
    if text is None:
        return None
    if not _HEX_ADDRESS_RE.fullmatch(text):
        raise ValueError(f"{name} must be a 0x-prefixed 20-byte address")
    return text


def _coerce_tx_hash_arg(value, name, *, required=True):
    text = _coerce_str_arg(value, name, required=required)
    if text is None:
        return None
    if not _HEX_TX_HASH_RE.fullmatch(text):
        raise ValueError(f"{name} must be a 0x-prefixed 32-byte transaction hash")
    return text


def _coerce_hexdata_arg(value, name, *, default=None):
    text = _coerce_str_arg(value, name)
    if text is None:
        return default
    if not _HEX_DATA_RE.fullmatch(text):
        raise ValueError(f"{name} must be 0x-prefixed hex data")
    return text


def _coerce_block_arg(value, name="block", *, default="latest"):
    if value is None or value == "":
        return default
    text = str(value).strip().lower()
    if text in _BLOCK_TAGS:
        return text
    if _HEX_DATA_RE.fullmatch(text):
        return text
    try:
        return hex(int(text))
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a block tag, 0x-hex, or decimal block number")


# ── Result summarizers ───────────────────────────────────────────────────


def _alchemy_summarize_call_frame(frame) -> dict:
    if not isinstance(frame, dict):
        return {"trace": "no_frame"}

    def _count(node):
        if not isinstance(node, dict):
            return 0
        subs = node.get("calls") or []
        return len(subs) + sum(_count(s) for s in subs if isinstance(s, dict))

    out = {
        "root_to": frame.get("to"),
        "root_from": frame.get("from"),
        "call_type": frame.get("type"),
        "value": frame.get("value"),
        "gas_used": frame.get("gasUsed"),
        "subcall_count": _count(frame),
        "reverted": bool(frame.get("error") or frame.get("revertReason")),
    }
    if frame.get("error"):
        out["error"] = str(frame.get("error"))[:200]
    if frame.get("revertReason"):
        out["revert_reason"] = str(frame.get("revertReason"))[:200]
    direct = []
    for sub in (frame.get("calls") or [])[:8]:
        if not isinstance(sub, dict):
            continue
        selector = sub.get("input") or ""
        direct.append({
            "to": sub.get("to"),
            "type": sub.get("type"),
            "selector": selector[:10] if isinstance(selector, str) and len(selector) >= 10 else None,
            "reverted": bool(sub.get("error")),
        })
    if direct:
        out["top_subcalls"] = direct
    return out


def _alchemy_summarize_asset_changes(result) -> dict:
    if not isinstance(result, dict):
        return {"asset_changes": "none"}
    changes = result.get("changes") or []
    summary = []
    for ch in changes[:30]:
        if not isinstance(ch, dict):
            continue
        summary.append({
            "assetType": ch.get("assetType"),
            "changeType": ch.get("changeType"),
            "from": ch.get("from"),
            "to": ch.get("to"),
            "amount": ch.get("amount"),
            "symbol": ch.get("symbol"),
            "contract": ch.get("contractAddress"),
        })
    out = {"change_count": len(changes), "changes": summary, "gas_used": result.get("gasUsed")}
    if result.get("error"):
        out["sim_error"] = str(result.get("error"))[:200]
    return out


def _alchemy_summarize_transfers(transfers) -> dict:
    counterparties: dict = {}
    assets: dict = {}
    sample = []
    for tr in transfers:
        if not isinstance(tr, dict):
            continue
        frm, to = tr.get("from"), tr.get("to")
        for cp in (frm, to):
            if cp:
                counterparties[cp] = counterparties.get(cp, 0) + 1
        asset = tr.get("asset") or (tr.get("rawContract") or {}).get("address") or "?"
        assets[asset] = assets.get(asset, 0) + 1
        if len(sample) < 15:
            sample.append({
                "dir": tr.get("_direction"), "from": frm, "to": to,
                "value": tr.get("value"), "asset": tr.get("asset"),
                "category": tr.get("category"), "hash": tr.get("hash"),
                "block": tr.get("blockNum"),
            })
    top_cp = sorted(counterparties.items(), key=lambda kv: kv[1], reverse=True)[:15]
    top_assets = sorted(assets.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return {
        "transfer_count": len(transfers),
        "distinct_counterparties": len(counterparties),
        "top_counterparties": [{"address": a, "transfers": c} for a, c in top_cp],
        "assets": [{"asset": a, "transfers": c} for a, c in top_assets],
        "sample": sample,
    }


def _alchemy_build_sim_tx(args):
    to = _coerce_address_arg(args.get("to"), "to")
    sender = _coerce_address_arg(args.get("from") or args.get("from_address"), "from")
    data = _coerce_hexdata_arg(args.get("data"), "data", default="0x")
    value = _coerce_hexdata_arg(args.get("value"), "value", default="0x0")
    network = _coerce_str_arg(args.get("network"), "network", default=None)
    return {"from": sender, "to": to, "value": value, "data": data}, network


# ── Handlers ─────────────────────────────────────────────────────────────


async def _alchemy_trace_onchain_tx(container, args) -> str:
    tool = "trace_onchain_tx"
    try:
        tx_hash = _coerce_tx_hash_arg(args.get("tx_hash") or args.get("transaction_hash"), "tx_hash")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        tracer = _coerce_str_arg(args.get("tracer"), "tracer", default="callTracer")
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    if tracer not in ("callTracer", "prestateTracer"):
        tracer = "callTracer"
    call = await _alchemy_rpc("debug_traceTransaction", [tx_hash, {"tracer": tracer}], network=network, container=container)

    def summarize(result):
        if tracer == "callTracer":
            return _alchemy_summarize_call_frame(result)
        return {"prestate_accounts": len(result) if isinstance(result, dict) else None}

    return await _alchemy_finish(container, tool=tool, slug=f"trace-{tx_hash[:10]}", call=call, summarize=summarize)


async def _alchemy_simulate_call(container, args) -> str:
    tool = "simulate_call"
    try:
        to = _coerce_address_arg(args.get("to"), "to")
        data = _coerce_hexdata_arg(args.get("data"), "data", default="0x")
        sender = _coerce_address_arg(args.get("from") or args.get("from_address"), "from", required=False)
        value = _coerce_hexdata_arg(args.get("value"), "value", default=None)
        gas = _coerce_hexdata_arg(args.get("gas"), "gas", default=None)
        block = _coerce_block_arg(args.get("block"), "block", default="latest")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        tracer = _coerce_str_arg(args.get("tracer"), "tracer", default="callTracer")
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    if tracer not in ("callTracer", "prestateTracer"):
        tracer = "callTracer"
    tx = {"to": to, "data": data}
    if sender:
        tx["from"] = sender
    if value is not None:
        tx["value"] = value
    if gas is not None:
        tx["gas"] = gas
    tracer_config = {"tracer": tracer}
    state_overrides = args.get("state_overrides")
    if isinstance(state_overrides, dict) and state_overrides:
        tracer_config["stateOverrides"] = state_overrides
    call = await _alchemy_rpc("debug_traceCall", [tx, block, tracer_config], network=network, container=container)

    def summarize(result):
        if tracer == "callTracer":
            return _alchemy_summarize_call_frame(result)
        return {"prestate_accounts": len(result) if isinstance(result, dict) else None}

    return await _alchemy_finish(container, tool=tool, slug=f"simcall-{to[:10]}", call=call, summarize=summarize)


async def _alchemy_state_diff(container, args) -> str:
    tool = "state_diff"
    try:
        tx_hash = _coerce_tx_hash_arg(args.get("tx_hash") or args.get("transaction_hash"), "tx_hash")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    call = await _alchemy_rpc("trace_replayTransaction", [tx_hash, ["trace", "stateDiff"]], network=network, container=container)

    def summarize(result):
        if not isinstance(result, dict):
            return {"state_diff": "none"}
        state_diff = result.get("stateDiff")
        if not isinstance(state_diff, dict):
            return {"changed_addresses": 0}
        changed = []
        for addr, diff in state_diff.items():
            if not isinstance(diff, dict):
                continue
            storage = diff.get("storage")
            changed.append({
                "address": addr,
                "storage_slots_changed": len(storage) if isinstance(storage, dict) else 0,
                "balance_changed": diff.get("balance") not in (None, "="),
                "nonce_changed": diff.get("nonce") not in (None, "="),
                "code_changed": diff.get("code") not in (None, "="),
            })
        changed.sort(key=lambda e: e["storage_slots_changed"], reverse=True)
        return {"changed_addresses": len(state_diff), "top_changes": changed[:12]}

    return await _alchemy_finish(container, tool=tool, slug=f"statediff-{tx_hash[:10]}", call=call, summarize=summarize)


async def _alchemy_enumerate_callers(container, args) -> str:
    from reentbotpro.tools import _coerce_bounded_int_arg
    tool = "enumerate_callers"
    try:
        address = _coerce_address_arg(args.get("address") or args.get("to_address"), "address")
        from_block = _coerce_block_arg(args.get("from_block"), "from_block", default=None)
        to_block = _coerce_block_arg(args.get("to_block"), "to_block", default="latest")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        count = _coerce_bounded_int_arg(args.get("count"), "count", default=100, minimum=1, maximum=1000)
        direction = _coerce_str_arg(args.get("direction"), "direction", default="to")
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    if from_block is None:
        return _alchemy_bad_args(tool, ValueError(
            "from_block is required; keep [from_block, to_block] bounded "
            "(trace_filter scans every block in the range)."
        ))
    filt = {"fromBlock": from_block, "toBlock": to_block, "count": count}
    if direction in ("from", "out"):
        filt["fromAddress"] = [address]
    else:
        filt["toAddress"] = [address]
    call = await _alchemy_rpc("trace_filter", [filt], network=network, container=container)

    def summarize(result):
        traces = result if isinstance(result, list) else []
        callers: dict = {}
        selectors: dict = {}
        for tr in traces:
            action = tr.get("action") if isinstance(tr, dict) else None
            if not isinstance(action, dict):
                continue
            frm = action.get("from")
            if frm:
                callers[frm] = callers.get(frm, 0) + 1
            inp = action.get("input") or ""
            if isinstance(inp, str) and len(inp) >= 10:
                selectors[inp[:10]] = selectors.get(inp[:10], 0) + 1
        top_callers = sorted(callers.items(), key=lambda kv: kv[1], reverse=True)[:15]
        top_selectors = sorted(selectors.items(), key=lambda kv: kv[1], reverse=True)[:15]
        return {
            "trace_count": len(traces),
            "distinct_callers": len(callers),
            "top_callers": [{"address": a, "calls": c} for a, c in top_callers],
            "top_selectors": [{"selector": s, "calls": c} for s, c in top_selectors],
            "truncated": len(traces) >= count,
        }

    return await _alchemy_finish(container, tool=tool, slug=f"callers-{address[:10]}", call=call, summarize=summarize)


async def _alchemy_get_asset_transfers(container, args) -> str:
    from reentbotpro.tools import _coerce_bounded_int_arg
    tool = "get_asset_transfers"
    try:
        address = _coerce_address_arg(args.get("address"), "address", required=False)
        from_address = _coerce_address_arg(args.get("from_address"), "from_address", required=False)
        to_address = _coerce_address_arg(args.get("to_address"), "to_address", required=False)
        from_block = _coerce_block_arg(args.get("from_block"), "from_block", default="0x0")
        to_block = _coerce_block_arg(args.get("to_block"), "to_block", default="latest")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        max_count = _coerce_bounded_int_arg(args.get("max_count"), "max_count", default=100, minimum=1, maximum=1000)
        order = _coerce_str_arg(args.get("order"), "order", default="desc")
        direction = _coerce_str_arg(args.get("direction"), "direction", default="both")
        page_key = _coerce_str_arg(args.get("page_key"), "page_key", default=None)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    if order not in ("asc", "desc"):
        order = "desc"
    categories = args.get("categories")
    if isinstance(categories, list) and categories:
        category = [str(c).strip().lower() for c in categories if str(c).strip()]
    else:
        category = ["external", "erc20", "erc721", "erc1155"]
    base = {
        "fromBlock": from_block, "toBlock": to_block, "category": category,
        "withMetadata": True, "excludeZeroValue": True,
        "maxCount": hex(max_count), "order": order,
    }
    contract_addresses = args.get("contract_addresses")
    if isinstance(contract_addresses, list) and contract_addresses:
        base["contractAddresses"] = [str(c) for c in contract_addresses]
    if page_key:
        base["pageKey"] = page_key

    plan = []
    if from_address:
        plan.append(("from", {**base, "fromAddress": from_address}))
    if to_address:
        plan.append(("to", {**base, "toAddress": to_address}))
    if not plan and address:
        if direction in ("out", "from"):
            plan.append(("from", {**base, "fromAddress": address}))
        elif direction in ("in", "to"):
            plan.append(("to", {**base, "toAddress": address}))
        else:
            plan.append(("from", {**base, "fromAddress": address}))
            plan.append(("to", {**base, "toAddress": address}))
    if not plan:
        return _alchemy_bad_args(tool, ValueError(
            "provide address (with direction in/out/both) or from_address/to_address"
        ))

    transfers = []
    page_keys = {}
    last_call = None
    for label, params in plan:
        call = await _alchemy_rpc("alchemy_getAssetTransfers", [params], network=network, container=container)
        last_call = call
        if not call.get("ok"):
            await _alchemy_trace_event(container, tool=tool, call=call)
            return _alchemy_error_digest(tool, call)
        result = call.get("result") or {}
        for tr in (result.get("transfers") or []):
            entry = dict(tr) if isinstance(tr, dict) else {}
            entry["_direction"] = label
            transfers.append(entry)
        if result.get("pageKey"):
            page_keys[label] = result.get("pageKey")

    await _alchemy_trace_event(container, tool=tool, call=last_call)
    artifact = await _write_alchemy_artifact(container, f"transfers-{(address or from_address or to_address or 'x')[:10]}", {
        "tool": tool, "method": "alchemy_getAssetTransfers", "network": last_call.get("network"),
        "cu_total": last_call.get("cu_total"), "page_keys": page_keys, "transfers": transfers,
    })
    digest = {
        "tool": tool, "ok": True, "network": last_call.get("network"),
        "method": "alchemy_getAssetTransfers", "artifact": artifact,
        "cu_total": last_call.get("cu_total"),
        "more_pages": bool(page_keys),
        "note": "Corroboration only — a runnable forge PoC is still required for findings.",
    }
    digest.update(_alchemy_summarize_transfers(transfers))
    return json.dumps(digest, indent=2, sort_keys=True, default=str)


async def _alchemy_get_token_prices(container, args) -> str:
    tool = "get_token_prices"
    raw_network = _coerce_str_arg(args.get("network"), "network", default=None)
    if raw_network:
        net = resolve_alchemy_network(raw_network)
        if not net:
            return _alchemy_bad_args(tool, ValueError(
                f"unrecognized network '{raw_network}'; use an Alchemy subdomain, chain name, or chain id"
            ))
    else:
        net = await _alchemy_context_network(container)
    entries = []
    tokens_arg = args.get("tokens")
    addresses_arg = args.get("addresses")
    if isinstance(tokens_arg, list) and tokens_arg:
        for token in tokens_arg[:25]:
            if isinstance(token, dict) and token.get("address"):
                token_net = resolve_alchemy_network(token.get("network")) or net
                entries.append({"network": token_net, "address": str(token.get("address"))})
    elif isinstance(addresses_arg, list) and addresses_arg:
        for addr in addresses_arg[:25]:
            if str(addr).strip():
                entries.append({"network": net, "address": str(addr).strip()})
    if not entries:
        return _alchemy_bad_args(tool, ValueError(
            "provide addresses[] (with network) or tokens[] as [{network, address}]"
        ))
    call = await _alchemy_prices_call({"addresses": entries}, endpoint="tokens/by-address", cu_method="prices_by_address")
    call["network"] = net

    def summarize(result):
        data = result.get("data") if isinstance(result, dict) else None
        prices = {}
        for item in (data or []):
            if not isinstance(item, dict):
                continue
            usd = None
            for price in (item.get("prices") or []):
                if isinstance(price, dict) and str(price.get("currency", "")).upper() == "USD":
                    usd = price.get("value")
                    break
            prices[item.get("address")] = usd
        return {"prices_usd": prices, "count": len(prices)}

    return await _alchemy_finish(container, tool=tool, slug="prices", call=call, summarize=summarize)


async def _alchemy_get_token_info(container, args) -> str:
    tool = "get_token_info"
    try:
        address = _coerce_address_arg(args.get("address"), "address")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    call = await _alchemy_rpc("alchemy_getTokenMetadata", [address], network=network, container=container)

    def summarize(result):
        if not isinstance(result, dict):
            return {}
        return {
            "name": result.get("name"), "symbol": result.get("symbol"),
            "decimals": result.get("decimals"), "logo": result.get("logo"),
        }

    return await _alchemy_finish(container, tool=tool, slug=f"token-{address[:10]}", call=call, summarize=summarize)


async def _alchemy_simulate_asset_changes(container, args) -> str:
    tool = "simulate_asset_changes"
    try:
        tx, network = _alchemy_build_sim_tx(args)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    call = await _alchemy_rpc("alchemy_simulateAssetChanges", [tx], network=network, container=container)
    return await _alchemy_finish(
        container, tool=tool, slug="simassets", call=call, summarize=_alchemy_summarize_asset_changes
    )


async def _alchemy_simulate_execution(container, args) -> str:
    tool = "simulate_execution"
    try:
        tx, network = _alchemy_build_sim_tx(args)
        block = _coerce_block_arg(args.get("block"), "block", default="latest")
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    call = await _alchemy_rpc("alchemy_simulateExecution", [tx, block, {"format": "NESTED"}], network=network, container=container)

    def summarize(result):
        if isinstance(result, dict) and ("calls" in result or "type" in result or "to" in result):
            return _alchemy_summarize_call_frame(result)
        if isinstance(result, dict):
            trace = result.get("trace")
            logs = result.get("logs")
            return {
                "trace_entries": len(trace) if isinstance(trace, list) else None,
                "log_count": len(logs) if isinstance(logs, list) else None,
            }
        return {}

    return await _alchemy_finish(container, tool=tool, slug="simexec", call=call, summarize=summarize)


async def _alchemy_simulate_sequence(container, args) -> str:
    tool = "simulate_sequence"
    txs_arg = args.get("transactions")
    if not isinstance(txs_arg, list) or not txs_arg:
        return _alchemy_bad_args(tool, ValueError(
            "transactions must be a non-empty array of {from, to, value, data} objects"
        ))
    network = _coerce_str_arg(args.get("network"), "network", default=None)
    mode = _coerce_str_arg(args.get("mode"), "mode", default="asset_changes")
    txs = []
    try:
        for index, item in enumerate(txs_arg[:20]):
            if not isinstance(item, dict):
                raise ValueError(f"transactions[{index}] must be an object")
            txs.append({
                "from": _coerce_address_arg(item.get("from") or item.get("from_address"), f"transactions[{index}].from"),
                "to": _coerce_address_arg(item.get("to"), f"transactions[{index}].to"),
                "value": _coerce_hexdata_arg(item.get("value"), f"transactions[{index}].value", default="0x0"),
                "data": _coerce_hexdata_arg(item.get("data"), f"transactions[{index}].data", default="0x"),
            })
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)
    method = "alchemy_simulateExecutionBundle" if mode == "execution" else "alchemy_simulateAssetChangesBundle"
    call = await _alchemy_rpc(method, txs, network=network, container=container)

    def summarize(result):
        if isinstance(result, list):
            items = result
        elif isinstance(result, dict):
            items = result.get("results") or result.get("changes") or []
        else:
            items = []
        per_tx = []
        for idx, item in enumerate(items[:20]):
            if mode == "execution":
                per_tx.append({"index": idx, **(_alchemy_summarize_call_frame(item) if isinstance(item, dict) else {})})
            else:
                per_tx.append({"index": idx, **(_alchemy_summarize_asset_changes(item) if isinstance(item, dict) else {})})
        return {"tx_count": len(txs), "result_count": len(items), "per_tx": per_tx}

    return await _alchemy_finish(container, tool=tool, slug="simseq", call=call, summarize=summarize)


# ── observed_tx_miner: pure-Python keccak-256 + ABI selector/calldata decode ──
#
# The miner matches on-chain calldata selectors to ABI function entries, which
# needs keccak-256 (Ethereum's variant — NOT stdlib sha3_256, which uses a
# different padding/domain byte). There is no keccak dependency in the venv, so
# this is a small self-contained keccak-f[1600] sponge (verified against known
# vectors in the tests). It is used only for 4-byte selector derivation and ABI
# matching; it never touches the submission gates.

_KECCAK_ROUNDS = 24
_KECCAK_RATE_BYTES = 136  # keccak-256: 1088-bit rate, 512-bit capacity
_KECCAK_MASK64 = (1 << 64) - 1
# Rho rotation offsets, indexed by lane (x + 5*y).
_KECCAK_ROT = (
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
)
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _keccak_rotl64(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _KECCAK_MASK64


def _keccak_f(state):
    for rnd in range(_KECCAK_ROUNDS):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _keccak_rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _keccak_rotl64(
                    state[x + 5 * y], _KECCAK_ROT[x + 5 * y]
                )
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= _KECCAK_RC[rnd]
    return state


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 digest (Ethereum variant). Pure-Python, no dependency."""
    state = [0] * 25
    rate = _KECCAK_RATE_BYTES
    padded = bytearray(data)
    padded.append(0x01)  # keccak domain byte (finalized SHA3 would use 0x06)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(padded[off + i * 8:off + i * 8 + 8], "little")
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
        if len(out) < 32:
            _keccak_f(state)
    return bytes(out[:32])


def _function_selector(signature: str) -> str:
    """4-byte selector (0x + 8 hex) for a canonical Solidity signature."""
    canonical = re.sub(r"\s+", "", str(signature or ""))
    return "0x" + _keccak256(canonical.encode("utf-8")).hex()[:8]


_SELECTOR_RE = re.compile(r"0x[0-9a-fA-F]{8}")


def _abi_canonical_type(component) -> str:
    """Canonical ABI type for a parameter, expanding tuples/arrays."""
    if not isinstance(component, dict):
        return str(component or "")
    base = str(component.get("type") or "")
    if base.startswith("tuple"):
        inner = ",".join(_abi_canonical_type(c) for c in (component.get("components") or []))
        return f"({inner}){base[len('tuple'):]}"
    return base


def _abi_entry_signature(entry: dict):
    name = str(entry.get("name") or "")
    types = [_abi_canonical_type(c) for c in (entry.get("inputs") or []) if c is not None]
    return f"{name}({','.join(types)})", types


def _abi_selector_index(abi) -> dict:
    """Map lowercase 0x-selector -> {name, signature, input_types}.

    Accepts both full ABI entry dicts and bare signature strings like
    ``transfer(address,uint256)``; ignores non-function/garbage entries."""
    index: dict = {}
    if not isinstance(abi, list):
        return index
    for entry in abi:
        try:
            if isinstance(entry, str):
                sig = re.sub(r"\s+", "", entry)
                if "(" not in sig or not sig.endswith(")"):
                    continue
                inner = sig[sig.index("(") + 1:sig.rindex(")")]
                types = [t for t in inner.split(",") if t] if inner else []
            elif isinstance(entry, dict):
                if str(entry.get("type", "function")) != "function" or not entry.get("name"):
                    continue
                sig, types = _abi_entry_signature(entry)
            else:
                continue
            selector = _function_selector(sig).lower()
            index[selector] = {"name": sig.split("(", 1)[0], "signature": sig, "input_types": types}
        except Exception:
            continue  # one malformed ABI entry must never break the index
    return index


def _resolve_target_selector(function, selector, abi_index):
    """Resolve a 4-byte selector from selector/function/abi.

    Returns (selector|None, error|None). ABI-only (no function/selector) returns
    (None, None) meaning observe every call and label by ABI."""
    raw_selector = str(selector or "").strip().lower()
    if raw_selector:
        if not _SELECTOR_RE.fullmatch(raw_selector):
            return None, "selector must be a 0x-prefixed 4-byte hex selector"
        return raw_selector, None
    text = str(function or "").strip()
    if text:
        low = text.lower()
        if _SELECTOR_RE.fullmatch(low):
            return low, None
        if "(" in text:
            return _function_selector(text).lower(), None
        for sel, meta in abi_index.items():
            if meta["name"] == text:
                return sel, None
        return None, (
            f"could not resolve a selector from function='{text}'; pass a 4-byte "
            "selector, a full signature like name(uint256,address), or include the abi"
        )
    return None, None


def _decode_abi_head_word(type_name: str, word: bytes) -> dict:
    base = str(type_name or "")
    head_hex = "0x" + word.hex()
    if base.endswith("]") or base in ("string", "bytes") or base.startswith(("tuple", "(")):
        return {"type": base, "head": head_hex,
                "note": "dynamic/complex — head word is an offset, value not decoded"}
    if base == "address":
        return {"type": base, "value": "0x" + word[-20:].hex()}
    if base == "bool":
        return {"type": base, "value": int.from_bytes(word, "big") != 0}
    if base.startswith("uint"):
        return {"type": base, "value": str(int.from_bytes(word, "big"))}
    if base.startswith("int"):
        return {"type": base, "value": str(int.from_bytes(word, "big", signed=True))}
    if base.startswith("bytes"):
        suffix = base[5:]
        n = int(suffix) if suffix.isdigit() else 32
        return {"type": base, "value": "0x" + word[:n].hex()}
    return {"type": base, "head": head_hex}


def _decode_calldata(calldata: str, input_types) -> list | None:
    """Best-effort decode of the 32-byte head words of an ABI-encoded payload.

    Static head types (address/uint/int/bool/bytesN) are decoded; dynamic/complex
    types surface their raw head word (an offset) rather than guessing a value."""
    text = str(calldata or "")
    body = text[10:] if text.startswith("0x") else text[8:]
    try:
        data = bytes.fromhex(body)
    except ValueError:
        return None
    words = [data[i:i + 32] for i in range(0, len(data), 32)]
    decoded = []
    for idx, type_name in enumerate(input_types or []):
        if idx >= len(words):
            break
        word = words[idx]
        if len(word) < 32:
            word = word.rjust(32, b"\x00")
        decoded.append(_decode_abi_head_word(type_name, word))
    return decoded


# ── observed_tx_miner handler ────────────────────────────────────────────

_OBSERVED_TX_DIR = "/workspace/campaign/observed-txs"
_OBSERVED_TX_WINDOW_BLOCKS = 50_000  # ~1 week on mainnet; agent should narrow it
_OBSERVED_TX_APPROVE_SELECTOR = "0x095ea7b3"
_OBSERVED_TX_TRANSFERFROM_SELECTOR = "0x23b872dd"


def _observed_tx_hex_to_int(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _observed_tx_candidates(traces, address, target_selector) -> list:
    """Top-level-preferred, deduped calls hitting ``address`` (optionally a single
    selector), ordered success > top-level > most-recent, one sample per tx."""
    addr = str(address).lower()
    matched = []
    for tr in traces:
        if not isinstance(tr, dict):
            continue
        action = tr.get("action")
        if not isinstance(action, dict):
            continue
        if str(action.get("to") or "").lower() != addr:
            continue
        inp = action.get("input") if isinstance(action.get("input"), str) else "0x"
        sel = inp[:10].lower() if len(inp) >= 10 else None
        if target_selector and sel != target_selector:
            continue
        block_int = _observed_tx_hex_to_int(tr.get("blockNumber"))
        matched.append({
            "tx_hash": tr.get("transactionHash"),
            "from": action.get("from"),
            "to": action.get("to"),
            "value": action.get("value") or "0x0",
            "input": inp,
            "selector": sel,
            "block": tr.get("blockNumber"),
            "block_int": block_int if block_int is not None else -1,
            "success": not bool(tr.get("error")),
            "top_level": (tr.get("traceAddress") == []),
            "call_type": action.get("callType") or tr.get("type"),
        })
    matched.sort(key=lambda c: (c["success"], c["top_level"], c["block_int"]), reverse=True)
    out, seen = [], set()
    for cand in matched:
        if cand["tx_hash"] in seen:
            continue
        seen.add(cand["tx_hash"])
        cand.pop("block_int", None)
        out.append(cand)
    return out


async def _observed_tx_transfers(container, address, net, from_block, to_block):
    """One getAssetTransfers sweep (both directions) indexed by lowercase tx hash."""
    index: dict = {}
    degraded = False
    fb = from_block if isinstance(from_block, str) and from_block.startswith("0x") else "0x0"
    tb = to_block if isinstance(to_block, str) and to_block else "latest"
    base = {
        "fromBlock": fb, "toBlock": tb,
        "category": ["external", "erc20", "erc721", "erc1155"],
        "withMetadata": True, "excludeZeroValue": True, "maxCount": hex(1000), "order": "desc",
    }
    for params in ({**base, "fromAddress": address}, {**base, "toAddress": address}):
        call = await _alchemy_rpc("alchemy_getAssetTransfers", [params], network=net, container=container)
        if not call.get("ok"):
            degraded = True
            continue
        for tr in ((call.get("result") or {}).get("transfers") or []):
            if not isinstance(tr, dict):
                continue
            tx_hash = str(tr.get("hash") or "").lower()
            if not tx_hash:
                continue
            index.setdefault(tx_hash, []).append({
                "from": tr.get("from"), "to": tr.get("to"), "asset": tr.get("asset"),
                "value": tr.get("value"), "category": tr.get("category"),
                "contract": (tr.get("rawContract") or {}).get("address"),
            })
    return index, degraded


async def _observed_tx_subcall_selectors(container, tx_hash, net):
    """Distinct selectors called within a tx (debug_traceTransaction callTracer)."""
    if not tx_hash:
        return [], False
    call = await _alchemy_rpc(
        "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}], network=net, container=container
    )
    if not call.get("ok"):
        return [], True
    selectors: list = []

    def walk(frame):
        if not isinstance(frame, dict):
            return
        for sub in (frame.get("calls") or []):
            if isinstance(sub, dict):
                inp = sub.get("input")
                if isinstance(inp, str) and len(inp) >= 10:
                    sel = inp[:10].lower()
                    if sel not in selectors:
                        selectors.append(sel)
                walk(sub)

    walk(call.get("result"))
    return selectors, False


def _observed_tx_build_sample(cand, abi_index, transfers, subcall_selectors, net) -> dict:
    selector = cand.get("selector")
    meta = abi_index.get((selector or "").lower()) if selector else None
    calldata = cand.get("input") or "0x"
    if meta is not None:
        arg_shape = meta["input_types"]
        args = _decode_calldata(calldata, meta["input_types"])
        raw_word_count = None
    else:
        arg_shape = None
        args = None
        body = calldata[10:] if calldata.startswith("0x") else calldata[8:]
        raw_word_count = (len(body) + 63) // 64  # 64 hex chars per 32-byte word

    value = cand.get("value") or "0x0"
    value_int = _observed_tx_hex_to_int(value)
    precondition_hints = []
    if value_int:
        precondition_hints.append(f"sends {value_int} wei of native value")
    distinct_assets = []
    for tr in transfers:
        asset = tr.get("asset")
        if asset and asset not in distinct_assets:
            distinct_assets.append(asset)
    if distinct_assets:
        precondition_hints.append("moves tokens: " + ", ".join(str(a) for a in distinct_assets[:6]))
    if _OBSERVED_TX_APPROVE_SELECTOR in subcall_selectors:
        precondition_hints.append("sets an ERC20 approval (approve) during the call")
    if _OBSERVED_TX_TRANSFERFROM_SELECTOR in subcall_selectors:
        precondition_hints.append("pulls tokens via transferFrom — caller likely needs a prior approval")

    replay_hints = {
        "network": net, "fork_block": cand.get("block"), "impersonate": cand.get("from"),
        "to": cand.get("to"), "value": value, "selector": selector, "calldata": calldata,
        "tx_hash": cand.get("tx_hash"),
        "foundry": "vm.createSelectFork(rpc, fork_block); vm.prank(impersonate); to.call{value: value}(calldata);",
    }

    sample = {
        "tx_hash": cand.get("tx_hash"), "from": cand.get("from"), "to": cand.get("to"),
        "success": cand.get("success"), "value": value, "selector": selector,
        "function": meta["signature"] if meta else None,
        "args": args, "arg_shape": arg_shape,
        "transfers": transfers, "precondition_hints": precondition_hints,
        "replay_hints": replay_hints, "block": cand.get("block"),
        "top_level": cand.get("top_level"),
    }
    if raw_word_count is not None:
        sample["raw_arg_word_count"] = raw_word_count
    return sample


def _observed_tx_synthesize_hints(samples, target_selector) -> dict:
    by_selector: dict = {}
    for sample in samples:
        sel = sample.get("selector")
        if not sel:
            continue
        entry = by_selector.setdefault(sel, {
            "selector": sel, "function": sample.get("function"),
            "arg_types": sample.get("arg_shape"), "observed_count": 0, "example_args": None,
        })
        entry["observed_count"] += 1
        if entry["example_args"] is None and sample.get("args") and sample.get("success"):
            entry["example_args"] = sample["args"]
    for sample in samples:  # fall back to any example if no successful one had args
        sel = sample.get("selector")
        if sel in by_selector and by_selector[sel]["example_args"] is None and sample.get("args"):
            by_selector[sel]["example_args"] = sample["args"]
    return {
        "primary_selector": target_selector or next(iter(by_selector), None),
        "by_selector": by_selector,
        "note": "feed example_args/arg_types into synthesize_args for this call",
    }


def _observed_tx_compose_hints(samples, address, net) -> dict:
    actors, selectors, tokens = [], [], []
    fork_block, fork_block_int = None, -1
    for sample in samples:
        frm = sample.get("from")
        if frm and frm not in actors:
            actors.append(frm)
        sel = sample.get("selector")
        if sel and sel not in selectors:
            selectors.append(sel)
        for tr in (sample.get("transfers") or []):
            asset = tr.get("asset")
            if asset and asset not in tokens:
                tokens.append(asset)
        block_int = _observed_tx_hex_to_int(sample.get("block"))
        if block_int is not None and block_int > fork_block_int:
            fork_block_int, fork_block = block_int, sample.get("block")
    return {
        "target": address, "network": net, "fork_block": fork_block,
        "actors": actors[:8], "selectors": selectors, "tokens": tokens[:12],
        "note": "feed into record_fork_context + compose_sequence_experiment",
    }


def _observed_tx_trim_sample(sample) -> dict:
    """Compact a sample for the model-visible response; full detail lives in the
    artifact. Caps transfers/args lists and the (potentially long) calldata."""
    trimmed = dict(sample)
    transfers = sample.get("transfers") or []
    if len(transfers) > 5:
        trimmed["transfers"] = transfers[:5]
        trimmed["transfers_truncated"] = len(transfers)
    args = sample.get("args")
    if isinstance(args, list) and len(args) > 16:
        trimmed["args"] = args[:16]
        trimmed["args_truncated"] = len(args)
    replay = sample.get("replay_hints")
    if isinstance(replay, dict):
        calldata = replay.get("calldata") or ""
        if isinstance(calldata, str) and len(calldata) > 210:
            new_replay = dict(replay)
            new_replay["calldata"] = calldata[:210] + "...(full calldata in artifact)"
            trimmed["replay_hints"] = new_replay
    return trimmed


def _observed_tx_unavailable(tool, address, target_selector, net, call, action_space) -> str:
    error = call.get("error")
    message = call.get("message") or error or "no on-chain data available"
    out = {
        "tool": tool, "ok": False, "status": "unavailable",
        "observed_tx_miner_id": None, "path": None, "network": net,
        "target": address, "selector": target_selector, "samples": [],
        "synthesize_args_hints": {}, "compose_sequence_hints": {},
        "blockers": [f"{error}: {message}" if error else message],
    }
    if action_space:
        out["action_space"] = action_space
    if call.get("degraded"):
        out["fallback"] = (
            "trace_filter/trace APIs are unavailable on this key/chain. Pass a narrower "
            "[from_block, to_block], try another chain, or replay from a forge/anvil fork; "
            "this does not block findings."
        )
    elif error == "alchemy_not_configured":
        out["fallback"] = (
            "Set ALCHEMY_API_KEY or api_keys.alchemy to mine on-chain transactions; "
            "forge/cast remain available for fork replay."
        )
    return json.dumps(out, indent=2, sort_keys=True, default=str)


async def _write_observed_tx_artifact(container, otx_id, payload) -> str:
    key = _alchemy_settings()
    content = json.dumps(_redact_alchemy(payload, key), indent=2, sort_keys=True, default=str)
    path = f"{_OBSERVED_TX_DIR}/{otx_id}.json"
    await container.write_file(path, content + "\n")
    return path


async def _alchemy_observed_tx_miner(container, args) -> str:
    """Mine representative real on-chain calls to a deployed contract: decoded
    argument shapes, actors, transfers, precondition hints, and replay hints.

    Composes the existing host-side Alchemy primitives (trace_filter to find
    calls, debug_traceTransaction for preconditions, getAssetTransfers for fund
    flow) and decodes calldata against a supplied ABI. Read-only corroboration/
    context — never relaxes the submission gates — and degrades cleanly with no
    key, no matching txs, or a chain where trace APIs are unavailable."""
    from reentbotpro.tools import (
        _coerce_bool_arg,
        _coerce_bounded_int_arg,
        _load_campaign_state,
        _next_campaign_id,
        _save_campaign_state,
    )
    tool = "observed_tx_miner"
    try:
        address = _coerce_address_arg(args.get("address"), "address")
        title = _coerce_str_arg(args.get("title"), "title", default=None)
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        function = _coerce_str_arg(args.get("function"), "function", default=None)
        selector = _coerce_str_arg(args.get("selector"), "selector", default=None)
        action_space = _coerce_str_arg(args.get("action_space"), "action_space", default=None)
        from_block = _coerce_block_arg(args.get("from_block"), "from_block", default=None)
        to_block = _coerce_block_arg(args.get("to_block"), "to_block", default="latest")
        max_transactions = _coerce_bounded_int_arg(
            args.get("max_transactions"), "max_transactions", default=5, minimum=1, maximum=20
        )
        include_traces = _coerce_bool_arg(args.get("include_traces"), "include_traces", default=True)
        include_transfers = _coerce_bool_arg(args.get("include_transfers"), "include_transfers", default=True)
        record_result = _coerce_bool_arg(args.get("record_result"), "record_result", default=True)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)

    abi_index = _abi_selector_index(args.get("abi"))
    target_selector, sel_error = _resolve_target_selector(function, selector, abi_index)
    if sel_error:
        return _alchemy_bad_args(tool, ValueError(sel_error))
    if function is None and selector is None and not abi_index:
        return _alchemy_bad_args(tool, ValueError(
            "provide function, selector, or abi to identify the target call(s)"
        ))
    # A full-signature `function` lets us decode args even without a separate abi.
    if function and "(" in function and target_selector and target_selector not in abi_index:
        abi_index.update(_abi_selector_index([function]))

    if network:
        net = resolve_alchemy_network(network)
        if not net:
            return _alchemy_bad_args(tool, ValueError(
                f"unrecognized network '{network}'; use an Alchemy subdomain, chain name, or chain id"
            ))
    else:
        # In the normal dispatch path the chain is resolved and injected before
        # this tool runs; here (no key, or a direct call) net may be None, and the
        # downstream _alchemy_rpc reports alchemy_not_configured (key checked
        # first) or chain_not_inferred, surfaced via _observed_tx_unavailable.
        net = await _alchemy_context_network(container)

    blockers: list = []
    enrichment_degraded = False

    # Resolve a bounded block window (trace_filter scans every block in range).
    if from_block is None:
        head = await _alchemy_rpc("eth_blockNumber", [], network=net, container=container)
        latest = _observed_tx_hex_to_int(head.get("result")) if head.get("ok") else None
        if latest is None:
            return _observed_tx_unavailable(tool, address, target_selector, net, head, action_space)
        from_block = hex(max(0, latest - _OBSERVED_TX_WINDOW_BLOCKS))
        if to_block == "latest":
            to_block = hex(latest)

    filt = {"fromBlock": from_block, "toBlock": to_block, "toAddress": [address],
            "count": min(1000, max(max_transactions * 25, 100))}
    tf = await _alchemy_rpc("trace_filter", [filt], network=net, container=container)
    if not tf.get("ok"):
        return _observed_tx_unavailable(tool, address, target_selector, net, tf, action_space)

    traces = tf.get("result") if isinstance(tf.get("result"), list) else []
    candidates = _observed_tx_candidates(traces, address, target_selector)
    if not candidates:
        scope = (f"selector {target_selector}" if target_selector else "any call")
        blockers.append(
            f"no transactions matched {scope} for {address} in [{from_block}, {to_block}]; "
            "widen the block range or pass a different selector"
        )
        out = {
            "tool": tool, "ok": False, "status": "partial",
            "observed_tx_miner_id": None, "path": None, "network": net,
            "target": address, "selector": target_selector, "samples": [],
            "synthesize_args_hints": {}, "compose_sequence_hints": {},
            "blockers": blockers, "from_block": from_block, "to_block": to_block,
            "cu_total": int(_ALCHEMY_USAGE["cu"]),
        }
        if action_space:
            out["action_space"] = action_space
        await _alchemy_trace_event(
            container, tool=tool, call={"network": net, "method": tool, "ok": False, "error": "no_match"}
        )
        return json.dumps(out, indent=2, sort_keys=True, default=str)

    selected = candidates[:max_transactions]

    transfers_by_tx: dict = {}
    if include_transfers:
        transfers_by_tx, transfers_degraded = await _observed_tx_transfers(
            container, address, net, from_block, to_block
        )
        if transfers_degraded:
            enrichment_degraded = True
            blockers.append("asset-transfer context unavailable on this key/chain")

    samples = []
    traces_degraded = False
    for cand in selected:
        subcall_selectors = []
        if include_traces:
            subcall_selectors, degraded = await _observed_tx_subcall_selectors(
                container, cand.get("tx_hash"), net
            )
            traces_degraded = traces_degraded or degraded
        transfers = transfers_by_tx.get(str(cand.get("tx_hash") or "").lower(), [])
        samples.append(_observed_tx_build_sample(cand, abi_index, transfers, subcall_selectors, net))
    if traces_degraded:
        enrichment_degraded = True
        blockers.append("per-transaction call traces unavailable on this key/chain")

    status = "partial" if enrichment_degraded else "observed"
    synthesize_hints = _observed_tx_synthesize_hints(samples, target_selector)
    compose_hints = _observed_tx_compose_hints(samples, address, net)

    observed_id, path = None, None
    if record_result:
        state = await _load_campaign_state(container)
        observed_id = _next_campaign_id(state, "observed_tx")
        path = await _write_observed_tx_artifact(container, observed_id, {
            "tool": tool, "title": title, "network": net, "target": address,
            "selector": target_selector,
            "from_block": from_block, "to_block": to_block, "status": status,
            "action_space": action_space, "samples": samples,
            "synthesize_args_hints": synthesize_hints, "compose_sequence_hints": compose_hints,
            "blockers": blockers, "cu_total": int(_ALCHEMY_USAGE["cu"]),
        })
        await _save_campaign_state(container, state)

    await _alchemy_trace_event(
        container, tool=tool, call={"network": net, "method": tool, "ok": True, "error": None}
    )
    digest = {
        "tool": tool, "ok": True, "status": status,
        "observed_tx_miner_id": observed_id, "path": path, "network": net,
        "target": address, "selector": target_selector,
        "from_block": from_block, "to_block": to_block,
        "samples": [_observed_tx_trim_sample(s) for s in samples],
        "synthesize_args_hints": synthesize_hints, "compose_sequence_hints": compose_hints,
        "blockers": blockers, "cu_total": int(_ALCHEMY_USAGE["cu"]),
        "note": ("Real observed transactions — corroboration/context for setup, calldata, and "
                 "fork replay. Not a finding; a runnable forge PoC is still required."),
    }
    if action_space:
        digest["action_space"] = action_space
    key = _alchemy_settings()
    return json.dumps(_redact_alchemy(digest, key), indent=2, sort_keys=True, default=str)


# ── Etherscan verified-source tool (host-side) ───────────────────────────
#
# Complements the Alchemy tools: Alchemy gives runtime truth (bytecode, traces,
# state, simulations); Etherscan gives *source* truth — verified Solidity, ABI,
# compiler settings, and proxy->implementation mapping for a deployed contract.
# Uses Etherscan's V2 multichain API (one key + chainid), reusing the same chain
# resolution as the Alchemy tools. Same invariants: strictly additive, host-side,
# key redacted everywhere, results are corroboration/context (never relax the
# submission gates), and degrade cleanly without a key or on a paywalled chain.

_ETHERSCAN_HTTP_TIMEOUT_SECONDS = 30
_ETHERSCAN_RUNTIME = {"api_key": None}
_ETHERSCAN_CAPABILITY: dict = {}
# Etherscan signals "needs a paid plan / not available on this chain" via status
# "0" with these markers; cache the chain as unavailable so we stop retrying.
_ETHERSCAN_UNAVAILABLE_MARKERS = (
    "upgrade", "paid plan", "pro plan", "api pro", "subscription",
    "not available on", "is not available", "forbidden", "not supported",
)


def set_etherscan_runtime(api_key) -> None:
    """Configure the host-side Etherscan tool for this run (called by the CLI)."""
    _ETHERSCAN_RUNTIME["api_key"] = api_key or None


def reset_etherscan_runtime() -> None:
    """Reset host-side Etherscan state (test helper)."""
    _ETHERSCAN_RUNTIME["api_key"] = None
    _ETHERSCAN_CAPABILITY.clear()


def etherscan_key_configured() -> bool:
    """True when an Etherscan API key is configured for this run."""
    return bool(_ETHERSCAN_RUNTIME.get("api_key"))


def _etherscan_api_key():
    return _ETHERSCAN_RUNTIME.get("api_key") or None


def _redact_etherscan(value, api_key):
    """Recursively replace the Etherscan key with a placeholder (defense-in-depth)."""
    if not api_key:
        return value
    if isinstance(value, str):
        return value.replace(api_key, "<etherscan-key>")
    if isinstance(value, dict):
        return {k: _redact_etherscan(v, api_key) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_etherscan(item, api_key) for item in value]
    return value


async def _etherscan_http_get(url, params, *, timeout):
    """GET an Etherscan V2 endpoint. Returns (status_code, parsed_body). The
    single network seam — tests patch this. parsed_body is a dict on JSON
    success, otherwise the raw response text."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(
            url,
            params=params,
            headers={"User-Agent": "ReentbotPro/0.1", "Accept": "application/json"},
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return resp.status_code, body


async def _etherscan_request(action, extra_params, *, network=None, chain_id=None, container=None) -> dict:
    """Call an Etherscan V2 contract endpoint. Returns a normalized dict and
    never raises; never leaks the key.

    The chain id is taken from the explicit ``chain_id``/``network`` args, else
    the latest record_fork_context chain. It never defaults to chain id 1: when
    no chain can be inferred it returns ``chain_not_inferred`` rather than
    silently querying Ethereum mainnet."""
    key = _etherscan_api_key()
    if not key:
        return {"ok": False, "error": "etherscan_not_configured",
                "message": "No Etherscan API key configured."}
    if chain_id is not None or (network is not None and str(network).strip() != ""):
        resolved_chain_id = resolve_chain_id(network, chain_id)
        if resolved_chain_id is None:
            return {"ok": False, "error": "invalid_network",
                    "message": (f"could not map network '{network}'/chain_id '{chain_id}' to a "
                                "chain id; pass a chain id (8453) or a known chain name (base)")}
        chain_id = resolved_chain_id
    else:
        default_subdomain = (
            await _alchemy_context_network(container) if container is not None else None
        )
        chain_id = resolve_chain_id(default_subdomain) if default_subdomain else None
        if chain_id is None:
            return {"ok": False, "error": "chain_not_inferred",
                    "message": _CHAIN_NOT_INFERRED_MESSAGE}
    blocked = _ETHERSCAN_CAPABILITY.get(chain_id)
    if blocked and blocked.get("available") is False:
        return {"ok": False, "error": "unavailable", "degraded": True,
                "chain_id": chain_id, "message": blocked.get("reason")}
    params = {"chainid": chain_id, "module": "contract", "action": action,
              "apikey": key, **extra_params}
    try:
        status, body = await _etherscan_http_get(
            ETHERSCAN_V2_API_URL, params, timeout=_ETHERSCAN_HTTP_TIMEOUT_SECONDS
        )
    except Exception as exc:
        return {"ok": False, "error": "request_failed", "chain_id": chain_id,
                "message": _redact_etherscan(str(exc), key)}
    if not isinstance(body, dict):
        return {"ok": False, "error": "non_json_response", "chain_id": chain_id,
                "http_status": status, "message": _redact_etherscan(str(body), key)[:500]}
    message = _redact_etherscan(str(body.get("message") or ""), key)
    result = _redact_etherscan(body.get("result"), key)
    if str(body.get("status")) != "1":
        haystack = f"{message} {result if isinstance(result, str) else ''}".lower()
        if any(marker in haystack for marker in _ETHERSCAN_UNAVAILABLE_MARKERS):
            _ETHERSCAN_CAPABILITY[chain_id] = {
                "available": False,
                "reason": message or "Etherscan API not available on this plan/chain",
            }
            return {"ok": False, "error": "unavailable", "degraded": True,
                    "chain_id": chain_id, "message": message, "result": result}
        return {"ok": False, "error": "etherscan_error", "chain_id": chain_id,
                "message": message, "result": result}
    return {"ok": True, "chain_id": chain_id, "message": message, "result": result}


def _etherscan_source_files(source_code) -> list:
    text = str(source_code or "").strip()
    if not text:
        return []
    obj = None
    try:
        if text.startswith("{{") and text.endswith("}}"):
            obj = json.loads(text[1:-1])  # Etherscan standard-json double-brace wrap
        elif text.startswith("{"):
            obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        sources = obj.get("sources")
        if isinstance(sources, dict):
            return list(sources.keys())
        if obj and all(isinstance(v, dict) for v in obj.values()):
            return list(obj.keys())  # older {path: {content}} multi-file format
    return ["<flattened>"]


def _parse_etherscan_source(result) -> dict:
    item = {}
    if isinstance(result, list) and result and isinstance(result[0], dict):
        item = result[0]
    elif isinstance(result, dict):
        item = result
    source_code = item.get("SourceCode") or ""
    abi = item.get("ABI") or ""
    verified = bool(str(source_code).strip()) and "not verified" not in str(abi).lower()
    implementation = str(item.get("Implementation") or "").strip() or None
    return {
        "is_verified": verified,
        "contract_name": (item.get("ContractName") or None) if verified else None,
        "compiler_version": (item.get("CompilerVersion") or None) if verified else None,
        "evm_version": item.get("EVMVersion") or None,
        "optimization_used": item.get("OptimizationUsed"),
        "runs": item.get("Runs"),
        "license": item.get("LicenseType") or None,
        "is_proxy": str(item.get("Proxy") or "0") == "1",
        "implementation": implementation,
        "abi_present": verified and bool(str(abi).strip()),
        "source_files": _etherscan_source_files(source_code),
        "abi": abi if verified else None,
        "source_code": source_code if verified else "",
    }


def _etherscan_source_summary(parsed) -> dict:
    return {
        "is_verified": parsed["is_verified"],
        "contract_name": parsed["contract_name"],
        "compiler_version": parsed["compiler_version"],
        "is_proxy": parsed["is_proxy"],
        "implementation": parsed["implementation"],
        "license": parsed["license"],
        "abi_present": parsed["abi_present"],
        "source_files": parsed["source_files"][:40],
    }


async def _write_etherscan_artifact(container, slug, payload) -> str:
    key = _etherscan_api_key()
    content = json.dumps(_redact_etherscan(payload, key), indent=2, sort_keys=True, default=str)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha1(content.encode("utf-8", "replace")).hexdigest()[:8]
    safe_slug = re.sub(r"[^a-z0-9]+", "-", str(slug).lower()).strip("-") or "etherscan"
    path = f"{_ALCHEMY_PROBE_DIR}/{safe_slug}-{stamp}-{digest}.json"
    await container.write_file(path, content + "\n")
    return path


def _etherscan_error_digest(tool, call) -> str:
    out = {"tool": tool, "ok": False, "error": call.get("error"), "message": call.get("message")}
    for field in ("chain_id", "http_status"):
        if call.get(field) is not None:
            out[field] = call.get(field)
    err = call.get("error")
    if call.get("degraded"):
        out["degraded"] = True
        out["fallback"] = (
            "Verified source is unavailable for this chain/plan. Use Alchemy bytecode + "
            "traces or the in-repo source; this does not block findings."
        )
    elif err == "etherscan_not_configured":
        out["fallback"] = (
            "Set ETHERSCAN_API_KEY or api_keys.etherscan to fetch verified source; "
            "fetch_url and forge/cast remain available."
        )
    return json.dumps(out, indent=2, sort_keys=True, default=str)


async def _etherscan_get_contract_source(container, args) -> str:
    from reentbotpro.tools import _coerce_bool_arg
    tool = "get_contract_source"
    try:
        address = _coerce_address_arg(args.get("address"), "address")
        network = _coerce_str_arg(args.get("network"), "network", default=None)
        chain_id = args.get("chain_id")
        follow_proxy = _coerce_bool_arg(args.get("follow_proxy"), "follow_proxy", default=True)
    except ValueError as exc:
        return _alchemy_bad_args(tool, exc)

    call = await _etherscan_request(
        "getsourcecode", {"address": address},
        network=network, chain_id=chain_id, container=container,
    )
    if not call.get("ok"):
        return _etherscan_error_digest(tool, call)

    parsed = _parse_etherscan_source(call.get("result"))
    chain_id = call.get("chain_id")

    if not parsed["is_verified"]:
        return json.dumps({
            "tool": tool, "ok": True, "address": address, "chain_id": chain_id,
            "is_verified": False,
            "note": ("Contract source is not verified on Etherscan for this chain. Use Alchemy "
                     "bytecode/traces (eth_getCode, trace_onchain_tx) or in-repo source instead."),
        }, indent=2, sort_keys=True, default=str)

    artifact_payload = {
        "tool": tool, "address": address, "chain_id": chain_id,
        "contract": {
            "contract_name": parsed["contract_name"],
            "compiler_version": parsed["compiler_version"],
            "evm_version": parsed["evm_version"],
            "optimization_used": parsed["optimization_used"],
            "runs": parsed["runs"],
            "license": parsed["license"],
            "is_proxy": parsed["is_proxy"],
            "implementation": parsed["implementation"],
            "source_files": parsed["source_files"],
            "abi": parsed["abi"],
            "source_code": parsed["source_code"],
        },
    }

    implementation_summary = None
    if follow_proxy and parsed["is_proxy"] and parsed["implementation"]:
        impl_call = await _etherscan_request(
            "getsourcecode", {"address": parsed["implementation"]},
            network=network, chain_id=chain_id, container=container,
        )
        if impl_call.get("ok"):
            impl_parsed = _parse_etherscan_source(impl_call.get("result"))
            implementation_summary = {
                "address": parsed["implementation"], **_etherscan_source_summary(impl_parsed)
            }
            artifact_payload["implementation"] = {
                "address": parsed["implementation"],
                "contract_name": impl_parsed["contract_name"],
                "compiler_version": impl_parsed["compiler_version"],
                "license": impl_parsed["license"],
                "source_files": impl_parsed["source_files"],
                "abi": impl_parsed["abi"],
                "source_code": impl_parsed["source_code"],
            }

    artifact = await _write_etherscan_artifact(container, f"source-{address[:10]}", artifact_payload)
    digest = {
        "tool": tool, "ok": True, "address": address, "chain_id": chain_id,
        "artifact": artifact,
        **_etherscan_source_summary(parsed),
        "note": ("Verified source + ABI written to the artifact — read_file it to analyze. "
                 "Corroboration/context, not a finding by itself."),
    }
    if implementation_summary:
        digest["implementation_source"] = implementation_summary
    return json.dumps(digest, indent=2, sort_keys=True, default=str)
