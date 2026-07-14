"""Local configuration helpers for ReentbotPro."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

CONFIG_FILENAME = "config.json"
DEFAULT_RPC_URL_KEY = "ethereum_mainnet"


def config_home() -> Path:
    """Return the ReentbotPro application config directory."""
    return Path(os.environ.get("REENTBOTPRO_HOME", Path.home() / ".reentbotpro"))


def config_path() -> Path:
    """Return the default local config file path."""
    return config_home() / CONFIG_FILENAME


def load_local_config(path: Path | None = None) -> dict[str, Any]:
    """Load plaintext local config, returning an empty dict when absent."""
    target = path or config_path()
    if not target.exists():
        return {}
    try:
        data = json.loads(target.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in local config {target}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Local config {target} must contain a JSON object")
    return data


def save_local_config(config: dict[str, Any], path: Path | None = None) -> None:
    """Persist local config as pretty-printed, key-sorted JSON.

    Creates the app config directory when absent and restricts the file to
    owner-only (0600), since it may hold API keys — mirroring the OAuth token
    file. Secret values in ``config`` are written verbatim to disk but are never
    logged or printed here.
    """
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(config, indent=2, sort_keys=True) + "\n"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(data)
    finally:
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass


def merge_local_config(
    updates: dict[str, Any], path: Path | None = None
) -> dict[str, Any]:
    """Shallow-merge ``updates`` into existing local config and persist it.

    Existing top-level keys not present in ``updates`` are preserved. Returns
    the merged config. Like :func:`save_local_config`, it never logs or prints
    secret values.
    """
    target = path or config_path()
    merged = {**load_local_config(target), **updates}
    save_local_config(merged, target)
    return merged


def _nonempty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _rpc_url_from_config(config: dict[str, Any]) -> str | None:
    """Return an *explicit* RPC override from local config, or None.

    This is the legacy, chain-agnostic lookup: top-level ``eth_rpc_url`` /
    ``rpc_url`` followed by the mainnet ``rpc_urls`` aliases. It deliberately
    does **not** derive an Alchemy URL from a bare key — chain-aware Alchemy
    derivation now lives in :func:`resolve_rpc_endpoint`, which knows the target
    chain and will not silently assume Ethereum mainnet.
    """
    direct = _nonempty_string(config.get("eth_rpc_url"))
    if direct:
        return direct
    direct = _nonempty_string(config.get("rpc_url"))
    if direct:
        return direct

    rpc_urls = config.get("rpc_urls")
    if isinstance(rpc_urls, dict):
        for key in (
            DEFAULT_RPC_URL_KEY,
            "eth_mainnet",
            "mainnet",
            "ethereum",
            "eth",
        ):
            value = _nonempty_string(rpc_urls.get(key))
            if value:
                return value

    return None


def resolve_rpc_url(
    cli_rpc_url: str | None = None,
    *,
    environ: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Resolve an *explicit* ETH RPC override (legacy, chain-agnostic).

    Precedence: CLI ``--rpc-url`` > ``ETH_RPC_URL`` > top-level config
    ``rpc_url`` / ``eth_rpc_url`` > legacy mainnet ``rpc_urls`` entry. It no
    longer derives an Alchemy mainnet URL from a bare key; use the canonical
    :func:`resolve_rpc_endpoint` for chain-aware Alchemy derivation.
    """
    cli_value = _nonempty_string(cli_rpc_url)
    if cli_value:
        return cli_value

    env = environ if environ is not None else os.environ
    env_value = _nonempty_string(env.get("ETH_RPC_URL"))
    if env_value:
        return env_value

    return _rpc_url_from_config(config if config is not None else load_local_config())


# ── Alchemy enhanced-API resolution ──────────────────────────────────────
#
# The vanilla RPC URL above is enough to drive cast probes, but the agent's
# enhanced-API tools (trace/debug, simulation, transfers, token, prices) need
# the *bare* Alchemy key so they can build per-network node URLs
# (https://{network}.g.alchemy.com/v2/{key}) and reach the Prices REST host
# (https://api.g.alchemy.com/...). These helpers are pure and additive; they
# never change how resolve_rpc_url behaves.

DEFAULT_ALCHEMY_NETWORK = "eth-mainnet"
ALCHEMY_NODE_URL_TEMPLATE = "https://{network}.g.alchemy.com/v2/{api_key}"
ALCHEMY_PRICES_URL_TEMPLATE = "https://api.g.alchemy.com/prices/v1/{api_key}/{endpoint}"

# A curated set of well-known Alchemy network subdomains, used for prompt hints
# and friendly validation messages. It is intentionally NOT exhaustive: any
# shape-valid subdomain is accepted so newly launched chains work without a code
# change (the host is always `*.g.alchemy.com`, so an unknown name simply fails
# at Alchemy rather than redirecting anywhere else).
KNOWN_ALCHEMY_NETWORKS: tuple[str, ...] = (
    "eth-mainnet",
    "eth-sepolia",
    "base-mainnet",
    "base-sepolia",
    "arb-mainnet",
    "arb-sepolia",
    "arbnova-mainnet",
    "opt-mainnet",
    "opt-sepolia",
    "polygon-mainnet",
    "polygon-amoy",
    "polygonzkevm-mainnet",
    "zksync-mainnet",
    "scroll-mainnet",
    "linea-mainnet",
    "blast-mainnet",
    "avax-mainnet",
    "bnb-mainnet",
    "opbnb-mainnet",
    "mantle-mainnet",
    "gnosis-mainnet",
    "celo-mainnet",
    "fantom-mainnet",
    "metis-mainnet",
    "zora-mainnet",
    "worldchain-mainnet",
    "unichain-mainnet",
    "ink-mainnet",
    "soneium-mainnet",
    "shape-mainnet",
    "apechain-mainnet",
)

_ALCHEMY_NETWORK_RE = re.compile(r"[a-z][a-z0-9-]{1,40}")
_ALCHEMY_URL_RE = re.compile(
    r"https?://([a-z0-9-]+)\.g\.alchemy\.com/v2/([^/?#\s]+)",
    re.IGNORECASE,
)
_ALCHEMY_PRICES_ENDPOINT_RE = re.compile(r"[a-z0-9/_-]{1,40}")


def normalize_alchemy_network(network: str | None) -> str:
    """Validate and normalize an Alchemy network subdomain.

    Empty/None falls back to ``DEFAULT_ALCHEMY_NETWORK``. Anything that is not a
    plain lowercase subdomain label raises ``ValueError`` so a malformed value
    can never alter the request host.
    """
    text = _nonempty_string(network)
    if not text:
        return DEFAULT_ALCHEMY_NETWORK
    candidate = text.strip().lower()
    if not _ALCHEMY_NETWORK_RE.fullmatch(candidate):
        raise ValueError(
            f"invalid Alchemy network '{network}': expected a subdomain label "
            "like eth-mainnet, base-mainnet, or arb-mainnet"
        )
    return candidate


def alchemy_node_url(network: str | None, api_key: str) -> str:
    """Build the JSON-RPC node URL for a network from a bare Alchemy key."""
    key = _nonempty_string(api_key)
    if not key:
        raise ValueError("alchemy api key is required")
    net = normalize_alchemy_network(network)
    return ALCHEMY_NODE_URL_TEMPLATE.format(network=net, api_key=key)


def alchemy_prices_url(api_key: str, endpoint: str = "tokens/by-address") -> str:
    """Build a Prices API REST URL from a bare Alchemy key."""
    key = _nonempty_string(api_key)
    if not key:
        raise ValueError("alchemy api key is required")
    safe_endpoint = str(endpoint or "").strip().strip("/")
    if not _ALCHEMY_PRICES_ENDPOINT_RE.fullmatch(safe_endpoint):
        raise ValueError(f"invalid prices endpoint '{endpoint}'")
    return ALCHEMY_PRICES_URL_TEMPLATE.format(api_key=key, endpoint=safe_endpoint)


def parse_alchemy_url(url: str | None) -> tuple[str, str] | None:
    """Extract (network, api_key) from an Alchemy node URL, or None."""
    text = _nonempty_string(url)
    if not text:
        return None
    match = _ALCHEMY_URL_RE.search(text)
    if not match:
        return None
    return match.group(1).lower(), match.group(2)


def resolve_alchemy_api_key(
    resolved_rpc_url: str | None = None,
    *,
    environ: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[str | None, str | None]:
    """Resolve a bare Alchemy API key and a best-effort primary network.

    Precedence: explicit ``ALCHEMY_API_KEY`` env var, then local config
    (``alchemy_api_key`` or ``api_keys.alchemy``), then the key embedded in a
    resolved or configured Alchemy RPC URL. Returns ``(api_key, network)`` where
    ``network`` is the subdomain parsed from an Alchemy URL when available, else
    ``None`` (callers default to ``eth-mainnet``). Returns ``(None, None)`` when
    no Alchemy key can be found.
    """
    env = environ if environ is not None else os.environ
    cfg = config if config is not None else load_local_config()

    parsed_resolved = parse_alchemy_url(resolved_rpc_url)
    network_hint = parsed_resolved[0] if parsed_resolved else None

    key = _nonempty_string(env.get("ALCHEMY_API_KEY"))
    if key:
        return key, network_hint

    key = _nonempty_string(cfg.get("alchemy_api_key"))
    api_keys = cfg.get("api_keys")
    if not key and isinstance(api_keys, dict):
        key = _nonempty_string(api_keys.get("alchemy"))
    if key:
        return key, network_hint

    if parsed_resolved:
        return parsed_resolved[1], parsed_resolved[0]

    parsed_cfg = parse_alchemy_url(_rpc_url_from_config(cfg))
    if parsed_cfg:
        return parsed_cfg[1], parsed_cfg[0]

    return None, None


# Friendly chain-name -> Alchemy subdomain aliases, so the agent can pass a
# human chain name and the tools still build the right node URL.
ALCHEMY_NETWORK_ALIASES = {
    "ethereum": "eth-mainnet", "eth": "eth-mainnet", "mainnet": "eth-mainnet",
    "ethereum-mainnet": "eth-mainnet",
    "sepolia": "eth-sepolia", "ethereum-sepolia": "eth-sepolia",
    "base": "base-mainnet",
    "arbitrum": "arb-mainnet", "arb": "arb-mainnet", "arbitrum-one": "arb-mainnet",
    "arbitrum-nova": "arbnova-mainnet", "arbnova": "arbnova-mainnet",
    "optimism": "opt-mainnet", "op": "opt-mainnet", "op-mainnet": "opt-mainnet",
    "polygon": "polygon-mainnet", "matic": "polygon-mainnet",
    "polygon-zkevm": "polygonzkevm-mainnet", "zkevm": "polygonzkevm-mainnet",
    "zksync": "zksync-mainnet", "zksync-era": "zksync-mainnet",
    "scroll": "scroll-mainnet",
    "linea": "linea-mainnet",
    "blast": "blast-mainnet",
    "avalanche": "avax-mainnet", "avax": "avax-mainnet",
    "bnb": "bnb-mainnet", "bsc": "bnb-mainnet", "binance": "bnb-mainnet",
    "opbnb": "opbnb-mainnet",
    "mantle": "mantle-mainnet",
    "gnosis": "gnosis-mainnet", "xdai": "gnosis-mainnet",
    "celo": "celo-mainnet",
    "fantom": "fantom-mainnet", "ftm": "fantom-mainnet",
    "metis": "metis-mainnet",
    "zora": "zora-mainnet",
}

# Chain id -> Alchemy subdomain, for resolving a fork context's chain_id (the
# unambiguous signal) into a node subdomain. Only well-known ids are listed;
# unknown chains are still reachable by passing the subdomain directly.
ALCHEMY_CHAIN_SUBDOMAINS = {
    1: "eth-mainnet", 11155111: "eth-sepolia",
    8453: "base-mainnet", 84532: "base-sepolia",
    42161: "arb-mainnet", 421614: "arb-sepolia", 42170: "arbnova-mainnet",
    10: "opt-mainnet", 11155420: "opt-sepolia",
    137: "polygon-mainnet", 80002: "polygon-amoy", 1101: "polygonzkevm-mainnet",
    324: "zksync-mainnet", 534352: "scroll-mainnet", 59144: "linea-mainnet",
    81457: "blast-mainnet", 43114: "avax-mainnet", 56: "bnb-mainnet",
    204: "opbnb-mainnet", 5000: "mantle-mainnet", 100: "gnosis-mainnet",
    42220: "celo-mainnet", 250: "fantom-mainnet", 1088: "metis-mainnet",
    7777777: "zora-mainnet",
}


def _parse_chain_id(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def resolve_alchemy_network(
    network: Any = None,
    chain_id: Any = None,
) -> str | None:
    """Resolve a chain hint to an Alchemy subdomain, or None if unrecognizable.

    Accepts a network string (Alchemy subdomain like ``base-mainnet``, a friendly
    name like ``base``/``arbitrum``, or a decimal chain id) and/or a ``chain_id``.
    Any subdomain-shaped string passes through so newly launched chains work
    without a code change.
    """
    text = _nonempty_string(network)
    if text:
        candidate = text.strip().lower()
        if candidate in ALCHEMY_NETWORK_ALIASES:
            return ALCHEMY_NETWORK_ALIASES[candidate]
        if candidate.isdigit():
            mapped = ALCHEMY_CHAIN_SUBDOMAINS.get(int(candidate))
            if mapped:
                return mapped
        if _ALCHEMY_NETWORK_RE.fullmatch(candidate):
            return candidate
    cid = _parse_chain_id(chain_id)
    if cid is not None:
        mapped = ALCHEMY_CHAIN_SUBDOMAINS.get(cid)
        if mapped:
            return mapped
    return None


# ── Etherscan V2 (verified source) resolution ────────────────────────────
#
# Etherscan's V2 API is multichain: one key + a `chainid` query param reaches
# 60+ EVM chains. It complements Alchemy (runtime/state) by providing verified
# source, ABI, and proxy->implementation mapping.

ETHERSCAN_V2_API_URL = "https://api.etherscan.io/v2/api"

# Inverse of ALCHEMY_CHAIN_SUBDOMAINS: Alchemy subdomain -> chain id, used to
# turn the agent's chain hint into the numeric chainid Etherscan V2 expects.
_ALCHEMY_SUBDOMAIN_CHAIN_IDS = {
    subdomain: chain_id for chain_id, subdomain in ALCHEMY_CHAIN_SUBDOMAINS.items()
}


def resolve_chain_id(network: Any = None, chain_id: Any = None) -> int | None:
    """Resolve a chain hint to a numeric chain id (for Etherscan V2), or None.

    Accepts a chain id (int/decimal/hex) or a network string (decimal id, a
    friendly name, or an Alchemy subdomain). Returns None when the chain id
    cannot be determined.
    """
    cid = _parse_chain_id(chain_id)
    if cid is not None:
        return cid
    text = _nonempty_string(network)
    if text:
        candidate = text.strip().lower()
        if candidate.isdigit():
            return int(candidate)
        subdomain = resolve_alchemy_network(candidate)
        if subdomain:
            return _ALCHEMY_SUBDOMAIN_CHAIN_IDS.get(subdomain)
    return None


# ── Block-explorer host -> chain inference ───────────────────────────────
#
# Explorer links in a README or docs page are a strong, human-authored signal
# of which chain a project is deployed to. This curated map covers the common
# EVM explorers; every chain id here is also in ALCHEMY_CHAIN_SUBDOMAINS so a
# host resolves cleanly to a node subdomain. It is intentionally conservative:
# an unknown host yields no binding rather than a guess.
KNOWN_EXPLORER_HOSTS = {
    "etherscan.io": 1,
    "sepolia.etherscan.io": 11155111,
    "basescan.org": 8453,
    "sepolia.basescan.org": 84532,
    "arbiscan.io": 42161,
    "sepolia.arbiscan.io": 421614,
    "nova.arbiscan.io": 42170,
    "optimistic.etherscan.io": 10,
    "sepolia-optimism.etherscan.io": 11155420,
    "polygonscan.com": 137,
    "amoy.polygonscan.com": 80002,
    "zkevm.polygonscan.com": 1101,
    "snowtrace.io": 43114,
    "bscscan.com": 56,
    "ftmscan.com": 250,
    "gnosisscan.io": 100,
    "celoscan.io": 42220,
    "lineascan.build": 59144,
    "scrollscan.com": 534352,
    "blastscan.io": 81457,
    "mantlescan.xyz": 5000,
}

_EXPLORER_URL_HOST_RE = re.compile(r"https?://([a-z0-9.\-]+)", re.IGNORECASE)


def chain_from_explorer_url(url: Any) -> tuple[str | None, int | None] | None:
    """Map a block-explorer URL or bare host to ``(network, chain_id)``, or None.

    Accepts a full URL (``https://basescan.org/address/0x...``) or a bare host
    (``basescan.org``), tolerating a leading ``www.``. Only hosts in
    :data:`KNOWN_EXPLORER_HOSTS` resolve; anything else returns ``None`` so an
    unrecognized link never fabricates a chain binding.
    """
    text = _nonempty_string(url)
    if not text:
        return None
    match = _EXPLORER_URL_HOST_RE.match(text)
    host = match.group(1) if match else text.strip()
    host = host.split("/")[0].strip().lower()
    if not host:
        return None
    chain_id = KNOWN_EXPLORER_HOSTS.get(host)
    if chain_id is None and host.startswith("www."):
        chain_id = KNOWN_EXPLORER_HOSTS.get(host[4:])
    if chain_id is None:
        return None
    return resolve_alchemy_network(None, chain_id), chain_id


def _recognized_network(value: Any, chain_id: int | None) -> str | None:
    """Return an Alchemy subdomain only for a *recognized* chain, else None.

    Unlike :func:`resolve_alchemy_network`, this does not pass arbitrary
    subdomain-shaped strings through — it accepts a known chain id, a friendly
    alias, or a curated known subdomain. Used by strict inference so a directory
    named ``localhost`` / ``hardhat`` / ``staging`` never becomes a chain.
    """
    if chain_id is not None:
        mapped = ALCHEMY_CHAIN_SUBDOMAINS.get(chain_id)
        if mapped:
            return mapped
    text = _nonempty_string(value)
    if text:
        candidate = text.strip().lower()
        if candidate in ALCHEMY_NETWORK_ALIASES:
            return ALCHEMY_NETWORK_ALIASES[candidate]
        if candidate in KNOWN_ALCHEMY_NETWORKS:
            return candidate
        if candidate.isdigit():
            return ALCHEMY_CHAIN_SUBDOMAINS.get(int(candidate))
    return None


def normalize_chain_hint(
    value: Any = None,
    *,
    chain_id: Any = None,
    strict: bool = False,
) -> tuple[str | None, int | None] | None:
    """Normalize a single chain hint to ``(alchemy_network, chain_id)``, or None.

    Unifies the recognized hint forms — a friendly chain name, an Alchemy
    subdomain, a decimal/hex chain id, or a block-explorer URL/host — into the
    canonical ``(network, chain_id)`` pair the resolvers use. Returns ``None``
    when nothing recognizable is present, so callers can keep a chain unbound
    rather than defaulting it. Filenames must have their extension stripped by
    the caller before being passed as ``value``.

    By default it is permissive: an unknown but subdomain-shaped name passes
    through (matching :func:`resolve_alchemy_network`, so newly launched chains
    work without a code change) — appropriate for explicit, agent-supplied
    hints. Pass ``strict=True`` for *inference* from arbitrary repo tokens,
    where only a known alias/subdomain/chain id should bind a chain.
    """
    explorer = chain_from_explorer_url(value) if value is not None else None
    if explorer:
        net, cid = explorer
        return net, (resolve_chain_id(None, chain_id) or cid)
    cid = resolve_chain_id(value, chain_id)
    network = (
        _recognized_network(value, cid)
        if strict
        else resolve_alchemy_network(value, chain_id)
    )
    if network or cid is not None:
        return network, cid
    return None


def resolve_default_chain_hint(
    *,
    environ: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[str | None, int | None, str | None]:
    """Resolve a run-level default chain hint as ``(network, chain_id, source)``.

    Precedence: ``REENTBOT_DEFAULT_NETWORK`` / ``REENTBOT_DEFAULT_CHAIN_ID`` env
    vars, then local config ``default_network`` / ``default_chain`` /
    ``default_chain_id``. This is a *run-level* fallback only — a deliberately
    weak signal that callers consult after explicit args, fork context, and the
    chain registry, so a single configured default never collapses a multi-chain
    scope. Returns ``(None, None, None)`` when no default is configured.
    """
    env = environ if environ is not None else os.environ
    cfg = config if config is not None else load_local_config()

    env_net = _nonempty_string(env.get("REENTBOT_DEFAULT_NETWORK"))
    env_cid_raw = env.get("REENTBOT_DEFAULT_CHAIN_ID")
    env_cid = (
        _nonempty_string(env_cid_raw)
        if isinstance(env_cid_raw, str)
        else env_cid_raw
    )
    if env_net or env_cid not in (None, ""):
        network = resolve_alchemy_network(env_net, env_cid)
        cid = resolve_chain_id(env_net, env_cid)
        if network or cid is not None:
            source = (
                "env:REENTBOT_DEFAULT_NETWORK"
                if env_net
                else "env:REENTBOT_DEFAULT_CHAIN_ID"
            )
            return network, cid, source

    cfg_net = _nonempty_string(cfg.get("default_network")) or _nonempty_string(
        cfg.get("default_chain")
    )
    cfg_cid = cfg.get("default_chain_id")
    if cfg_net or cfg_cid is not None:
        network = resolve_alchemy_network(cfg_net, cfg_cid)
        cid = resolve_chain_id(cfg_net, cfg_cid)
        if network or cid is not None:
            source = "config:default_network" if cfg_net else "config:default_chain_id"
            return network, cid, source

    return None, None, None


# ── Chain-aware RPC endpoint resolution ──────────────────────────────────
#
# resolve_rpc_endpoint is the canonical resolver. Given an optional target
# chain (a network name, an Alchemy subdomain, or a chain id) it derives the
# correct per-chain Alchemy node URL from a bare ALCHEMY_API_KEY, while still
# honoring explicit overrides (--rpc-url, ETH_RPC_URL, per-chain or top-level
# config rpc_urls). A bare key is never silently treated as Ethereum mainnet:
# the caller must supply a chain, configure a default chain, or opt in with
# allow_default_mainnet=True (which flags the result assumed_default_mainnet).
#
# resolve_rpc_url above is the demoted legacy path: explicit overrides only.


@dataclass(frozen=True)
class ResolvedRpcEndpoint:
    """A resolved RPC endpoint plus provenance for display and logging."""

    url: str | None
    provider: Literal["alchemy", "explicit", "none"]
    network: str | None
    chain_id: int | None
    source: str
    is_override: bool = False
    assumed_default_mainnet: bool = False


def _rpc_url_from_config_for_chain(
    config: dict[str, Any],
    *,
    network: Any = None,
    chain_id: Any = None,
) -> str | None:
    """Return an explicit per-chain ``rpc_urls`` entry for the chain, or None.

    Checks likely keys in order: the normalized Alchemy subdomain, the raw
    network string (as given and lowercased), the decimal and hex chain id,
    and — only when the chain resolves to Ethereum mainnet — the legacy mainnet
    aliases (so an existing ``rpc_urls.ethereum_mainnet`` still works).
    """
    rpc_urls = config.get("rpc_urls")
    if not isinstance(rpc_urls, dict):
        return None

    candidates: list[str] = []

    normalized = resolve_alchemy_network(network, chain_id)
    if normalized:
        candidates.append(normalized)

    if isinstance(network, str):
        stripped = network.strip()
        if stripped:
            candidates.append(stripped)
            candidates.append(stripped.lower())

    cid = resolve_chain_id(network, chain_id)
    if cid is not None:
        candidates.append(str(cid))
        candidates.append(hex(cid))

    if normalized == DEFAULT_ALCHEMY_NETWORK or cid == 1:
        candidates.extend(
            (DEFAULT_RPC_URL_KEY, "eth_mainnet", "mainnet", "ethereum", "eth")
        )

    seen: set[str] = set()
    for key in candidates:
        if key in seen:
            continue
        seen.add(key)
        value = _nonempty_string(rpc_urls.get(key))
        if value:
            return value
    return None


def _explicit_rpc_endpoint(
    url: str,
    source: str,
    resolved_network: str | None,
    resolved_chain_id: int | None,
) -> ResolvedRpcEndpoint:
    """Wrap an explicit override URL, parsing chain hints from Alchemy URLs."""
    parsed = parse_alchemy_url(url)
    if parsed:
        network = parsed[0]
        chain_id = resolve_chain_id(network) or resolved_chain_id
    else:
        network = resolved_network
        chain_id = resolved_chain_id
    return ResolvedRpcEndpoint(
        url=url,
        provider="explicit",
        network=network,
        chain_id=chain_id,
        source=source,
        is_override=True,
    )


def resolve_rpc_endpoint(
    *,
    rpc_url: str | None = None,
    cli_rpc_url: str | None = None,
    network: str | None = None,
    chain_id: int | str | None = None,
    allow_default_mainnet: bool = False,
    environ: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> ResolvedRpcEndpoint:
    """Resolve a chain-aware RPC endpoint.

    Precedence: per-call ``rpc_url`` > ``cli_rpc_url`` > ``ETH_RPC_URL`` >
    chain-specific config ``rpc_urls`` entry > top-level config
    ``rpc_url``/``eth_rpc_url`` > Alchemy URL derived from a bare key plus the
    resolved chain > (only with ``allow_default_mainnet``) a derived eth-mainnet
    URL > nothing. The target chain comes from ``network``/``chain_id``, falling
    back to config ``default_network``/``default_chain``/``default_chain_id``.
    """
    env = environ if environ is not None else os.environ

    # 1-3: explicit override URLs (per-call, CLI, environment) win outright and
    # never need local config, so resolve them before touching the config file
    # (a malformed config must not break an explicit --rpc-url / ETH_RPC_URL).
    arg_network = resolve_alchemy_network(network, chain_id)
    arg_chain_id = resolve_chain_id(network, chain_id)
    for candidate, source in (
        (rpc_url, "rpc_url"),
        (cli_rpc_url, "cli_rpc_url"),
        (env.get("ETH_RPC_URL"), "ETH_RPC_URL"),
    ):
        value = _nonempty_string(candidate)
        if value:
            return _explicit_rpc_endpoint(value, source, arg_network, arg_chain_id)

    cfg = config if config is not None else load_local_config()

    # Determine the effective chain: explicit args win, then config defaults,
    # then (only if allowed) an assumed Ethereum mainnet fallback.
    effective_network: Any = network
    effective_chain_id: Any = chain_id
    if effective_network is None and effective_chain_id is None:
        cfg_network = _nonempty_string(cfg.get("default_network")) or _nonempty_string(
            cfg.get("default_chain")
        )
        cfg_chain_id = cfg.get("default_chain_id")
        if cfg_network is not None or cfg_chain_id is not None:
            effective_network = cfg_network
            effective_chain_id = cfg_chain_id

    assumed_default_mainnet = False
    if (
        effective_network is None
        and effective_chain_id is None
        and allow_default_mainnet
    ):
        effective_network = DEFAULT_ALCHEMY_NETWORK
        assumed_default_mainnet = True

    resolved_network = resolve_alchemy_network(effective_network, effective_chain_id)
    resolved_chain_id = resolve_chain_id(effective_network, effective_chain_id)

    # 4: chain-specific config rpc_urls entry is an explicit per-chain override.
    chain_specific = _rpc_url_from_config_for_chain(
        cfg, network=effective_network, chain_id=effective_chain_id
    )
    if chain_specific:
        return _explicit_rpc_endpoint(
            chain_specific, "config:rpc_urls", resolved_network, resolved_chain_id
        )

    # 5: top-level config rpc_url / eth_rpc_url, also explicit overrides.
    for cfg_key in ("eth_rpc_url", "rpc_url"):
        value = _nonempty_string(cfg.get(cfg_key))
        if value:
            return _explicit_rpc_endpoint(
                value, f"config:{cfg_key}", resolved_network, resolved_chain_id
            )

    # 6-7: derive an Alchemy node URL from a bare key plus the resolved chain.
    alchemy_key, _ = resolve_alchemy_api_key(None, environ=env, config=cfg)
    if alchemy_key and resolved_network:
        return ResolvedRpcEndpoint(
            url=alchemy_node_url(resolved_network, alchemy_key),
            provider="alchemy",
            network=resolved_network,
            chain_id=resolved_chain_id,
            source="alchemy_default_mainnet"
            if assumed_default_mainnet
            else "alchemy_api_key",
            assumed_default_mainnet=assumed_default_mainnet,
        )

    # 8: nothing resolvable — do not invent a chain.
    return ResolvedRpcEndpoint(
        url=None,
        provider="none",
        network=resolved_network,
        chain_id=resolved_chain_id,
        source="none",
    )


def resolve_etherscan_api_key(
    *,
    environ: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Resolve an Etherscan V2 API key from env or local config.

    Precedence: ``ETHERSCAN_API_KEY`` env var, then local config
    ``etherscan_api_key`` or ``api_keys.etherscan``. One key works across all
    Etherscan V2 chains. Returns None when no key is configured.
    """
    env = environ if environ is not None else os.environ
    cfg = config if config is not None else load_local_config()
    key = _nonempty_string(env.get("ETHERSCAN_API_KEY"))
    if key:
        return key
    key = _nonempty_string(cfg.get("etherscan_api_key"))
    if key:
        return key
    api_keys = cfg.get("api_keys")
    if isinstance(api_keys, dict):
        return _nonempty_string(api_keys.get("etherscan"))
    return None
