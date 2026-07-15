"""CLI entry point and interactive setup."""

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel

from reentbotpro.agent import (
    DEFAULT_MAX_TIME_MINUTES,
    _report_visible_tools,
    calculate_max_context,
    chat_loop,
    get_model_max_output_tokens,
    run_audit,
    run_report,
)
from reentbotpro.config import (
    ResolvedRpcEndpoint,
    load_local_config,
    merge_local_config,
    parse_alchemy_url,
    resolve_alchemy_api_key,
    resolve_alchemy_network,
    resolve_chain_id,
    resolve_etherscan_api_key,
    resolve_rpc_endpoint,
    resolve_rpc_url,
)
from reentbotpro.display import Display
from reentbotpro.docker import AuditContainer
from reentbotpro.llm import (
    DEFAULT_MODEL, OPENAI_API_PROVIDER, OPENAI_CODEX_PROVIDER, AuthError,
    create_client, get_model_settings, normalize_reasoning,
    resolve_reasoning_effort,
)
from reentbotpro.prompt import build_system_prompt
from reentbotpro.tools import set_alchemy_runtime, set_etherscan_runtime


def _resolve_context_budgets(
    context_window: int,
    user_max_context: int | None,
    report_output_reserve: int,
) -> tuple[int, int, bool]:
    """Resolve the audit/report history budgets and whether the user capped them.

    Returns ``(max_context, report_max_context, max_context_is_user_cap)``.

    Without an explicit ``--max-context`` the audit budget is the conservative
    full-tool reserve (``calculate_max_context``) and ``max_context_is_user_cap``
    is False, so run_audit may reclaim the unused tool-schema space per turn from
    ``context_window`` (a demand-driven turn sends far fewer than the full tool
    set). The report budget reserves only the small read/write schema surface it
    actually sends. With an explicit cap it is a hard ceiling: both budgets are
    clamped to it so the user's limit is always honored. The report phase also
    keeps its larger output reserve, so its history budget can still be smaller.
    """
    report_budget = calculate_max_context(
        context_window,
        output_reserve=report_output_reserve,
        tools=_report_visible_tools(),
    )
    if user_max_context is not None:
        return user_max_context, min(user_max_context, report_budget), True
    return calculate_max_context(context_window), report_budget, False


def _resolve_chain_defaults(
    *,
    cli_chain: str | None,
    cli_chain_id: str | int | None,
    config: dict,
    explicit_rpc_url: str | None,
) -> tuple[str | None, int | None]:
    """Resolve the run-level default chain as ``(alchemy_network, chain_id)``.

    Precedence: CLI ``--chain``/``--network``, then CLI ``--chain-id``, then local
    config (``default_network`` / ``default_chain`` / ``default_chain_id``), then
    the network embedded in an explicit Alchemy RPC override. Either element is
    ``None`` when it cannot be determined; both are ``None`` when no chain hint
    exists at all, in which case the agent infers the chain during recon.
    """
    # 1 & 2: CLI flags. ``--chain`` drives the subdomain, ``--chain-id`` the id;
    # passing both to the resolvers lets either one alone determine the chain.
    network = resolve_alchemy_network(cli_chain, cli_chain_id)
    chain_id = resolve_chain_id(cli_chain, cli_chain_id)
    if network or chain_id is not None:
        return network, chain_id

    # 3: local config defaults.
    cfg_network = config.get("default_network") or config.get("default_chain")
    cfg_chain_id = config.get("default_chain_id")
    network = resolve_alchemy_network(cfg_network, cfg_chain_id)
    chain_id = resolve_chain_id(cfg_network, cfg_chain_id)
    if network or chain_id is not None:
        return network, chain_id

    # 4: network embedded in an explicit Alchemy RPC override (--rpc-url/ETH_RPC_URL).
    parsed = parse_alchemy_url(explicit_rpc_url)
    if parsed:
        return resolve_alchemy_network(parsed[0]), resolve_chain_id(parsed[0])

    # 5: nothing known — the agent records the chain during recon / fork context.
    return None, None


def _rpc_metadata(
    endpoint: ResolvedRpcEndpoint, *, alchemy_configured: bool
) -> dict:
    """Machine-readable RPC provenance for ``findings.json``.

    Captures how (and whether) a run-level endpoint was resolved so a report or
    downstream tool can see the provider, target chain, and override status
    without parsing a URL.
    """
    return {
        "configured": endpoint.url is not None,
        "provider": endpoint.provider,
        "network": endpoint.network,
        "chain_id": endpoint.chain_id,
        "source": endpoint.source,
        "override": endpoint.is_override,
        "assumed_default_mainnet": endpoint.assumed_default_mainnet,
        "alchemy_key_configured": alchemy_configured,
    }


@dataclass(frozen=True)
class _RunRpcConfig:
    """Resolved run-level RPC/credential posture, derived from CLI + env + config."""

    endpoint: ResolvedRpcEndpoint
    alchemy_key: str | None
    etherscan_key: str | None
    default_network: str | None
    default_chain_id: int | None
    explicit_rpc_url: str | None
    rpc_meta: dict


def _resolve_run_rpc(
    *,
    cli_rpc_url: str | None,
    cli_chain: str | None,
    cli_chain_id: str | int | None,
    config: dict,
    environ: dict[str, str] | None = None,
) -> _RunRpcConfig:
    """Resolve credentials, the target chain, and the run-level RPC endpoint.

    The persistent credential model is Alchemy/Etherscan-first: a bare Alchemy key
    plus a known chain derives the chain-specific node URL. ``--rpc-url`` /
    ``ETH_RPC_URL`` / config ``rpc_url`` remain explicit advanced overrides via the
    legacy :func:`resolve_rpc_url` path. ``allow_default_mainnet`` is intentionally
    off: a bare key with no known chain yields no URL, and the agent derives one
    once it infers the chain (the container still receives the bare key).
    """
    explicit_rpc_url = resolve_rpc_url(cli_rpc_url, environ=environ, config=config)
    alchemy_key, _ = resolve_alchemy_api_key(
        explicit_rpc_url, environ=environ, config=config
    )
    etherscan_key = resolve_etherscan_api_key(environ=environ, config=config)
    default_network, default_chain_id = _resolve_chain_defaults(
        cli_chain=cli_chain,
        cli_chain_id=cli_chain_id,
        config=config,
        explicit_rpc_url=explicit_rpc_url,
    )
    endpoint = resolve_rpc_endpoint(
        cli_rpc_url=explicit_rpc_url or cli_rpc_url,
        network=default_network,
        chain_id=default_chain_id,
        allow_default_mainnet=False,
        environ=environ,
        config=config,
    )
    return _RunRpcConfig(
        endpoint=endpoint,
        alchemy_key=alchemy_key,
        etherscan_key=etherscan_key,
        default_network=default_network,
        default_chain_id=default_chain_id,
        explicit_rpc_url=explicit_rpc_url,
        rpc_meta=_rpc_metadata(endpoint, alchemy_configured=bool(alchemy_key)),
    )


async def _copy_container_tree(
    container: AuditContainer,
    container_root: str,
    host_root: str,
) -> int:
    """Copy a binary-safe file tree out of the audit container if it exists."""
    return await container.copy_tree_from_container(container_root, host_root)


async def _save_campaign_artifacts(
    container: AuditContainer,
    output_dir: str,
    display: Display,
) -> dict:
    """Persist campaign state, result logs, and experiment scaffolds to host."""
    campaign_dir = os.path.join(output_dir, "campaign")
    experiments_dir = os.path.join(output_dir, "experiments")
    warnings = []
    try:
        campaign_files = await _copy_container_tree(
            container,
            "/workspace/campaign",
            campaign_dir,
        )
    except Exception as exc:
        campaign_files = 0
        warnings.append(f"campaign artifact copy skipped: {exc}")
    try:
        experiment_files = await _copy_container_tree(
            container,
            "/workspace/experiments",
            experiments_dir,
        )
    except Exception as exc:
        experiment_files = 0
        warnings.append(f"experiment artifact copy skipped: {exc}")
    if campaign_files or experiment_files:
        display.status(
            "Saved campaign artifacts "
            f"({campaign_files} campaign files, "
            f"{experiment_files} experiment files)"
        )
    elif warnings:
        display.status("Campaign artifact save skipped: " + "; ".join(warnings))
    return {
        "campaign_files": campaign_files,
        "experiment_files": experiment_files,
        "campaign_dir": campaign_dir if campaign_files else None,
        "experiments_dir": experiments_dir if experiment_files else None,
        "warnings": warnings,
    }


def _build_findings_data(
    *,
    run_id: str,
    source_dir: str,
    model: str,
    rpc_url: str | None,
    started_at: str,
    messages: list[dict],
    explored: dict,
    report_content: str,
    campaign_artifacts: dict,
    findings: list[dict],
    rpc_meta: dict | None = None,
    interrupted: bool = False,
    partial: bool = False,
) -> dict:
    data = {
        "run_id": run_id,
        "source_dir": source_dir,
        "model": model,
        # Legacy compatibility field — kept but no longer primary. The structured
        # provenance lives under "rpc" below.
        "rpc_url": (rpc_url[:40] + "...") if rpc_url else "not set",
        "started_at": started_at,
        "total_turns": len([m for m in messages if m.get("role") == "assistant"]),
        "llm_error": explored.get("llm_error"),
        "report_generated": bool(report_content),
        "campaign_artifacts": campaign_artifacts,
        "findings": findings,
    }
    if rpc_meta is not None:
        data["rpc"] = rpc_meta
    if explored.get("audit_status"):
        data["audit_status"] = explored.get("audit_status")
        data["audit_status_reason"] = explored.get("audit_status_reason")
    if explored.get("final_readiness"):
        data["final_readiness"] = explored.get("final_readiness")
    if interrupted:
        data["interrupted"] = True
    if partial:
        data["partial"] = True
    return data


def _write_findings_json(output_dir: str, data: dict) -> str:
    findings_path = os.path.join(output_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return findings_path


async def _save_run_output(
    *,
    container: AuditContainer,
    output_dir: str,
    display: Display,
    run_id: str,
    source_dir: str,
    model: str,
    rpc_url: str | None,
    started_at: str,
    messages: list[dict],
    explored: dict,
    report_content: str,
    findings: list[dict],
    rpc_meta: dict | None = None,
    interrupted: bool = False,
    partial: bool = False,
) -> tuple[dict, str]:
    campaign_artifacts = {}
    if getattr(container, "is_running", False):
        try:
            campaign_artifacts = await _save_campaign_artifacts(
                container,
                output_dir,
                display,
            )
        except Exception as exc:
            display.error(f"Could not save campaign artifacts: {exc}")
            campaign_artifacts = {
                "campaign_files": 0,
                "experiment_files": 0,
                "campaign_dir": None,
                "experiments_dir": None,
                "warnings": [f"campaign artifact copy skipped: {exc}"],
            }
    data = _build_findings_data(
        run_id=run_id,
        source_dir=source_dir,
        model=model,
        rpc_url=rpc_url,
        started_at=started_at,
        messages=messages,
        explored=explored,
        report_content=report_content,
        campaign_artifacts=campaign_artifacts,
        findings=findings,
        rpc_meta=rpc_meta,
        interrupted=interrupted,
        partial=partial,
    )
    return data, _write_findings_json(output_dir, data)


def _interactive_setup(
    console: Console,
    *,
    api_key: str | None,
    model: str | None,
    max_time: int,
    alchemy_key: str | None,
    etherscan_key: str | None,
    default_network: str | None,
    explicit_rpc_url: str | None,
    verbosity: str | None = None,
    default_verbosity: str = "partial",
    reasoning: str | None = None,
) -> dict:
    """Prompt for missing configuration values interactively.

    The normal path asks only for the Alchemy and Etherscan keys; the target
    chain is inferred from scope/deployment metadata at audit time. The default
    chain and the explicit RPC URL are optional advanced hints, offered together
    behind a single opt-in gate (default no) and only when not already supplied
    via flags/env/config. Anything the user types here (and that was not already
    supplied by env/config) is offered for persistence to local config so it
    need not be re-entered. Key values are never echoed back.
    """
    config: dict = {}
    persist: dict = {}

    console.print(Panel("[bold cyan]ReentbotPro Setup[/]", border_style="cyan"))

    # Authentication
    if api_key:
        config["api_key"] = api_key
        console.print("\n  [green]Using OpenAI API key authentication.[/]")
    else:
        config["api_key"] = None
        console.print(
            "\n  [cyan]Authentication:[/] ChatGPT/Codex login will be used "
            "unless OPENAI_API_KEY is set."
        )

    # Alchemy API key — the normal credential; enables chain-aware RPC derivation
    # and the host-side enhanced-API tools.
    if alchemy_key:
        config["alchemy_key"] = alchemy_key
        console.print("\n  [green]Alchemy API key: configured.[/]")
    else:
        entered = console.input(
            "\n  Alchemy API key (enables chain-aware RPC + on-chain tools, "
            "optional — press Enter to skip): "
        ).strip()
        if entered:
            config["alchemy_key"] = entered
            persist["alchemy_api_key"] = entered
        else:
            config["alchemy_key"] = None
            console.print(
                "  [dim]Skipped — derived RPC and Alchemy enhanced-API tools "
                "won't be available.[/]"
            )

    # Etherscan API key — verified-source / ABI / proxy lookups.
    if etherscan_key:
        config["etherscan_key"] = etherscan_key
        console.print("\n  [green]Etherscan API key: configured.[/]")
    else:
        entered = console.input(
            "\n  Etherscan API key (enables verified-source lookup, "
            "optional — press Enter to skip): "
        ).strip()
        if entered:
            config["etherscan_key"] = entered
            persist["etherscan_api_key"] = entered
        else:
            config["etherscan_key"] = None
            console.print(
                "  [dim]Skipped — get_contract_source won't be available.[/]"
            )

    # Chain selection is inferred from scope/deployment metadata, so the normal
    # path asks only for keys. The default chain and the explicit RPC override
    # are optional advanced hints; values already supplied via flags/env/config
    # are used as-is and shown, never re-prompted.
    console.print(
        "\n  [cyan]Target chain will be inferred from scope/deployment "
        "metadata.[/]\n  [dim]Use --chain or config default_chain only as an "
        "optional hint.[/]"
    )
    config["default_chain"] = default_network
    if default_network:
        console.print(f"  [green]Default chain hint:[/] {default_network}")
    config["rpc_url"] = explicit_rpc_url
    if explicit_rpc_url:
        console.print(
            "  [dim]Using explicit RPC override from flags/env/config.[/]"
        )

    # Offer the advanced gate only when an advanced value is still unset. It
    # defaults to no, keeping the normal path to keys only; default_chain is
    # persisted only when explicitly entered here.
    need_default_chain = default_network is None
    need_rpc_override = explicit_rpc_url is None
    if need_default_chain or need_rpc_override:
        answer = console.input(
            "\n  [dim]Configure optional advanced defaults "
            "(default chain, RPC override)?[/] \\[y/[not bold blue]N[/]]: "
        ).strip().lower()
        if answer in ("y", "yes"):
            if need_default_chain:
                entered = console.input(
                    "\n  Default chain/network (e.g. base, arbitrum, "
                    "eth-mainnet; optional — press Enter to skip): "
                ).strip()
                if entered:
                    config["default_chain"] = entered
                    persist["default_chain"] = entered
            if need_rpc_override:
                entered = console.input(
                    "\n  Explicit RPC URL override "
                    "(optional — press Enter to skip): "
                ).strip()
                config["rpc_url"] = entered or None

    # Model
    if model:
        config["model"] = model
    else:
        m = console.input(f"\n  Model \\[[not bold blue]{DEFAULT_MODEL}[/]]: ").strip()
        config["model"] = m if m else DEFAULT_MODEL

    # Reasoning
    if reasoning:
        config["reasoning"] = normalize_reasoning(reasoning)
    else:
        provider_name = (
            OPENAI_API_PROVIDER if config.get("api_key") else OPENAI_CODEX_PROVIDER
        )
        model_settings = get_model_settings(
            config.get("model"),
            provider_name=provider_name,
        )
        choices = " / ".join(model_settings.reasoning_efforts)
        default_reasoning = model_settings.default_reasoning
        while True:
            r = console.input(
                f"\n  Reasoning effort — {choices} \\[[not bold blue]{default_reasoning}[/]]: "
            ).strip().lower()
            if not r:
                config["reasoning"] = default_reasoning
                break
            normalized = normalize_reasoning(r)
            if normalized in model_settings.reasoning_efforts:
                config["reasoning"] = normalized
                break
            console.print(f"  [not bold red]Invalid choice — must be {choices}[/]")

    # Max time
    time_min = max_time // 60
    while True:
        t = console.input(f"\n  Max wall-clock time in minutes \\[[not bold blue]{time_min}[/]]: ").strip()
        if not t:
            config["max_time"] = max_time
            break
        try:
            val = int(t)
        except ValueError:
            console.print(f"  [not bold red]Invalid number: {t}[/]")
            continue
        if val <= 0:
            console.print("  [not bold red]Must be a positive number[/]")
            continue
        config["max_time"] = val * 60
        break

    # Verbosity
    if verbosity:
        config["verbosity"] = verbosity
    else:
        while True:
            v = console.input(
                f"\n  Tool output verbosity — off / partial / full \\[[not bold blue]{default_verbosity}[/]]: "
            ).strip().lower()
            if not v:
                config["verbosity"] = default_verbosity
                break
            if v in ("off", "partial", "full"):
                config["verbosity"] = v
                break
            console.print("  [not bold red]Invalid choice — must be off, partial, or full[/]")

    # Persist newly entered credentials/defaults so the user need not re-enter
    # them each run. Only values typed just now (never an existing env/config key)
    # are in ``persist``, so the merge cannot clobber a key the user already had.
    if persist:
        answer = console.input(
            "\n  Save these to ~/.reentbotpro/config.json for next time? "
            "\\[[not bold blue]Y[/]/n]: "
        ).strip().lower()
        if answer in ("", "y", "yes"):
            try:
                merge_local_config(persist)
                console.print("  [dim]Saved to local config (key values not shown).[/]")
            except OSError as exc:
                console.print(f"  [not bold red]Could not save local config: {exc}[/]")
        else:
            console.print("  [dim]Not saved — applies to this run only.[/]")

    console.print()
    return config


def _should_prompt_setup(*, stdin_is_tty: bool, no_chat: bool) -> bool:
    """Return whether to run the interactive setup wizard."""
    if not stdin_is_tty:
        return False
    if no_chat:
        return False
    return True


async def _run(
    source_dir: str,
    api_key: str | None,
    model: str | None,
    max_time: int,
    output: str,
    image: str,
    rpc_url: str | None,
    no_chat: bool,
    verbosity: str | None,
    chain: str | None = None,
    chain_id: str | None = None,
    context_window: int | None = None,
    max_context: int | None = None,
    reasoning: str | None = None,
    force_login: bool = False,
):
    """Async main entry point."""
    console = Console()
    # The CLI exposes minutes; the agent loops compare elapsed seconds.
    max_time_seconds = max_time * 60

    # Resolve env vars (CLI flags take priority over env vars)
    if force_login and api_key:
        console.print("[bold red]Error:[/] --login cannot be combined with --api-key.")
        sys.exit(1)
    if api_key is None and not force_login:
        api_key = os.environ.get("OPENAI_API_KEY")
    if model is None:
        model = os.environ.get("REENTBOTPRO_MODEL")

    # Load local config once and reuse it for credentials, the target chain, and
    # the RPC endpoint. A malformed config never breaks startup here.
    try:
        local_config = load_local_config()
    except ValueError:
        local_config = {}

    # Resolve the Alchemy/Etherscan-first credential model + chain + endpoint from
    # CLI flags, environment, and local config.
    rpc_cfg = _resolve_run_rpc(
        cli_rpc_url=rpc_url,
        cli_chain=chain,
        cli_chain_id=chain_id,
        config=local_config,
    )

    # Non-interactive mode: skip setup wizard for CI/pipes and --no-chat batch runs.
    if _should_prompt_setup(stdin_is_tty=sys.stdin.isatty(), no_chat=no_chat):
        config = _interactive_setup(
            console,
            api_key=api_key,
            model=model,
            max_time=max_time_seconds,
            alchemy_key=rpc_cfg.alchemy_key,
            etherscan_key=rpc_cfg.etherscan_key,
            default_network=rpc_cfg.default_network,
            explicit_rpc_url=rpc_cfg.explicit_rpc_url,
            verbosity=verbosity,
            reasoning=reasoning,
        )
        # Re-resolve the endpoint with any credentials/chain the user just entered.
        # Newly typed keys may not be in env/config (the user can decline to save),
        # so layer them onto an effective config before deriving the endpoint.
        effective_config = dict(local_config)
        if config.get("alchemy_key"):
            effective_config["alchemy_api_key"] = config["alchemy_key"]
        if config.get("etherscan_key"):
            effective_config["etherscan_api_key"] = config["etherscan_key"]
        rpc_cfg = _resolve_run_rpc(
            cli_rpc_url=config.get("rpc_url") or rpc_url,
            cli_chain=config.get("default_chain") or chain,
            cli_chain_id=chain_id,
            config=effective_config,
        )
    else:
        config = {
            "api_key": api_key,
            "model": model or DEFAULT_MODEL,
            "max_time": max_time_seconds,
            "verbosity": verbosity or "partial",
            "reasoning": normalize_reasoning(reasoning) if reasoning else None,
        }

    api_key = config.get("api_key")
    model = config["model"]
    max_time = config["max_time"]
    # The run-level RPC posture: chain-aware endpoint, credentials, provenance.
    endpoint = rpc_cfg.endpoint
    alchemy_key = rpc_cfg.alchemy_key
    etherscan_key = rpc_cfg.etherscan_key
    default_network = rpc_cfg.default_network
    default_chain_id = rpc_cfg.default_chain_id
    rpc_url = endpoint.url
    rpc_meta = rpc_cfg.rpc_meta

    provider_name = OPENAI_API_PROVIDER if api_key else OPENAI_CODEX_PROVIDER
    model_settings = get_model_settings(model, provider_name=provider_name)
    context_window = context_window or model_settings.context_window
    requested_reasoning = config["reasoning"] or model_settings.default_reasoning
    reasoning = resolve_reasoning_effort(
        model,
        requested_reasoning,
        provider_name=provider_name,
    )
    reasoning_config = {"effort": reasoning.api_effort} if reasoning.api_effort else None
    # Separate the user's hard cap (--max-context) from the auto-derived budget:
    # without a cap, run_audit reclaims per-turn visible-tool space from
    # context_window; with one, both budgets honor the explicit ceiling.
    max_context, report_max_context, max_context_is_user_cap = (
        _resolve_context_budgets(
            context_window, max_context, get_model_max_output_tokens(model)
        )
    )
    verbosity = config["verbosity"]

    display = Display(console=console, verbosity=verbosity)

    # Configure host-side runtimes. Alchemy enhanced-API tools (trace/debug,
    # simulation, transfers, token, prices) need the bare key; the agent still
    # selects the chain per call / from record_fork_context, so the default
    # network here is only a last-resort fallback. Etherscan's verified-source
    # tool needs only its key (one key works across all V2 chains). Both degrade
    # cleanly when unset.
    set_alchemy_runtime(alchemy_key, default_network or endpoint.network)
    set_etherscan_runtime(etherscan_key)

    if alchemy_key:
        if rpc_url and endpoint.provider == "alchemy":
            display.status(
                f"Alchemy RPC derived for {endpoint.network}; enhanced APIs enabled."
            )
        elif rpc_url and endpoint.is_override:
            display.status(
                "Explicit RPC override in use; Alchemy enhanced APIs enabled "
                "(agent selects the chain per call)."
            )
        else:
            display.status(
                "Alchemy configured; RPC derives after chain inference / "
                "record_fork_context."
            )
    elif rpc_url:
        display.status(
            "Explicit RPC override in use (no Alchemy key; enhanced APIs disabled)."
        )
    if etherscan_key:
        display.status("Etherscan verified-source tool enabled (get_contract_source).")

    # Resolve paths and record start time
    source_dir = os.path.abspath(source_dir)
    run_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    started_at = datetime.now(timezone.utc).isoformat()
    output_dir = os.path.join(os.path.abspath(output), run_id)
    os.makedirs(output_dir, exist_ok=True)
    findings: list[dict] = []
    messages: list[dict] = []
    explored: dict = {}
    report_content = ""
    output_saved = False

    # Show header
    display.header(source_dir, model, {
        "max_time": max_time,
        "context_window": context_window,
        "reasoning": reasoning.display_effort,
        "rpc_provider": endpoint.provider,
        "rpc_is_override": endpoint.is_override,
        "chain_network": default_network or endpoint.network,
        "chain_id": default_chain_id if default_chain_id is not None else endpoint.chain_id,
        "alchemy": bool(alchemy_key),
        "etherscan": bool(etherscan_key),
    })

    if reasoning.note:
        display.status(reasoning.note)
    if reasoning_config:
        display.status(f"Reasoning effort: {reasoning.display_effort}")

    # Create LLM client. Without an OpenAI API key this will use the
    # ChatGPT/Codex OAuth profile, prompting interactively on first run.
    try:
        client = create_client(
            api_key,
            console=console,
            interactive=sys.stdin.isatty(),
            force_login=force_login,
        )
    except AuthError as e:
        console.print(f"[bold red]Authentication error:[/] {e}")
        sys.exit(1)
    display.status(f"Using {client.provider_name}")

    # Start container. Pass the bare credentials and resolved default-chain hints
    # so in-container tooling can derive a chain-specific endpoint even when no
    # ETH_RPC_URL was pre-derived (a bare key with no known chain).
    container = AuditContainer(image_name=image)
    try:
        await container.start(
            source_dir,
            rpc_url=rpc_url,
            on_status=display.status,
            alchemy_api_key=alchemy_key,
            etherscan_api_key=etherscan_key,
            default_network=default_network,
            default_chain_id=default_chain_id,
        )

        # Build system prompt
        system_prompt = build_system_prompt()

        # Collect init report for the agent's first message
        init_report = (
            "\n".join(container.init_report)
            if container.init_report else None
        )

        # ── Audit phase ──
        display.phase("Audit Phase")
        findings, messages, explored = await run_audit(
            client=client,
            model=model,
            system_prompt=system_prompt,
            container=container,
            display=display,
            max_time_seconds=max_time,
            max_context=max_context,
            reasoning_config=reasoning_config,
            init_report=init_report,
            context_window=context_window,
            max_context_is_user_cap=max_context_is_user_cap,
        )

        # ── Report phase ──
        report_content = await run_report(
            client, model, messages, container, display, findings,
            explored=explored,
            max_time_seconds=max_time,
            max_context=report_max_context,
            reasoning_config=reasoning_config,
        )

        # Save report to host and render in TUI
        if report_content:
            report_path = os.path.join(output_dir, "report.md")
            with open(report_path, "w") as f:
                f.write(report_content)
            display.report(report_content)
        else:
            display.error("Report was not generated.")

        _, findings_path = await _save_run_output(
            container=container,
            output_dir=output_dir,
            display=display,
            run_id=run_id,
            source_dir=source_dir,
            model=model,
            rpc_url=rpc_url,
            rpc_meta=rpc_meta,
            started_at=started_at,
            messages=messages,
            explored=explored,
            report_content=report_content,
            findings=findings,
        )
        output_saved = True

        # Show summary
        run_error = explored.get("llm_error")
        if not report_content:
            run_error = run_error or "report generation failed"
        display.summary(
            findings,
            output_dir,
            report_generated=bool(report_content),
            run_error=run_error,
        )

        # ── Chat phase ──
        if not no_chat:
            output_saved = False
            pre_chat_count = len(findings)
            await chat_loop(
                client, model, messages, container, display, findings,
                explored=explored,
                max_time_seconds=max_time,
                max_context=max_context,
                reasoning_config=reasoning_config,
                context_window=context_window,
                max_context_is_user_cap=max_context_is_user_cap,
            )

            # Re-save after chat because findings or campaign artifacts may
            # have changed even when the finding count did not.
            _, findings_path = await _save_run_output(
                container=container,
                output_dir=output_dir,
                display=display,
                run_id=run_id,
                source_dir=source_dir,
                model=model,
                rpc_url=rpc_url,
                rpc_meta=rpc_meta,
                started_at=started_at,
                messages=messages,
                explored=explored,
                report_content=report_content,
                findings=findings,
            )
            output_saved = True
            if len(findings) > pre_chat_count:
                display.status(f"Updated findings saved ({len(findings)} total)")

    except KeyboardInterrupt:
        display.status("Interrupted — saving findings...")
        _, findings_path = await _save_run_output(
            container=container,
            output_dir=output_dir,
            display=display,
            run_id=run_id,
            source_dir=source_dir,
            model=model,
            rpc_url=rpc_url,
            rpc_meta=rpc_meta,
            started_at=started_at,
            messages=messages,
            explored=explored,
            report_content=report_content,
            findings=findings,
            interrupted=True,
            partial=True,
        )
        output_saved = True
        display.status(f"Findings saved to {findings_path}")
    except Exception as e:
        display.error(str(e))
        raise
    finally:
        if not output_saved:
            try:
                display.status("Saving partial run output before cleanup...")
                _, findings_path = await _save_run_output(
                    container=container,
                    output_dir=output_dir,
                    display=display,
                    run_id=run_id,
                    source_dir=source_dir,
                    model=model,
                    rpc_url=rpc_url,
                    rpc_meta=rpc_meta,
                    started_at=started_at,
                    messages=messages,
                    explored=explored,
                    report_content=report_content,
                    findings=findings,
                    interrupted=True,
                    partial=True,
                )
                display.status(f"Partial findings saved to {findings_path}")
            except Exception as e:
                display.error(f"Could not save partial run output: {e}")
        display.status("Cleaning up container...")
        await container.stop()
        display.status("Done.")


@click.command()
@click.argument("source_dir", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--api-key",
    default=None,
    help="OpenAI API key (or set OPENAI_API_KEY). If omitted, ChatGPT/Codex login is used.",
)
@click.option("--model", default=None, help="OpenAI model to use; settings are inferred automatically")
@click.option(
    "--max-time",
    default=DEFAULT_MAX_TIME_MINUTES,
    help="Wall clock limit in minutes for agent loops",
)
@click.option("--output", default="./findings", help="Output directory for findings and report")
@click.option("--image", default="reentbotpro-tools", help="Docker image name")
@click.option(
    "--chain",
    "--network",
    "chain",
    default=None,
    help=(
        "Default target chain/network, e.g. base, base-mainnet, arbitrum, "
        "eth-mainnet. Used to derive Alchemy RPC URLs when --rpc-url is not "
        "supplied."
    ),
)
@click.option(
    "--chain-id",
    default=None,
    help=(
        "Default target chain id, e.g. 8453 for Base. Used to derive Alchemy RPC "
        "URLs when --rpc-url is not supplied."
    ),
)
@click.option(
    "--rpc-url",
    default=None,
    help=(
        "Advanced explicit RPC endpoint override. Usually not needed when "
        "ALCHEMY_API_KEY and --chain/--chain-id are configured."
    ),
)
@click.option("--no-chat", is_flag=True, help="Skip interactive chat after audit")
@click.option(
    "--verbosity", default=None, type=click.Choice(["off", "partial", "full"], case_sensitive=False),
    help="Tool output verbosity: off (headers only), partial (truncated, default), full (complete)",
)
@click.option(
    "--context-window", default=None, type=int,
    help="Advanced override for model context window; inferred from --model by default",
)
@click.option(
    "--max-context", default=None, type=int,
    help=(
        "Advanced hard cap on retained conversation-history tokens. By default "
        "this is auto-sized from the context window and shrinks per turn to the "
        "tools actually in use; set it to pin a fixed ceiling."
    ),
)
@click.option(
    "--reasoning", default=None,
    type=click.Choice(
        ["none", "minimal", "low", "medium", "high", "xhigh", "max"],
        case_sensitive=False,
    ),
    help="OpenAI reasoning effort; unsupported values are adjusted for the selected model",
)
@click.option("--login", "force_login", is_flag=True, help="Force a fresh ChatGPT/Codex browser login")
def main(
    source_dir,
    api_key,
    model,
    max_time,
    output,
    image,
    chain,
    chain_id,
    rpc_url,
    no_chat,
    verbosity,
    context_window,
    max_context,
    reasoning,
    force_login,
):
    """Audit smart contracts for exploitable vulnerabilities."""
    asyncio.run(_run(
        source_dir=source_dir,
        api_key=api_key,
        model=model,
        max_time=max_time,
        output=output,
        image=image,
        chain=chain,
        chain_id=chain_id,
        rpc_url=rpc_url,
        no_chat=no_chat,
        verbosity=verbosity,
        context_window=context_window,
        max_context=max_context,
        reasoning=reasoning,
        force_login=force_login,
    ))
