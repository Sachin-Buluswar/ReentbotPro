"""Rich terminal output formatting for the audit agent."""

import json

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text


SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}


class Display:
    """Handles all terminal output formatting."""

    # Verbosity levels:
    #   "off"     — tool invocation line only, no result panels
    #   "partial" — truncate long results (default)
    #   "full"    — show complete tool output, no truncation
    VERBOSITY_LEVELS = ("off", "partial", "full")

    def __init__(self, console: Console | None = None, verbosity: str = "partial"):
        self.console = console or Console()
        if verbosity not in self.VERBOSITY_LEVELS:
            verbosity = "partial"
        self.verbosity = verbosity
        self.finding_count = 0
        self._streaming = False
        self._reasoning_started = False

    def header(self, source_dir: str, model: str, budget: dict):
        """Print audit header with config info.

        The credential model is Alchemy/Etherscan-first, so the header reports
        the target chain and how the RPC was obtained (derived from Alchemy, an
        explicit override, pending chain inference, or not configured) rather
        than a truncated URL.
        """
        lines = [
            f"[bold]Target:[/]  {source_dir}",
            f"[bold]Model:[/]   {model}",
            (
                f"[bold]Limit:[/]   [cyan]{budget['max_time'] // 60}[/cyan] min | "
                f"[cyan]{budget.get('context_window', 1_050_000) // 1000}k[/cyan] context"
            ),
        ]

        network = budget.get("chain_network")
        chain_id = budget.get("chain_id")
        if network and chain_id is not None:
            chain_str = f"{network} ({chain_id})"
        elif network:
            chain_str = str(network)
        elif chain_id is not None:
            chain_str = f"chain {chain_id}"
        else:
            chain_str = "not yet inferred"
        lines.append(f"[bold]Chain:[/]   {chain_str}")

        provider = budget.get("rpc_provider", "none")
        if provider == "alchemy":
            rpc_label = "derived from Alchemy"
        elif provider == "explicit":
            rpc_label = "explicit override"
        elif budget.get("alchemy"):
            # Alchemy key present but no chain yet: an endpoint derives per chain
            # once recon / record_fork_context fixes the target chain.
            rpc_label = "will be derived after chain inference"
        else:
            rpc_label = "not configured"
        lines.append(f"[bold]RPC:[/]     {rpc_label}")

        lines.append(
            "[bold]Alchemy:[/] "
            + ("configured" if budget.get("alchemy") else "not configured")
        )
        lines.append(
            "[bold]Etherscan:[/] "
            + ("configured" if budget.get("etherscan") else "not configured")
        )

        reasoning = budget.get("reasoning", "none")
        if reasoning != "none":
            lines.append(f"[bold]Reasoning:[/] {reasoning}")
        self.console.print(Panel(
            Text.from_markup("\n".join(lines)),
            title="[bold cyan]ReentbotPro[/]",
            border_style="cyan",
        ))

    def phase(self, name: str):
        """Print a phase separator."""
        self._end_stream()
        self.console.print()
        self.console.rule(f"[bold]{name}[/]", style="dim")
        self.console.print()

    def stream_text(self, text: str):
        """Stream agent reasoning text."""
        if not self._streaming:
            self._streaming = True
        self.console.print(Text(text, style="dim"), end="")

    def _end_stream(self):
        """End a streaming block."""
        if self._streaming:
            self.console.print()
            self._streaming = False

    def stream_reasoning(self, text: str):
        """Stream reasoning/thinking content according to verbosity.

        - off: suppress entirely
        - partial: show 'thinking...' indicator on first chunk, suppress rest
        - full: stream all reasoning tokens in dim italic style
        """
        if self.verbosity == "off":
            return
        if self.verbosity == "partial":
            if not self._reasoning_started:
                self._reasoning_started = True
                self._end_stream()
                self.console.print("  [dim italic]thinking...[/]")
            return
        # full verbosity — stream all reasoning content
        if not self._reasoning_started:
            self._reasoning_started = True
            self._end_stream()
        self.console.print(Text(text, style="dim italic"), end="")

    def end_reasoning(self):
        """Signal end of a reasoning block."""
        if self._reasoning_started:
            if self.verbosity == "full":
                self.console.print()  # newline after streamed reasoning
            self._reasoning_started = False

    def reasoning_summary(self, token_count: int):
        """Show reasoning token count summary."""
        if self.verbosity == "off" or token_count <= 0:
            return
        if token_count >= 1000:
            display_str = f"{token_count / 1000:.1f}k"
        else:
            display_str = str(token_count)
        self.console.print(f"  [dim]\\[reasoning: [cyan]{display_str}[/cyan] tokens][/]", highlight=False)

    def tool_start(self, tool_call: dict):
        """Show that a tool is being invoked."""
        self._end_stream()
        name = tool_call["function"]["name"]
        try:
            args = json.loads(tool_call["function"]["arguments"])
        except (json.JSONDecodeError, KeyError):
            args = {}

        # Build a short summary of the call
        summary = _tool_summary(name, args)
        self.console.print(f"\n[bold cyan]>> {name}:[/] {summary}")

    def tool_result(self, tool_call: dict, result: str):
        """Show tool result according to verbosity level.

        submit_finding results are always shown (via finding()).
        write_file to /output/report.md is never truncated.
        Everything else respects the verbosity setting.
        """
        name = tool_call["function"]["name"]
        if name == "submit_finding":
            return  # Findings get their own display via finding()

        # Never truncate the report write
        is_report_write = False
        if name == "write_file":
            try:
                args = json.loads(tool_call["function"]["arguments"])
                if "/output/report" in args.get("path", ""):
                    is_report_write = True
            except (json.JSONDecodeError, KeyError):
                pass

        if self.verbosity == "off" and not is_report_write:
            return  # Show nothing beyond the tool_start line

        display_result = result
        if self.verbosity == "partial" and not is_report_write and len(display_result) > 800:
            display_result = display_result[:350] + "\n... [truncated] ...\n" + display_result[-350:]

        self.console.print(Panel(
            display_result,
            title=f"[dim]{name}[/]",
            border_style="dim",
            expand=False,
            width=min(self.console.width, 120),
        ))

    def finding(self, finding: dict):
        """Prominently display a new finding."""
        self._end_stream()
        self.finding_count += 1
        severity = finding.get("severity", "info")
        style = SEVERITY_STYLES.get(severity, "dim")
        title = finding.get("title", "Untitled")
        validated = finding.get("validated", False)
        check = " [green]PoC validated[/]" if validated else ""

        affected = ""
        for loc in finding.get("affected_code", []):
            affected += f"\n  {loc.get('file', '?')}:[cyan]{loc.get('lines', '?')}[/cyan]"

        description = finding.get("description", "")
        self.console.print(Panel(
            Text.from_markup(
                f"[bold]{title}[/]\n"
                f"{description}\n"
                f"[dim]Affected:{affected}[/]{check}"
            ),
            title=f"Finding #{self.finding_count} \u2014 {severity.upper()}",
            border_style=style.split()[-1] if " " in style else style,
            expand=False,
            width=min(self.console.width, 120),
        ))

    def progress_status(
        self,
        elapsed: float,
        time_max: float,
        turn: int,
        reasoning_tokens: int = 0,
    ):
        """Show audit progress line."""
        self._end_stream()
        mins_elapsed = int(elapsed) // 60
        secs_elapsed = int(elapsed) % 60
        mins_max = int(time_max) // 60
        reasoning_str = ""
        if reasoning_tokens > 0:
            r_k = reasoning_tokens // 1000
            reasoning_str = f" | Reasoning: [cyan]{r_k}k[/cyan]"
        self.console.print(
            f"[dim]\u23f1 Turn [cyan]{turn}[/cyan] | "
            f"Time: [cyan]{mins_elapsed}:{secs_elapsed:02d}[/cyan]/[cyan]{mins_max}:00[/cyan]"
            f"{reasoning_str}[/]",
            highlight=False,
        )

    def agent_done(self):
        """Show completion message."""
        self._end_stream()
        self.console.print("\n[bold green]Agent completed.[/]")

    def chat_start(self):
        """Show chat mode header."""
        self.console.print()
        self.console.rule("[bold]Chat Mode[/]", style="dim")
        self.console.print(
            "[dim]Ask questions, request attack contracts, or type 'exit' to quit.\n"
            "Type 'keep-auditing' to resume the audit.[/]\n"
        )

    def resuming_audit(self):
        """Show that audit is resuming."""
        self.console.print("\n[bold cyan]Resuming audit...[/]\n")

    def error(self, message: str):
        """Show error message."""
        self._end_stream()
        self.console.print(f"[bold red]Error:[/] {escape(str(message))}")

    def status(self, message: str):
        """Show a status message."""
        self.console.print(f"[dim]{message}[/]")

    def report(self, content: str):
        """Render the markdown report in the terminal."""
        self._end_stream()
        self.console.print()
        self.console.rule("[bold]Vulnerability Report[/]", style="cyan")
        self.console.print()
        self.console.print(Markdown(content))
        self.console.print()

    def summary(
        self,
        findings: list[dict],
        output_dir: str,
        report_generated: bool = True,
        run_error: str | None = None,
    ):
        """Show audit summary."""
        self._end_stream()
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES.get(sev, "")
                parts.append(f"[{style}]{count} {sev}[/]")

        findings_str = ", ".join(parts) if parts else "No findings"
        report_str = f"{output_dir}/report.md" if report_generated else "not generated"
        lines = [
            f"[bold]Findings:[/] {findings_str}",
            f"[bold]Report:[/]   {report_str}",
            f"[bold]JSON:[/]     {output_dir}/findings.json",
        ]
        if run_error:
            lines.append(f"[bold red]Run error:[/] {run_error}")

        self.console.print(Panel(
            "\n".join(lines),
            title="[bold]Audit Complete[/]",
            border_style="red" if run_error else "green",
        ))


def _tool_summary(name: str, args: dict) -> str:
    """Create a short summary string for a tool call."""
    match name:
        case "list_files":
            return args.get("path", "/audit")
        case "read_file":
            path = args.get("path", "?")
            extra = ""
            if "offset" in args:
                extra = f" (from line {args['offset']})"
            return f"{path}{extra}"
        case "search_code":
            pattern = args.get("pattern", "?")
            path = args.get("path", "")
            return f"'{pattern}' in {path or '/audit'}"
        case "write_file":
            return args.get("path", "?")
        case "read_campaign":
            return args.get("section", "all")
        case "update_campaign":
            section = args.get("section", "?")
            action = args.get("action", "add")
            title = args.get("title", "?")
            if len(title) > 50:
                title = title[:47] + "..."
            return f"{action} {section}: {title}"
        case "request_toolset":
            toolset = args.get("toolset", "?")
            reason = args.get("reason", "")
            if len(reason) > 50:
                reason = reason[:47] + "..."
            return f"{toolset}{f': {reason}' if reason else ''}"
        case "run_experiment":
            cmd = args.get("command", "?")
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            return cmd
        case "run_sequence_minimization":
            title = args.get("title", "")
            if title:
                if len(title) > 50:
                    title = title[:47] + "..."
                return title
            return args.get("sequence", "?")
        case "run_campaign_fuzz":
            title = args.get("title", "")
            if title:
                if len(title) > 50:
                    title = title[:47] + "..."
                return title
            cmd = args.get("command", "?")
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            return cmd
        case "diagnose_build":
            for key in ("command", "experiment", "log_path", "profile"):
                value = args.get(key)
                if value:
                    text = str(value)
                    if len(text) > 70:
                        text = text[:67] + "..."
                    return text
            if args.get("log"):
                return "parse build log"
            return args.get("path", "/audit")
        case "snapshot_state":
            title = args.get("title", "?")
            if len(title) > 50:
                title = title[:47] + "..."
            return title
        case "compare_snapshots":
            before = args.get("before", "?")
            after = args.get("after", "?")
            return f"{before} -> {after}"
        case "evaluate_objective":
            comparison = args.get("comparison", "?")
            objectives = args.get("objectives") or []
            return f"{comparison} ({len(objectives)} objectives)"
        case "record_fork_context":
            title = args.get("title", "?")
            targets = sum(
                len(args.get(name) or [])
                for name in (
                    "contracts",
                    "tokens",
                    "pools",
                    "oracles",
                    "flash_loan_providers",
                )
            )
            if len(title) > 50:
                title = title[:47] + "..."
            return f"{title} ({targets} targets)"
        case "estimate_amm_economics":
            title = args.get("title", "")
            pools = args.get("pools") or []
            if title:
                if len(title) > 50:
                    title = title[:47] + "..."
                return f"{title} ({len(pools)} pools)"
            return f"{len(pools)} pool(s)"
        case "estimate_flash_loan":
            title = args.get("title", "")
            assets = args.get("assets") or []
            if title:
                if len(title) > 50:
                    title = title[:47] + "..."
                return f"{title} ({len(assets)} assets)"
            return f"{len(assets)} asset(s)"
        case "estimate_lending_health":
            title = args.get("title", "")
            positions = args.get("positions") or []
            if title:
                if len(title) > 50:
                    title = title[:47] + "..."
                return f"{title} ({len(positions)} positions)"
            return f"{len(positions)} position(s)"
        case "review_finding_evidence":
            title = args.get("title", "?")
            if len(title) > 60:
                title = title[:57] + "..."
            return title
        case "review_report_quality":
            title = args.get("title", "?")
            if len(title) > 60:
                title = title[:57] + "..."
            return title
        case "build_campaign_brief":
            focus = args.get("focus", "")
            title = args.get("title", "campaign resume brief")
            if len(title) > 50:
                title = title[:47] + "..."
            return f"{title}{f' ({focus})' if focus else ''}"
        case "attack_search":
            action = args.get("action", "sync")
            branch_id = args.get("branch_id", "")
            focus = args.get("focus", "")
            detail = branch_id or focus
            if len(detail) > 50:
                detail = detail[:47] + "..."
            return f"{action}{f': {detail}' if detail else ''}"
        case "map_protocol_graph":
            files = args.get("files")
            if files:
                return f"{len(files)} file(s)"
            path = args.get("path", "/audit")
            if len(path) > 70:
                path = path[:67] + "..."
            return path
        case "summarize_trace":
            path = args.get("path", "?")
            if len(path) > 70:
                path = path[:67] + "..."
            return path
        case "extract_call_sequence":
            path = args.get("path", "?")
            if len(path) > 60:
                path = path[:57] + "..."
            action_space = args.get("action_space")
            return f"{path} ({action_space or 'no action space'})"
        case "map_action_space":
            files = args.get("files")
            if files:
                return f"{len(files)} file(s)"
            path = args.get("path", "/audit")
            if len(path) > 70:
                path = path[:67] + "..."
            return path
        case "map_live_reachability":
            action_space = args.get("action_space") or "latest action space"
            profiles = args.get("profiles") or []
            if not profiles:
                max_profiles = args.get("max_profiles")
                if max_profiles:
                    return f"{action_space} (auto profiles, max {max_profiles})"
                return f"{action_space} (auto profiles)"
            return f"{action_space} ({len(profiles)} profile(s))"
        case "inventory_live_targets":
            title = args.get("title", "live target inventory")
            targets = args.get("targets") or []
            if len(title) > 50:
                title = title[:47] + "..."
            if not targets:
                return f"{title} (inferred targets)"
            return f"{title} ({len(targets)} target(s))"
        case "build_attack_graph":
            action_space = args.get("action_space") or "latest action space"
            reachability = args.get("live_reachability") or "latest reachability"
            return f"{action_space} + {reachability}"
        case "compose_sequence_experiment":
            title = args.get("title", "?")
            actions = args.get("actions") or []
            if len(title) > 50:
                title = title[:47] + "..."
            if not actions and (args.get("attack_graph") or args.get("candidate_id")):
                return f"{title} (attack-graph candidate)"
            return f"{title} ({len(actions)} steps)"
        case "complete_sequence_experiment":
            sequence = args.get("sequence", "?")
            mode = args.get("mode", "full")
            extras = []
            if args.get("target_addresses"):
                extras.append(f"{len(args['target_addresses'])} targets")
            if args.get("arg_synthesis"):
                extras.append("arg-synthesis")
            suffix = f" [{', '.join(extras)}]" if extras else ""
            return f"{sequence} ({mode}){suffix}"
        case "compose_invariant_harness":
            title = args.get("title", "?")
            actions = args.get("actions") or []
            if len(title) > 50:
                title = title[:47] + "..."
            return f"{title} ({len(actions)} handler actions)"
        case "mutate_hypothesis":
            source = args.get("source_hypothesis_id", "?")
            mutations = args.get("mutations") or []
            return f"{source} -> {len(mutations)} mutation(s)"
        case "run_command":
            cmd = args.get("command", "?")
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            return cmd
        case "web_search":
            return f'"{args.get("query", "?")}"'
        case "fetch_url":
            url = args.get("url", "?")
            if len(url) > 60:
                url = url[:57] + "..."
            return url
        case "submit_finding":
            return f'[{args.get("severity", "?")}] {args.get("title", "?")}'
        case _:
            return str(args)[:80]
