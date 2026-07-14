"""Workspace primitive tools: file, search, shell, and web helpers.

These are the base I/O layer of the tool set — read/write/list files, run shell
commands inside the audit container, and do host-side web search/fetch. They
depend only on the standard library and ``AuditContainer``; nothing here reaches
into the campaign core, so ``tools.py`` imports and re-exports them (and the
tests resolve them on that facade).

Extracted from ``tools.py`` as a genuine base layer: the campaign core calls
*into* these primitives, and these primitives call nothing in the core. Note
``_search_code`` deliberately stays in ``tools.py`` because it depends on the
action-source-path helpers that belong with the source-mapping split.
"""

from __future__ import annotations

import ipaddress
import posixpath
import shlex
import socket
from urllib.parse import urlparse

from reentbotpro.docker import AuditContainer

_FIND_PRUNE_NAMES = (
    ".git", "node_modules", "out", "artifacts", "cache",
    "build", "coverage", "typechain", "typechain-types",
    ".context", ".next", "dist", "findings", "logs", "tmp",
    "poc-tests", "minitest", "ssrtest", "test", "tests", "script", "scripts",
)
_FIND_PRUNE_PATTERNS = ("*_poc", "*-poc", "poc-*", "poc_*")


def _truncate(text: str, max_chars: int = 50000) -> str:
    """Truncate long output, keeping beginning and end."""
    if len(text) <= max_chars:
        return text
    keep = max_chars // 2 - 50
    return (
        text[:keep]
        + f"\n\n... [truncated — {len(text)} total chars, showing first and last {keep}] ...\n\n"
        + text[-keep:]
    )


async def _list_files(container: AuditContainer, args: dict) -> str:
    path = args.get("path", "/audit")
    depth = min(args.get("depth", 10), 10)
    include_artifacts = bool(args.get("include_artifacts", False))
    if depth < 1:
        depth = 1

    if depth == 1:
        # Simple listing for depth 1
        exit_code, output = await container.exec(
            f"ls -la {shlex.quote(path)} 2>&1", timeout=10
        )
    else:
        # Recursive listing.  Prune common noise directories (node_modules,
        # build artifacts, old PoCs, etc.) so the listing shows project
        # structure, not dependency trees or prior attempts.
        name_expr = " -o ".join(
            f"-name {shlex.quote(d)}" for d in _FIND_PRUNE_NAMES
        )
        pattern_expr = " -o ".join(
            f"-name {shlex.quote(d)}" for d in _FIND_PRUNE_PATTERNS
        )
        prune_expr = " -o ".join(
            part for part in (name_expr, pattern_expr) if part
        )
        prune_clause = (
            f"\\( {prune_expr} \\) -prune -o "
            if not include_artifacts and prune_expr
            else ""
        )
        exit_code, output = await container.exec(
            f"find {shlex.quote(path)} -maxdepth {depth} "
            f"{prune_clause}-print "
            f"| sort 2>&1",
            timeout=30,
        )

    lines = output.strip().split("\n")
    if len(lines) > 200:
        total = len(lines)
        lines = lines[:200]
        lines.append(f"... [truncated, showing first 200 of {total} lines]")
    return "\n".join(lines)


async def _read_file(container: AuditContainer, args: dict) -> str:
    path = args.get("path", "")
    if not path:
        return "Error: 'path' is required"
    offset = args.get("offset", 1)
    limit = args.get("limit", 500)
    if offset < 1:
        offset = 1

    # Get total line count first
    safe_path = shlex.quote(path)
    _, wc_out = await container.exec(f"wc -l < {safe_path} 2>&1", timeout=10)
    total_lines = 0
    try:
        total_lines = int(wc_out.strip())
    except ValueError:
        pass

    end_line = offset + limit - 1
    exit_code, output = await container.exec(
        f"sed -n '{offset},{end_line}p' {safe_path} 2>&1", timeout=15
    )
    if exit_code != 0:
        return f"Error reading file: {output}"

    output = _truncate(output)

    if total_lines > end_line:
        output += f"\n... [truncated, {total_lines} total lines. Use offset to read more.]"
    return output


async def _write_file(container: AuditContainer, args: dict) -> str:
    path = args.get("path", "")
    content = args.get("content", "")
    if not path:
        return "Error: 'path' is required"

    # Normalize to resolve .. and . components, then validate the path as a
    # child of an allowed root.  A plain startswith check would allow paths
    # such as /workspaceevil/out.txt.
    path = posixpath.normpath(path)
    allowed_prefixes = ("/audit", "/workspace", "/output")
    if not any(path.startswith(f"{p}/") for p in allowed_prefixes):
        return (
            "Error: writes only allowed to files under "
            f"{', '.join(allowed_prefixes)}"
        )

    await container.write_file(path, content)
    return f"Written {len(content)} bytes to {path}"


async def _run_command(container: AuditContainer, args: dict) -> str:
    command = args.get("command", "")
    if not command:
        return "Error: 'command' is required"
    working_dir = args.get("working_dir", "/audit")
    timeout = min(args.get("timeout", 600), 1800)

    # Wrap with shell-level timeout so the process is killed if it hangs.
    # --kill-after=5: send SIGKILL 5s after SIGTERM if still alive.
    # The asyncio timeout (timeout + 10) is a backstop in case `timeout` itself hangs.
    wrapped = f"timeout --kill-after=5 {timeout}s bash -c {shlex.quote(command)}"
    exit_code, output = await container.exec(
        wrapped, working_dir=working_dir, timeout=timeout + 10
    )
    output = _truncate(output)

    result = output
    if exit_code == 124:
        # 124 = shell `timeout` killed the process
        result = f"Command timed out after {timeout}s (killed)"
    elif exit_code == -1:
        result = f"Command timed out after {timeout}s"
    elif exit_code != 0:
        result += f"\n[exit code: {exit_code}]"
    return result


async def _web_search(args: dict) -> str:
    query = args.get("query", "")
    if not query:
        return "Error: 'query' is required"
    max_results = args.get("max_results", 5)

    try:
        from ddgs import DDGS

        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "No results found."

        lines = []
        for r in results:
            lines.append(f"**{r['title']}**\n{r['href']}\n{r['body']}\n")
        return "\n".join(lines)
    except Exception as e:
        return f"Search error: {e}"


async def _fetch_url(args: dict) -> str:
    url = args.get("url", "")
    if not url:
        return "Error: 'url' is required"

    # SSRF guard: block requests to private/internal networks (runs on host)
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return "Error: only http and https URLs are supported"
        hostname = parsed.hostname
        if hostname:
            addrs = socket.getaddrinfo(hostname, None)
            for _, _, _, _, sockaddr in addrs:
                ip = ipaddress.ip_address(sockaddr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return "Error: cannot fetch URLs pointing to private/internal networks"
    except (socket.gaierror, ValueError):
        pass  # Let httpx handle DNS/parsing failures naturally

    try:
        import re

        import httpx

        req_timeout = args.get("timeout", 60)
        async with httpx.AsyncClient(follow_redirects=True, timeout=req_timeout) as client:
            resp = await client.get(url, headers={"User-Agent": "ReentbotPro/0.1"})
            resp.raise_for_status()
            text = resp.text

        # Simple HTML to text
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:50000]
    except Exception as e:
        return f"Fetch error: {e}"
