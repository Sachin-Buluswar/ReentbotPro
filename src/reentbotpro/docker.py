"""Docker container lifecycle management for audit runs."""

import asyncio
import io
import os
import posixpath
import secrets
import shlex
import subprocess
import tarfile
from pathlib import Path

import docker as docker_lib
from docker.errors import ImageNotFound, NotFound, APIError

# Always build and run as linux/amd64.  The Solidity toolchain does not publish
# native Linux ARM64 binaries — on Apple Silicon this causes fallback to WASM
# solc builds that hit memory limits and produce unreliable results.
PLATFORM = "linux/amd64"


class AuditContainer:
    """Manages the Docker container lifecycle for an audit run."""

    def __init__(self, image_name: str = "reentbotpro-tools"):
        self.image_name = image_name
        self._docker: docker_lib.DockerClient | None = None
        self._container = None
        self.init_report: list[str] = []
        self._write_lock = asyncio.Lock()

    def _get_client(self) -> docker_lib.DockerClient:
        if self._docker is None:
            try:
                self._docker = docker_lib.from_env()
                self._docker.ping()
            except docker_lib.errors.DockerException as e:
                raise RuntimeError(
                    "Docker is not running or not accessible. "
                    "Please start Docker and try again."
                ) from e
        return self._docker

    async def ensure_image(self, on_status=None) -> None:
        """Build the Docker image if it doesn't exist or has wrong architecture."""
        client = self._get_client()
        try:
            img = client.images.get(self.image_name)
            if img.attrs.get("Architecture") == "amd64":
                if on_status:
                    on_status("Image found (cached)")
                return
            # Wrong architecture (e.g. arm64 from before platform enforcement).
            # Rebuilding with the same tag replaces the old image.
            if on_status:
                on_status("Cached image is not amd64 — rebuilding...")
        except ImageNotFound:
            pass

        if on_status:
            on_status("Building audit container image (this may take several minutes on first run)...")

        # Find the Dockerfile bundled with the package
        dockerfile_path = Path(__file__).parent / "Dockerfile"
        if not dockerfile_path.exists():
            raise FileNotFoundError(
                f"Dockerfile not found at {dockerfile_path}. "
                "Ensure the package is installed correctly."
            )

        def _build():
            result = subprocess.run(
                [
                    "docker", "buildx", "build",
                    "--platform", PLATFORM,
                    "--load",
                    "-t", self.image_name,
                    "-f", str(dockerfile_path),
                    str(dockerfile_path.parent),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Docker image build failed:\n{result.stderr}"
                )

        await asyncio.to_thread(_build)

        # Verify the built image has the correct architecture.
        try:
            img = client.images.get(self.image_name)
        except ImageNotFound:
            raise RuntimeError(
                "Docker image build completed but image was not found. "
                "This may indicate an issue with 'docker buildx build --load'."
            )
        if img.attrs.get("Architecture") != "amd64":
            raise RuntimeError(
                f"Docker image build completed but produced "
                f"'{img.attrs.get('Architecture')}' architecture instead of 'amd64'. "
                f"Ensure Docker Desktop has cross-platform build support enabled."
            )

        if on_status:
            on_status("Image built successfully")

    async def start(
        self,
        source_dir: str,
        rpc_url: str | None = None,
        on_status=None,
        extra_env: dict[str, str] | None = None,
        *,
        alchemy_api_key: str | None = None,
        etherscan_api_key: str | None = None,
        default_network: str | None = None,
        default_chain_id: int | str | None = None,
    ) -> None:
        """Start a container with source_dir mounted at /audit.

        Beyond an explicit ``rpc_url`` (set as ``ETH_RPC_URL`` for cast/anvil),
        the container receives the persistent credential model: the bare Alchemy
        and Etherscan keys plus the resolved default-chain hints. With those, the
        in-container tooling can derive a chain-specific endpoint even when no
        ``ETH_RPC_URL`` was pre-derived (a bare key with no known chain). Key
        injection is deliberately simple here — explicit args win over
        ``extra_env``, which wins over the host process environment.
        """
        client = self._get_client()
        await self.ensure_image(on_status=on_status)

        abs_source = os.path.abspath(source_dir)
        if not os.path.isdir(abs_source):
            raise ValueError(f"Source directory does not exist: {abs_source}")

        env_vars: dict[str, str] = {}
        if rpc_url:
            env_vars["ETH_RPC_URL"] = rpc_url
        extra = extra_env or {}
        for name, explicit in (
            ("ALCHEMY_API_KEY", alchemy_api_key),
            ("ETHERSCAN_API_KEY", etherscan_api_key),
        ):
            value = explicit or extra.get(name) or os.environ.get(name)
            if value:
                env_vars[name] = value
        if default_network:
            env_vars["REENTBOT_DEFAULT_NETWORK"] = default_network
        if default_chain_id is not None and str(default_chain_id).strip():
            env_vars["REENTBOT_DEFAULT_CHAIN_ID"] = str(default_chain_id)

        if on_status:
            on_status("Starting container...")

        def _create_and_start():
            container = client.containers.run(
                self.image_name,
                detach=True,
                volumes={
                    abs_source: {"bind": "/audit", "mode": "rw"},
                },
                tmpfs={"/workspace": "size=1G"},
                environment=env_vars,
                mem_limit="8g",
                cpu_period=100000,
                cpu_quota=200000,
                working_dir="/audit",
                # Network access enabled for cast/anvil/forge install
                network_mode="bridge",
            )
            return container

        self._container = await asyncio.to_thread(_create_and_start)
        await self._init_source(on_status=on_status)
        if on_status:
            on_status("Container ready")

    async def _init_source(self, on_status=None) -> None:
        """Initialize the mounted source: git, submodules, and dependencies.

        Does minimal setup and reports results honestly.  The agent handles
        any remaining dependency issues — it's better at diagnosing problems
        than brittle init code.

        Collects status lines in self.init_report for the agent's first turn.
        """
        report: list[str] = []

        # ── 1. Ensure a git repo exists ──
        # Many Solidity tools (forge, slither) need git to function.  If the
        # source was downloaded as a ZIP archive, create a lightweight repo.
        exit_code, _ = await self.exec("[ -d .git ]", timeout=5)
        if exit_code != 0:
            if on_status:
                on_status("Initializing git repository...")
            # Split init from commit — git init + add is fast and ensures
            # tooling works.  The commit may be slow on large repos.
            await self.exec(
                "git init -q && git add -A 2>/dev/null || true",
                timeout=30,
            )
            await self.exec(
                "git commit -q -m 'init' 2>/dev/null || true",
                timeout=120,
            )
            report.append("Git repo: initialized (no prior .git directory)")
        else:
            report.append("Git repo: existing")

        # ── 2. Git config ──
        # Trust bind-mounted repos (host UID ≠ container root).
        await self.exec(
            "git config --global --add safe.directory '*'", timeout=5
        )
        # Rewrite SSH URLs to HTTPS — the container has no SSH keys, so
        # git@github.com: URLs (common in .gitmodules) would fail.
        await self.exec(
            "git config --global url.'https://github.com/'.insteadOf "
            "'git@github.com:'",
            timeout=5,
        )

        # ── 3. Detect project root ──
        project_root = await self._find_project_root()
        report.append(f"Project root: {project_root}")

        # ── 4. Submodules — one attempt, report honestly ──
        exit_code, _ = await self.exec("[ -f .gitmodules ]", timeout=5)
        if exit_code == 0:
            if on_status:
                on_status("Initializing git submodules...")
            exit_code, output = await self.exec(
                "git submodule update --init --recursive 2>&1",
                timeout=120,
            )
            if exit_code == 0:
                report.append("Submodules: initialized")
            else:
                report.append(
                    f"Submodules: git submodule update FAILED (exit {exit_code})"
                )
            # Report which submodule directories are empty so the agent
            # knows exactly what needs fixing.
            empty = await self._list_empty_submodules()
            if empty:
                report.append(
                    "Empty submodule dirs (need manual install): "
                    + ", ".join(empty)
                )

        # ── 5. Install node dependencies ──
        package_json_paths = [posixpath.join(project_root, "package.json")]
        if project_root != "/audit":
            package_json_paths.append("/audit/package.json")
        package_json_check = " || ".join(
            f"[ -f {shlex.quote(path)} ]" for path in package_json_paths
        )
        exit_code, _ = await self.exec(package_json_check, timeout=5)
        if exit_code == 0:
            dep_line = await self._install_node_deps(
                project_root, on_status=on_status
            )
            report.append(dep_line)

        # ── 6. Install forge-std if needed ──
        exit_code, _ = await self.exec(
            f"[ -d .git ] && [ -f {project_root}/foundry.toml ] "
            f"&& [ ! -d {project_root}/lib/forge-std ]",
            timeout=5,
        )
        if exit_code == 0:
            if on_status:
                on_status("Installing forge-std...")
            exit_code, output = await self.exec(
                "forge install foundry-rs/forge-std --no-commit 2>&1",
                working_dir=project_root,
                timeout=60,
            )
            if exit_code == 0:
                report.append("forge-std: installed")
            else:
                report.append(f"forge-std: install failed (exit {exit_code})")

        self.init_report = report

    async def _list_empty_submodules(self) -> list[str]:
        """List submodule paths from .gitmodules that are missing or empty."""
        exit_code, output = await self.exec(
            "git config -f .gitmodules "
            "--get-regexp 'submodule\\..*\\.path' 2>/dev/null",
            timeout=10,
        )
        if exit_code != 0 or not output.strip():
            return []

        empty: list[str] = []
        for line in output.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            sub_path = parts[1]
            safe = shlex.quote(f"/audit/{sub_path}")
            ec, _ = await self.exec(
                f'[ -d {safe} ] && [ "$(ls -A {safe} 2>/dev/null)" ]',
                timeout=5,
            )
            if ec != 0:
                empty.append(sub_path)

        return empty

    async def _install_node_deps(
        self, project_root: str, on_status=None
    ) -> str:
        """Install Node.js dependencies using the appropriate package manager.

        Searches for lock files at both the project root and /audit (monorepos
        may keep the lock file at the repo root).  Tries frozen install first,
        then falls back to unfrozen.  Returns a status line for the init report.
        """
        if on_status:
            on_status("Installing node dependencies...")

        # Detect package manager by lock file presence.
        search_dirs = [project_root]
        if project_root != "/audit":
            search_dirs.append("/audit")

        pm: str | None = None
        install_dir = project_root
        for d in search_dirs:
            for lockfile, manager in [
                ("pnpm-lock.yaml", "pnpm"),
                ("yarn.lock", "yarn"),
                ("package-lock.json", "npm"),
            ]:
                ec, _ = await self.exec(
                    f"[ -f {shlex.quote(posixpath.join(d, lockfile))} ]",
                    timeout=5,
                )
                if ec == 0:
                    pm = manager
                    install_dir = d
                    break
            if pm:
                break

        if pm is None:
            pm = "npm"
            for d in search_dirs:
                ec, _ = await self.exec(
                    f"[ -f {shlex.quote(posixpath.join(d, 'package.json'))} ]",
                    timeout=5,
                )
                if ec == 0:
                    install_dir = d
                    break

        # Build install commands (frozen first, then unfrozen fallback)
        if pm == "pnpm":
            frozen = "pnpm install --frozen-lockfile 2>&1"
            unfrozen = "pnpm install 2>&1"
        elif pm == "yarn":
            frozen = "yarn install --frozen-lockfile 2>&1"
            unfrozen = "yarn install 2>&1"
        else:
            frozen = "npm ci 2>&1"
            unfrozen = "npm install 2>&1"

        exit_code, output = await self.exec(
            frozen, working_dir=install_dir, timeout=120
        )
        if exit_code == 0:
            return f"Dependencies: {pm} install succeeded"

        # Frozen install failed — try unfrozen
        exit_code, output = await self.exec(
            unfrozen, working_dir=install_dir, timeout=120
        )
        if exit_code == 0:
            return (
                f"Dependencies: {pm} install succeeded "
                "(frozen failed, used unfrozen)"
            )

        # Both failed
        lines = output.strip().splitlines()
        tail = "\n".join(lines[-5:]) if lines else "no output"
        return f"Dependencies: {pm} install FAILED — {tail}"

    async def _find_project_root(self) -> str:
        """Detect the Solidity project root inside the mounted source.

        Looks for foundry.toml or hardhat config up to 3 levels deep,
        preferring the shallowest match.  Falls back to /audit.
        """
        # Check /audit itself first (most common case).
        exit_code, _ = await self.exec("[ -f /audit/foundry.toml ]", timeout=5)
        if exit_code == 0:
            return "/audit"

        # Search subdirectories for foundry.toml.
        exit_code, found = await self.exec(
            "find /audit -maxdepth 3 -name foundry.toml "
            "-not -path '*/node_modules/*' -not -path '*/lib/*' "
            "2>/dev/null | head -1",
            timeout=10,
        )
        if exit_code == 0 and found.strip():
            return found.strip().rsplit("/foundry.toml", 1)[0] or "/audit"

        # Fall back to hardhat config.
        exit_code, found = await self.exec(
            "find /audit -maxdepth 3 "
            "\\( -name 'hardhat.config.js' -o -name 'hardhat.config.ts' \\) "
            "-not -path '*/node_modules/*' "
            "2>/dev/null | head -1",
            timeout=10,
        )
        if exit_code == 0 and found.strip():
            return found.strip().rsplit("/", 1)[0] or "/audit"

        return "/audit"

    async def exec(
        self,
        command: str,
        working_dir: str = "/audit",
        timeout: int = 120,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        """Run a command inside the container. Returns (exit_code, output).

        ``extra_env`` injects per-exec environment variables (e.g. chain-specific
        ``ETH_RPC_URL``/``RPC_URL_<chain>`` endpoints derived by ``run_experiment``
        from the experiment's fork context). They win over the variables baked
        into the container at startup for this command only.
        """
        if self._container is None:
            raise RuntimeError("Container not started")

        environment = {str(k): str(v) for k, v in (extra_env or {}).items()} or None

        def _run():
            result = self._container.exec_run(
                ["bash", "-c", command],
                workdir=working_dir,
                demux=False,
                environment=environment,
            )
            output = (result.output or b"").decode("utf-8", errors="replace")
            return result.exit_code, output

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_run), timeout=timeout
            )
        except asyncio.TimeoutError:
            # Try to kill any lingering process
            return -1, f"Command timed out after {timeout}s"

    @staticmethod
    def _single_file_tar(name: str, data: bytes) -> io.BytesIO:
        """Build a tar stream containing one file at the archive root."""
        tarstream = io.BytesIO()
        tarinfo = tarfile.TarInfo(name=name)
        tarinfo.size = len(data)
        tarinfo.mode = 0o644
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            tar.addfile(tarinfo, io.BytesIO(data))
        tarstream.seek(0)
        return tarstream

    @staticmethod
    def _archive_member_relpath(member_name: str, root_name: str) -> str | None:
        """Return a safe relative path for a tar member from get_archive."""
        normalized = member_name.replace("\\", "/").lstrip("/")
        parts = [part for part in normalized.split("/") if part not in ("", ".")]
        if any(part == ".." for part in parts):
            return None
        if parts and parts[0] == root_name:
            parts = parts[1:]
        if not parts:
            return None
        return "/".join(parts)

    @staticmethod
    def _extract_archive_tree(
        archive: io.BytesIO,
        container_root: str,
        host_root: str,
    ) -> int:
        """Extract regular files from a tar archive into host_root."""
        copied = 0
        root_name = posixpath.basename(container_root.rstrip("/"))
        host_base = os.path.abspath(host_root)
        real_base = os.path.realpath(host_base)
        os.makedirs(host_base, exist_ok=True)

        with tarfile.open(fileobj=archive, mode="r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                rel_path = AuditContainer._archive_member_relpath(
                    member.name,
                    root_name,
                )
                if not rel_path:
                    continue

                host_path = os.path.abspath(
                    os.path.join(host_base, *rel_path.split("/"))
                )
                if os.path.commonpath([host_base, host_path]) != host_base:
                    continue

                parent = os.path.dirname(host_path)
                os.makedirs(parent, exist_ok=True)
                if os.path.commonpath([real_base, os.path.realpath(parent)]) != real_base:
                    continue
                if os.path.islink(host_path):
                    os.unlink(host_path)

                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with open(host_path, "wb") as f:
                    f.write(extracted.read())
                try:
                    mode = member.mode & 0o777
                    if mode:
                        os.chmod(host_path, mode)
                except OSError:
                    pass
                copied += 1
        return copied

    async def copy_tree_from_container(
        self,
        container_root: str,
        host_root: str,
    ) -> int:
        """Copy a container directory tree to the host using a tar stream."""
        if self._container is None:
            raise RuntimeError("Container not started")

        normalized_root = posixpath.normpath(container_root)
        if not normalized_root.startswith("/") or normalized_root == "/":
            raise ValueError("container_root must be an absolute directory path")

        safe_root = shlex.quote(normalized_root)
        exit_code, _ = await self.exec(f"[ -d {safe_root} ]", timeout=5)
        if exit_code != 0:
            return 0

        parent = posixpath.dirname(normalized_root) or "/"
        root_name = posixpath.basename(normalized_root)

        def _download_archive() -> io.BytesIO:
            result = self._container.exec_run(
                ["tar", "-C", parent, "-cf", "-", root_name],
                demux=False,
            )
            if result.exit_code != 0:
                detail = (result.output or b"").decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"Failed to archive {normalized_root}: "
                    f"{detail.strip() or f'exit code {result.exit_code}'}"
                )
            archive = io.BytesIO(result.output or b"")
            archive.seek(0)
            return archive

        try:
            archive = await asyncio.to_thread(_download_archive)
        except NotFound:
            return 0
        if archive.getbuffer().nbytes == 0:
            return 0

        try:
            return await asyncio.to_thread(
                self._extract_archive_tree,
                archive,
                normalized_root,
                host_root,
            )
        except tarfile.TarError as exc:
            raise RuntimeError(
                f"Failed to extract archive for {normalized_root}: {exc}"
            ) from exc

    async def write_file(self, container_path: str, content: str) -> None:
        """Write a UTF-8 file into the container.

        Docker's archive endpoint requires its target directory to already be
        visible to the daemon.  Tmpfs children created from inside the container
        can still return 404 through that endpoint, so stage the bytes in /tmp
        and let the container shell create parents and move the file into place.
        """
        if self._container is None:
            raise RuntimeError("Container not started")

        normalized_path = posixpath.normpath(container_path)
        if not normalized_path.startswith("/") or normalized_path == "/":
            raise ValueError("container_path must be an absolute file path")

        async with self._write_lock:
            tmp_name = f".reentbotpro-write-{secrets.token_hex(16)}"
            tmp_path = f"/tmp/{tmp_name}"
            data = content.encode("utf-8")

            def _upload():
                self._container.put_archive(
                    "/tmp", self._single_file_tar(tmp_name, data)
                )

            await asyncio.to_thread(_upload)

            parent = posixpath.dirname(normalized_path) or "/"
            safe_parent = shlex.quote(parent)
            safe_tmp = shlex.quote(tmp_path)
            safe_dest = shlex.quote(normalized_path)
            exit_code, output = await self.exec(
                "set -e\n"
                f"mkdir -p {safe_parent}\n"
                f"if [ -d {safe_dest} ]; then\n"
                "  echo 'destination exists and is a directory' >&2\n"
                "  exit 1\n"
                "fi\n"
                f"mv -f {safe_tmp} {safe_dest}\n",
                timeout=30,
            )
            if exit_code != 0:
                await self.exec(f"rm -f {safe_tmp}", timeout=5)
                detail = output.strip() or f"exit code {exit_code}"
                raise RuntimeError(
                    f"Failed to write {normalized_path}: {detail}"
                )

    async def read_file(self, container_path: str) -> str:
        """Read a file from the container."""
        safe_path = shlex.quote(container_path)
        exit_code, output = await self.exec(f"cat {safe_path}")
        if exit_code != 0:
            raise FileNotFoundError(f"Failed to read {container_path}: {output}")
        return output

    async def stop(self) -> None:
        """Stop and remove the container."""
        if self._container is not None:
            def _stop():
                try:
                    self._container.stop(timeout=5)
                except (APIError, NotFound):
                    pass
                try:
                    self._container.remove(force=True)
                except (APIError, NotFound):
                    pass

            await asyncio.to_thread(_stop)
            self._container = None

    @property
    def is_running(self) -> bool:
        return self._container is not None
