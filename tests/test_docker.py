import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from reentbotpro.docker import AuditContainer


class FakeExecResult:
    def __init__(self, exit_code: int, output: bytes = b""):
        self.exit_code = exit_code
        self.output = output


class FakeDockerContainer:
    def __init__(self):
        self.archives: list[tuple[str, list[tuple[str, bytes]]]] = []
        self.tar_archives: dict[tuple[str, str], bytes] = {}
        self.last_environment: dict[str, str] | None = None

    def put_archive(self, path, tarstream):
        tarstream.seek(0)
        files: list[tuple[str, bytes]] = []
        with tarfile.open(fileobj=tarstream, mode="r") as tar:
            for member in tar.getmembers():
                extracted = tar.extractfile(member)
                files.append((member.name, extracted.read() if extracted else b""))
        self.archives.append((path, files))

    def exec_run(self, command, workdir="/audit", demux=False, environment=None):
        del workdir, demux
        self.last_environment = environment
        if command[:3] == ["bash", "-c", "[ -d /workspace/campaign ]"]:
            return FakeExecResult(0)
        if command[:3] == ["tar", "-C", "/workspace"]:
            data = self.tar_archives[(command[2], command[5])]
            return FakeExecResult(0, data)
        return FakeExecResult(1, b"unexpected command")


def _archive_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    archive.seek(0)
    return archive.getvalue()


class FakeContainers:
    def __init__(self):
        self.run_kwargs = None

    def run(self, *args, **kwargs):
        self.run_kwargs = kwargs
        return FakeDockerContainer()


class FakeDockerClient:
    def __init__(self):
        self.containers = FakeContainers()


class RecordingAuditContainer(AuditContainer):
    def __init__(self, exec_results=None):
        super().__init__()
        self.fake_container = FakeDockerContainer()
        self._container = self.fake_container
        self.commands: list[str] = []
        self.exec_results = list(exec_results or [(0, "")])

    async def exec(self, command: str, working_dir: str = "/audit", timeout: int = 120):
        self.commands.append(command)
        if self.exec_results:
            return self.exec_results.pop(0)
        return 0, ""


class NodeDepsAuditContainer(AuditContainer):
    def __init__(self, files=None):
        super().__init__()
        self.files = set(files or [])
        self.commands: list[tuple[str, str]] = []

    async def exec(self, command: str, working_dir: str = "/audit", timeout: int = 120):
        del timeout
        self.commands.append((command, working_dir))
        if command.startswith("[ -f "):
            for path in self.files:
                if path in command:
                    return 0, ""
            return 1, ""
        if command in {
            "npm ci 2>&1",
            "npm install 2>&1",
            "pnpm install --frozen-lockfile 2>&1",
            "pnpm install 2>&1",
            "yarn install --frozen-lockfile 2>&1",
            "yarn install 2>&1",
        }:
            return 0, ""
        return 0, ""


class InitSourceAuditContainer(AuditContainer):
    def __init__(self):
        super().__init__()
        self.commands: list[str] = []
        self.installed_project_root: str | None = None

    async def _find_project_root(self) -> str:
        return "/audit/contracts"

    async def _list_empty_submodules(self) -> list[str]:
        return []

    async def _install_node_deps(self, project_root: str, on_status=None) -> str:
        del on_status
        self.installed_project_root = project_root
        return "Dependencies: npm install succeeded"

    async def exec(self, command: str, working_dir: str = "/audit", timeout: int = 120):
        del working_dir, timeout
        self.commands.append(command)
        if command == "[ -d .git ]":
            return 0, ""
        if command == "[ -f .gitmodules ]":
            return 1, ""
        if "package.json" in command:
            return (0, "") if "/audit/package.json" in command else (1, "")
        if "foundry.toml" in command:
            return 1, ""
        return 0, ""


class StartRecordingAuditContainer(AuditContainer):
    def __init__(self):
        super().__init__()
        self.client = FakeDockerClient()

    def _get_client(self):
        return self.client

    async def ensure_image(self, on_status=None) -> None:
        return None

    async def _init_source(self, on_status=None) -> None:
        self.init_report = ["ready"]


class AuditContainerWriteFileTests(unittest.IsolatedAsyncioTestCase):
    def test_dockerfile_uses_current_echidna_asset_names(self):
        dockerfile = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "reentbotpro"
            / "Dockerfile"
        ).read_text()

        self.assertIn("ARG ECHIDNA_VERSION=2.3.2", dockerfile)
        self.assertIn(
            "echidna-${ECHIDNA_VERSION}-x86_64-linux.tar.gz",
            dockerfile,
        )
        self.assertIn(
            "echidna-${ECHIDNA_VERSION}-aarch64-linux.tar.gz",
            dockerfile,
        )
        self.assertIn(
            "go install github.com/crytic/medusa@${MEDUSA_VERSION}",
            dockerfile,
        )
        self.assertNotIn("github.com/crytic/medusa/cmd/medusa", dockerfile)
        self.assertNotIn("Linux-x86_64", dockerfile)
        self.assertNotIn("Linux-aarch64", dockerfile)

    async def test_start_passes_rpc_and_etherscan_env(self):
        container = StartRecordingAuditContainer()

        with tempfile.TemporaryDirectory() as source_dir:
            await container.start(
                source_dir,
                rpc_url="https://rpc.example",
                extra_env={"ETHERSCAN_API_KEY": "etherscan-key"},
            )

        env = container.client.containers.run_kwargs["environment"]
        self.assertEqual(env["ETH_RPC_URL"], "https://rpc.example")
        self.assertEqual(env["ETHERSCAN_API_KEY"], "etherscan-key")

    async def test_start_passes_rpc_and_provider_credentials(self):
        container = StartRecordingAuditContainer()

        with tempfile.TemporaryDirectory() as source_dir:
            await container.start(
                source_dir,
                rpc_url="https://rpc.example",
                alchemy_api_key="alchemy-key",
                etherscan_api_key="etherscan-key",
            )

        env = container.client.containers.run_kwargs["environment"]
        # The legacy ETH_RPC_URL seed still works when an endpoint is supplied.
        self.assertEqual(env["ETH_RPC_URL"], "https://rpc.example")
        # The persistent credential model is forwarded without chain settings.
        self.assertEqual(env["ALCHEMY_API_KEY"], "alchemy-key")
        self.assertEqual(env["ETHERSCAN_API_KEY"], "etherscan-key")
        self.assertNotIn("REENTBOT_DEFAULT_NETWORK", env)
        self.assertNotIn("REENTBOT_DEFAULT_CHAIN_ID", env)

    async def test_start_without_rpc_still_forwards_alchemy_key(self):
        # A bare Alchemy key with no derived endpoint: the container starts
        # without ETH_RPC_URL but still receives the key so the agent can derive
        # an endpoint after it infers the chain.
        container = StartRecordingAuditContainer()

        with tempfile.TemporaryDirectory() as source_dir:
            await container.start(
                source_dir,
                rpc_url=None,
                alchemy_api_key="alchemy-key",
            )

        env = container.client.containers.run_kwargs["environment"]
        self.assertNotIn("ETH_RPC_URL", env)
        self.assertEqual(env["ALCHEMY_API_KEY"], "alchemy-key")
        self.assertNotIn("REENTBOT_DEFAULT_NETWORK", env)
        self.assertNotIn("REENTBOT_DEFAULT_CHAIN_ID", env)

    async def test_start_no_chain_forwards_both_keys_without_eth_rpc_url(self):
        # The canonical no-chain startup: both keys forwarded so in-container
        # tooling can derive an endpoint later, but no ETH_RPC_URL and no
        # target-chain settings are never injected.
        container = StartRecordingAuditContainer()

        with tempfile.TemporaryDirectory() as source_dir:
            await container.start(
                source_dir,
                rpc_url=None,
                alchemy_api_key="alchemy-key",
                etherscan_api_key="etherscan-key",
            )

        env = container.client.containers.run_kwargs["environment"]
        self.assertNotIn("ETH_RPC_URL", env)
        self.assertEqual(env["ALCHEMY_API_KEY"], "alchemy-key")
        self.assertEqual(env["ETHERSCAN_API_KEY"], "etherscan-key")
        self.assertNotIn("REENTBOT_DEFAULT_NETWORK", env)
        self.assertNotIn("REENTBOT_DEFAULT_CHAIN_ID", env)

    async def test_write_file_stages_in_tmp_and_moves_inside_container(self):
        container = RecordingAuditContainer()

        await container.write_file(
            "/workspace/nested path/out.txt",
            "hello",
        )

        self.assertEqual(container.fake_container.archives[0][0], "/tmp")
        [(tmp_name, data)] = container.fake_container.archives[0][1]
        self.assertTrue(tmp_name.startswith(".reentbotpro-write-"))
        self.assertEqual(data, b"hello")
        self.assertIn("mkdir -p '/workspace/nested path'", container.commands[0])
        self.assertIn("mv -f /tmp/.reentbotpro-write-", container.commands[0])
        self.assertIn("'/workspace/nested path/out.txt'", container.commands[0])

    async def test_write_file_rejects_non_file_paths(self):
        container = RecordingAuditContainer()

        with self.assertRaises(ValueError):
            await container.write_file("workspace/out.txt", "x")

        with self.assertRaises(ValueError):
            await container.write_file("/", "x")

    async def test_write_file_cleans_staged_file_after_move_failure(self):
        container = RecordingAuditContainer(exec_results=[(1, "nope"), (0, "")])

        with self.assertRaisesRegex(RuntimeError, "Failed to write /workspace/out.txt: nope"):
            await container.write_file("/workspace/out.txt", "x")

        self.assertEqual(len(container.commands), 2)
        self.assertTrue(container.commands[1].startswith("rm -f /tmp/.reentbotpro-write-"))

    async def test_copy_tree_from_container_uses_tar_stream(self):
        fake = FakeDockerContainer()
        fake.tar_archives[("/workspace", "campaign")] = _archive_bytes([
            ("campaign/state.json", b"{}"),
            ("campaign/raw/blob.bin", b"\x00\xffbinary\n"),
        ])
        container = AuditContainer()
        container._container = fake

        with tempfile.TemporaryDirectory() as tmp:
            copied = await container.copy_tree_from_container(
                "/workspace/campaign",
                tmp,
            )

            self.assertEqual(copied, 2)
            with open(os.path.join(tmp, "state.json"), "rb") as f:
                self.assertEqual(f.read(), b"{}")
            with open(os.path.join(tmp, "raw", "blob.bin"), "rb") as f:
                self.assertEqual(f.read(), b"\x00\xffbinary\n")

    async def test_node_deps_install_uses_audit_root_package_json_for_monorepo(self):
        container = NodeDepsAuditContainer(files={"/audit/package.json"})

        result = await container._install_node_deps("/audit/contracts")

        self.assertEqual(result, "Dependencies: npm install succeeded")
        self.assertIn(("npm ci 2>&1", "/audit"), container.commands)

    async def test_init_source_checks_package_json_at_project_and_audit_roots(self):
        container = InitSourceAuditContainer()

        await container._init_source()

        package_checks = [
            command for command in container.commands if "package.json" in command
        ]
        self.assertEqual(
            package_checks,
            ["[ -f /audit/contracts/package.json ] || [ -f /audit/package.json ]"],
        )
        self.assertEqual(container.installed_project_root, "/audit/contracts")
        self.assertIn("Dependencies: npm install succeeded", container.init_report)

    def test_extract_archive_tree_preserves_binary_and_rejects_traversal(self):
        archive = io.BytesIO(_archive_bytes([
            ("campaign/state.json", b"{}"),
            ("campaign/raw/blob.bin", b"\x00\xffbinary\n"),
            ("campaign/../evil.txt", b"bad"),
        ]))

        with tempfile.TemporaryDirectory() as tmp:
            copied = AuditContainer._extract_archive_tree(
                archive,
                "/workspace/campaign",
                os.path.join(tmp, "campaign"),
            )

            self.assertEqual(copied, 2)
            with open(os.path.join(tmp, "campaign", "state.json"), "rb") as f:
                self.assertEqual(f.read(), b"{}")
            with open(os.path.join(tmp, "campaign", "raw", "blob.bin"), "rb") as f:
                self.assertEqual(f.read(), b"\x00\xffbinary\n")
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.txt")))


if __name__ == "__main__":
    unittest.main()
