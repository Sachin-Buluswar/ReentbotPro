import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import reentbotpro.cli as cli
from reentbotpro.agent import (
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_MAX_TIME_MINUTES,
    DEFAULT_MAX_TIME_SECONDS,
    _report_visible_tools,
    calculate_max_context,
)
from reentbotpro.cli import (
    _build_findings_data,
    _copy_container_tree,
    _interactive_setup,
    _resolve_context_budgets,
    _resolve_run_rpc,
    _rpc_metadata,
    _save_campaign_artifacts,
    _save_run_output,
    _should_prompt_setup,
    main,
)
from reentbotpro.config import load_local_config
from reentbotpro.llm import DEFAULT_MODEL


def _params_by_name(cmd) -> dict:
    return {p.name: p for p in cmd.params}


class CliSurfaceTests(unittest.TestCase):
    def test_capital_flag_is_removed(self):
        params = _params_by_name(main)
        self.assertNotIn("capital", params)

    def test_default_max_time_is_720_minutes(self):
        params = _params_by_name(main)
        self.assertEqual(params["max_time"].default, DEFAULT_MAX_TIME_MINUTES)
        self.assertEqual(DEFAULT_MAX_TIME_MINUTES, 720)
        self.assertEqual(DEFAULT_MAX_TIME_SECONDS, 43_200)
        self.assertEqual(params["max_time"].default * 60, DEFAULT_MAX_TIME_SECONDS)
        self.assertIn("minutes", params["max_time"].help)

    def test_no_chat_skips_interactive_setup_prompt(self):
        self.assertFalse(_should_prompt_setup(stdin_is_tty=True, no_chat=True))
        self.assertFalse(_should_prompt_setup(stdin_is_tty=False, no_chat=False))
        self.assertTrue(_should_prompt_setup(stdin_is_tty=True, no_chat=False))

    def test_context_budget_options_default_to_auto(self):
        # Both context knobs are advanced overrides that default to auto (None):
        # max_context is only a user cap when explicitly set.
        params = _params_by_name(main)
        self.assertIn("max_context", params)
        self.assertIsNone(params["max_context"].default)
        self.assertIsNone(params["context_window"].default)

    def test_chain_options_removed_and_rpc_url_is_advanced_override(self):
        params = _params_by_name(main)
        self.assertNotIn("chain", params)
        self.assertNotIn("chain_id", params)
        self.assertIn("Advanced", params["rpc_url"].help)
        self.assertIn("per-chain", params["rpc_url"].help)


class ResolveContextBudgetsTests(unittest.TestCase):
    """E: the CLI distinguishes an auto budget from an explicit user cap."""

    def test_auto_budget_is_not_a_user_cap(self):
        max_context, report_max_context, is_user_cap = _resolve_context_budgets(
            DEFAULT_CONTEXT_WINDOW, None, 128_000
        )
        self.assertFalse(is_user_cap)
        # The audit budget is the conservative full-tool reserve so run_audit can
        # reclaim visible-tool space per turn.
        self.assertEqual(max_context, calculate_max_context(DEFAULT_CONTEXT_WINDOW))
        self.assertEqual(
            report_max_context,
            calculate_max_context(
                DEFAULT_CONTEXT_WINDOW,
                output_reserve=128_000,
                tools=_report_visible_tools(),
            ),
        )
        self.assertGreater(
            report_max_context,
            calculate_max_context(DEFAULT_CONTEXT_WINDOW, output_reserve=128_000),
        )

    def test_explicit_value_is_a_user_cap(self):
        max_context, report_max_context, is_user_cap = _resolve_context_budgets(
            DEFAULT_CONTEXT_WINDOW, 50_000, 128_000
        )
        self.assertTrue(is_user_cap)
        # The explicit cap is honored by both phases.
        self.assertEqual(max_context, 50_000)
        self.assertLessEqual(report_max_context, 50_000)


class FakeContainer:
    def __init__(self):
        self.files: dict[str, bytes | str] = {}
        self.is_running = True

    async def copy_tree_from_container(
        self,
        container_root: str,
        host_root: str,
    ) -> int:
        copied = 0
        root_prefix = container_root.rstrip("/") + "/"
        for container_path, content in self.files.items():
            if not container_path.startswith(root_prefix):
                continue
            rel_path = container_path[len(root_prefix):]
            if not rel_path or rel_path.startswith("../") or "/../" in rel_path:
                continue
            data = content if isinstance(content, bytes) else content.encode()
            host_path = os.path.join(host_root, rel_path)
            os.makedirs(os.path.dirname(host_path), exist_ok=True)
            with open(host_path, "wb") as f:
                f.write(data)
            copied += 1
        return copied


class FakeDisplay:
    def __init__(self):
        self.messages: list[str] = []

    def status(self, message: str):
        self.messages.append(message)


class CampaignArtifactCopyTests(unittest.IsolatedAsyncioTestCase):
    async def test_copy_container_tree_preserves_relative_paths(self):
        container = FakeContainer()
        container.files = {
            "/workspace/campaign/state.json": '{"ok": true}',
            "/workspace/campaign/results/res-001.log": "log",
        }

        with tempfile.TemporaryDirectory() as tmp:
            copied = await _copy_container_tree(
                container,
                "/workspace/campaign",
                tmp,
            )

            self.assertEqual(copied, 2)
            with open(os.path.join(tmp, "state.json")) as f:
                self.assertEqual(f.read(), '{"ok": true}')
            with open(os.path.join(tmp, "results/res-001.log")) as f:
                self.assertEqual(f.read(), "log")

    async def test_copy_container_tree_preserves_binary_files(self):
        container = FakeContainer()
        container.files = {
            "/workspace/campaign/raw/blob.bin": b"\x00\xffbinary\n",
        }

        with tempfile.TemporaryDirectory() as tmp:
            copied = await _copy_container_tree(
                container,
                "/workspace/campaign",
                tmp,
            )

            self.assertEqual(copied, 1)
            with open(os.path.join(tmp, "raw/blob.bin"), "rb") as f:
                self.assertEqual(f.read(), b"\x00\xffbinary\n")

    async def test_save_campaign_artifacts_reports_counts(self):
        container = FakeContainer()
        container.files = {
            "/workspace/campaign/state.json": "{}",
            "/workspace/experiments/exp-001/README.md": "readme",
        }
        display = FakeDisplay()

        with tempfile.TemporaryDirectory() as tmp:
            result = await _save_campaign_artifacts(container, tmp, display)

            self.assertEqual(result["campaign_files"], 1)
            self.assertEqual(result["experiment_files"], 1)
            self.assertTrue(os.path.exists(os.path.join(tmp, "campaign/state.json")))
            self.assertTrue(os.path.exists(os.path.join(
                tmp,
                "experiments/exp-001/README.md",
            )))
            self.assertEqual(len(display.messages), 1)

    async def test_save_campaign_artifacts_handles_stopped_container(self):
        class StoppedContainer(FakeContainer):
            def __init__(self):
                super().__init__()
                self.is_running = False

            async def copy_tree_from_container(
                self,
                container_root: str,
                host_root: str,
            ) -> int:
                del container_root, host_root
                raise RuntimeError("container is not running")

        display = FakeDisplay()

        with tempfile.TemporaryDirectory() as tmp:
            result = await _save_campaign_artifacts(
                StoppedContainer(),
                tmp,
                display,
            )

            self.assertEqual(result["campaign_files"], 0)
            self.assertEqual(result["experiment_files"], 0)
            self.assertEqual(len(result["warnings"]), 2)
            self.assertIn("container is not running", display.messages[0])

    def test_build_findings_data_marks_partial_interrupts(self):
        data = _build_findings_data(
            run_id="run-1",
            source_dir="/tmp/target",
            model="gpt-5.5",
            rpc_url="https://example.invalid/abcdef",
            started_at="2026-05-03T00:00:00+00:00",
            messages=[{"role": "assistant"}, {"role": "user"}],
            explored={"llm_error": "stopped"},
            report_content="",
            campaign_artifacts={"campaign_files": 1},
            findings=[],
            interrupted=True,
            partial=True,
        )

        self.assertTrue(data["interrupted"])
        self.assertTrue(data["partial"])
        self.assertEqual(data["total_turns"], 1)
        self.assertEqual(data["llm_error"], "stopped")
        self.assertIn("https://example.invalid/abcdef", data["rpc_url"])

    async def test_save_run_output_persists_partial_artifacts(self):
        container = FakeContainer()
        container.files = {
            "/workspace/campaign/state.json": "{}",
            "/workspace/experiments/exp-001/README.md": "readme",
        }
        display = FakeDisplay()

        with tempfile.TemporaryDirectory() as tmp:
            data, findings_path = await _save_run_output(
                container=container,
                output_dir=tmp,
                display=display,
                run_id="run-1",
                source_dir="/tmp/target",
                model="gpt-5.5",
                rpc_url=None,
                started_at="2026-05-03T00:00:00+00:00",
                messages=[],
                explored={},
                report_content="",
                findings=[],
                interrupted=True,
                partial=True,
            )

            self.assertTrue(os.path.exists(findings_path))
            self.assertTrue(data["partial"])
            self.assertEqual(data["campaign_artifacts"]["campaign_files"], 1)
            self.assertTrue(os.path.exists(os.path.join(tmp, "campaign/state.json")))
            with open(findings_path) as f:
                saved = f.read()
            self.assertIn('"partial": true', saved)


class ResolveRunRpcTests(unittest.TestCase):
    """Alchemy/Etherscan credentials plus an optional explicit endpoint."""

    KEY = "alchemy-test-key"

    def test_bare_alchemy_key_yields_no_url_but_keeps_key(self):
        cfg = _resolve_run_rpc(
            cli_rpc_url=None,
            config={},
            environ={"ALCHEMY_API_KEY": self.KEY},
        )
        self.assertIsNone(cfg.endpoint.url)
        self.assertEqual(cfg.endpoint.provider, "none")
        self.assertEqual(cfg.alchemy_key, self.KEY)
        self.assertFalse(cfg.rpc_meta["configured"])
        self.assertTrue(cfg.rpc_meta["alchemy_key_configured"])
        self.assertFalse(cfg.rpc_meta["assumed_default_mainnet"])

    def test_explicit_rpc_url_overrides_derived_alchemy(self):
        cfg = _resolve_run_rpc(
            cli_rpc_url="https://explicit.example",
            config={},
            environ={"ALCHEMY_API_KEY": self.KEY},
        )
        self.assertEqual(cfg.endpoint.url, "https://explicit.example")
        self.assertEqual(cfg.endpoint.provider, "explicit")
        self.assertTrue(cfg.endpoint.is_override)
        self.assertEqual(cfg.explicit_rpc_url, "https://explicit.example")
        self.assertTrue(cfg.rpc_meta["override"])

    def test_eth_rpc_url_env_is_an_explicit_override(self):
        cfg = _resolve_run_rpc(
            cli_rpc_url=None,
            config={},
            environ={"ALCHEMY_API_KEY": self.KEY, "ETH_RPC_URL": "https://env.example"},
        )
        self.assertEqual(cfg.endpoint.url, "https://env.example")
        self.assertTrue(cfg.endpoint.is_override)
        self.assertEqual(cfg.explicit_rpc_url, "https://env.example")

    def test_legacy_default_chain_config_is_ignored(self):
        cfg = _resolve_run_rpc(
            cli_rpc_url=None,
            config={
                "alchemy_api_key": self.KEY,
                "default_chain": "arbitrum",
                "default_network": "base-mainnet",
                "default_chain_id": 10,
            },
            environ={},
        )
        self.assertIsNone(cfg.endpoint.url)
        self.assertIsNone(cfg.endpoint.network)
        self.assertIsNone(cfg.endpoint.chain_id)
        self.assertEqual(cfg.alchemy_key, self.KEY)

    def test_etherscan_key_resolved_from_config(self):
        cfg = _resolve_run_rpc(
            cli_rpc_url=None,
            config={"etherscan_api_key": "escan"},
            environ={},
        )
        self.assertEqual(cfg.etherscan_key, "escan")

    def test_local_config_keys_only_is_valid(self):
        # The normal setup: only Alchemy + Etherscan keys, no chain anywhere.
        # Resolution must succeed and derive no endpoint, while keeping both keys
        # so the agent can derive one once it infers the chain during recon.
        cfg = _resolve_run_rpc(
            cli_rpc_url=None,
            config={"alchemy_api_key": self.KEY, "etherscan_api_key": "escan"},
            environ={},
        )
        self.assertIsNone(cfg.endpoint.url)
        self.assertEqual(cfg.endpoint.provider, "none")
        self.assertEqual(cfg.alchemy_key, self.KEY)
        self.assertEqual(cfg.etherscan_key, "escan")
        self.assertFalse(cfg.rpc_meta["configured"])
        self.assertTrue(cfg.rpc_meta["alchemy_key_configured"])
        self.assertFalse(cfg.rpc_meta["assumed_default_mainnet"])

class RpcMetadataTests(unittest.TestCase):
    def test_metadata_captures_provider_and_chain(self):
        from reentbotpro.config import resolve_rpc_endpoint

        endpoint = resolve_rpc_endpoint(
            network="base",
            environ={"ALCHEMY_API_KEY": "k"},
            config={},
        )
        meta = _rpc_metadata(endpoint, alchemy_configured=True)
        self.assertEqual(
            meta,
            {
                "configured": True,
                "provider": "alchemy",
                "network": "base-mainnet",
                "chain_id": 8453,
                "source": "alchemy_api_key",
                "override": False,
                "assumed_default_mainnet": False,
                "alchemy_key_configured": True,
            },
        )


class DisplayHeaderTests(unittest.TestCase):
    """The audit header reports chain/RPC posture, never a 'missing RPC' error."""

    @staticmethod
    def _render(budget):
        from io import StringIO

        from rich.console import Console

        from reentbotpro.display import Display

        buf = StringIO()
        Display(console=Console(file=buf, width=200, no_color=True)).header(
            "./contracts", "gpt-x", budget
        )
        return buf.getvalue()

    @staticmethod
    def _render_error(message: str):
        from io import StringIO

        from rich.console import Console

        from reentbotpro.display import Display

        buf = StringIO()
        Display(console=Console(file=buf, width=200, no_color=True)).error(message)
        return buf.getvalue()

    def test_no_chain_startup_reports_inference_pending_not_an_error(self):
        out = self._render(
            {
                "max_time": 600,
                "rpc_provider": "none",
                "chain_network": None,
                "chain_id": None,
                "alchemy": True,
                "etherscan": True,
                "reasoning": "none",
            }
        )
        # Chain not yet inferred; RPC will be derived after inference — not framed
        # as a missing-variable error.
        self.assertIn("not yet inferred", out)
        self.assertIn("will be derived after chain inference", out)
        self.assertNotIn("missing", out.lower())
        self.assertNotIn("ETH_RPC_URL", out)
        # Credential posture is surfaced explicitly.
        self.assertIn("Alchemy:", out)
        self.assertIn("Etherscan:", out)

    def test_derived_alchemy_chain_shown_in_header(self):
        out = self._render(
            {
                "max_time": 600,
                "rpc_provider": "alchemy",
                "chain_network": "base-mainnet",
                "chain_id": 8453,
                "alchemy": True,
                "etherscan": False,
                "reasoning": "none",
            }
        )
        self.assertIn("base-mainnet (8453)", out)
        self.assertIn("derived from Alchemy", out)

    def test_explicit_override_shown_in_header(self):
        out = self._render(
            {
                "max_time": 600,
                "rpc_provider": "explicit",
                "chain_network": None,
                "chain_id": None,
                "alchemy": False,
                "etherscan": False,
                "reasoning": "none",
            }
        )
        self.assertIn("explicit override", out)

    def test_no_alchemy_key_and_no_chain_reports_not_configured(self):
        # Degraded setup (no Alchemy key, no chain, no override): the RPC line is
        # honest — nothing will derive without a key — and is still not an error.
        out = self._render(
            {
                "max_time": 600,
                "rpc_provider": "none",
                "chain_network": None,
                "chain_id": None,
                "alchemy": False,
                "etherscan": False,
                "reasoning": "none",
            }
        )
        self.assertIn("RPC:", out)
        self.assertIn("not configured", out)
        self.assertNotIn("will be derived after chain inference", out)
        self.assertNotIn("missing", out.lower())

    def test_error_escapes_markup_like_paths(self):
        out = self._render_error("failed while reading [/audit]/contracts")
        self.assertIn("Error:", out)
        self.assertIn("[/audit]/contracts", out)


class ScriptedConsole:
    """Minimal rich.Console stand-in: scripted inputs, recorded prompts/outputs."""

    def __init__(self, answers):
        self._answers = list(answers)
        self.prompts: list[str] = []
        self.outputs: list[str] = []

    def print(self, *args, **kwargs):
        self.outputs.append(" ".join(str(a) for a in args))

    def input(self, prompt=""):
        self.prompts.append(prompt)
        return self._answers.pop(0) if self._answers else ""


class InteractiveSetupTests(unittest.TestCase):
    BASE_KWARGS = dict(
        api_key="sk-test",
        model="gpt-x",
        max_time=600,
        verbosity="off",
        reasoning="high",
    )

    def test_normal_path_prompts_for_keys_and_infers_chains(self):
        # Normal setup with missing keys: it prompts for the Alchemy and
        # Etherscan keys and surfaces the chain-inference message. The optional
        # explicit RPC override is declined here (empty answer defaults to no).
        console = ScriptedConsole(answers=[])
        config = _interactive_setup(
            console,
            alchemy_key=None,
            etherscan_key=None,
            explicit_rpc_url=None,
            **self.BASE_KWARGS,
        )
        # Alchemy/Etherscan are the normal credential prompts.
        self.assertTrue(any("Alchemy API key" in p for p in console.prompts))
        self.assertTrue(any("Etherscan API key" in p for p in console.prompts))
        # The legacy "Ethereum RPC URL" prompt is gone from the normal path.
        self.assertFalse(any("Ethereum RPC URL" in p for p in console.prompts))
        self.assertFalse(any("Default chain" in p for p in console.prompts))
        self.assertTrue(
            any("explicit RPC override" in p for p in console.prompts)
        )
        # The chain-inference message is shown.
        joined = " ".join(console.outputs)
        self.assertIn("inferred from scope/deployment", joined)
        # Nothing entered and the override declined.
        self.assertIsNone(config["rpc_url"])

    def test_declining_rpc_override_persists_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                console = ScriptedConsole(answers=[
                    "alchemy-test-key",    # Alchemy key
                    "etherscan-test-key",  # Etherscan key
                    "n",                   # explicit RPC override: decline
                    "",                    # max time: default
                    "",                    # persist confirmation: yes
                ])
                config = _interactive_setup(
                    console,
                    alchemy_key=None,
                    etherscan_key=None,
                    explicit_rpc_url=None,
                    **self.BASE_KWARGS,
                )

                self.assertEqual(config["alchemy_key"], "alchemy-test-key")
                self.assertEqual(config["etherscan_key"], "etherscan-test-key")

                saved = load_local_config()
                self.assertEqual(saved["alchemy_api_key"], "alchemy-test-key")
                self.assertEqual(saved["etherscan_api_key"], "etherscan-test-key")
                self.assertNotIn("rpc_url", saved)

            # Key values are never echoed back to the console.
            joined = " ".join(console.outputs)
            self.assertNotIn("alchemy-test-key", joined)
            self.assertNotIn("etherscan-test-key", joined)

    def test_advanced_setup_applies_rpc_override_to_current_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                console = ScriptedConsole(answers=[
                    "alchemy-test-key",    # Alchemy key
                    "etherscan-test-key",  # Etherscan key
                    "y",                   # explicit RPC override: opt in
                    "https://rpc.example", # RPC override
                    "",                    # max time: default
                    "",                    # persist confirmation: yes
                ])
                config = _interactive_setup(
                    console,
                    alchemy_key=None,
                    etherscan_key=None,
                    explicit_rpc_url=None,
                    **self.BASE_KWARGS,
                )

                self.assertEqual(config["rpc_url"], "https://rpc.example")

                saved = load_local_config()
                self.assertEqual(saved["alchemy_api_key"], "alchemy-test-key")
                self.assertEqual(saved["etherscan_api_key"], "etherscan-test-key")
                self.assertNotIn("rpc_url", saved)

    def test_declining_persistence_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                console = ScriptedConsole(answers=[
                    "alchemy-test-key",  # Alchemy key
                    "",                  # Etherscan key: skip
                    "n",                 # explicit RPC override: decline
                    "",                  # max time: default
                    "n",                 # persist confirmation: decline
                ])
                _interactive_setup(
                    console,
                    alchemy_key=None,
                    etherscan_key=None,
                    explicit_rpc_url=None,
                    **self.BASE_KWARGS,
                )
                self.assertEqual(load_local_config(), {})

    def test_existing_keys_are_not_reprompted_or_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                # Answers cover the explicit-RPC gate (declined) and max time.
                console = ScriptedConsole(answers=["", ""])
                config = _interactive_setup(
                    console,
                    alchemy_key="existing-alchemy",
                    etherscan_key="existing-etherscan",
                    explicit_rpc_url=None,
                    **self.BASE_KWARGS,
                )
                self.assertEqual(config["alchemy_key"], "existing-alchemy")
                self.assertEqual(config["etherscan_key"], "existing-etherscan")
                # Nothing newly typed → nothing persisted, no confirmation prompt.
                self.assertEqual(load_local_config(), {})
                joined_prompts = " ".join(console.prompts)
                self.assertNotIn("Alchemy API key", joined_prompts)
                self.assertNotIn("Etherscan API key", joined_prompts)
                self.assertNotIn("Default chain", joined_prompts)
                self.assertNotIn("Save these", joined_prompts)


class FakeRunContainer:
    """Records start kwargs; never touches Docker."""

    def __init__(self, image_name=None):
        self.image_name = image_name
        self.start_kwargs: dict | None = None
        self.is_running = False
        self.init_report: list[str] = []

    async def start(self, source_dir, **kwargs):
        self.start_kwargs = kwargs

    async def stop(self):
        return None


class RunWiringTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end wiring of the resolved RPC/credential posture through _run."""

    async def _invoke_run(self, *, env_extra, no_chat=True, **run_kwargs):
        fake_container = FakeRunContainer()
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as out_dir, \
                tempfile.TemporaryDirectory() as src_dir:
            env = {"REENTBOTPRO_HOME": home, **env_extra}
            with patch.dict(os.environ, env, clear=False), \
                    patch("reentbotpro.cli.AuditContainer", lambda image_name=None: fake_container), \
                    patch("reentbotpro.cli.create_client", return_value=MagicMock(provider_name="test")), \
                    patch("reentbotpro.cli.run_audit", new=AsyncMock(return_value=([], [], {}))), \
                    patch("reentbotpro.cli.run_report", new=AsyncMock(return_value="# Report")), \
                    patch("reentbotpro.cli.chat_loop", new=AsyncMock(return_value=None)), \
                    patch("reentbotpro.cli.set_alchemy_runtime") as mock_alchemy, \
                    patch("reentbotpro.cli.set_etherscan_runtime") as mock_etherscan, \
                    patch("sys.stdin.isatty", return_value=False):
                # Defeat any host ETH_RPC_URL / model so derivation is deterministic.
                os.environ.pop("ETH_RPC_URL", None)
                os.environ.pop("REENTBOTPRO_MODEL", None)
                await cli._run(
                    source_dir=src_dir,
                    model=DEFAULT_MODEL,
                    max_time=5,
                    output=out_dir,
                    image="img",
                    no_chat=no_chat,
                    verbosity="off",
                    **run_kwargs,
                )
                run_dirs = os.listdir(out_dir)
                self.assertEqual(len(run_dirs), 1)
                with open(os.path.join(out_dir, run_dirs[0], "findings.json")) as f:
                    findings = json.load(f)
        return fake_container, mock_alchemy, mock_etherscan, findings

    async def test_bare_alchemy_key_starts_without_eth_rpc(self):
        container, mock_alchemy, _, findings = await self._invoke_run(
            env_extra={"ALCHEMY_API_KEY": "alchemy-key"},
            api_key="sk-test",
            rpc_url=None,
        )

        # No chain known → no derived endpoint, but the key is still forwarded.
        self.assertIsNone(container.start_kwargs["rpc_url"])
        self.assertEqual(container.start_kwargs["alchemy_api_key"], "alchemy-key")
        self.assertNotIn("default_network", container.start_kwargs)
        self.assertNotIn("default_chain_id", container.start_kwargs)
        mock_alchemy.assert_called_once_with("alchemy-key")
        self.assertEqual(findings["rpc"]["provider"], "none")
        self.assertFalse(findings["rpc"]["configured"])
        self.assertTrue(findings["rpc"]["alchemy_key_configured"])

    async def test_both_keys_no_chain_starts_and_forwards_both_keys(self):
        # The canonical user setup: ALCHEMY_API_KEY + ETHERSCAN_API_KEY and no
        # chain. Startup must succeed; both keys and host runtimes are configured;
        # no ETH_RPC_URL is invented; the chain is left for the agent to infer.
        container, mock_alchemy, mock_etherscan, findings = await self._invoke_run(
            env_extra={
                "ALCHEMY_API_KEY": "alchemy-key",
                "ETHERSCAN_API_KEY": "etherscan-key",
            },
            api_key="sk-test",
            rpc_url=None,
        )

        self.assertIsNone(container.start_kwargs["rpc_url"])
        self.assertEqual(container.start_kwargs["alchemy_api_key"], "alchemy-key")
        self.assertEqual(container.start_kwargs["etherscan_api_key"], "etherscan-key")
        self.assertNotIn("default_network", container.start_kwargs)
        self.assertNotIn("default_chain_id", container.start_kwargs)
        mock_alchemy.assert_called_once_with("alchemy-key")
        mock_etherscan.assert_called_once_with("etherscan-key")
        # Provenance: not configured, both keys present, no mainnet assumption.
        self.assertEqual(findings["rpc"]["provider"], "none")
        self.assertFalse(findings["rpc"]["configured"])
        self.assertTrue(findings["rpc"]["alchemy_key_configured"])
        self.assertFalse(findings["rpc"]["assumed_default_mainnet"])

    async def test_explicit_rpc_override_wins_over_alchemy(self):
        container, _, _, findings = await self._invoke_run(
            env_extra={"ALCHEMY_API_KEY": "alchemy-key"},
            api_key="sk-test",
            rpc_url="https://explicit.example",
        )
        self.assertEqual(container.start_kwargs["rpc_url"], "https://explicit.example")
        self.assertEqual(findings["rpc"]["provider"], "explicit")
        self.assertTrue(findings["rpc"]["override"])

    async def test_chat_resave_path_still_writes_rpc_metadata(self):
        # The post-chat re-save is a separate _save_run_output site; make sure it
        # also carries the structured rpc provenance.
        _, _, _, findings = await self._invoke_run(
            env_extra={"ALCHEMY_API_KEY": "alchemy-key"},
            no_chat=False,
            api_key="sk-test",
            rpc_url="https://base-mainnet.g.alchemy.com/v2/alchemy-key",
        )
        self.assertEqual(findings["rpc"]["provider"], "explicit")
        self.assertEqual(findings["rpc"]["network"], "base-mainnet")


if __name__ == "__main__":
    unittest.main()
