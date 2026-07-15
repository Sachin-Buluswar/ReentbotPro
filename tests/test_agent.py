import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from reentbotpro.llm import DEFAULT_MODEL
from reentbotpro.agent import (
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_TOOLSETS,
    _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS,
    _CAMPAIGN_SUMMARY_COUNTERS,
    _CAMPAIGN_TOOL_TRACKING,
    _FINAL_READINESS_NUDGE,
    _MIN_AUDIT_TURNS,
    _TOOLS_TOKEN_OVERHEAD,
    _age_tool_outputs,
    _activate_requested_toolsets,
    _attack_search_expected_tools,
    _attack_search_result_next_action,
    _build_explored_summary,
    _build_truncation_note,
    _campaign_stop_readiness,
    _execute_tool_calls,
    _is_context_window_error,
    _report_visible_tools,
    _record_final_readiness,
    _run_command_is_diagnostic,
    _run_experiment_targets_local_workspace,
    _strip_old_reasoning,
    _stream_turn,
    _stream_turn_with_recovery,
    _summarize_tool_result,
    _tool_result_failed,
    _toolsets_from_attack_search_next_action,
    _tools_token_overhead,
    _truncate_messages,
    _turn_history_budget,
    _update_explored,
    _visible_tools,
    calculate_max_context,
    chat_loop,
    get_model_max_output_tokens,
    run_audit,
    run_report,
)
from reentbotpro.tools import (
    PARALLEL_SAFE,
    TOOL_BY_NAME,
    expand_toolsets,
    tool_names_for_toolsets,
    tools_for_toolsets,
)
from reentbotpro.display import _tool_summary

_ALCHEMY_INVESTIGATION_TOOLS = (
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
)


class FakeDisplay:
    def __init__(self):
        self.phases: list[str] = []
        self.errors: list[str] = []
        self.statuses: list[str] = []

    def phase(self, title):
        self.phases.append(title)

    def error(self, message):
        self.errors.append(message)

    def status(self, message):
        self.statuses.append(message)

    def tool_start(self, tool_call):
        pass

    def tool_result(self, tool_call, result):
        pass

    def progress_status(self, *args, **kwargs):
        pass

    def agent_done(self):
        pass


class FakeContainer:
    def __init__(self):
        self.files: dict[str, str] = {}

    async def read_file(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]


class StreamTurnTests(unittest.TestCase):
    def test_legacy_default_context_window_remains_stable(self):
        self.assertEqual(DEFAULT_CONTEXT_WINDOW, 272_000)

    def test_default_output_limit_is_audit_reserve(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
        ))

        self.assertEqual(client.kwargs["max_output_tokens"], 16_384)

    def test_default_visible_tools_are_core_only(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
        ))

        names = {tool["function"]["name"] for tool in client.kwargs["tools"]}
        self.assertIn("inspect_scope", names)
        self.assertIn("request_toolset", names)
        self.assertIn("attack_search", names)
        self.assertIn("build_campaign_brief", names)
        self.assertTrue({
            "create_experiment",
            "plan_attack_campaign",
            "prepare_fork_exploit_workbench",
            "review_attack_surface_coverage",
            "review_campaign_progress",
        }.isdisjoint(names))
        self.assertNotIn("compose_sequence_experiment", names)
        self.assertNotIn("submit_finding", names)

    def test_explicit_empty_tool_list_is_preserved(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
            tools=[],
        ))

        self.assertEqual(client.kwargs["tools"], [])

    def test_visible_tools_can_include_requested_experiment_set(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()
        tools = _visible_tools({"active_toolsets": {"core", "experiment"}})

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
            tools=tools,
        ))

        names = {tool["function"]["name"] for tool in client.kwargs["tools"]}
        self.assertIn("compose_sequence_experiment", names)
        self.assertIn("run_sequence_minimization", names)
        self.assertNotIn("submit_finding", names)

    def test_report_visible_tools_are_read_and_write_only(self):
        names = {tool["function"]["name"] for tool in _report_visible_tools()}

        self.assertEqual(names, {
            "list_files",
            "read_file",
            "write_file",
            "read_campaign",
        })
        self.assertNotIn("run_command", names)
        self.assertNotIn("run_experiment", names)
        self.assertNotIn("request_toolset", names)
        self.assertNotIn("submit_finding", names)

    def test_run_report_injects_authoritative_findings_json_and_report_tools(self):
        container = FakeContainer()
        container.files["/output/report.md"] = "# Report\n"
        messages = [{"role": "system", "content": "system prompt"}]
        findings = [{
            "id": "finding-001",
            "title": "Unauthorized vault drain",
            "severity": "critical",
            "validated": True,
            "test_output": "Test result: ok. 1 passed; 0 failed",
        }]
        captured: dict[str, object] = {}

        async def fake_stream_turn_with_recovery(
            client,
            model,
            turn_messages,
            display,
            **kwargs,
        ):
            captured["messages"] = list(turn_messages)
            captured["tools"] = kwargs["tools"]
            return {"role": "assistant", "content": "done"}, 0, 0, "stop", turn_messages

        with patch(
            "reentbotpro.agent._stream_turn_with_recovery",
            side_effect=fake_stream_turn_with_recovery,
        ):
            report = asyncio.run(run_report(
                client=object(),
                model=DEFAULT_MODEL,
                messages=messages,
                container=container,
                display=FakeDisplay(),
                findings=findings,
                max_time_seconds=5,
            ))

        self.assertEqual(report, "# Report\n")
        tool_names = {
            tool["function"]["name"]
            for tool in captured["tools"]
        }
        self.assertEqual(tool_names, {
            "list_files",
            "read_file",
            "write_file",
            "read_campaign",
        })
        self.assertNotIn("run_command", tool_names)
        self.assertNotIn("run_experiment", tool_names)
        self.assertNotIn("request_toolset", tool_names)
        self.assertNotIn("submit_finding", tool_names)

        report_prompt = captured["messages"][-1]["content"]
        self.assertIn("AUTHORITATIVE_SUBMITTED_FINDINGS_JSON:", report_prompt)
        self.assertIn('"id": "finding-001"', report_prompt)
        self.assertIn('"title": "Unauthorized vault drain"', report_prompt)
        self.assertIn('"validated": true', report_prompt)
        self.assertNotIn("Here are all submitted findings for reference", report_prompt)

    def test_run_report_fallback_uses_only_report_phase_output(self):
        container = FakeContainer()
        audit_chunk = "AUDIT_REASONING_SHOULD_NOT_BE_A_REPORT " * 30
        report_chunk = "# Report\n\nValidated submitted findings only. " * 20
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "assistant", "content": audit_chunk},
        ]

        async def fake_stream_turn_with_recovery(
            client,
            model,
            turn_messages,
            display,
            **kwargs,
        ):
            return (
                {"role": "assistant", "content": report_chunk},
                0,
                0,
                "stop",
                turn_messages,
            )

        with patch(
            "reentbotpro.agent._stream_turn_with_recovery",
            side_effect=fake_stream_turn_with_recovery,
        ):
            report = asyncio.run(run_report(
                client=object(),
                model=DEFAULT_MODEL,
                messages=messages,
                container=container,
                display=FakeDisplay(),
                findings=[],
                max_time_seconds=5,
            ))

        self.assertEqual(report, report_chunk)
        self.assertNotIn("AUDIT_REASONING_SHOULD_NOT_BE_A_REPORT", report)

    def test_stop_readiness_blocks_high_signal_active_branch(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 1,
    "actionable": 1,
    "parked": 0,
    "campaign_ready": false
  },
  "next_action": {
    "branch_id": "br-001",
    "status": "needs_evidence",
    "tool": "summarize_trace",
    "must_follow": true
  },
  "branches": [{
    "id": "br-001",
    "title": "Live vault withdrawal branch",
    "status": "needs_evidence",
    "source": "attack_graph_candidate",
    "priority": "high",
    "priority_score": 28,
    "next_tool": "summarize_trace"
  }]
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertFalse(readiness["ready"])
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "attack_search_not_ready",
        )
        self.assertEqual(readiness["blockers"][0]["actionable"], 1)

    def test_stop_readiness_accepts_branchless_campaign_ready_state(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 0,
    "actionable": 0,
    "parked": 0,
    "campaign_ready": true
  },
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": null,
    "must_follow": false
  },
  "branches": []
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["blockers"], [])
        self.assertEqual(readiness["checked"], {"attack_search": True})

    def test_stop_readiness_requires_attack_search_state(self):
        readiness = asyncio.run(_campaign_stop_readiness(FakeContainer()))

        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["checked"], {"attack_search": False})
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "missing_attack_search_state",
        )

    def test_campaign_ready_next_action_does_not_guard_unrelated_tool(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": "map_protocol_graph",
    "expected_tools": ["map_protocol_graph"],
    "must_follow": false
  },
  "branches": []
}
"""
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "write_file",
                "arguments": "{\"path\":\"/workspace/notes.txt\",\"content\":\"done\"}",
            },
        }]

        with patch(
            "reentbotpro.agent.execute_tool",
            new=AsyncMock(return_value="ran write_file"),
        ) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        mocked.assert_awaited_once()
        self.assertEqual(results[0]["content"], "ran write_file")
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])

    def test_stop_readiness_blocks_nonparked_next_action_regardless_of_score(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 1,
    "actionable": 1,
    "parked": 0,
    "campaign_ready": false
  },
  "next_action": {
    "branch_id": "br-001",
    "status": "needs_context",
    "tool": "source_slice",
    "must_follow": true
  },
  "branches": [{
    "id": "br-001",
    "title": "Source-review coverage gap: MockSpell::cast",
    "status": "needs_context",
    "source": "coverage_high_attention_gap",
    "priority": "high",
    "priority_score": 14,
    "next_tool": "source_slice then update_campaign or attack_search decision",
    "action_keys": ["MockSpell::cast"],
    "target_actions": [{
      "key": "MockSpell::cast",
      "contract": "MockSpell",
      "function": "cast",
      "file": "/audit/test/MockSpell.sol",
      "affordances": ["state_mutating_entrypoint"]
    }]
  }]
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertFalse(readiness["ready"])
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "attack_search_not_ready",
        )

    def test_stop_readiness_accepts_campaign_ready_with_parked_branches(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 0,
    "actionable": 0,
    "parked": 1,
    "campaign_ready": true
  },
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": null,
    "must_follow": false
  },
  "branches": [{
    "id": "br-001",
    "title": "Source-review coverage gap: Vault::withdraw",
    "status": "parked_needs_live_context",
    "source": "coverage_high_attention_gap",
    "priority": "high",
    "priority_score": 22,
    "next_tool": "source_slice then update_campaign or attack_search decision",
    "action_keys": ["Vault::withdraw"],
    "target_actions": [{
      "key": "Vault::withdraw",
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "affordances": ["value_out_or_burn"]
    }]
  }]
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["blockers"], [])

    def test_stop_readiness_consumes_controller_summary_without_status_duplication(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 1,
    "actionable": 0,
    "parked": 1,
    "campaign_ready": true
  },
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": null,
    "must_follow": false
  },
  "branches": [{
    "id": "br-future",
    "status": "parked_by_future_controller_policy"
  }]
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["blockers"], [])

    def test_stop_readiness_fails_closed_without_controller_summary(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": null,
    "must_follow": false
  },
  "branches": []
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertFalse(readiness["ready"])
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "attack_search_not_ready",
        )

    def test_record_final_readiness_runs_fresh_sync_before_reading_state(self):
        container = FakeContainer()
        ready_state = {
            "summary": {
                "active": 0,
                "actionable": 0,
                "parked": 0,
                "campaign_ready": True,
            },
            "next_action": {
                "branch_id": None,
                "status": "campaign_ready",
                "tool": None,
                "must_follow": False,
            },
            "branches": [],
        }

        async def sync_controller(name, arguments, target, findings):
            self.assertEqual(name, "attack_search")
            self.assertEqual(
                arguments,
                {"action": "sync", "record_result": False},
            )
            self.assertIs(target, container)
            self.assertEqual(findings, [])
            target.files["/workspace/campaign/attack-search/current.json"] = (
                json.dumps(ready_state)
            )
            return json.dumps({
                "summary": ready_state["summary"],
                "next_action": ready_state["next_action"],
            })

        explored = {}
        with patch(
            "reentbotpro.agent.execute_tool",
            new=AsyncMock(side_effect=sync_controller),
        ) as mocked:
            readiness = asyncio.run(_record_final_readiness(
                container,
                explored,
                reason="wrap_up_requested",
            ))

        mocked.assert_awaited_once()
        self.assertTrue(readiness["ready"])
        self.assertEqual(
            readiness["sync"],
            {"action": "sync", "attempted": True, "succeeded": True},
        )
        self.assertEqual(explored["attack_search_runs"], 1)
        self.assertNotIn("audit_status", explored)

    def test_record_final_readiness_rejects_stale_ready_state_when_sync_fails(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = json.dumps({
            "summary": {"actionable": 0, "campaign_ready": True},
            "next_action": {
                "branch_id": None,
                "status": "campaign_ready",
                "must_follow": False,
            },
            "branches": [],
        })
        explored = {}

        with patch(
            "reentbotpro.agent.execute_tool",
            new=AsyncMock(return_value="Error: controller sync unavailable"),
        ) as mocked:
            readiness = asyncio.run(_record_final_readiness(
                container,
                explored,
                reason="wrap_up_requested",
            ))

        mocked.assert_awaited_once()
        self.assertFalse(readiness["ready"])
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "final_attack_search_sync_failed",
        )
        self.assertFalse(readiness["sync"]["succeeded"])
        self.assertEqual(
            explored["audit_status"],
            "incomplete_no_validated_findings",
        )
        self.assertEqual(explored["audit_status_reason"], "wrap_up_requested")

    def test_wall_clock_wrap_up_performs_fresh_final_sync(self):
        container = FakeContainer()
        ready_state = {
            "summary": {"actionable": 0, "campaign_ready": True},
            "next_action": {
                "branch_id": None,
                "status": "campaign_ready",
                "tool": None,
                "must_follow": False,
            },
            "branches": [],
        }

        async def finish_turn(*_args, **_kwargs):
            return (
                {"role": "assistant", "content": "Wrapped up."},
                0,
                0,
                "stop",
                [],
            )

        async def sync_controller(_name, arguments, target, _findings):
            self.assertEqual(arguments["action"], "sync")
            target.files["/workspace/campaign/attack-search/current.json"] = (
                json.dumps(ready_state)
            )
            return json.dumps({
                "summary": ready_state["summary"],
                "next_action": ready_state["next_action"],
            })

        with (
            patch(
                "reentbotpro.agent._stream_turn_with_recovery",
                side_effect=finish_turn,
            ),
            patch(
                "reentbotpro.agent.execute_tool",
                new=AsyncMock(side_effect=sync_controller),
            ) as synced,
        ):
            _findings, _messages, explored = asyncio.run(run_audit(
                client=object(),
                model=DEFAULT_MODEL,
                system_prompt="system",
                container=container,
                display=FakeDisplay(),
                max_time_seconds=0,
            ))

        synced.assert_awaited_once()
        self.assertTrue(explored["final_readiness"]["ready"])
        self.assertTrue(explored["final_readiness"]["sync"]["succeeded"])
        self.assertEqual(explored["attack_search_syncs"], 1)

    def test_stop_readiness_rejects_inconsistent_ready_state(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "summary": {
    "active": 1,
    "actionable": 1,
    "parked": 0,
    "campaign_ready": true
  },
  "next_action": {
    "branch_id": null,
    "status": "campaign_ready",
    "tool": null,
    "must_follow": false
  },
  "branches": [{
    "id": "br-001",
    "title": "Unreviewed objective evidence",
    "status": "needs_evidence",
    "source": "result_without_objective",
    "priority": "high",
    "priority_score": 28,
    "next_tool": "summarize_trace"
  }]
}
"""

        readiness = asyncio.run(_campaign_stop_readiness(container))

        self.assertFalse(readiness["ready"])
        self.assertEqual(
            readiness["blockers"][0]["kind"],
            "attack_search_not_ready",
        )

    def test_execute_tool_calls_blocks_tool_that_violates_attack_search_next_action(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "next_action": {
    "branch_id": "br-001",
    "status": "needs_mapping",
    "tool": "map_protocol_graph"
  },
  "branches": [{
    "id": "br-001",
    "title": "Map protocol graph",
    "status": "needs_mapping",
    "source": "missing_map",
    "priority": "high",
    "priority_score": 18,
    "next_tool": "map_protocol_graph"
  }]
}
"""
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "build_attack_graph",
                "arguments": "{}",
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])
        self.assertIn("map_protocol_graph", results[0]["content"])

    def test_execute_tool_calls_rejects_malformed_json_without_running_tool(self):
        container = FakeContainer()
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "read_file", "arguments": "{not valid json"},
        }]
        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls, container, [], FakeDisplay(),
            ))
        self.assertFalse(mocked.called)
        self.assertIn("invalid_tool_arguments_json", results[0]["content"])

    def test_execute_tool_calls_empty_arguments_still_runs_tool(self):
        # No-argument tools may send "" / omit arguments — must still run.
        container = FakeContainer()
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "inspect_scope", "arguments": ""},
        }]
        with patch(
            "reentbotpro.agent.execute_tool",
            new=AsyncMock(return_value="ok"),
        ) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls, container, [], FakeDisplay(),
            ))
        self.assertTrue(mocked.called)
        self.assertEqual(results[0]["content"], "ok")

    def test_execute_tool_calls_allows_read_when_required_tool_is_paired(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = """
{
  "next_action": {
    "branch_id": "br-001",
    "status": "needs_mapping",
    "tool": "map_protocol_graph"
  },
  "branches": [{
    "id": "br-001",
    "title": "Map protocol graph",
    "status": "needs_mapping",
    "source": "missing_map",
    "priority": "high",
    "priority_score": 18,
    "next_tool": "map_protocol_graph"
  }]
}
"""
        tool_calls = [
            {
                "id": "call_1",
                "function": {
                    "name": "read_file",
                    "arguments": '{"path":"/audit/src/Vault.sol"}',
                },
            },
            {
                "id": "call_2",
                "function": {
                    "name": "map_protocol_graph",
                    "arguments": "{}",
                },
            },
        ]

        async def fake_execute_tool(name, *_args):
            return f"ran {name}"

        with patch("reentbotpro.agent.execute_tool", side_effect=fake_execute_tool) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual([item["content"] for item in results], ["ran read_file", "ran map_protocol_graph"])

    def _next_action_search_json(self, tool: str = "compose_sequence_experiment") -> str:
        return (
            '{\n'
            '  "next_action": {\n'
            '    "branch_id": "br-001",\n'
            '    "status": "needs_concretization",\n'
            f'    "tool": "{tool}"\n'
            '  },\n'
            '  "branches": [{\n'
            '    "id": "br-001",\n'
            '    "title": "Concretize experiment",\n'
            '    "status": "needs_concretization",\n'
            '    "source": "experiment_without_result",\n'
            '    "priority": "high",\n'
            '    "priority_score": 18,\n'
            f'    "next_tool": "{tool}"\n'
            '  }]\n'
            '}\n'
        )

    def _run_one_tool(self, tool_calls, container):
        async def fake_execute_tool(name, *_args):
            return f"ran {name}"

        with patch(
            "reentbotpro.agent.execute_tool",
            side_effect=fake_execute_tool,
        ) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))
        return mocked, results

    def _assert_cognitive_tool_is_always_allowed(self, name, arguments="{}"):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json()
        )
        tool_calls = [{
            "id": "call_1",
            "function": {"name": name, "arguments": arguments},
        }]

        mocked, results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called, f"{name} should not be blocked by the guard")
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])
        self.assertEqual(results[0]["content"], f"ran {name}")

    def test_read_file_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "read_file",
            '{"path":"/audit/src/Vault.sol"}',
        )

    def test_search_code_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "search_code",
            '{"query":"msg.sender"}',
        )

    def test_source_slice_is_always_allowed_against_unrelated_next_action(self):
        # source_slice is cognitive/source-review surface; the controller's
        # branch ordering must not block it even though artifact recording means
        # it is not parallel-safe.
        self._assert_cognitive_tool_is_always_allowed(
            "source_slice",
            '{"path":"/audit/src/Vault.sol","function":"withdraw"}',
        )

    def test_list_files_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "list_files",
            '{"path":"/audit/src"}',
        )

    def test_inspect_scope_is_always_allowed_against_unrelated_next_action(self):
        # inspect_scope writes the scope manifest other map tools depend on,
        # so blocking it created a cascade where map_protocol_graph kept failing.
        self._assert_cognitive_tool_is_always_allowed("inspect_scope")

    def test_update_campaign_is_always_allowed_against_unrelated_next_action(self):
        # The agent must always be able to record observations / decisions /
        # fix sequence_quality, even when a different branch is "first".
        self._assert_cognitive_tool_is_always_allowed(
            "update_campaign",
            '{"action":"add","section":"hypothesis","content":"HYP-001"}',
        )

    def test_mutate_hypothesis_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "mutate_hypothesis",
            (
                '{"source_hypothesis_id":"hyp-001",'
                '"failed_assumption":"pool is attacker controlled",'
                '"interpretation":"pool is immutable",'
                '"mutations":[{"title":"Test deposit fee","hypothesis":"...",'
                '"rationale":"...","experiment":"..."}]}'
            ),
        )

    def test_build_campaign_brief_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed("build_campaign_brief")

    def test_synthesize_args_is_always_allowed_against_unrelated_next_action(self):
        # synthesize_args is cognitive planning (candidate args/setup/blockers).
        # It writes an arg-synthesis artifact but invents no gated evidence, so
        # the controller's branch ordering must not block it.
        self._assert_cognitive_tool_is_always_allowed(
            "synthesize_args",
            '{"action":{"contract":"Vault","function":"withdraw"}}',
        )

    def test_diagnose_build_is_always_allowed_against_unrelated_next_action(self):
        # diagnose_build is a diagnostic/cognitive tool: it classifies build
        # blockers and writes only a campaign artifact, never mutating an
        # experiment, so the controller's branch ordering must not block it.
        self._assert_cognitive_tool_is_always_allowed(
            "diagnose_build",
            '{"command":"forge build"}',
        )

    def test_extract_state_transition_model_is_always_allowed_against_unrelated_next_action(self):
        # Generic state/invariant modeling is read-only cognitive planning
        # surface: it writes a planning artifact but no evidence the submission
        # gates rely on, so the controller's branch ordering must not block it.
        self._assert_cognitive_tool_is_always_allowed(
            "extract_state_transition_model",
            '{"path":"/audit/src/Vault.sol"}',
        )

    def test_fetch_url_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "fetch_url",
            '{"url":"https://example.com"}',
        )

    def test_web_search_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "web_search",
            '{"query":"hypervisor uniswap v3 callback"}',
        )

    def test_trace_onchain_tx_is_always_allowed_against_unrelated_next_action(self):
        # Live Alchemy investigation is read-only cognitive surface: the
        # controller's branch ordering must not block it (same class as
        # fetch_url/web_search).
        self._assert_cognitive_tool_is_always_allowed(
            "trace_onchain_tx",
            '{"tx_hash":"0x' + "ab" * 32 + '"}',
        )

    def test_get_asset_transfers_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "get_asset_transfers",
            '{"address":"0x' + "ab" * 20 + '"}',
        )

    def test_simulate_asset_changes_is_always_allowed_against_unrelated_next_action(self):
        self._assert_cognitive_tool_is_always_allowed(
            "simulate_asset_changes",
            '{"from":"0x' + "ab" * 20 + '","to":"0x' + "cd" * 20 + '"}',
        )

    def test_observed_tx_miner_is_always_allowed_against_unrelated_next_action(self):
        # The on-chain transaction miner composes the read-only Alchemy primitives;
        # like trace_onchain_tx/get_asset_transfers it is cognitive recon surface
        # the controller's branch ordering must not block.
        self._assert_cognitive_tool_is_always_allowed(
            "observed_tx_miner",
            '{"address":"0x' + "ab" * 20 + '","selector":"0xa9059cbb"}',
        )

    def test_run_experiment_targeting_local_workspace_is_always_allowed(self):
        # The agent's own validation tests live under /workspace/experiments/.
        # The controller must not block forge test on them, even when a
        # different branch is "first".
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": (
                    '{"command":"cd /workspace/experiments/exp-001-callback/'
                    ' && FOUNDRY_PROFILE=contract_Hypervisor_a807 forge test -vvv"}'
                ),
            },
        }]

        mocked, results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called)
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])
        self.assertEqual(results[0]["content"], "ran run_experiment")

    def test_run_experiment_with_local_working_dir_is_always_allowed(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": json.dumps({
                    "command": "FOUNDRY_PROFILE=generated forge test -vvv",
                    "working_dir": "/workspace/experiments/exp-001-callback/",
                }),
            },
        }]

        mocked, results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called)
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])

    def test_repair_experiment_is_always_allowed_against_unrelated_next_action(self):
        # repair_experiment only ever edits the agent's own /workspace/experiments/
        # workspace, so -- like run_experiment against the local workspace -- the
        # controller must not block repairing an experiment so it can be validated,
        # even when a different branch is "first".
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "repair_experiment",
                "arguments": '{"experiment":"exp-001"}',
            },
        }]

        mocked, results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called)
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])
        self.assertEqual(results[0]["content"], "ran repair_experiment")

    def test_run_experiment_with_workspace_root_argument_is_allowed(self):
        # A parsed --root target is an explicit local-workspace binding.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": (
                    '{"command":"forge test --root /workspace/experiments/'
                    'exp-001-callback -vvv"}'
                ),
            },
        }]

        mocked, _results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called)

    def test_run_experiment_workspace_substring_does_not_bypass_guard(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": json.dumps({
                    "command": (
                        "echo /workspace/experiments/exp-001-callback "
                        "&& rm -rf /audit"
                    ),
                }),
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])

    def test_run_experiment_with_non_workspace_command_still_respects_guard(self):
        # Generic run_experiment usage (e.g. cast call against mainnet) should
        # still be subject to the controller when a must-follow next action
        # demands a different tool. This preserves campaign discipline for the
        # non-validation uses of run_experiment.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": (
                    '{"command":"cast call 0xa8076ae31e4b6c64d07b1ed27889924a962a70d3'
                    ' \\"totalSupply()(uint256)\\""}'
                ),
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])

    def test_run_experiment_with_missing_command_falls_through_to_guard(self):
        # If the agent omits or malforms command, the guard should still run.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": '{}',
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])

    def test_run_experiment_with_invalid_arguments_json_is_rejected_before_running(self):
        # Malformed arguments are rejected with a re-emit request before the tool
        # runs or the guard is consulted — a side-effecting tool never executes
        # with silently-emptied arguments or out of order.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="write_file")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_experiment",
                "arguments": "not-json",
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("invalid_tool_arguments_json", results[0]["content"])

    def test_non_allowed_tool_still_blocked(self):
        # Tools NOT in the cognitive allowlist still get blocked when the
        # controller has a must-follow next action for a different tool.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="map_protocol_graph")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "write_file",
                "arguments": '{"path":"/workspace/scratch.txt","content":"x"}',
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container,
                [],
                FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])
        self.assertIn("write_file", results[0]["content"])

    def test_output_limit_is_capped_by_model_limit(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
            max_output_tokens=999_999,
        ))

        self.assertEqual(client.kwargs["max_output_tokens"], 128_000)

    def test_none_output_limit_uses_model_maximum(self):
        class FakeClient:
            async def stream_turn(self, **kwargs):
                self.kwargs = kwargs
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        client = FakeClient()

        asyncio.run(_stream_turn(
            client,
            DEFAULT_MODEL,
            [{"role": "user", "content": "inspect"}],
            display=object(),
            max_output_tokens=None,
        ))

        self.assertEqual(
            client.kwargs["max_output_tokens"],
            get_model_max_output_tokens(DEFAULT_MODEL),
        )

    # ── Diagnostic run_command permissiveness ──────────────────────────

    def test_diagnostic_run_command_allowed_against_unrelated_next_action(self):
        # forge build is a read-only diagnostic; the controller must not block it
        # even while a different branch demands another tool first.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="compose_sequence_experiment")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "run_command", "arguments": '{"command":"forge build"}'},
        }]

        mocked, results = self._run_one_tool(tool_calls, container)

        self.assertTrue(mocked.called)
        self.assertNotIn("attack_search_next_action_required", results[0]["content"])
        self.assertEqual(results[0]["content"], "ran run_command")

    def test_non_diagnostic_run_command_blocked_against_unrelated_next_action(self):
        # `forge test` (no --list) runs stateful tests; it stays subject to the
        # controller when a must-follow next action demands a different tool.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="compose_sequence_experiment")
        )
        tool_calls = [{
            "id": "call_1",
            "function": {
                "name": "run_command",
                "arguments": '{"command":"forge test --match-contract Vault -vvv"}',
            },
        }]

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                tool_calls, container, [], FakeDisplay(),
            ))

        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])

    def test_diagnostic_run_command_cannot_overwrite_protected_campaign_artifacts(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = (
            self._next_action_search_json(tool="compose_sequence_experiment")
        )
        commands = (
            "forge build > /workspace/campaign/attack-search/current.json",
            "slither . --json /workspace/campaign/state.json",
            "slither . --json /workspace/campaign/results/res-001.log",
            "forge build > /output/report.md",
            "forge build --use /audit/bin/evil-solc",
        )

        for index, command in enumerate(commands, start=1):
            tool_calls = [{
                "id": f"call_{index}",
                "function": {
                    "name": "run_command",
                    "arguments": json.dumps({"command": command}),
                },
            }]
            with self.subTest(command=command):
                with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
                    results = asyncio.run(_execute_tool_calls(
                        tool_calls, container, [], FakeDisplay(),
                    ))

                self.assertFalse(mocked.called)
                self.assertIn(
                    "attack_search_next_action_required",
                    results[0]["content"],
                )

    def test_structured_expected_tools_overrides_text_scan(self):
        # next_action carries an explicit expected_tools list; the guard honors
        # those exact names instead of scanning the free-text `tool` field, which
        # here names no registered tool at all.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = json.dumps({
            "next_action": {
                "branch_id": "br-001",
                "status": "needs_mapping",
                "tool": "do the next thing",
                "expected_tools": ["map_protocol_graph"],
            },
            "branches": [{
                "id": "br-001",
                "status": "needs_mapping",
                "next_tool": "do the next thing",
            }],
        })

        mocked, results = self._run_one_tool(
            [{"id": "call_1",
              "function": {"name": "map_protocol_graph", "arguments": "{}"}}],
            container,
        )
        self.assertTrue(mocked.called)
        self.assertEqual(results[0]["content"], "ran map_protocol_graph")

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                [{"id": "call_1",
                  "function": {"name": "write_file",
                               "arguments": '{"path":"/workspace/x","content":"y"}'}}],
                container, [], FakeDisplay(),
            ))
        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])

    def test_structured_pipeline_steps_define_expected_tools(self):
        # An ordered pipeline lists complete_sequence_experiment, which is NOT in
        # the always-allowed set — the guard allows it because the pipeline pins
        # it, while an unrelated side-effecting tool is still blocked.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-search/current.json"] = json.dumps({
            "next_action": {
                "branch_id": "br-001",
                "status": "needs_run",
                "tool": "follow the pipeline",
                "pipeline": [
                    {"tool": "synthesize_args"},
                    {"tool": "complete_sequence_experiment"},
                ],
            },
            "branches": [{
                "id": "br-001",
                "status": "needs_run",
                "next_tool": "follow the pipeline",
            }],
        })

        mocked, results = self._run_one_tool(
            [{"id": "call_1",
              "function": {"name": "complete_sequence_experiment",
                           "arguments": '{"sequence":"exp-001"}'}}],
            container,
        )
        self.assertTrue(mocked.called)
        self.assertEqual(results[0]["content"], "ran complete_sequence_experiment")

        with patch("reentbotpro.agent.execute_tool", new=AsyncMock()) as mocked:
            results = asyncio.run(_execute_tool_calls(
                [{"id": "call_1",
                  "function": {"name": "write_file",
                               "arguments": '{"path":"/workspace/x","content":"y"}'}}],
                container, [], FakeDisplay(),
            ))
        self.assertFalse(mocked.called)
        self.assertIn("attack_search_next_action_required", results[0]["content"])


class AgentStateTests(unittest.TestCase):
    def test_request_toolset_activates_specialized_tools(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {
                "name": "request_toolset",
                "arguments": '{"toolset":"evidence","reason":"compare snapshots"}',
            },
        }]

        activated = _activate_requested_toolsets(tool_calls, explored)

        self.assertEqual(activated, {"evidence"})
        self.assertIn("evidence", explored["active_toolsets"])
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("snapshot_state", names)
        self.assertIn("evaluate_objective", names)

    def test_request_all_toolset_exposes_report_tools(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {
                "name": "request_toolset",
                "arguments": '{"toolset":"all","reason":"full campaign handoff"}',
            },
        }]

        _activate_requested_toolsets(tool_calls, explored)

        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("submit_finding", names)
        self.assertIn("map_protocol_graph", names)
        self.assertIn("run_campaign_fuzz", names)

    def test_unknown_toolset_request_does_not_activate(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {
                "name": "request_toolset",
                "arguments": '{"toolset":"unknown","reason":"bad request"}',
            },
        }]

        activated = _activate_requested_toolsets(tool_calls, explored)

        self.assertEqual(activated, set())
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("request_toolset", names)
        self.assertNotIn("submit_finding", names)

    def test_campaign_tool_tracking_counts_lending_health_estimates(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {
                "name": "estimate_lending_health",
                "arguments": '{"title":"Borrower branch","positions":[{}]}',
            },
        }]

        _update_explored(tool_calls, explored)

        self.assertEqual(explored["campaign_updates"], 1)
        self.assertEqual(explored["economics_estimates"], 1)
        self.assertEqual(explored["lending_health_estimates"], 1)
        self.assertEqual(explored["campaign_sections"], {"result"})
        self.assertIn(
            "Lending health estimates recorded: 1",
            _build_explored_summary(explored),
        )

    def test_campaign_tool_tracking_counts_sequence_completions(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {
                "name": "complete_sequence_experiment",
                "arguments": '{"sequence":"exp-001"}',
            },
        }]

        _update_explored(tool_calls, explored)

        self.assertEqual(explored["campaign_updates"], 1)
        self.assertEqual(explored["sequence_completions"], 1)
        self.assertEqual(explored["campaign_sections"], {"experiment", "result"})
        self.assertIn(
            "Sequence experiments completed: 1",
            _build_explored_summary(explored),
        )

    def test_retired_workflow_tools_are_absent_from_agent_tracking(self):
        retired_tools = {
            "create_experiment",
            "plan_attack_campaign",
            "prepare_fork_exploit_workbench",
            "review_attack_surface_coverage",
            "review_campaign_progress",
        }

        self.assertTrue(retired_tools.isdisjoint(_CAMPAIGN_TOOL_TRACKING))
        self.assertTrue(retired_tools.isdisjoint(_ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS))
        self.assertTrue(retired_tools.isdisjoint(TOOL_BY_NAME))
        self.assertTrue(retired_tools.isdisjoint(tool_names_for_toolsets({"all"})))
        summary_counters = {name for name, _label in _CAMPAIGN_SUMMARY_COUNTERS}
        self.assertTrue({
            "campaign_plans",
            "coverage_reviews",
            "experiments_created",
            "progress_reviews",
        }.isdisjoint(summary_counters))

    @staticmethod
    def _run_attack_search(next_action, *, with_results=True, explored=None):
        """Run _update_explored for one attack_search call and return explored.

        The controller's result payload (with ``next_action``) drives
        demand-driven toolset activation, so the default passes a result message;
        ``with_results=False`` exercises the legacy (no-result) signature.
        """
        if explored is None:
            explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "attack_search", "arguments": '{"action":"sync"}'},
        }]
        results = None
        if with_results:
            results = [{
                "role": "tool",
                "tool_call_id": "call_1",
                "content": json.dumps({"next_action": next_action}),
            }]
        _update_explored(tool_calls, explored, results)
        return explored

    def test_attack_search_activates_only_declared_required_toolset(self):
        # next_action requiring build_attack_graph (map) activates map only — not
        # the whole experiment/evidence surface the old code unlocked.
        explored = self._run_attack_search({
            "branch_id": "br-1",
            "status": "needs_mapping",
            "tool": "build_attack_graph",
            "required_toolsets": ["map"],
        })

        self.assertEqual(explored["attack_search_runs"], 1)
        self.assertEqual(explored["attack_search_syncs"], 1)
        self.assertIn("map", explored["active_toolsets"])
        self.assertNotIn("experiment", explored["active_toolsets"])
        self.assertNotIn("evidence", explored["active_toolsets"])
        self.assertNotIn("report", explored["active_toolsets"])
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("build_attack_graph", names)
        self.assertIn("map_action_space", names)
        self.assertNotIn("compose_sequence_experiment", names)
        self.assertNotIn("evaluate_objective", names)
        # Branch locator is still recorded for the truncation/recovery note.
        self.assertEqual(explored["attack_branch"]["branch_id"], "br-1")

    def test_attack_search_activates_map_for_extract_state_transition_model(self):
        # F: a next_action that recommends extract_state_transition_model with
        # required_toolsets=["map"] activates the map toolset only.
        explored = self._run_attack_search({
            "branch_id": "br-stm",
            "status": "needs_mapping",
            "tool": "extract_state_transition_model",
            "required_toolsets": ["map"],
        })

        self.assertIn("map", explored["active_toolsets"])
        self.assertNotIn("experiment", explored["active_toolsets"])
        self.assertNotIn("evidence", explored["active_toolsets"])
        self.assertNotIn("report", explored["active_toolsets"])
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("extract_state_transition_model", names)
        self.assertIn("build_attack_graph", names)
        self.assertNotIn("compose_sequence_experiment", names)

    def test_attack_search_activates_experiment_from_expected_tools(self):
        # No required_toolsets: the explicit expected_tools list resolves the
        # owning toolset (experiment only).
        explored = self._run_attack_search({
            "branch_id": "br-2",
            "status": "needs_run",
            "tool": "do the next thing",
            "expected_tools": ["complete_sequence_experiment"],
        })

        self.assertIn("experiment", explored["active_toolsets"])
        self.assertNotIn("map", explored["active_toolsets"])
        self.assertNotIn("evidence", explored["active_toolsets"])
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("complete_sequence_experiment", names)
        self.assertNotIn("map_action_space", names)

    def test_attack_search_activates_experiment_from_pipeline(self):
        # A pipeline of synthesize_args -> complete_sequence_experiment (both in
        # experiment) activates experiment only.
        explored = self._run_attack_search({
            "branch_id": "br-3",
            "status": "needs_run",
            "tool": "follow the pipeline",
            "pipeline": [
                {"tool": "synthesize_args"},
                {"tool": "complete_sequence_experiment"},
            ],
        })

        self.assertEqual(
            {ts for ts in explored["active_toolsets"] if ts != "core"},
            {"experiment"},
        )
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("synthesize_args", names)
        self.assertIn("complete_sequence_experiment", names)

    def test_attack_search_activates_report_from_tool_fallback(self):
        # No structured fields: the free-text tool names review_finding_evidence,
        # which lives in the report toolset (not evidence) — so report activates.
        explored = self._run_attack_search({
            "branch_id": "br-4",
            "status": "needs_finding_review",
            "tool": "review_finding_evidence",
        })

        self.assertIn("report", explored["active_toolsets"])
        self.assertNotIn("map", explored["active_toolsets"])
        self.assertNotIn("experiment", explored["active_toolsets"])
        self.assertNotIn("evidence", explored["active_toolsets"])
        names = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertIn("review_finding_evidence", names)

    def test_attack_search_campaign_ready_next_action_activates_nothing(self):
        # A branchless ready campaign must not unlock any specialized toolset.
        explored = self._run_attack_search({
            "branch_id": None,
            "status": "campaign_ready",
            "tool": None,
            "required_toolsets": ["map"],
            "expected_tools": ["map_protocol_graph"],
            "campaign_ready": True,
            "must_follow": False,
        })

        self.assertEqual(
            {ts for ts in explored.get("active_toolsets", set()) if ts != "core"},
            set(),
        )

    def test_attack_search_legacy_signature_does_not_blanket_activate(self):
        # Without a result payload there is no next_action to read, so the legacy
        # call records the run but unlocks nothing (no map+experiment+evidence
        # blanket). The agent falls back to request_toolset.
        explored = self._run_attack_search(None, with_results=False)

        self.assertEqual(explored["attack_search_runs"], 1)
        self.assertEqual(explored["attack_search_syncs"], 1)
        self.assertEqual(
            {ts for ts in explored.get("active_toolsets", set()) if ts != "core"},
            set(),
        )

    def test_attack_search_status_does_not_satisfy_final_sync_counter(self):
        explored = {"files_read": set(), "tools_run": set()}
        _update_explored(
            [{
                "id": "call_status",
                "function": {
                    "name": "attack_search",
                    "arguments": '{"action":"status"}',
                },
            }],
            explored,
            [{
                "role": "tool",
                "tool_call_id": "call_status",
                "content": json.dumps({
                    "next_action": {"status": "campaign_ready"},
                }),
            }],
        )

        self.assertEqual(explored["attack_search_runs"], 1)
        self.assertEqual(explored.get("attack_search_syncs", 0), 0)

    def test_attack_search_single_tool_next_action_is_smaller_than_full_surface(self):
        # The whole point: a single-tool next_action exposes fewer tools than the
        # old core+map+experiment+evidence unlock.
        explored = self._run_attack_search({
            "branch_id": "br-5",
            "status": "needs_mapping",
            "tool": "build_attack_graph",
            "required_toolsets": ["map"],
        })
        visible = len(_visible_tools(explored))
        old_surface = len(tools_for_toolsets({"core", "map", "experiment", "evidence"}))
        self.assertLess(visible, old_surface)

    def test_attack_search_visible_tools_match_active_toolsets(self):
        # Tools sent to the LLM correspond exactly to the active toolsets.
        explored = self._run_attack_search({
            "branch_id": "br-6",
            "status": "needs_run",
            "tool": "x",
            "required_toolsets": ["experiment"],
        })
        visible = {tool["function"]["name"] for tool in _visible_tools(explored)}
        self.assertEqual(visible, set(tool_names_for_toolsets(explored["active_toolsets"])))

    def test_attack_search_activation_preserves_prior_requested_toolsets(self):
        # A later attack_search that needs `map` must not wipe a toolset the
        # agent explicitly requested earlier; request_toolset is the durable
        # escape hatch while controller visibility is replaceable.
        explored = {"files_read": set(), "tools_run": set()}
        _activate_requested_toolsets(
            [{"function": {"name": "request_toolset",
                           "arguments": '{"toolset":"evidence"}'}}],
            explored,
        )
        self.assertIn("evidence", explored["active_toolsets"])

        tool_calls = [{
            "id": "call_1",
            "function": {"name": "attack_search", "arguments": '{"action":"sync"}'},
        }]
        results = [{
            "role": "tool",
            "tool_call_id": "call_1",
            "content": json.dumps({"next_action": {
                "branch_id": "br-1",
                "status": "needs_mapping",
                "tool": "build_attack_graph",
                "required_toolsets": ["map"],
            }}),
        }]
        _update_explored(tool_calls, explored, results)

        self.assertIn("map", explored["active_toolsets"])
        self.assertIn("evidence", explored["active_toolsets"])  # not clobbered
        self.assertNotIn("experiment", explored["active_toolsets"])

    def test_attack_search_replaces_prior_controller_toolset(self):
        explored = {"files_read": set(), "tools_run": set()}
        self._run_attack_search(
            {
                "branch_id": "br-map",
                "status": "needs_mapping",
                "tool": "build_attack_graph",
                "required_toolsets": ["map"],
            },
            explored=explored,
        )
        self.assertEqual(explored["controller_toolsets"], {"map"})

        self._run_attack_search(
            {
                "branch_id": "br-run",
                "status": "needs_run",
                "tool": "compose_sequence_experiment",
                "required_toolsets": ["experiment"],
            },
            explored=explored,
        )

        self.assertEqual(explored["controller_toolsets"], {"experiment"})
        self.assertEqual(explored["requested_toolsets"], set())
        self.assertEqual(
            {name for name in explored["active_toolsets"] if name != "core"},
            {"experiment"},
        )

    def test_campaign_ready_clears_controller_but_keeps_requested_toolset(self):
        explored = {"files_read": set(), "tools_run": set()}
        _activate_requested_toolsets(
            [{"function": {"name": "request_toolset",
                            "arguments": '{"toolset":"evidence"}'}}],
            explored,
        )
        self._run_attack_search(
            {
                "branch_id": "br-map",
                "status": "needs_mapping",
                "tool": "build_attack_graph",
                "required_toolsets": ["map"],
            },
            explored=explored,
        )
        self._run_attack_search(
            {
                "branch_id": None,
                "status": "campaign_ready",
                "campaign_ready": True,
                "must_follow": False,
            },
            explored=explored,
        )

        self.assertEqual(explored["controller_toolsets"], set())
        self.assertEqual(explored["requested_toolsets"], {"evidence"})
        self.assertEqual(
            {name for name in explored["active_toolsets"] if name != "core"},
            {"evidence"},
        )

    def test_toolsets_from_next_action_core_only_declaration_activates_nothing(self):
        # An all-core declaration is authoritative and resolves to no specialized
        # toolset (it does not fall through to a tool scan).
        self.assertEqual(
            _toolsets_from_attack_search_next_action(
                {"required_toolsets": ["core"], "tool": "update_campaign"}
            ),
            set(),
        )

    def test_toolsets_from_next_action_bogus_declaration_falls_through(self):
        # A declaration naming no known toolset falls through to the pinned tool.
        self.assertEqual(
            _toolsets_from_attack_search_next_action(
                {"required_toolsets": ["nope"], "tool": "build_attack_graph"}
            ),
            {"map"},
        )

    def test_attack_search_result_next_action_parsing(self):
        payload = json.dumps({"next_action": {"tool": "x", "required_toolsets": ["map"]}})
        self.assertEqual(
            _attack_search_result_next_action(payload),
            {"tool": "x", "required_toolsets": ["map"]},
        )
        self.assertIsNone(_attack_search_result_next_action("not json"))
        self.assertIsNone(
            _attack_search_result_next_action(
                json.dumps({"error": "attack_search_next_action_required"})
            )
        )

    def test_update_explored_skips_guard_blocked_calls(self):
        # A guard-blocked call must not inflate progress counters; it is tallied
        # as a failed call by name instead.
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "map_action_space", "arguments": '{"path":"/audit"}'},
        }]
        results = [{
            "role": "tool",
            "tool_call_id": "call_1",
            "content": json.dumps({"error": "attack_search_next_action_required"}),
        }]

        _update_explored(tool_calls, explored, results)

        self.assertNotIn("campaign_updates", explored)
        self.assertNotIn("action_spaces_mapped", explored)
        self.assertEqual(explored["failed_tool_calls"], {"map_action_space": 1})

    def test_update_explored_skips_invalid_arguments_calls(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "read_file", "arguments": "not-json"},
        }]
        results = [{
            "role": "tool",
            "tool_call_id": "call_1",
            "content": json.dumps({"error": "invalid_tool_arguments_json"}),
        }]

        _update_explored(tool_calls, explored, results)

        self.assertEqual(explored["files_read"], set())
        self.assertEqual(explored["failed_tool_calls"], {"read_file": 1})

    def test_update_explored_counts_only_successful_outcomes(self):
        # Two read_file calls in one turn: one succeeds (recorded), one errors
        # (skipped and tallied as failed).
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [
            {"id": "call_1",
             "function": {"name": "read_file",
                          "arguments": '{"path":"/audit/src/Vault.sol"}'}},
            {"id": "call_2",
             "function": {"name": "read_file",
                          "arguments": '{"path":"/audit/src/Missing.sol"}'}},
        ]
        results = [
            {"role": "tool", "tool_call_id": "call_1", "content": "contract Vault {}"},
            {"role": "tool", "tool_call_id": "call_2", "content": "Error: file not found"},
        ]

        _update_explored(tool_calls, explored, results)

        self.assertEqual(explored["files_read"], {"/audit/src/Vault.sol"})
        self.assertEqual(explored["failed_tool_calls"], {"read_file": 1})

    def test_update_explored_failed_calls_render_in_summary(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "compose_sequence_experiment", "arguments": "{}"},
        }]
        results = [{
            "role": "tool",
            "tool_call_id": "call_1",
            "content": json.dumps({"error": "tool_failed"}),
        }]

        _update_explored(tool_calls, explored, results)

        self.assertIn(
            "Failed or blocked tool calls: compose_sequence_experiment (1)",
            _build_explored_summary(explored),
        )

    def test_update_explored_legacy_signature_counts_all(self):
        # Omitting results preserves the legacy count-everything behaviour other
        # callers/tests rely on.
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "function": {"name": "map_action_space", "arguments": '{"path":"/audit"}'},
        }]

        _update_explored(tool_calls, explored)

        self.assertEqual(explored["action_spaces_mapped"], 1)
        self.assertNotIn("failed_tool_calls", explored)

    def test_retains_encrypted_response_items_since_last_user_message(self):
        messages = [
            {"role": "user", "content": "start"},
            {
                "role": "assistant",
                "reasoning": "old display text",
                "response_items": [{"type": "reasoning", "encrypted_content": "a"}],
                "tool_calls": [{"id": "call_a", "function": {"name": "read_file"}}],
            },
            {"role": "tool", "tool_call_id": "call_a", "content": "a"},
            {
                "role": "assistant",
                "reasoning": "latest display text",
                "response_items": [{"type": "reasoning", "encrypted_content": "b"}],
                "tool_calls": [{"id": "call_b", "function": {"name": "read_file"}}],
            },
        ]

        _strip_old_reasoning(messages)

        self.assertNotIn("reasoning", messages[1])
        self.assertEqual(messages[1]["response_items"][0]["encrypted_content"], "a")
        self.assertEqual(messages[3]["reasoning"], "latest display text")
        self.assertEqual(messages[3]["response_items"][0]["encrypted_content"], "b")

    def test_strips_response_items_before_latest_user_message(self):
        messages = [
            {
                "role": "assistant",
                "response_items": [{"type": "reasoning", "encrypted_content": "old"}],
            },
            {"role": "user", "content": "new task"},
            {
                "role": "assistant",
                "response_items": [{"type": "reasoning", "encrypted_content": "new"}],
            },
        ]

        _strip_old_reasoning(messages)

        self.assertNotIn("response_items", messages[0])
        self.assertEqual(messages[2]["response_items"][0]["encrypted_content"], "new")

    def test_tool_execution_preserves_model_order_across_side_effect_barriers(self):
        tool_calls = [
            {
                "id": "write",
                "function": {"name": "write_file", "arguments": '{"path":"/workspace/a","content":"x"}'},
            },
            {
                "id": "read",
                "function": {"name": "read_file", "arguments": '{"path":"/workspace/a"}'},
            },
            {
                "id": "list",
                "function": {"name": "list_files", "arguments": '{"path":"/workspace"}'},
            },
            {
                "id": "run",
                "function": {"name": "run_command", "arguments": '{"command":"true"}'},
            },
        ]
        executed: list[str] = []

        async def fake_execute_tool(name, arguments, container, findings, display):
            executed.append(name)
            return f"result:{name}"

        with patch("reentbotpro.agent.execute_tool", side_effect=fake_execute_tool):
            results = asyncio.run(_execute_tool_calls(
                tool_calls,
                container=object(),
                findings=[],
                display=FakeDisplay(),
        ))

        self.assertEqual([r["tool_call_id"] for r in results], ["write", "read", "list", "run"])
        self.assertEqual(results[0]["content"], "result:write_file")
        self.assertLess(executed.index("write_file"), executed.index("read_file"))
        self.assertLess(executed.index("list_files"), executed.index("run_command"))

    def test_ages_old_tool_outputs_but_keeps_three_recent_tool_turns(self):
        messages = [{"role": "system", "content": "system"}]
        raw_contents = []
        for i in range(4):
            content = f"tool {i}\n" + ("x" * 3_000)
            raw_contents.append(content)
            messages.extend([
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": f"call_{i}",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command":"true"}',
                        },
                    }],
                },
                {
                    "role": "tool",
                    "tool_call_id": f"call_{i}",
                    "content": content,
                },
            ])

        aged = _age_tool_outputs(messages)
        tool_messages = [m for m in aged if m.get("role") == "tool"]

        self.assertIn("compressed", tool_messages[0]["content"])
        self.assertLess(len(tool_messages[0]["content"]), 1_200)
        self.assertEqual(
            [m["content"] for m in tool_messages[1:]],
            raw_contents[1:],
        )

    def _big_tool_turns(self, n=4):
        messages = [{"role": "system", "content": "system"}]
        for i in range(n):
            messages.extend([
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": f"call_{i}",
                        "type": "function",
                        "function": {"name": "run_command", "arguments": '{"command":"true"}'},
                    }],
                },
                {"role": "tool", "tool_call_id": f"call_{i}", "content": f"tool {i}\n" + ("x" * 3_000)},
            ])
        return messages

    def test_age_tool_outputs_is_append_only_under_budget(self):
        # CTX-1: comfortably under budget -> return the same list untouched so the
        # prompt-cache prefix stays byte-stable (no compression).
        messages = self._big_tool_turns()
        snapshot = [dict(m) for m in messages]
        aged = _age_tool_outputs(messages, max_context=10_000_000)
        self.assertIs(aged, messages)
        self.assertEqual(messages, snapshot)
        self.assertNotIn("compressed", messages[2]["content"])

    def test_age_tool_outputs_compresses_when_near_budget(self):
        # Tiny budget -> over the append-only threshold -> old tool outputs shrink.
        messages = self._big_tool_turns()
        aged = _age_tool_outputs(messages, max_context=1)
        tool_messages = [m for m in aged if m.get("role") == "tool"]
        self.assertIn("compressed", tool_messages[0]["content"])

    def test_truncate_messages_untouched_under_budget(self):
        # CTX-1: under budget, history is returned byte-identical (reasoning and
        # encrypted response_items preserved) so the cache prefix is stable.
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "[init]"},
            {
                "role": "assistant",
                "content": "thinking",
                "reasoning": "display only text",
                "response_items": [{"type": "reasoning", "encrypted_content": "abc"}],
            },
        ]
        snapshot = [dict(m) for m in messages]
        out = _truncate_messages(messages, [], {}, max_estimated_tokens=10_000_000)
        self.assertIs(out, messages)
        self.assertEqual(messages, snapshot)
        self.assertEqual(messages[2]["reasoning"], "display only text")
        self.assertEqual(
            messages[2]["response_items"],
            [{"type": "reasoning", "encrypted_content": "abc"}],
        )

    def test_context_window_errors_are_identified(self):
        self.assertTrue(_is_context_window_error(RuntimeError(
            "Responses API error: Your input exceeds the context window of this model."
        )))
        self.assertFalse(_is_context_window_error(RuntimeError("HTTP 500")))

    def test_context_recovery_retries_with_smaller_payload_once(self):
        class FakeClient:
            def __init__(self):
                self.calls: list[list[dict]] = []

            async def stream_turn(self, **kwargs):
                self.calls.append(json_round_trip(kwargs["messages"]))
                if len(self.calls) == 1:
                    raise RuntimeError(
                        "Responses API error: Your input exceeds the context window."
                    )
                return {"role": "assistant", "content": "ok"}, 1, 0, "stop"

        def json_round_trip(value):
            import json

            return json.loads(json.dumps(value))

        messages = [{"role": "system", "content": "system"}]
        for i in range(25):
            messages.append({"role": "user", "content": f"turn {i} " + ("x" * 2_000)})
            messages.append({"role": "assistant", "content": "ack"})

        client = FakeClient()
        display = FakeDisplay()

        response, _, _, _, recovered_messages = asyncio.run(
            _stream_turn_with_recovery(
                client,
                DEFAULT_MODEL,
                messages,
                display,
                findings=[],
                explored={"files_read": set(), "tools_run": set()},
                max_context=20_000,
            )
        )

        self.assertEqual(response["content"], "ok")
        self.assertEqual(len(client.calls), 2)
        self.assertLess(
            len(str(client.calls[1])),
            len(str(client.calls[0])),
        )
        self.assertEqual(recovered_messages, client.calls[1])
        self.assertTrue(any(
            "context-window error" in m.get("content", "")
            for m in recovered_messages
        ))


class DisplaySummaryTests(unittest.TestCase):
    def test_request_toolset_summary_includes_reason(self):
        self.assertEqual(
            _tool_summary(
                "request_toolset",
                {"toolset": "experiment", "reason": "reduce fuzz candidate"},
            ),
            "experiment: reduce fuzz candidate",
        )

    def test_lending_health_tool_summary_uses_position_count(self):
        self.assertEqual(
            _tool_summary(
                "estimate_lending_health",
                {"title": "Liquidation route", "positions": [{}, {}]},
            ),
            "Liquidation route (2 positions)",
        )

    def test_new_map_tool_summaries_are_compact(self):
        self.assertEqual(
            _tool_summary(
                "inventory_live_targets",
                {"title": "Vault inventory", "targets": [{}, {}, {}]},
            ),
            "Vault inventory (3 target(s))",
        )
        self.assertEqual(
            _tool_summary(
                "inventory_live_targets",
                {"title": "Vault inventory"},
            ),
            "Vault inventory (inferred targets)",
        )
        self.assertEqual(
            _tool_summary(
                "build_attack_graph",
                {"action_space": "as-001", "live_reachability": "lr-001"},
            ),
            "as-001 + lr-001",
        )
        self.assertEqual(
            _tool_summary(
                "map_live_reachability",
                {"action_space": "as-001", "profiles": [{}, {}]},
            ),
            "as-001 (2 profile(s))",
        )
        self.assertEqual(
            _tool_summary(
                "map_live_reachability",
                {"action_space": "as-001", "max_profiles": 25},
            ),
            "as-001 (auto profiles, max 25)",
        )
class AlchemyToolRegistrationTests(unittest.TestCase):
    def test_all_alchemy_tools_have_schemas(self):
        for name in _ALCHEMY_INVESTIGATION_TOOLS:
            self.assertIn(name, TOOL_BY_NAME, f"{name} missing from TOOLS schema list")

    def test_all_alchemy_tools_are_always_allowed(self):
        for name in _ALCHEMY_INVESTIGATION_TOOLS:
            self.assertIn(
                name,
                _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS,
                f"{name} should bypass the attack_search guard like other read-only tools",
            )

    def test_alchemy_tools_hidden_until_map_evidence_active(self):
        # Kept out of the default 'core' set so they don't bloat every turn's
        # tool list; they become visible once attack_search activates map/evidence.
        core_names = {
            tool["function"]["name"]
            for tool in _visible_tools({"active_toolsets": {"core"}})
        }
        for name in _ALCHEMY_INVESTIGATION_TOOLS:
            self.assertNotIn(name, core_names)

    def test_alchemy_tools_visible_after_activation(self):
        names = {
            tool["function"]["name"]
            for tool in _visible_tools(
                {"active_toolsets": {"core", "map", "experiment", "evidence"}}
            )
        }
        for name in _ALCHEMY_INVESTIGATION_TOOLS:
            self.assertIn(name, names, f"{name} should be visible once map/evidence are active")

    def test_get_contract_source_registered_and_visible(self):
        self.assertIn("get_contract_source", TOOL_BY_NAME)
        self.assertIn("get_contract_source", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS)
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        with_map = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core", "map"}})}
        self.assertNotIn("get_contract_source", core)
        self.assertIn("get_contract_source", with_map)

    def test_observed_tx_miner_registered_allowed_and_in_map(self):
        # Real-transaction miner: a real schema, always allowed past the guard
        # (read-only host-side recon, like the other Alchemy tools), and revealed
        # by the map toolset rather than bloating the default core surface.
        self.assertIn("observed_tx_miner", TOOL_BY_NAME)
        self.assertIn("observed_tx_miner", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS)
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        with_map = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core", "map"}})}
        self.assertNotIn("observed_tx_miner", core)
        self.assertIn("observed_tx_miner", with_map)

    def test_extract_state_transition_model_registered_allowed_and_in_map(self):
        # Generic state/invariant modeling: a real schema, always allowed past
        # the guard (read-only planning surface), and revealed by the map
        # toolset rather than bloating the default core surface.
        self.assertIn("extract_state_transition_model", TOOL_BY_NAME)
        self.assertIn(
            "extract_state_transition_model", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS
        )
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        with_map = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core", "map"}})}
        self.assertNotIn("extract_state_transition_model", core)
        self.assertIn("extract_state_transition_model", with_map)


class SourceSliceAgentTests(unittest.TestCase):
    def test_source_slice_registered_allowed_and_core_visible(self):
        self.assertIn("source_slice", TOOL_BY_NAME)
        self.assertIn("source_slice", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS)
        self.assertNotIn("source_slice", PARALLEL_SAFE)
        # Core surface like read_file/search_code: visible without activation.
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        self.assertIn("source_slice", core)

    def test_summarize_source_slice_preserves_skeleton(self):
        content = json.dumps({
            "status": "observed",
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "withdraw",
            "line_range": {"start": 25, "end": 27},
            "signature": "withdraw(uint256)",
            "modifiers": ["onlyOwner"],
            "body": "function withdraw(uint256 amount) external onlyOwner {\n" + "x" * 4000,
            "hints": {
                "value_flows": [{"line": 26, "text": "asset.transfer(msg.sender, amount);"}],
                "authorization_checks": [{"line": 25, "text": "external onlyOwner"}],
            },
        })

        summary = _summarize_tool_result("source_slice", content)

        # Locator + signature metadata survive (not just the first 300 chars).
        self.assertIn('"contract": "Vault"', summary)
        self.assertIn('"function": "withdraw"', summary)
        self.assertIn('"signature": "withdraw(uint256)"', summary)
        self.assertIn("line_range", summary)
        self.assertIn("onlyOwner", summary)
        self.assertIn("value_flows", summary)
        # The 4k-char body is elided, not embedded verbatim.
        self.assertNotIn("x" * 200, summary)
        self.assertLess(len(summary), len(content))

    def test_summarize_source_slice_preserves_parameters_and_returns(self):
        content = json.dumps({
            "status": "observed",
            "contract": "Vault",
            "function": "withdraw",
            "signature": "withdraw(uint256,address,address)",
            "parameters": [
                {"name": "shares", "raw": "uint256 shares"},
                {"name": "receiver", "raw": "address receiver"},
                {"name": "owner", "raw": "address owner"},
            ],
            "returns": "uint256 assets",
            "body": "x" * 4000,
        })

        summary = _summarize_tool_result("source_slice", content)

        # Parameter names/types and the return type survive compression.
        self.assertIn("uint256 shares", summary)
        self.assertIn("address receiver", summary)
        self.assertIn("uint256 assets", summary)
        self.assertNotIn("x" * 200, summary)

    def test_summarize_source_slice_tolerates_non_json(self):
        summary = _summarize_tool_result("source_slice", "not json at all")
        self.assertIn("not json at all", summary)


class StateTransitionModelAgentSummaryTests(unittest.TestCase):
    def _sample(self) -> str:
        return json.dumps({
            "state_transition_model_id": "stm-001",
            "path": "/workspace/campaign/state-transition-models/stm-001.json",
            "status": "observed",
            "focus": "auto",
            "scope": {"path": "/audit", "contract": "Vault", "files_scanned": 1},
            "summary": {
                "tracked_state": 3,
                "entrypoints": 2,
                "candidate_invariants": 4,
                "contracts": 1,
            },
            "tracked_state": [
                {"name": "balanceOf", "kind": "mapping", "evidence": ["a:1"]},
            ],
            "entrypoints": [
                {"contract": "Vault", "function": "deposit", "line": 10,
                 "candidate_preconditions": ["x" * 300]},
                {"contract": "Vault", "function": "withdraw", "line": 20},
            ],
            "candidate_invariants": [
                {"id": "inv-001", "kind": "conservation", "statement": "x" * 500},
                {"id": "inv-002", "kind": "external_call_safety",
                 "statement": "y" * 500},
            ],
            "experiment_prompts": [{"title": "t", "objective": "o" * 500}],
            "lenses": {"vault_like": True},
            "blockers": ["needs live binding"],
            "notes": ["This is planning context, not evidence."],
        })

    def test_summary_keeps_invariant_kinds_path_and_entrypoints(self):
        summary = _summarize_tool_result(
            "extract_state_transition_model", self._sample()
        )
        # Locator + status survive (not just the first 300 chars).
        self.assertIn("stm-001", summary)
        self.assertIn(
            "/workspace/campaign/state-transition-models/stm-001.json", summary
        )
        # Invariant KINDS are the load-bearing planning signal.
        self.assertIn("conservation", summary)
        self.assertIn("external_call_safety", summary)
        # Top entrypoints + present lens names survive.
        self.assertIn("deposit", summary)
        self.assertIn("vault_like", summary)
        self.assertIn("needs live binding", summary)
        # The bulky statements/prompts/preconditions are elided, not embedded.
        self.assertNotIn("x" * 200, summary)
        self.assertNotIn("y" * 200, summary)
        self.assertNotIn("o" * 200, summary)
        self.assertLess(len(summary), len(self._sample()))

    def test_summary_tolerates_non_json(self):
        summary = _summarize_tool_result(
            "extract_state_transition_model", "Error: no source"
        )
        self.assertIn("Error: no source", summary)


class SynthesizeArgsAgentTests(unittest.TestCase):
    def test_registered_allowed_and_experiment_visible(self):
        self.assertIn("synthesize_args", TOOL_BY_NAME)
        # Cognitive planning surface: always allowed past the controller guard.
        self.assertIn("synthesize_args", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS)
        # It belongs to the experiment toolset, so it is visible once activated.
        experiment = {
            tool["function"]["name"]
            for tool in _visible_tools({"active_toolsets": {"experiment"}})
        }
        self.assertIn("synthesize_args", experiment)
        # Not part of the core surface (needs experiment activation).
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        self.assertNotIn("synthesize_args", core)

    def test_summary_preserves_planning_skeleton(self):
        content = json.dumps({
            "arg_synthesis_id": "arg-001",
            "path": "/workspace/campaign/arg-synthesis/arg-001.json",
            "status": "partial",
            "contract": "Vault",
            "function": "withdrawWithSig",
            "signature": "withdrawWithSig(uint256,bytes)",
            "parameter_plan": [
                {
                    "index": 0, "name": "amount", "type": "uint256",
                    "candidates": ["DEFAULT_AMOUNT"], "setup_requirements": [],
                    "blockers": [],
                },
                {
                    "index": 1, "name": "signature", "type": "bytes",
                    "candidates": [], "setup_requirements": ["x" * 400],
                    "blockers": [{
                        "class": "signature_required",
                        "parameter": "signature",
                        "reason": "y" * 400,
                    }],
                },
            ],
            "candidate_calls": [{
                "args": ["DEFAULT_AMOUNT", "signature"],
                "confidence": 0.6,
                "setup_requirements": ["x" * 400],
                "notes": ["z" * 400],
            }],
            "blockers": [{
                "class": "signature_required",
                "parameter": "signature",
                "reason": "y" * 400,
            }],
            "notes": ["n" * 400],
        })

        summary = _summarize_tool_result("synthesize_args", content)

        # Locator + target + status survive.
        self.assertIn('"arg_synthesis_id": "arg-001"', summary)
        self.assertIn('"status": "partial"', summary)
        self.assertIn('"function": "withdrawWithSig"', summary)
        # Blocker class + counts + top call survive.
        self.assertIn("signature_required", summary)
        self.assertIn('"parameters": 2', summary)
        self.assertIn("top_call_args", summary)
        # The bulky per-parameter setup/notes prose is elided.
        self.assertNotIn("x" * 200, summary)
        self.assertNotIn("z" * 200, summary)
        self.assertLess(len(summary), len(content))

    def test_summary_tolerates_non_json(self):
        summary = _summarize_tool_result("synthesize_args", "not json at all")
        self.assertIn("not json at all", summary)


class SemanticToolSummaryTests(unittest.TestCase):
    """Compressed-context summaries for the JSON/text campaign tools.

    Each summary must keep the audit-relevant skeleton (status, readiness,
    blockers, artifact paths) rather than an arbitrary first-300-chars slice, and
    must preserve load-bearing falsy values like ``runnable: false``.
    """

    def test_run_experiment_preserves_classification_and_artifacts(self):
        content = (
            "Ran 1 test for test/Exploit.t.sol:ExploitTest\n"
            "[PASS] test_drain_profit() (gas: 12345)\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped\n"
            + ("noise output line that is not a marker\n" * 60)
            + "\n\nRecorded campaign result: res-001 (observed)\n"
            "Run classification: objective_run / objective "
            "(satisfies_experiment_run=true)\n"
            "Full log: /workspace/campaign/results/res-001.log\n"
            "Replay follow-up: /workspace/campaign/results/res-001.followup.json"
        )

        summary = _summarize_tool_result("run_experiment", content)

        # Recorded-result locator + classification survive.
        self.assertIn('"result_id": "res-001"', summary)
        self.assertIn('"status": "observed"', summary)
        self.assertIn('"run_kind": "objective_run"', summary)
        self.assertIn('"evidence_grade": "objective"', summary)
        self.assertIn('"satisfies_experiment_run": true', summary)
        self.assertIn('"exit_code": 0', summary)
        # Artifact paths survive so the agent can re-read the full log/follow-up.
        self.assertIn("/workspace/campaign/results/res-001.log", summary)
        self.assertIn("res-001.followup.json", summary)
        # Objective markers (test pass + suite result) survive.
        self.assertIn("Suite result", summary)
        self.assertIn("[PASS]", summary)
        # The bulky non-marker output is elided.
        self.assertNotIn("noise output line", summary)
        self.assertLess(len(summary), len(content))

    def test_run_experiment_marks_timeout_exit(self):
        content = (
            "Command timed out after 600s (killed)\n\n"
            "Recorded campaign result: res-002 (blocked)\n"
            "Run classification: build / blocked "
            "(satisfies_experiment_run=false)\n"
            "Full log: /workspace/campaign/results/res-002.log"
        )

        summary = _summarize_tool_result("run_experiment", content)

        self.assertIn('"status": "blocked"', summary)
        self.assertIn('"exit_code": "timeout"', summary)
        self.assertIn('"satisfies_experiment_run": false', summary)

    def test_run_experiment_tolerates_unstructured_output(self):
        summary = _summarize_tool_result("run_experiment", "totally unstructured text")
        self.assertIn("totally unstructured text", summary)

    def test_compose_sequence_experiment_preserves_readiness(self):
        content = json.dumps({
            "experiment_id": "exp-001",
            "workspace": "/workspace/experiments/exp-001",
            "steps": [{"index": 0}, {"index": 1}],
            "graph_context": {"bulk": "x" * 4000},
            "scaffold_quality": {
                "runnable": False,
                "proof_readiness": "partial",
                "executable_sequence_calls": 1,
                "partial_sequence_calls": 1,
                "blocked_sequence_calls": 0,
                "harness_limit_blockers": ["signature_required"],
                "source_blockers": [],
            },
            "unmatched_actions": [{"a": 1}],
        })

        summary = _summarize_tool_result("compose_sequence_experiment", content)

        self.assertIn('"experiment_id": "exp-001"', summary)
        self.assertIn("/workspace/experiments/exp-001", summary)
        self.assertIn('"proof_readiness": "partial"', summary)
        # runnable: false and the 0/1 counts are load-bearing and must survive.
        self.assertIn('"runnable": false', summary)
        self.assertIn('"executable_sequence_calls": 1', summary)
        self.assertIn('"blocked_sequence_calls": 0', summary)
        self.assertIn("signature_required", summary)
        self.assertIn('"steps": 2', summary)
        # The bulky graph_context is elided.
        self.assertNotIn("x" * 200, summary)
        self.assertLess(len(summary), len(content))

    def test_complete_sequence_experiment_preserves_blockers_and_build(self):
        content = json.dumps({
            "experiment_id": "exp-001",
            "workspace": "/workspace/experiments/exp-001",
            "sequence_path": "/workspace/experiments/exp-001/sequence.json",
            "mode": "objective",
            "steps": [{"index": 0}],
            "objective_probe": {"snapshots": ["x" * 4000]},
            "applied_changes": ["a", "b"],
            "remaining_blockers": ["bind target address(0)"],
            "scaffold_quality": {
                "runnable": True,
                "proof_readiness": "ready",
                "executable_sequence_calls": 1,
            },
            "build": {
                "command": "forge build",
                "exit_code": 1,
                "blockers": ["solc: undeclared identifier"],
                "log_path": "/x.log",
            },
            "validated": False,
        })

        summary = _summarize_tool_result("complete_sequence_experiment", content)

        self.assertIn('"experiment_id": "exp-001"', summary)
        self.assertIn("sequence.json", summary)
        self.assertIn('"proof_readiness": "ready"', summary)
        self.assertIn('"runnable": true', summary)
        self.assertIn('"applied_changes": 2', summary)
        self.assertIn("bind target address(0)", summary)
        self.assertIn("forge build", summary)
        self.assertIn("solc: undeclared identifier", summary)
        self.assertIn('"validated": false', summary)
        # The bulky probe snapshots are elided.
        self.assertNotIn("x" * 200, summary)

    def test_diagnose_build_preserves_first_error_and_kinds(self):
        content = json.dumps({
            "build_diagnostic_id": "bdiag-001",
            "status": "blocked",
            "build_system": "foundry",
            "suggested_next": "complete_sequence_experiment",
            "exit_code": 1,
            "log_path": "/workspace/campaign/build-diagnostics/bdiag-001.log",
            "first_error": {
                "kind": "wrong_interface",
                "message": "m" * 400,
                "file": "test/Exploit.t.sol",
                "line": 42,
            },
            "diagnostics": [
                {"kind": "wrong_interface"},
                {"kind": "undeclared_identifier"},
            ],
        })

        summary = _summarize_tool_result("diagnose_build", content)

        self.assertIn('"status": "blocked"', summary)
        self.assertIn('"build_system": "foundry"', summary)
        self.assertIn('"suggested_next": "complete_sequence_experiment"', summary)
        self.assertIn("wrong_interface", summary)
        self.assertIn("undeclared_identifier", summary)
        self.assertIn('"diagnostic_count": 2', summary)
        self.assertIn("bdiag-001.log", summary)
        # The 400-char first-error message is truncated, not embedded verbatim.
        self.assertNotIn("m" * 300, summary)

    def test_attack_search_preserves_next_action_and_dossier(self):
        content = json.dumps({
            "search_id": "search-001",
            "action": "sync",
            "next_action": {
                "branch_id": "branch-003",
                "branch_title": "Donation redeem profit",
                "status": "needs_run",
                "tool": "run_experiment",
                "source": "attack_graph",
                "dossier_path": "/workspace/campaign/branch-dossiers/branch-003.json",
                "campaign_ready": False,
                "must_follow": True,
                "required_args": {"compose_sequence_experiment": {"x": 1}},
                "instructions": "y" * 2000,
            },
            "active_branches": [
                {
                    "id": "branch-003",
                    "title": "Donation redeem profit",
                    "status": "needs_run",
                    "next_tool": "run_experiment",
                    "instructions": "z" * 2000,
                },
            ],
            "summary": {
                "branches": 4,
                "active": 3,
                "actionable": 3,
                "parked": 0,
                "terminal": 1,
                "campaign_ready": False,
            },
        })

        summary = _summarize_tool_result("attack_search", content)

        self.assertIn('"branch_id": "branch-003"', summary)
        self.assertIn('"status": "needs_run"', summary)
        self.assertIn('"tool": "run_experiment"', summary)
        self.assertIn('"campaign_ready": false', summary)
        self.assertIn('"must_follow": true', summary)
        self.assertIn('"actionable": 3', summary)
        self.assertIn('"parked": 0', summary)
        # The dossier path is the one-read recovery handle and must survive.
        self.assertIn("/workspace/campaign/branch-dossiers/branch-003.json", summary)
        self.assertIn("required_args_keys", summary)
        self.assertIn("compose_sequence_experiment", summary)
        # The bulky per-branch instructions are elided.
        self.assertNotIn("y" * 200, summary)
        self.assertNotIn("z" * 200, summary)
        self.assertLess(len(summary), len(content))

    def test_attack_search_preserves_branchless_campaign_ready_state(self):
        content = json.dumps({
            "search_id": "search-002",
            "action": "sync",
            "next_action": {
                "branch_id": None,
                "status": "campaign_ready",
                "tool": None,
                "campaign_ready": True,
                "must_follow": False,
            },
            "active_branches": [],
            "summary": {
                "branches": 2,
                "active": 0,
                "actionable": 0,
                "parked": 2,
                "terminal": 0,
                "campaign_ready": True,
            },
        })

        summary = _summarize_tool_result("attack_search", content)

        self.assertIn('"status": "campaign_ready"', summary)
        self.assertIn('"campaign_ready": true', summary)
        self.assertIn('"must_follow": false', summary)
        self.assertIn('"actionable": 0', summary)
        self.assertIn('"parked": 2', summary)

    def test_observed_tx_miner_summary_preserves_hashes_and_arg_shapes(self):
        content = json.dumps({
            "tool": "observed_tx_miner",
            "ok": True,
            "status": "observed",
            "observed_tx_miner_id": "otx-001",
            "path": "/workspace/campaign/observed-txs/otx-001.json",
            "network": "eth-mainnet",
            "target": "0x" + "b2" * 20,
            "selector": "0xa9059cbb",
            "from_block": "0x10",
            "to_block": "0x3000",
            "samples": [
                {
                    "tx_hash": "0x" + "cd" * 32,
                    "from": "0x" + "a1" * 20,
                    "selector": "0xa9059cbb",
                    "function": "transfer(address,uint256)",
                    "success": True,
                    "arg_shape": ["address", "uint256"],
                    "args": [{"type": "address", "value": "0x" + "b2" * 20}],
                    # Bulky fields that must be elided from the compressed view.
                    "transfers": [{"asset": "USDC"}] * 50,
                    "replay_hints": {"calldata": "0x" + "ab" * 2000},
                },
            ],
            "synthesize_args_hints": {"primary_selector": "0xa9059cbb", "by_selector": {"x": "y" * 4000}},
            "compose_sequence_hints": {"actors": ["0x" + "a1" * 20], "tokens": ["t"] * 200},
            "blockers": [],
        })

        summary = _summarize_tool_result("observed_tx_miner", content)

        # The artifact locator + target/selector survive for one-read recovery.
        self.assertIn('"observed_tx_miner_id": "otx-001"', summary)
        self.assertIn("/workspace/campaign/observed-txs/otx-001.json", summary)
        self.assertIn('"status": "observed"', summary)
        self.assertIn('"primary_selector": "0xa9059cbb"', summary)
        # Per-sample tx hash + decoded argument shape are the load-bearing facts.
        self.assertIn("cd" * 32, summary)
        self.assertIn('"arg_shape": ["address", "uint256"]', summary)
        # The bulky transfers/calldata/hints are elided.
        self.assertNotIn("ab" * 200, summary)
        self.assertNotIn("y" * 200, summary)
        self.assertLess(len(summary), len(content))

    def test_observed_tx_miner_summary_tolerates_non_json(self):
        summary = _summarize_tool_result("observed_tx_miner", "Error: container unavailable")
        self.assertIn("Error: container unavailable", summary)

    def test_review_summaries_preserve_verdict_and_missing_evidence(self):
        content = json.dumps({
            "review_id": "find-rev-001",
            "path": "/workspace/campaign/finding-reviews/find-rev-001.json",
            "ready": False,
            "blocking_gaps": ["missing objective evaluation", "no minimized replay"],
            "warnings": ["affected_code inferred"],
            "missing_evidence_paths": [
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "checked_evidence_paths": ["x" * 4000],
        })

        for tool in ("review_finding_evidence", "review_report_quality"):
            summary = _summarize_tool_result(tool, content)
            # ready: false is the verdict and must survive.
            self.assertIn('"ready": false', summary)
            self.assertIn("missing objective evaluation", summary)
            self.assertIn("/workspace/campaign/evaluations/eval-001.json", summary)
            # The bulky checked-path list is elided.
            self.assertNotIn("x" * 200, summary)

    def test_new_json_summaries_tolerate_non_json(self):
        for tool in (
            "compose_sequence_experiment",
            "complete_sequence_experiment",
            "diagnose_build",
            "attack_search",
            "review_finding_evidence",
            "review_report_quality",
        ):
            summary = _summarize_tool_result(tool, "Error: build container unavailable")
            self.assertIn("Error: build container unavailable", summary)


class TruncationNoteBranchTests(unittest.TestCase):
    """The compaction note must carry the current attack_search branch forward."""

    def _explored_with_branch(self) -> dict:
        return {
            "files_read": set(),
            "tools_run": set(),
            "attack_branch": {
                "branch_id": "branch-003",
                "branch_title": "Donation redeem profit",
                "status": "needs_run",
                "tool": "run_experiment",
                "source": "attack_graph",
                "dossier_path": (
                    "/workspace/campaign/branch-dossiers/branch-003.json"
                ),
            },
        }

    def test_truncation_note_includes_branch_and_dossier_when_known(self):
        note = _build_truncation_note([], self._explored_with_branch())
        content = note["content"]

        self.assertIn("Current attack_search branch: branch-003", content)
        self.assertIn("status=needs_run", content)
        self.assertIn("next tool=run_experiment", content)
        self.assertIn(
            "/workspace/campaign/branch-dossiers/branch-003.json", content
        )
        # The standard recovery instruction is still present.
        self.assertIn("read_campaign now", content)

    def test_truncation_note_emergency_keeps_branch_and_error_marker(self):
        note = _build_truncation_note(
            [], self._explored_with_branch(), emergency=True
        )
        content = note["content"]

        self.assertIn("context-window error", content)
        self.assertIn("Current attack_search branch: branch-003", content)
        self.assertIn(
            "/workspace/campaign/branch-dossiers/branch-003.json", content
        )

    def test_truncation_note_without_branch_falls_back(self):
        note = _build_truncation_note([], {"files_read": set(), "tools_run": set()})
        content = note["content"]

        self.assertNotIn("Current attack_search branch", content)
        self.assertIn("read_campaign now", content)

    def test_update_explored_records_attack_search_branch(self):
        explored = {"files_read": set(), "tools_run": set()}
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "attack_search", "arguments": '{"action":"sync"}'},
        }]
        results = [{
            "tool_call_id": "call_1",
            "content": json.dumps({
                "search_id": "search-001",
                "next_action": {
                    "branch_id": "branch-003",
                    "branch_title": "Donation redeem profit",
                    "status": "needs_run",
                    "tool": "run_experiment",
                    "dossier_path": (
                        "/workspace/campaign/branch-dossiers/branch-003.json"
                    ),
                },
            }),
        }]

        _update_explored(tool_calls, explored, results)

        branch = explored["attack_branch"]
        self.assertEqual(branch["branch_id"], "branch-003")
        self.assertEqual(
            branch["dossier_path"],
            "/workspace/campaign/branch-dossiers/branch-003.json",
        )
        # The recorded branch flows straight into the truncation note.
        note = _build_truncation_note([], explored)["content"]
        self.assertIn("branch-003", note)
        self.assertIn(
            "/workspace/campaign/branch-dossiers/branch-003.json", note
        )

    def test_update_explored_clears_stale_branch_when_campaign_is_ready(self):
        # A fresh branchless readiness result must not leave a stale dossier
        # locator in truncation/recovery state.
        explored = {
            "files_read": set(),
            "tools_run": set(),
            "attack_branch": {"branch_id": "branch-003"},
        }
        tool_calls = [{
            "id": "call_1",
            "function": {"name": "attack_search", "arguments": '{"action":"sync"}'},
        }]
        results = [{
            "tool_call_id": "call_1",
            "content": json.dumps({
                "search_id": "search-001",
                "next_action": {
                    "branch_id": None,
                    "status": "campaign_ready",
                    "campaign_ready": True,
                    "must_follow": False,
                },
            }),
        }]

        _update_explored(tool_calls, explored, results)

        self.assertNotIn("attack_branch", explored)


class DiagnoseBuildAgentTests(unittest.TestCase):
    def test_registered_allowed_and_experiment_visible(self):
        self.assertIn("diagnose_build", TOOL_BY_NAME)
        # Diagnostic/cognitive surface: always allowed past the controller guard.
        self.assertIn("diagnose_build", _ATTACK_SEARCH_ALWAYS_ALLOWED_TOOLS)
        # It belongs to the experiment toolset, so it is visible once activated.
        experiment = {
            tool["function"]["name"]
            for tool in _visible_tools({"active_toolsets": {"experiment"}})
        }
        self.assertIn("diagnose_build", experiment)
        # Not part of the core surface (needs experiment activation).
        core = {tool["function"]["name"] for tool in _visible_tools({"active_toolsets": {"core"}})}
        self.assertNotIn("diagnose_build", core)

    def test_campaign_tracking_records_build_diagnostics(self):
        counters, sections = _CAMPAIGN_TOOL_TRACKING["diagnose_build"]
        self.assertIn("build_diagnostics", counters)
        self.assertIn("result", sections)
        # The counter has a human-readable summary label.
        labels = dict(_CAMPAIGN_SUMMARY_COUNTERS)
        self.assertIn("build_diagnostics", labels)

    def test_campaign_tracking_records_experiment_repairs(self):
        counters, sections = _CAMPAIGN_TOOL_TRACKING["repair_experiment"]
        self.assertIn("experiment_repairs", counters)
        # repair_experiment touches the experiment entry and records a result.
        self.assertIn("experiment", sections)
        self.assertIn("result", sections)
        labels = dict(_CAMPAIGN_SUMMARY_COUNTERS)
        self.assertIn("experiment_repairs", labels)


class ControllerPermissivenessHelperTests(unittest.TestCase):
    def test_local_experiment_target_accepts_only_explicit_normalized_bindings(self):
        allowed = (
            {
                "command": "forge test -vvv",
                "working_dir": "/workspace/experiments/exp-001/",
            },
            {
                "command": "forge test -vvv",
                "working_dir": (
                    "/workspace/experiments/exp-old/../exp-normalized"
                ),
            },
            {
                "command": (
                    "FOUNDRY_PROFILE=ci forge test --root "
                    "/workspace/experiments/exp-001 -vvv"
                ),
            },
            {
                "command": (
                    "forge build --root=/workspace/experiments/exp-001"
                ),
            },
            {
                "command": (
                    "forge test --out "
                    "/workspace/experiments/exp-001/out"
                ),
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": (
                    "forge coverage --report lcov --report-file "
                    "/workspace/campaign/static-analysis/exp-001.lcov"
                ),
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": (
                    "forge test --debug --dump "
                    "/workspace/experiments/exp-001/debug.json"
                ),
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": (
                    "cd /workspace/experiments/exp-001 && "
                    "FOUNDRY_PROFILE=ci forge test -vvv"
                ),
            },
        )
        for arguments in allowed:
            self.assertTrue(
                _run_experiment_targets_local_workspace(arguments),
                f"expected local experiment binding: {arguments!r}",
            )

    def test_local_experiment_target_rejects_mentions_traversal_and_chains(self):
        blocked = (
            {"command": "echo /workspace/experiments/exp-001"},
            {"command": "forge test # --root /workspace/experiments/exp-001"},
            {
                "command": (
                    "forge test --match-path "
                    "/workspace/experiments/exp-001/test/PoC.t.sol"
                ),
            },
            {
                "command": "forge test",
                "working_dir": "/workspace/experiments",
            },
            {
                "command": "forge test",
                "working_dir": "/workspace/experiments-evil/exp-001",
            },
            {
                "command": "forge test",
                "working_dir": "/workspace/experiments/../../audit",
            },
            {
                "command": (
                    "forge test --root /workspace/experiments/exp-001 "
                    "&& rm -rf /audit"
                ),
            },
            {
                "command": (
                    "cd /workspace/experiments/exp-001 && forge test "
                    "&& rm -rf /audit"
                ),
            },
            {
                "command": "rm -rf /audit",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": (
                    "forge test --root /workspace/experiments/exp-001 "
                    "--root /audit"
                ),
            },
            {
                "command": "FOUNDRY_OUT=/audit/src forge test",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "PATH=/tmp forge test",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --out /audit/src",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --cache-path ../../audit/src",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --config-path /audit/foundry.toml",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --ffi",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": (
                    "forge coverage --report lcov --report-file "
                    "/audit/overwrite.sol"
                ),
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --debug --dump /audit/debug.json",
                "working_dir": "/workspace/experiments/exp-001",
            },
            {
                "command": "forge test --use /audit/bin/evil-solc",
                "working_dir": "/workspace/experiments/exp-001",
            },
        )
        for arguments in blocked:
            self.assertFalse(
                _run_experiment_targets_local_workspace(arguments),
                f"expected guarded experiment command: {arguments!r}",
            )

    def test_run_command_diagnostic_allowed_examples(self):
        for command in (
            "forge build",
            "forge build --sizes",
            "FOUNDRY_PROFILE=ci forge build",
            "forge config",
            "forge inspect Vault storageLayout",
            "forge test --list",
            "forge test --list --match-contract Vault",
            (
                "forge build --out "
                "/workspace/campaign/build-diagnostics/scratch/forge-out"
            ),
            (
                "forge build -o/workspace/campaign/build-diagnostics/"
                "scratch/forge-out-short"
            ),
            "slither .",
            "slither src --exclude naming-convention",
            "slither . > /workspace/campaign/static-analysis/slither.txt",
            "slither . --json /workspace/campaign/static-analysis/slither.json",
            "forge build > /output/diagnostics/forge-build.log",
            "slither . --sarif=-",
        ):
            self.assertTrue(
                _run_command_is_diagnostic({"command": command}),
                f"expected diagnostic: {command!r}",
            )

    def test_run_command_non_diagnostic_blocked_examples(self):
        for command in (
            "forge test",
            "forge test --match-contract Vault -vvv",
            "forge install foundry-rs/forge-std",
            "npm install",
            "cast send 0xabc 'foo()'",
            "forge build && rm -rf /audit",
            "forge build; echo done",
            "forge build # diagnostic-looking shell comment",
            "forge build | tee out.txt",
            "echo $(whoami)",
            "FOUNDRY_OUT=/audit/src forge build",
            "PATH=/tmp forge build",
            "forge build --out /audit/src",
            "forge build -o/audit/src",
            "forge build --cache-path ../../audit/src",
            "forge build --contracts /audit/src",
            "forge config --config-path /audit/foundry.toml",
            "forge build --broadcast /audit/broadcast",
            "forge build --ffi",
            "forge build --use /audit/bin/evil-solc",
            "forge build --config-path /workspace/experiments/unsafe.toml",
            "forge build > /workspace/campaign/attack-search/current.json",
            "slither . --json /workspace/campaign/state.json",
            "slither . --json /workspace/campaign/results/res-001.log",
            "forge build > /output/report.md",
            "slither . > /audit/out.txt",
            "slither . --json /audit/slither.json",
            "slither . --sarif=/audit/slither.sarif",
            "slither . --compile-custom-build 'touch /audit/owned'",
            "slither . --compile-custom 'touch /audit/owned'",
            "slither . --generate-patches",
            "slither . --triage-mode",
            "slither . --solc /tmp/evil-solc",
            "slither . --config-file /workspace/experiments/unsafe.json",
            "slither . --etherscan-apikey super-secret",
            "slither . --foundry-out=/audit/out",
            "rm -rf /audit",
        ):
            self.assertFalse(
                _run_command_is_diagnostic({"command": command}),
                f"expected non-diagnostic: {command!r}",
            )

    def test_run_command_diagnostic_handles_bad_input(self):
        self.assertFalse(_run_command_is_diagnostic(None))
        self.assertFalse(_run_command_is_diagnostic({}))
        self.assertFalse(_run_command_is_diagnostic({"command": ""}))
        self.assertFalse(_run_command_is_diagnostic({"command": 123}))

    def test_tool_result_failed_detects_failure_markers(self):
        self.assertTrue(_tool_result_failed("Error: 'title' is required"))
        for code in (
            "invalid_tool_arguments_json",
            "invalid_tool_arguments_shape",
            "attack_search_next_action_required",
            "tool_failed",
        ):
            self.assertTrue(
                _tool_result_failed(json.dumps({"error": code})),
                f"expected failure for error code {code!r}",
            )

    def test_tool_result_failed_treats_useful_output_as_success(self):
        self.assertFalse(_tool_result_failed("ran read_file"))
        self.assertFalse(_tool_result_failed(""))
        self.assertFalse(
            _tool_result_failed(json.dumps({"status": "observed", "path": "/audit/x.sol"}))
        )
        # A nested per-probe error inside an otherwise-successful payload is not a
        # top-level failure (e.g. snapshot_state with one failed probe).
        self.assertFalse(
            _tool_result_failed(
                json.dumps({"snapshot_id": "snap-001", "probes": [{"error": "rpc down"}]})
            )
        )

    def test_attack_search_expected_tools_prefers_structured_fields(self):
        # Free text names map_protocol_graph, but the structured list pins
        # synthesize_args — the structured field wins, with no regex fallback.
        resolved = _attack_search_expected_tools({
            "tool": "run map_protocol_graph somehow",
            "expected_tools": ["synthesize_args"],
        })
        self.assertEqual(resolved, {"synthesize_args"})

    def test_attack_search_expected_tools_reads_pipeline(self):
        resolved = _attack_search_expected_tools({
            "tool": "anything",
            "pipeline": [
                {"tool": "synthesize_args"},
                {"tool": "complete_sequence_experiment"},
            ],
        })
        self.assertEqual(resolved, {"synthesize_args", "complete_sequence_experiment"})

    def test_attack_search_expected_tools_falls_back_to_text_scan(self):
        self.assertEqual(
            _attack_search_expected_tools({"tool": "map_protocol_graph"}),
            {"map_protocol_graph"},
        )
        # Unknown structured names do not resolve, so the text scan still applies.
        self.assertEqual(
            _attack_search_expected_tools({
                "tool": "map_protocol_graph",
                "expected_tools": ["not_a_real_tool"],
            }),
            {"map_protocol_graph"},
        )

    def test_visible_tool_overhead_is_below_full_tool_overhead(self):
        core_tools = tools_for_toolsets({"core"})
        self.assertLess(_tools_token_overhead(core_tools), _tools_token_overhead())
        # The argument-less helper matches the conservative module constant.
        self.assertEqual(_tools_token_overhead(), _TOOLS_TOKEN_OVERHEAD)

    def test_calculate_max_context_default_unchanged_and_tools_aware(self):
        full = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        # Default reserves the full tool overhead (byte-stable public budget).
        self.assertEqual(full, calculate_max_context(DEFAULT_CONTEXT_WINDOW, tools=None))
        # A smaller visible toolset reserves less, leaving more room for history.
        core_only = calculate_max_context(
            DEFAULT_CONTEXT_WINDOW, tools=tools_for_toolsets({"core"})
        )
        self.assertGreater(core_only, full)


class TurnHistoryBudgetTests(unittest.TestCase):
    """_turn_history_budget separates the auto budget from an explicit user cap."""

    def _budget(self, max_context, *, toolsets, context_window, user_cap):
        return _turn_history_budget(
            max_context,
            context_window=context_window,
            visible_tools=tools_for_toolsets(toolsets),
            max_context_is_user_cap=user_cap,
        )

    def test_no_user_cap_reclaims_above_static_full_tool_budget(self):
        # B: without a user cap the per-turn budget is the visible-tool budget,
        # which is LARGER than the conservative full-tool max_context — the
        # reclaimed headroom the old min() clamp used to throw away.
        full = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        budget = self._budget(
            full, toolsets={"core"}, context_window=DEFAULT_CONTEXT_WINDOW,
            user_cap=False,
        )
        self.assertEqual(
            budget,
            calculate_max_context(
                DEFAULT_CONTEXT_WINDOW, tools=tools_for_toolsets({"core"})
            ),
        )
        self.assertGreater(budget, full)

    def test_user_cap_below_visible_budget_binds(self):
        # C: an explicit hard cap below the visible-tool budget is respected.
        budget = self._budget(
            50_000, toolsets={"core"}, context_window=DEFAULT_CONTEXT_WINDOW,
            user_cap=True,
        )
        self.assertEqual(budget, 50_000)

    def test_user_cap_never_inflates_past_visible_budget(self):
        # A cap larger than the window can hold is clamped down to the visible
        # budget (a cap is a ceiling, never a floor).
        visible = calculate_max_context(
            DEFAULT_CONTEXT_WINDOW, tools=tools_for_toolsets({"core"})
        )
        budget = self._budget(
            visible + 500_000, toolsets={"core"},
            context_window=DEFAULT_CONTEXT_WINDOW, user_cap=True,
        )
        self.assertEqual(budget, visible)

    def test_budget_shrinks_as_visible_toolsets_expand(self):
        # D: more visible tools -> more schema overhead -> smaller history budget.
        full = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        core = self._budget(
            full, toolsets={"core"}, context_window=DEFAULT_CONTEXT_WINDOW,
            user_cap=False,
        )
        core_map = self._budget(
            full, toolsets={"core", "map"},
            context_window=DEFAULT_CONTEXT_WINDOW, user_cap=False,
        )
        everything = self._budget(
            full, toolsets={"all"}, context_window=DEFAULT_CONTEXT_WINDOW,
            user_cap=False,
        )
        self.assertGreater(core, core_map)
        self.assertGreater(core_map, everything)

    def test_missing_context_window_falls_back_to_static_max_context(self):
        # Requirement 4 fallback: no window known -> static max_context unchanged,
        # regardless of the visible toolset or cap flag.
        for user_cap in (False, True):
            self.assertEqual(
                self._budget(
                    123_456, toolsets={"core"}, context_window=None,
                    user_cap=user_cap,
                ),
                123_456,
            )


class ChatHistoryBudgetTests(unittest.TestCase):
    def _capture_chat_budget(self, *, max_context, user_cap):
        captured: dict[str, object] = {}
        explored = {
            "files_read": set(),
            "tools_run": set(),
            "active_toolsets": {"core"},
        }

        async def fake_stream(client, model, messages, display, **kwargs):
            captured["max_context"] = kwargs["max_context"]
            captured["tools"] = kwargs["tools"]
            return (
                {"role": "assistant", "content": "done"},
                0,
                0,
                "stop",
                messages,
            )

        with (
            patch("builtins.input", side_effect=["summarize", "exit"]),
            patch(
                "reentbotpro.agent._stream_turn_with_recovery",
                side_effect=fake_stream,
            ),
        ):
            asyncio.run(chat_loop(
                client=object(),
                model=DEFAULT_MODEL,
                messages=[{"role": "system", "content": "system"}],
                container=FakeContainer(),
                display=MagicMock(),
                findings=[],
                explored=explored,
                max_time_seconds=5,
                max_context=max_context,
                context_window=DEFAULT_CONTEXT_WINDOW,
                max_context_is_user_cap=user_cap,
            ))
        return captured

    def test_chat_reserves_model_max_output_and_visible_schemas(self):
        audit_budget = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        captured = self._capture_chat_budget(
            max_context=audit_budget,
            user_cap=False,
        )
        expected = calculate_max_context(
            DEFAULT_CONTEXT_WINDOW,
            output_reserve=get_model_max_output_tokens(DEFAULT_MODEL),
            tools=captured["tools"],
        )
        self.assertEqual(captured["max_context"], expected)
        self.assertLess(captured["max_context"], audit_budget)

    def test_chat_preserves_explicit_user_context_cap(self):
        captured = self._capture_chat_budget(max_context=40_000, user_cap=True)
        self.assertLessEqual(captured["max_context"], 40_000)


class RunAuditBudgetTests(unittest.TestCase):
    """run_audit threads the visible-tool budget into each turn's truncation."""

    def _capture_first_turn(self, *, context_window, max_context, user_cap):
        captured: dict[str, object] = {}

        async def fake_stream(client, model, messages, display, **kwargs):
            captured["max_context"] = kwargs["max_context"]
            captured["tools"] = kwargs["tools"]
            # Break the loop deterministically after the first turn is sized.
            raise RuntimeError("stop-after-capture")

        with patch(
            "reentbotpro.agent._stream_turn_with_recovery",
            side_effect=fake_stream,
        ):
            asyncio.run(run_audit(
                client=object(),
                model=DEFAULT_MODEL,
                system_prompt="system",
                container=FakeContainer(),
                display=FakeDisplay(),
                max_time_seconds=3600,
                max_context=max_context,
                context_window=context_window,
                max_context_is_user_cap=user_cap,
            ))
        return captured

    def _default_visible_budget(self, context_window):
        explored = {"active_toolsets": set(expand_toolsets(DEFAULT_TOOLSETS))}
        return calculate_max_context(
            context_window, tools=_visible_tools(explored)
        )

    def test_reclaims_visible_budget_without_user_cap(self):
        # B (end to end): with a context_window and no user cap, the first turn's
        # history budget is the visible-tool budget, exceeding the full-tool
        # max_context the CLI used to pass unconditionally.
        full = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        captured = self._capture_first_turn(
            context_window=DEFAULT_CONTEXT_WINDOW, max_context=full,
            user_cap=False,
        )
        self.assertEqual(
            captured["max_context"],
            self._default_visible_budget(DEFAULT_CONTEXT_WINDOW),
        )
        self.assertGreater(captured["max_context"], full)
        # The same visible subset is the tool set placed on the wire.
        self.assertEqual(
            {t["function"]["name"] for t in captured["tools"]},
            {
                t["function"]["name"]
                for t in _visible_tools(
                    {"active_toolsets": set(expand_toolsets(DEFAULT_TOOLSETS))}
                )
            },
        )

    def test_respects_explicit_user_cap(self):
        # C (end to end): an explicit cap below the visible budget binds even
        # though the window could hold more.
        captured = self._capture_first_turn(
            context_window=DEFAULT_CONTEXT_WINDOW, max_context=50_000,
            user_cap=True,
        )
        self.assertEqual(captured["max_context"], 50_000)

    def test_without_context_window_uses_static_max_context(self):
        # Fallback: legacy callers that pass no context_window keep the static
        # max_context budget unchanged.
        full = calculate_max_context(DEFAULT_CONTEXT_WINDOW)
        captured = self._capture_first_turn(
            context_window=None, max_context=full, user_cap=False,
        )
        self.assertEqual(captured["max_context"], full)


class EarlyStopNudgeTests(unittest.TestCase):
    """The no-tool-call early-stop nudge must steer toward the modern harness:
    diagnose_build/repair_experiment before manual dependency loops, and a
    source_slice-based manual-review fallback that routes back through the
    controller — while still refusing to let the agent stop after shallow,
    no-tool analysis."""

    def test_minimum_audit_turn_floor_remains_ten_thousand(self):
        self.assertEqual(_MIN_AUDIT_TURNS, 10000)

    def _capture_early_stop_nudge(self) -> str:
        captured: dict[str, object] = {}
        calls = {"n": 0}

        async def fake_stream(client, model, messages, display, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                # A no-tool-call response before the minimum-turn floor is the
                # premature stop the early-stop nudge is meant to intercept.
                return (
                    {"role": "assistant", "content": "I think I'm done."},
                    0,
                    0,
                    "stop",
                    messages,
                )
            # On the next turn the nudge has been injected; capture and bail.
            captured["messages"] = list(messages)
            raise RuntimeError("stop-after-capture")

        with patch(
            "reentbotpro.agent._stream_turn_with_recovery",
            side_effect=fake_stream,
        ):
            asyncio.run(run_audit(
                client=object(),
                model=DEFAULT_MODEL,
                system_prompt="system",
                container=FakeContainer(),
                display=FakeDisplay(),
                max_time_seconds=3600,
            ))

        nudges = [
            m["content"]
            for m in captured["messages"]
            if m.get("role") == "user" and "do not stop" in m.get("content", "")
        ]
        self.assertEqual(
            len(nudges), 1, "expected exactly one early-stop nudge to be injected"
        )
        return nudges[0]

    def test_nudge_directs_to_diagnose_build_before_manual_repair(self):
        nudge = self._capture_early_stop_nudge()
        self.assertIn("diagnose_build", nudge)
        self.assertIn("before any manual dependency repair", nudge)
        self.assertLess(
            nudge.index("diagnose_build"),
            nudge.index("manual dependency repair"),
            "diagnose_build should be recommended before manual dependency repair",
        )

    def test_prelimit_voluntary_stop_is_rejected(self):
        nudge = self._capture_early_stop_nudge()
        self.assertIn("do not stop", nudge)
        self.assertGreater(_MIN_AUDIT_TURNS, 1)

    def test_final_readiness_nudge_uses_authoritative_controller_rule(self):
        self.assertIn(
            "Any nonterminal, nonparked branch",
            _FINAL_READINESS_NUDGE,
        )
        self.assertIn("parked integrity limit", _FINAL_READINESS_NUDGE)
        self.assertIn("branchless campaign_ready", _FINAL_READINESS_NUDGE)
        self.assertIn("regardless of its score", _FINAL_READINESS_NUDGE)
        self.assertNotIn("high/critical", _FINAL_READINESS_NUDGE)

    def test_nudge_routes_generated_experiment_failures_to_repair_experiment(self):
        nudge = self._capture_early_stop_nudge()
        self.assertIn("generated experiment workspace", nudge)
        self.assertIn("repair_experiment", nudge)

    def test_nudge_recommends_source_slice_review_through_controller(self):
        nudge = self._capture_early_stop_nudge()
        self.assertIn("manual source review", nudge)
        self.assertIn("source_slice", nudge)
        # The build-blocked fallback continues through the controller, not a stop.
        self.assertIn("attack_search", nudge)

    def test_nudge_preserves_anti_stall_and_drops_legacy_install_loops(self):
        nudge = self._capture_early_stop_nudge()
        # Still strongly discourages stopping after shallow / no-tool analysis.
        self.assertIn("do not stop", nudge)
        # It must not primarily push manual forge install / clone-missing-libs
        # loops ahead of diagnosis.
        self.assertNotIn("forge install", nudge)
        self.assertNotIn("clone missing libraries", nudge)

    def test_nudge_offers_generic_invariant_branch_workflow(self):
        nudge = self._capture_early_stop_nudge()
        self.assertIn("extract_state_transition_model", nudge)
        self.assertIn("build_attack_graph", nudge)


if __name__ == "__main__":
    unittest.main()
