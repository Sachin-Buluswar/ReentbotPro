import json
import os
import unittest
from unittest import mock

from reentbotpro.tools import (
    _CAMPAIGN_ID_PREFIXES,
    _CAMPAIGN_STATE_PATH,
    _ast_source_unit_to_parsed_file,
    _collect_line_hints,
    _coverage_attention,
    _line_starts,
    _structural_action_affordances,
    _attack_search,
    _attack_search_branch_dossier,
    _attack_graph_candidate_score,
    _reachability_high_trust,
    _authority_probe_command,
    _build_campaign_brief,
    _check_test_output,
    _classify_build_output,
    _compare_snapshots,
    _complete_sequence_experiment,
    _compose_invariant_harness,
    _compose_sequence_experiment,
    _create_experiment,
    _diagnose_build,
    _infer_build_system,
    _load_campaign_state,
    _normalize_force_route_kinds,
    _normalize_force_callback_kinds,
    _objective_clearly_non_economic,
    _objective_evaluation_alt_path_active,
    _parse_forge_test_summary,
    _parse_parameters,
    _ast_parameters,
    _action_grammar_quality,
    _action_uses_attacker_contract,
    _callback_kind_for_token,
    _step_declares_callback_or_reentry_intent,
    _sequence_call_is_executable,
    _sequence_call_value_expression,
    _sequence_calldata_is_supported,
    _sequence_callback_attacker_configure,
    _sequence_callback_attacker_contract,
    _sequence_callback_attacker_plan,
    _sequence_executable_step_block,
    _sequence_experiment_contract,
    _sequence_materialized_steps,
    _sequence_objective_probe_fragments,
    _sequence_objective_probe_plan,
    _sequence_step_readiness,
    _sequence_value_expression_is_supported,
    _sequence_route_composition_plan,
    _evaluate_objective,
    _estimate_amm_economics,
    _estimate_flash_loan,
    _estimate_lending_health,
    _extract_call_sequence,
    _extract_state_transition_model,
    _state_transition_model_attack_candidates,
    _source_only_attack_graph_candidates,
    _source_only_candidate_score,
    _source_only_candidate_priority,
    _source_only_allows_critical,
    _build_attack_graph,
    _inventory_live_targets,
    _inspect_scope,
    _map_action_space,
    _map_live_reachability,
    _map_protocol_graph,
    _mutate_hypothesis,
    _plan_add_branch,
    _plan_attack_campaign,
    _plan_branch_from_action_gap,
    _plan_branch_from_protocol_hotspot,
    _fork_workbench_adapter,
    _generic_state_transition_workbench_adapter,
    _infer_fork_workbench_mechanism,
    _prepare_fork_exploit_workbench,
    _read_campaign,
    _record_fork_context,
    _repair_experiment,
    _review_attack_surface_coverage,
    _review_campaign_progress,
    _review_finding_evidence,
    _review_report_quality,
    _request_toolset,
    _run_campaign_fuzz,
    _run_experiment,
    _run_sequence_minimization,
    _snapshot_state,
    _source_slice,
    _submit_finding_checked,
    _submit_finding,
    _summarize_trace,
    _synthesize_args,
    _classify_action_reachability,
    _update_campaign,
    _write_file,
    execute_tool,
    tool_names_for_toolsets,
)
from reentbotpro import host_tools as host_tools_mod
from reentbotpro.tools import (
    _redact_alchemy,
    reset_alchemy_runtime,
    reset_etherscan_runtime,
    set_alchemy_runtime,
    set_etherscan_runtime,
)
from reentbotpro.tools import (
    _CHAIN_REGISTRY_PATH,
    _build_chain_registry,
    _chain_hint_from_path,
    _chain_hints_for_address_or_contract,
    _chain_hints_from_json_obj,
    _chain_hints_from_text,
    _collect_chain_hints,
    _command_needs_rpc,
    _experiment_readme,
    _foundry_template_contract,
    _latest_chain_registry,
    _network_env_token,
    _next_chain_registry_id,
    _parse_chain_ref,
    _resolve_experiment_rpc_endpoints,
    _resolve_tool_rpc_endpoint,
    _resolve_tool_rpc_endpoints_for_chains,
    _rpc_endpoint_summary,
    _sequence_target_chain_refs,
    _write_chain_registry,
)
from reentbotpro.config import ResolvedRpcEndpoint


class FakeContainer:
    def __init__(self):
        self.writes: list[tuple[str, str]] = []
        self.files: dict[str, str] = {}
        self.exec_calls: list[tuple[str, str, int]] = []
        self.exec_envs: list[dict[str, str] | None] = []
        self.exec_result: tuple[int, str] = (0, "")
        self.exec_results: list[tuple[int, str]] = []

    async def write_file(self, path: str, content: str) -> None:
        self.writes.append((path, content))
        self.files[path] = content

    async def read_file(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    async def exec(
        self,
        command: str,
        working_dir: str = "/audit",
        timeout: int = 120,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        self.exec_calls.append((command, working_dir, timeout))
        self.exec_envs.append(extra_env)
        if self.exec_results:
            return self.exec_results.pop(0)
        return self.exec_result


def _exploitability_fields(**overrides):
    fields = {
        "preconditions": [
            (
                "The unprivileged attacker can call the deployed public entrypoints "
                "with attacker-owned funds; no victim-specific approval or "
                "privileged action is required."
            )
        ],
        "precondition_provenance": [
            {
                "precondition": "Attacker-controlled public call path with attacker funds",
                "provenance": "attacker_controlled",
                "evidence": (
                    "Source review and fork replay use only attacker-signed "
                    "transactions against the deployed target entrypoints."
                ),
            }
        ],
        "production_reachability": (
            "The target address is bound in fork context, and the replay calls "
            "the same public entrypoints that are exposed by the deployed contract."
        ),
        "funds_at_risk": (
            "eval-001 records nonzero attacker profit against protocol liquidity "
            "reachable through the deployed target."
        ),
        "negative_controls": [
            "A baseline replay without the exploit setup records no attacker profit."
        ],
    }
    fields.update(overrides)
    return fields


class CampaignIdTests(unittest.TestCase):
    def test_campaign_id_prefixes_are_unique(self):
        prefixes = list(_CAMPAIGN_ID_PREFIXES.values())

        self.assertEqual(len(prefixes), len(set(prefixes)))
        self.assertEqual(_CAMPAIGN_ID_PREFIXES["invariant"], "inv")
        self.assertEqual(_CAMPAIGN_ID_PREFIXES["live_inventory"], "linv")


class WriteFileToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_write_file_rejects_similar_prefixes(self):
        container = FakeContainer()

        result = await _write_file(container, {
            "path": "/workspaceevil/out.txt",
            "content": "x",
        })

        self.assertIn("writes only allowed", result)
        self.assertEqual(container.writes, [])

    async def test_write_file_rejects_allowed_root_as_destination(self):
        container = FakeContainer()

        result = await _write_file(container, {
            "path": "/workspace",
            "content": "x",
        })

        self.assertIn("writes only allowed", result)
        self.assertEqual(container.writes, [])

    async def test_write_file_normalizes_before_validating(self):
        container = FakeContainer()

        result = await _write_file(container, {
            "path": "/audit/../output/report.md",
            "content": "ok",
        })

        self.assertEqual(result, "Written 2 bytes to /output/report.md")
        self.assertEqual(container.writes, [("/output/report.md", "ok")])


class ToolsetRequestTests(unittest.IsolatedAsyncioTestCase):
    def test_request_toolset_accepts_known_toolset(self):
        result = json.loads(_request_toolset({
            "toolset": "experiment",
            "reason": "compose a replay from a fuzz candidate",
        }))

        self.assertEqual(result["requested_toolset"], "experiment")
        self.assertEqual(result["activated_toolsets"], ["experiment"])
        self.assertIn("prepare_fork_exploit_workbench", result["available_tools"])
        self.assertIn("compose_sequence_experiment", result["available_tools"])
        self.assertIn("run_experiment", result["available_tools"])
        self.assertIn("request_toolset", result["available_tools"])
        self.assertIn("available on the next turn", result["message"])

    def test_request_toolset_rejects_unknown_toolset(self):
        result = json.loads(_request_toolset({
            "toolset": "taxonomy",
            "reason": "not a real toolset",
        }))

        self.assertIn("error", result)
        self.assertEqual(result["requested_toolset"], "taxonomy")

    async def test_execute_tool_dispatches_specialized_tool_even_when_not_core(self):
        container = FakeContainer()

        result = await execute_tool(
            "estimate_lending_health",
            {
                "title": "Borrower health",
                "positions": [{
                    "collateral_amount_decimal": "100",
                    "collateral_decimals": 6,
                    "collateral_price_usd": "1",
                    "liquidation_threshold_bps": 8000,
                    "debt_amount_decimal": "50",
                    "debt_decimals": 6,
                    "debt_price_usd": "1",
                }],
            },
            container,
            [],
        )

        payload = json.loads(result)
        self.assertEqual(payload["economics_id"], "econ-001")
        self.assertEqual(payload["summary"]["positions"], 1)


class ScopeInspectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_inspect_scope_ranks_profiles_and_records_manifest(self):
        container = FakeContainer()
        container.files["/audit/foundry.toml"] = """
# Vault (0x1111111111111111111111111111111111111111)
[profile.contract_Vault_abcd]
src = "src/Vault_abcd"
out = "out/contract_Vault_abcd"
cache_path = "cache/contract_Vault_abcd"
solc = "0.8.20"

# TransparentUpgradeableProxy (0x2222222222222222222222222222222222222222)
[profile.contract_TransparentUpgradeableProxy_dead]
src = "src/TransparentUpgradeableProxy_dead"
out = "out/contract_TransparentUpgradeableProxy_dead"
cache_path = "cache/contract_TransparentUpgradeableProxy_dead"
solc = "0.8.20"
"""
        container.exec_results = [
            (0, ""),  # /audit/src exists for _default_source_scan_roots
            (
                0,
                "/audit/src/Vault_abcd/src/Vault.sol\n"
                "/audit/src/TransparentUpgradeableProxy_dead/Proxy.sol\n",
            ),
            (0, "/audit/findings\n/audit/out\n/audit/rewards_poc\n"),
        ]

        result = json.loads(await _inspect_scope(container, {}))

        self.assertEqual(result["source_roots_for_default_scans"], ["/audit/src"])
        self.assertEqual(result["foundry_profiles"], 2)
        self.assertEqual(result["ranked_profiles"][0]["contract"], "Vault")
        self.assertEqual(
            result["ranked_profiles"][0]["address"],
            "0x1111111111111111111111111111111111111111",
        )
        self.assertIn("vault/accounting", result["ranked_profiles"][0]["tags"])
        self.assertEqual(
            result["ranked_profiles"][0]["build_command"],
            "FOUNDRY_PROFILE=contract_Vault_abcd forge build src/Vault_abcd",
        )
        self.assertIn("/workspace/campaign/scope-manifest.json", container.files)

    async def test_search_code_defaults_to_source_root_and_excludes_artifacts(self):
        container = FakeContainer()
        container.exec_results = [
            (0, ""),  # /audit/src exists
            (0, "/audit/src/Vault.sol:10:function withdraw() external {}\n"),
        ]

        result = await execute_tool(
            "search_code",
            {"pattern": "withdraw", "path": "/audit"},
            container,
            [],
        )

        self.assertIn("withdraw", result)
        command = container.exec_calls[-1][0]
        self.assertIn("/audit/src", command)
        self.assertIn("--exclude-dir=findings", command)
        self.assertIn("--exclude-dir='*_poc'", command)


class CampaignToolTests(unittest.IsolatedAsyncioTestCase):
    def _seed_non_economic_minimization_review(self, container: FakeContainer) -> None:
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/minimizations/min-001.json"] = json.dumps({
            "id": "min-001",
            "summary": {
                "baseline_preserved": True,
                "preserved_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
            },
            "baseline": {
                "log_path": "/workspace/campaign/minimizations/min-001/baseline.log",
            },
            "best_variant": {
                "id": "drop-step-001",
                "kind": "drop_step",
                "log_path": "/workspace/campaign/minimizations/min-001/drop-step-001.log",
            },
        })
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "ready": True,
            "sequence_minimizations": [{
                "id": "min-001",
                "path": "/workspace/campaign/minimizations/min-001.json",
                "baseline_preserved": True,
                "preserved_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
                "best_variant_id": "drop-step-001",
                "best_variant_log": "/workspace/campaign/minimizations/min-001/drop-step-001.log",
            }],
        })

    async def test_read_campaign_initializes_empty_state(self):
        container = FakeContainer()

        result = await _read_campaign(container, {})

        self.assertIn("Initialized empty campaign state", result)
        self.assertIn(_CAMPAIGN_STATE_PATH, container.files)
        self.assertIn('"hypothesis": 0', result)

    async def test_update_campaign_adds_artifact_with_id(self):
        container = FakeContainer()

        result = await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Spot price can overvalue collateral",
            "content": "Test whether a flash-loan swap changes collateral value.",
            "priority": "high",
            "evidence": ["contracts/Lending.sol:120"],
        })

        self.assertIn("hyp-001", result)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "hyp-001"', state)
        self.assertIn('"priority": "high"', state)
        self.assertIn("contracts/Lending.sol:120", state)

    async def test_update_campaign_updates_existing_artifact(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Manipulate pool then borrow",
            "content": "Initial test plan.",
        })

        result = await _update_campaign(container, {
            "section": "experiment",
            "action": "update",
            "id": "exp-001",
            "title": "Manipulate pool then borrow",
            "content": "Observed no profit because TWAP is used.",
            "status": "rejected",
            "related_ids": ["hyp-001"],
        })

        self.assertIn("Updated campaign artifact exp-001", result)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"status": "rejected"', state)
        self.assertIn("Observed no profit because TWAP is used.", state)
        self.assertIn('"hyp-001"', state)

    async def test_update_campaign_rejects_missing_update_id(self):
        container = FakeContainer()

        result = await _update_campaign(container, {
            "section": "hypothesis",
            "action": "update",
            "title": "Missing id",
            "content": "Cannot update without an id.",
        })

        self.assertIn("'id' is required", result)

    async def test_update_campaign_rejects_unknown_status(self):
        container = FakeContainer()

        result = await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Bad status",
            "content": "Status should be validated.",
            "status": "maybe",
        })

        self.assertIn("unknown campaign status", result)
        self.assertEqual(container.files, {})

    async def test_attack_search_initializes_foundation_branch(self):
        container = FakeContainer()

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "title": "Initial deterministic search",
            "record_result": False,
        }))

        self.assertEqual(result["search_id"], "search-001")
        self.assertEqual(result["next_action"]["tool"], "update_campaign")
        self.assertEqual(result["next_action"]["status"], "needs_context")
        self.assertTrue(result["next_action"]["must_follow"])
        self.assertEqual(result["trace_path"], "/workspace/campaign/trace.jsonl")
        trace = container.files["/workspace/campaign/trace.jsonl"].strip().splitlines()
        self.assertEqual(len(trace), 1)
        self.assertEqual(json.loads(trace[0])["event"], "attack_search")
        self.assertIn("/workspace/campaign/attack-search/current.json", container.files)
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(
            state["attack_search"]["current"]["next_action"]["tool"],
            "update_campaign",
        )

    async def test_attack_search_writes_branch_dossier(self):
        container = FakeContainer()

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "title": "Initial deterministic search",
            "record_result": False,
        }))

        next_action = result["next_action"]
        branch_id = next_action["branch_id"]
        self.assertTrue(branch_id)
        dossier_path = f"/workspace/campaign/branch-dossiers/{branch_id}.json"
        # next_action (compacted response) carries the dossier path...
        self.assertEqual(next_action["dossier_path"], dossier_path)
        # ...the dossier artifact was written with the branch skeleton...
        self.assertIn(dossier_path, container.files)
        dossier = json.loads(container.files[dossier_path])
        self.assertEqual(dossier["branch_id"], branch_id)
        self.assertEqual(dossier["status"], next_action["status"])
        self.assertEqual(dossier["next_tool"], next_action["tool"])
        self.assertIn("history_summary", dossier)
        self.assertEqual(dossier["search_id"], result["search_id"])
        # ...and the saved search state persists the dossier path on next_action.
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(
            state["attack_search"]["current"]["next_action"]["dossier_path"],
            dossier_path,
        )

    def test_branch_dossier_derives_objective_and_inventory_blocker(self):
        search = {
            "id": "search-001",
            "focus": "vault",
            "paths": {"history": "/workspace/campaign/attack-search/search-001.json"},
        }
        branch = {
            "id": "branch-007",
            "key": "graph:donation",
            "title": "Donation redeem profit",
            "status": "blocked_setup",
            "source": "attack_graph",
            "next_tool": "complete_sequence_experiment",
            "instructions": "i" * 2000,
            "target_actions": [
                {"key": "Vault.redeem", "contract": "Vault", "function": "redeem"},
            ],
            "required_args": {
                "compose_sequence_experiment": {
                    "objective": "drain vault via donation",
                },
            },
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "inventory_context": {
                "hard_blockers": [{"label": "Vault", "target_binding": "no_code"}],
            },
            "history": [
                {"at": "t0", "event": "created", "status": "needs_hypothesis"},
                {
                    "at": "t1",
                    "event": "status_changed",
                    "from": "needs_run",
                    "to": "blocked_setup",
                    "reason": "compile failed",
                },
            ],
        }

        dossier = _attack_search_branch_dossier(search, branch)

        self.assertEqual(dossier["branch_id"], "branch-007")
        self.assertEqual(
            dossier["hypothesis_or_objective"], "drain vault via donation"
        )
        self.assertIn("Vault=no_code", dossier["last_blocker"])
        self.assertEqual(dossier["history_summary"]["events"], 2)
        self.assertEqual(dossier["search_id"], "search-001")
        self.assertEqual(dossier["next_tool"], "complete_sequence_experiment")
        # Bulky instructions are truncated, not embedded verbatim.
        self.assertLessEqual(len(dossier["instructions"]), 1200)

    def test_branch_dossier_last_blocker_falls_back_to_history(self):
        search = {"id": "search-001"}
        branch = {
            "id": "branch-008",
            "title": "Objective probe",
            "status": "objective_failed",
            "next_tool": "mutate_hypothesis",
            "history": [
                {"at": "t0", "event": "created", "status": "needs_run"},
                {
                    "at": "t1",
                    "event": "decision",
                    "to": "objective_failed",
                    "reason": "no profit observed at settlement",
                },
            ],
        }

        dossier = _attack_search_branch_dossier(search, branch)

        self.assertIn("no profit observed at settlement", dossier["last_blocker"])
        # Empty/absent fields are dropped from the compact artifact.
        self.assertNotIn("inventory_context", dossier)

    async def test_attack_search_requires_mapping_after_foundation(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        tools = {branch["next_tool"] for branch in result["active_branches"]}
        self.assertIn("map_protocol_graph", tools)
        self.assertIn("map_action_space", tools)
        self.assertEqual(result["next_action"]["status"], "needs_mapping")

    async def test_attack_search_repairs_invalid_action_space_before_later_maps(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        action_space_path = "/workspace/campaign/action-spaces/as-001.json"
        container.files[action_space_path] = json.dumps({
            "id": "as-001",
            "status": "invalid_empty_source",
            "source": {
                "path": "/audit/src",
                "files_requested": 2,
                "files_scanned": 0,
                "read_errors": [
                    {"path": "/audit/src/src/BridgeV2.sol", "error": "missing"}
                ],
            },
            "summary": {"actions": 0, "observations": 0},
            "actions": [],
            "observations": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Invalid action-space map",
            "content": "The previous action-space map scanned no readable source files.",
            "evidence": [action_space_path],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        self.assertEqual(result["next_action"]["tool"], "map_action_space")
        self.assertEqual(result["next_action"]["source"], "invalid_action_space")
        self.assertEqual(result["next_action"]["status"], "needs_mapping")
        self.assertEqual(len(result["active_branches"]), 1)

    async def test_attack_search_requires_evidence_after_experiment_run(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Donation redeem fork replay",
            "content": "Run a Foundry fork test and measure attacker balance.",
            "related_ids": ["hyp-001"],
        })
        container.exec_result = (
            0,
            "[PASS] test_donation_redeem_profit() (gas: 123)\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped\n",
        )
        await _run_experiment(container, {
            "title": "Donation redeem fork replay",
            "command": "forge test --match-test test_donation_redeem_profit -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        evidence_branches = [
            branch for branch in result["active_branches"]
            if branch["status"] == "needs_evidence"
        ]
        self.assertEqual(len(evidence_branches), 1)
        self.assertEqual(
            evidence_branches[0]["next_tool"],
            "summarize_trace then snapshot_state/compare_snapshots/evaluate_objective",
        )
        self.assertIn("res-001", evidence_branches[0]["related_ids"])
        self.assertEqual(result["next_action"]["status"], "needs_evidence")

    async def test_attack_search_does_not_treat_build_as_objective_run(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Vault invariant harness",
            "content": "Run a Foundry invariant harness and measure loss.",
            "related_ids": ["hyp-001"],
        })
        container.exec_result = (0, "Compiler run successful!\n")

        run = await _run_experiment(container, {
            "title": "Vault profile build",
            "command": "FOUNDRY_PROFILE=contract_Vault forge build --skip test",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        self.assertIn("Recorded campaign result: res-001 (observed)", run)
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(
            state["sections"]["result"][0]["run_classification"]["run_kind"],
            "build",
        )
        self.assertFalse(
            state["sections"]["result"][0]["run_classification"]["satisfies_experiment_run"]
        )
        self.assertFalse([
            branch for branch in result["active_branches"]
            if branch["status"] == "needs_evidence"
        ])
        experiment_branches = [
            branch for branch in result["active_branches"]
            if branch["source"] == "experiment_without_result"
        ]
        self.assertEqual(len(experiment_branches), 1)
        self.assertIn("setup-only", experiment_branches[0]["instructions"])

    async def test_run_experiment_marks_forge_noop_as_blocked_not_objective(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Vault replay",
            "objective": "Replay a value-moving vault sequence.",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "expected_effect": "unauthorized value leaves the vault",
            }],
            "observations": [{
                "label": "target balance",
                "target": "Vault",
                "call": "address(Vault).balance",
            }],
        })
        container.exec_result = (0, "Nothing to compile\n")

        run = await _run_experiment(container, {
            "title": "No-op sequence replay",
            "command": "forge test --match-path ReentbotProSequence.t.sol -vvv",
            "working_dir": "/workspace/experiments/exp-001-vault-replay",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })

        self.assertIn("Recorded campaign result: res-001 (blocked)", run)
        self.assertIn("Satisfies experiment run: false", container.files[
            "/workspace/campaign/results/res-001.log"
        ])
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        result = state["sections"]["result"][0]
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["run_classification"]["satisfies_experiment_run"])
        self.assertIn(
            "did not execute any tests",
            result["run_classification"]["reason"],
        )
        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        self.assertEqual(progress["summary"]["blocked_results_without_decisions"], 1)
        attack = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertFalse([
            branch for branch in attack["active_branches"]
            if branch["source"] == "result_without_objective"
        ])

    async def test_attack_search_advance_rejects_branch(self):
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        advanced = json.loads(await _attack_search(container, {
            "action": "advance",
            "branch_id": branch_id,
            "status": "rejected",
            "notes": "No meaningful value flow after source review.",
            "evidence": ["dec-001"],
            "record_result": False,
        }))

        terminal = advanced["terminal_branches"][0]
        self.assertEqual(terminal["id"], branch_id)
        self.assertEqual(terminal["status"], "rejected")
        self.assertIn("dec-001", terminal["evidence"])

    async def test_attack_search_decision_records_branch_decision(self):
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        decided = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": branch_id,
            "decision_status": "rejected",
            "failed_assumption": "No value flow exists.",
            "decision": "Source review showed this branch cannot affect funds.",
            "impact_assessment": "No loss, lock, or profit path exists.",
            "evidence": ["src/Vault.sol:10"],
            "record_result": False,
        }))

        self.assertEqual(decided["decision_id"], "dec-001")
        self.assertEqual(decided["summary"]["active"], 0)
        terminal = decided["terminal_branches"][0]
        self.assertEqual(terminal["id"], branch_id)
        self.assertEqual(terminal["status"], "rejected")
        self.assertTrue(terminal["terminal_decision"])
        self.assertEqual(terminal["decision_id"], "dec-001")
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["sections"]["decision"][0]["id"], "dec-001")
        self.assertIn("No value flow exists", state["sections"]["decision"][0]["content"])

    async def test_attack_search_decision_parks_branch_as_harness_limited(self):
        # A harness-limit park is terminal-ish for this pass but must never be
        # summarized as a rejection: it preserves a plausible-but-hard branch.
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        decided = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": branch_id,
            "decision_status": "unproven_due_to_harness_limit",
            "decision": (
                "Branch is plausible but the PoC needs an EIP-712 permit signature "
                "the harness cannot forge yet."
            ),
            "next_focus": (
                "Reopen once synthesize_args or a real signer can supply the "
                "permit calldata."
            ),
            "record_result": False,
        }))

        self.assertEqual(decided["decision_id"], "dec-001")
        # Terminal-ish for this pass (no active branch left) but the status is the
        # harness-limit status, not a rejection.
        self.assertEqual(decided["summary"]["active"], 0)
        terminal = decided["terminal_branches"][0]
        self.assertEqual(terminal["id"], branch_id)
        self.assertEqual(terminal["status"], "unproven_due_to_harness_limit")
        self.assertTrue(terminal["terminal_decision"])
        # The summary must not count it as rejected.
        by_status = decided["summary"]["by_status"]
        self.assertEqual(by_status.get("unproven_due_to_harness_limit"), 1)
        self.assertNotIn("rejected", by_status)
        # The recorded decision keeps the harness-limit status verbatim.
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertIn(
            "unproven_due_to_harness_limit",
            state["sections"]["decision"][0]["content"],
        )

    async def test_attack_search_advance_parks_branch_below_active_work(self):
        # parked_harness_limit is non-terminal (still active, never summarized as
        # rejected) and, unlike an ordinary advanced status, survives a re-sync so
        # the park persists until the agent explicitly un-parks it. Its rank (20,
        # below every active proof status) is pinned by _ATTACK_SEARCH_STATUS_ORDER.
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        parked = json.loads(await _attack_search(container, {
            "action": "advance",
            "branch_id": branch_id,
            "status": "parked_harness_limit",
            "notes": "Park until a real flash-loan signature is available.",
            "record_result": False,
        }))
        parked_branch = next(
            item for item in parked["active_branches"] if item["id"] == branch_id
        )
        # Still active (non-terminal) and not summarized as terminal/rejected.
        self.assertEqual(parked_branch["status"], "parked_harness_limit")
        self.assertGreaterEqual(parked["summary"]["active"], 1)
        self.assertNotIn("rejected", parked["summary"]["by_status"])
        # A re-sync keeps the branch parked instead of re-deriving its status.
        resynced = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        resynced_branch = next(
            item for item in resynced["active_branches"] if item["id"] == branch_id
        )
        self.assertEqual(resynced_branch["status"], "parked_harness_limit")

    async def test_attack_search_advance_parking_requires_notes(self):
        # Parking is a budget judgment, so it must record why. action=advance to
        # any parked_* status without notes is rejected.
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        error = await _attack_search(container, {
            "action": "advance",
            "branch_id": branch_id,
            "status": "parked_low_roi",
            "record_result": False,
        })
        self.assertTrue(error.startswith("Error:"), error)
        self.assertIn("notes", error)
        # The branch was not parked.
        synced = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch = next(
            item for item in synced["active_branches"] if item["id"] == branch_id
        )
        self.assertNotEqual(branch["status"], "parked_low_roi")

    async def test_attack_search_advance_parking_is_not_a_rejection(self):
        # Parking via advance is non-terminal: it does not set terminal_decision,
        # does not create a decision, and is never summarized as rejected. It
        # records parking_reason and an optional recommended_budget.
        container = FakeContainer()
        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch_id = result["next_action"]["branch_id"]

        parked = json.loads(await _attack_search(container, {
            "action": "advance",
            "branch_id": branch_id,
            "status": "parked_needs_live_context",
            "notes": "Need a mainnet fork of the live router before this is provable.",
            "parking_reason": "no fork context for the router yet",
            "recommended_budget": "revisit after fork context",
            "record_result": False,
        }))
        branch = next(
            item for item in parked["active_branches"] if item["id"] == branch_id
        )
        self.assertEqual(branch["status"], "parked_needs_live_context")
        # Non-terminal: still active, never summarized as terminal/rejected.
        self.assertNotIn("terminal_decision", branch)
        self.assertGreaterEqual(parked["summary"]["active"], 1)
        self.assertEqual(parked["summary"].get("terminal", 0), 0)
        self.assertNotIn("rejected", parked["summary"]["by_status"])
        # No decision artifact was created by parking.
        self.assertIsNone(parked.get("decision_id"))
        # Parking metadata is recorded and surfaced on the branch and next_action.
        self.assertEqual(branch["parking_reason"], "no fork context for the router yet")
        self.assertEqual(branch["recommended_budget"], "revisit after fork context")
        self.assertIn("scheduling_score", branch)
        self.assertIn("scheduling_score", parked["next_action"])
        self.assertEqual(
            parked["next_action"]["parking_reason"],
            "no fork context for the router yet",
        )
        # No decision section was written to campaign state.
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["sections"].get("decision", []), [])

    async def test_attack_search_decision_dedupes_coverage_by_action_key(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "affordances": ["value_out_or_burn"],
                "modifiers": [],
            }],
            "observations": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Action space",
            "content": "as-001",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Coverage review",
            "record_result": True,
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        coverage_branch = next(
            branch for branch in result["active_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        )
        self.assertEqual(coverage_branch["action_keys"], ["Vault::withdraw"])

        await _attack_search(container, {
            "action": "decision",
            "branch_id": coverage_branch["id"],
            "decision_status": "rejected",
            "decision": "Withdraw path is not attacker exploitable.",
            "failed_assumption": "Withdraw was untested.",
            "record_result": False,
        })
        stale_progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        self.assertEqual(
            stale_progress["summary"]["coverage_high_attention_gaps"],
            0,
        )
        stale_sync = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertFalse([
            branch for branch in stale_sync["active_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        ])
        review = json.loads(await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Coverage review after decision",
            "record_result": False,
        }))

        self.assertEqual(review["summary"]["high_attention_gaps"], 0)
        review_artifact = json.loads(container.files[review["path"]])
        self.assertEqual(review_artifact["covered_actions"][0]["coverage"], "decided")
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertIn("Vault::withdraw", state["attack_search"]["decided_action_keys"])

    async def test_attack_search_source_reviews_coverage_gap_after_empty_live_map(self):
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "affordances": ["value_out_or_burn"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps",
            "content": "Action space and empty live reachability are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
            ],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Coverage review",
            "record_result": True,
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "coverage_high_attention_gap"
        )
        self.assertEqual(branch["status"], "needs_context")
        self.assertEqual(
            branch["next_tool"],
            "source_slice then update_campaign or attack_search decision",
        )
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertEqual(
            branch["required_args"]["source_slice"],
            {"path": "/audit/src/Vault.sol", "function": "withdraw"},
        )
        self.assertNotIn(
            "compose_sequence_experiment",
            branch.get("required_args", {}),
        )
        self.assertTrue(
            any("deployment" in item for item in branch["required_evidence"])
        )

    async def test_attack_search_parks_hypothesis_after_empty_live_map(self):
        container = FakeContainer()
        await self._record_foundation(container)
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Empty live reachability",
            "content": "No deployed target was bound.",
            "evidence": ["/workspace/campaign/live-reachability/lr-001.json"],
        })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Source-only callback may move value",
            "content": "Needs deployed target context before any harness work.",
            "priority": "high",
            "evidence": ["/audit/src/Vault.sol:20"],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "hypothesis_without_experiment"
        )
        self.assertEqual(branch["status"], "parked_needs_live_context")
        self.assertEqual(branch["next_tool"], "record_fork_context or update_campaign")
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertIn("live reachability", branch["parking_reason"])
        self.assertNotIn("compose_sequence_experiment", branch.get("required_args", {}))

    async def test_attack_search_concretizes_vague_hypothesis_before_harness(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Suspicious accounting edge",
            "content": "This branch still needs source review before it is testable.",
            "priority": "high",
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "hypothesis_without_experiment"
        )
        self.assertEqual(branch["status"], "needs_context")
        self.assertIn("source_slice", branch["next_tool"])
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertFalse(branch["readiness"]["ready"])
        self.assertNotIn("compose_sequence_experiment", branch.get("required_args", {}))

    async def test_attack_search_allows_ready_hypothesis_to_reach_harness(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Attacker withdraws excess assets via Vault::withdraw",
            "content": (
                "An unprivileged attacker calls Vault::withdraw after depositing. "
                "The objective is to measure before/after asset balance profit "
                "and a vault accounting invariant loss on a deployed fork address."
            ),
            "priority": "high",
            "evidence": ["/audit/src/Vault.sol:42"],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "hypothesis_without_experiment"
        )
        self.assertEqual(branch["status"], "needs_harness")
        self.assertIn("compose_sequence_experiment", branch["next_tool"])
        self.assertEqual(branch["required_toolsets"], ["experiment"])
        self.assertTrue(branch["readiness"]["ready"])

    async def test_attack_search_routes_context_missing_sequence_away_from_completion(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Unbound target sequence",
            "content": "Workspace: /workspace/experiments/unbound",
            "priority": "high",
        })
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        experiment = state["sections"]["experiment"][0]
        experiment["sequence_quality"] = {
            "runnable": False,
            "proof_readiness": "partial",
            "executable_sequence_calls": 1,
            "requires_manual_assertions": False,
            "harness_limit_blockers": ["missing_target_binding"],
            "non_executable_steps": [{
                "blocker_classes": ["missing_target_binding"],
                "notes": "target address missing",
            }],
        }
        container.files[_CAMPAIGN_STATE_PATH] = json.dumps(state)

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "experiment_without_result"
        )
        self.assertEqual(branch["status"], "needs_context")
        self.assertNotEqual(branch["next_tool"], "complete_sequence_experiment")
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertNotIn("complete_sequence_experiment", branch.get("required_args", {}))

    async def test_attack_search_routes_context_missing_attack_graph_sequence_away_from_completion(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "summary": {"live_deployed_profiles": 1, "target_bindings": {"Vault": "0x1111111111111111111111111111111111111111"}},
            "profiles": [{"address": "0x1111111111111111111111111111111111111111"}],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-context",
                "attack_key": "vault-context",
                "title": "Materialized sequence still missing deployment context",
                "priority": "critical",
                "priority_score": 30,
                "action_key": "Vault::withdraw",
                "contract": "Vault",
                "function": "withdraw",
                "target_address": "0x1111111111111111111111111111111111111111",
                "exposure": "exposed",
                "objective": "Vault::withdraw must not release unauthorized value.",
                "actions": [{
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "target": "0x1111111111111111111111111111111111111111",
                    "args": ["amount"],
                    "expected_effect": "unauthorized value leaves the vault",
                }],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                    "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                },
            }],
        })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "agcand-context sequence",
            "content": "Workspace: /workspace/experiments/agcand-context",
            "priority": "critical",
            "related_ids": ["agcand-context"],
            "evidence": ["/workspace/experiments/agcand-context/sequence.json"],
        })
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        experiment = state["sections"]["experiment"][0]
        experiment["sequence_quality"] = {
            "runnable": False,
            "proof_readiness": "partial",
            "executable_sequence_calls": 1,
            "requires_manual_assertions": False,
            "harness_limit_blockers": ["missing deployment context"],
            "non_executable_steps": [{
                "blocker_classes": ["missing_target_binding"],
                "notes": "target address exists, but chain binding/source context is missing",
            }],
        }
        container.files[_CAMPAIGN_STATE_PATH] = json.dumps(state)
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, protocol graph, and attack graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "attack_graph_candidate"
        )
        self.assertEqual(branch["status"], "needs_context")
        self.assertNotEqual(branch["next_tool"], "complete_sequence_experiment")
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertNotIn("complete_sequence_experiment", branch.get("required_args", {}))

    async def test_attack_search_routes_blocked_compile_result_to_poc_repair(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Generated Vault PoC",
            "content": "Workspace: /workspace/experiments/vault-poc",
            "priority": "high",
        })
        followup_path = "/workspace/campaign/results/res-001.followup.json"
        log_path = "/workspace/campaign/results/res-001.log"
        container.files[log_path] = "Compiler run failed: Undeclared identifier"
        container.files[followup_path] = json.dumps({
            "failure_diagnosis": {
                "kind": "compile_error",
                "confidence": "high",
                "summary": "The generated harness failed before execution.",
                "suggested_repairs": ["fix imports before changing the hypothesis"],
                "recommended_next_tool": "run_experiment",
                "evidence_lines": ["Undeclared identifier"],
            },
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Generated Vault PoC run",
            "content": "Command: forge test\nLog: /workspace/campaign/results/res-001.log",
            "status": "blocked",
            "priority": "high",
            "related_ids": ["exp-001"],
            "evidence": [log_path, followup_path],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "blocked_result"
        )
        self.assertEqual(branch["status"], "needs_poc_repair")
        self.assertIn("repair_experiment", branch["next_tool"])
        self.assertEqual(branch["failure_diagnosis"]["kind"], "compile_error")
        self.assertEqual(
            branch["required_args"]["repair_experiment"],
            {"experiment": "exp-001", "diagnostic": log_path},
        )
        self.assertEqual(
            branch["required_args"]["diagnose_build"],
            {"experiment": "exp-001", "log_path": log_path},
        )

    async def test_progress_coverage_gaps_compacts_duplicate_high_attention_items(self):
        container = FakeContainer()
        container.files["/workspace/campaign/coverage-reviews/cov-001.json"] = json.dumps({
            "id": "cov-001",
            "title": "Coverage review",
            "action_space": "/workspace/campaign/action-spaces/as-001.json",
            "summary": {
                "high_attention_gaps": 3,
                "hypothesized_not_experimented": 0,
            },
            "high_attention_gaps": [
                {
                    "key": "Vault::withdraw",
                    "contract": "Vault",
                    "function": "withdraw",
                    "file": "/audit/src/Vault.sol",
                    "line": 20,
                    "attention_score": 5,
                    "affordances": ["value_out_or_burn"],
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                },
                {
                    "key": "Vault::withdraw",
                    "contract": "Vault",
                    "function": "withdraw",
                    "file": "/audit/profiles/Vault.sol",
                    "line": 42,
                    "attention_score": 4,
                    "affordances": ["value_out_or_burn"],
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                },
                {
                    "key": "Oracle::updatePrice",
                    "contract": "Oracle",
                    "function": "updatePrice",
                    "file": "/audit/src/Oracle.sol",
                    "line": 55,
                    "attention_score": 4,
                    "affordances": ["valuation_dependency", "market_or_router"],
                    "parameters": [{"name": "price", "raw": "uint256 price"}],
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Coverage review result",
            "content": "Coverage review cov-001.",
            "evidence": ["/workspace/campaign/coverage-reviews/cov-001.json"],
        })

        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))

        coverage = progress["coverage_high_attention_gaps"][0]
        self.assertEqual(coverage["summary"]["raw_high_attention_gaps"], 3)
        self.assertEqual(coverage["summary"]["high_attention_gaps"], 2)
        self.assertEqual(coverage["summary"]["duplicate_high_attention_gaps"], 1)
        self.assertEqual(
            [item["key"] for item in coverage["top_high_attention_gaps"]],
            ["Vault::withdraw", "Oracle::updatePrice"],
        )

    async def test_coarse_coverage_branch_does_not_resurface_after_rejection(self):
        # Regression: a rejected coarse coverage branch must not reappear when
        # the agent re-runs review_attack_surface_coverage on the same action
        # space. The branch is keyed by the stable action-space id, so a fresh
        # review artifact (new id) merges onto the existing terminal branch
        # instead of spawning a new active twin.
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })

        def _write_review(review_id):
            container.files[
                f"/workspace/campaign/coverage-reviews/{review_id}.json"
            ] = json.dumps({
                "id": review_id,
                "title": f"Coverage review {review_id}",
                "action_space": "as-001",
                "summary": {
                    "high_attention_gaps": 0,
                    "hypothesized_not_experimented": 1,
                },
                "high_attention_gaps": [],
            })

        async def _record_review_result(review_id):
            await _update_campaign(container, {
                "section": "result",
                "title": f"Coverage review {review_id} result",
                "content": f"Recorded {review_id}.",
                "evidence": [
                    f"/workspace/campaign/coverage-reviews/{review_id}.json"
                ],
            })

        _write_review("cov-001")
        await _record_review_result("cov-001")

        first_sync = json.loads(await _attack_search(container, {
            "action": "sync",
            "max_branches": 40,
            "record_result": False,
        }))
        coarse_branches = [
            branch for branch in first_sync["active_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        ]
        self.assertEqual(len(coarse_branches), 1)
        coarse_branch = coarse_branches[0]
        self.assertEqual(coarse_branch["status"], "needs_context")
        self.assertEqual(coarse_branch["required_toolsets"], ["core"])

        decision = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": coarse_branch["id"],
            "decision_status": "rejected",
            "decision": "Leftover coverage gaps are expected behavior.",
            "record_result": False,
        }))
        self.assertEqual(decision["action"], "decision")

        # A second review of the same action space mints a new artifact id.
        _write_review("cov-002")
        await _record_review_result("cov-002")

        second_sync = json.loads(await _attack_search(container, {
            "action": "sync",
            "max_branches": 40,
            "include_terminal": True,
            "record_result": False,
        }))
        self.assertFalse([
            branch for branch in second_sync["active_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        ])
        terminal_ids = {
            branch["id"] for branch in second_sync["terminal_branches"]
        }
        self.assertIn(coarse_branch["id"], terminal_ids)

    async def test_coverage_family_decision_supersedes_helper_siblings(self):
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/coverage-reviews/cov-001.json"] = json.dumps({
            "id": "cov-001",
            "title": "Coverage review",
            "action_space": "as-001",
            "summary": {
                "high_attention_gaps": 2,
                "hypothesized_not_experimented": 0,
            },
            "high_attention_gaps": [
                {
                    "key": "MockSpell::schedule",
                    "contract": "MockSpell",
                    "function": "schedule",
                    "file": "/audit/test/MockSpell.sol",
                    "line": 20,
                    "attention_score": 4,
                    "affordances": ["state_mutating_entrypoint"],
                    "parameters": [],
                },
                {
                    "key": "MockSpell::cast",
                    "contract": "MockSpell",
                    "function": "cast",
                    "file": "/audit/test/MockSpell.sol",
                    "line": 35,
                    "attention_score": 4,
                    "affordances": ["state_mutating_entrypoint"],
                    "parameters": [],
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Coverage review",
            "content": "Coverage review cov-001.",
            "evidence": ["/workspace/campaign/coverage-reviews/cov-001.json"],
        })

        first_sync = json.loads(await _attack_search(container, {
            "action": "sync",
            "max_branches": 40,
            "record_result": False,
        }))
        coverage = [
            branch for branch in first_sync["active_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        ]
        self.assertEqual(len(coverage), 2)

        await _attack_search(container, {
            "action": "decision",
            "branch_id": coverage[0]["id"],
            "decision_status": "rejected",
            "decision": (
                "Same helper mock family: test-only wrapper, not a production "
                "value flow."
            ),
            "record_result": False,
        })
        decided = json.loads(await _attack_search(container, {
            "action": "sync",
            "include_terminal": True,
            "record_result": False,
        }))

        terminal_coverage = [
            branch for branch in decided["terminal_branches"]
            if branch["source"] == "coverage_high_attention_gap"
        ]
        self.assertEqual(
            {branch["status"] for branch in terminal_coverage},
            {"rejected", "superseded"},
        )

    async def test_mutate_hypothesis_creates_linked_next_steps(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Spot price manipulation overvalues collateral",
            "content": "Swap before borrow should inflate collateral value.",
            "priority": "high",
        })

        result = await _mutate_hypothesis(container, {
            "source_hypothesis_id": "hyp-001",
            "failed_assumption": "The protocol reads spot price directly.",
            "interpretation": (
                "The experiment showed the borrow path uses a TWAP value, so "
                "single-block spot movement is not enough."
            ),
            "evidence": ["res-001", "eval-001"],
            "source_status": "rejected",
            "mutations": [{
                "title": "TWAP update cadence can be exploited",
                "hypothesis": (
                    "If the TWAP is stale or updated after attacker-controlled "
                    "trades, collateral can still be overvalued."
                ),
                "rationale": "The failed spot-price test leaves TWAP freshness open.",
                "experiment": (
                    "Fork before oracle update, manipulate the pool, advance "
                    "time to the update boundary, then borrow."
                ),
                "expected_observation": "Borrow limit increases without durable collateral.",
                "priority": "high",
            }],
            "open_questions": [{
                "title": "Oracle update permissions",
                "question": "Who can trigger the TWAP update and at what cadence?",
                "priority": "medium",
            }],
        })

        self.assertIn('"mutation_id": "mut-001"', result)
        self.assertIn('"hypothesis_id": "hyp-002"', result)
        self.assertIn('"experiment_id": "exp-001"', result)
        self.assertIn('"decision_id": "dec-001"', result)
        self.assertIn("/workspace/campaign/mutations/mut-001.json", container.files)
        mutation = container.files["/workspace/campaign/mutations/mut-001.json"]
        self.assertIn('"source_found": true', mutation)
        self.assertIn("TWAP update cadence", mutation)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"mutation": 1', state)
        self.assertIn('"status": "rejected"', state)
        self.assertIn('"id": "hyp-002"', state)
        self.assertIn('"id": "exp-001"', state)
        self.assertIn('"id": "dec-001"', state)
        self.assertIn('"id": "oq-001"', state)
        self.assertIn("Mutation mut-001", state)

    async def test_mutate_hypothesis_rejects_empty_mutations(self):
        container = FakeContainer()

        result = await _mutate_hypothesis(container, {
            "source_hypothesis_id": "hyp-001",
            "failed_assumption": "No effect was observed.",
            "interpretation": "The branch should be mutated.",
            "mutations": [],
        })

        self.assertIn("requires at least one mutation", result)
        self.assertEqual(container.files, {})

    async def test_review_campaign_progress_flags_process_gaps(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Donation sequence can profit",
            "content": "Needs an experiment and objective evaluation.",
            "priority": "high",
        })
        await _create_experiment(container, {
            "title": "Donation sequence proof",
            "hypothesis_id": "hyp-001",
        })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Unexplored oracle cadence branch",
            "content": "No experiment has been designed yet.",
            "priority": "medium",
        })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Unrun accounting branch",
            "content": "Experiment exists but has no result yet.",
            "priority": "medium",
        })
        await _create_experiment(container, {
            "title": "Unrun accounting probe",
            "hypothesis_id": "hyp-003",
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Oracle cadence run blocked",
            "content": "Fork dependency was missing.",
            "status": "blocked",
            "related_ids": ["hyp-002"],
        })
        container.files["/workspace/campaign/evaluations/eval-001.json"] = """
{
  "id": "eval-001",
  "title": "Profit objective",
  "summary": {"objectives": 1, "passed": 0, "failed": 1, "unmatched": 0},
  "related_ids": ["hyp-001", "exp-001"]
}
"""
        await _update_campaign(container, {
            "section": "result",
            "title": "Objective evaluation showed no profit",
            "content": "Evaluation failed and should be mutated or rejected.",
            "status": "observed",
            "evidence": ["/workspace/campaign/evaluations/eval-001.json"],
            "related_ids": ["hyp-001", "exp-001", "eval-001"],
        })
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = """
{"id": "fr-001", "title": "Ready evidence", "severity": "high", "ready": true}
"""
        container.files["/workspace/campaign/report-reviews/rr-001.json"] = """
{"id": "rr-001", "title": "Ready report", "severity": "high", "ready": true}
"""
        await _update_campaign(container, {
            "section": "result",
            "title": "Ready review artifacts",
            "content": "Candidate has both reviews ready.",
            "status": "observed",
            "evidence": [
                "/workspace/campaign/finding-reviews/fr-001.json",
                "/workspace/campaign/report-reviews/rr-001.json",
            ],
            "related_ids": ["fr-001", "rr-001"],
        })

        result = await _review_campaign_progress(container, {
            "title": "Mid-campaign review",
        })

        self.assertIn('"review_id": "prg-001"', result)
        # Advisory tool: it surfaces gaps but defers scheduling to the controller.
        self.assertIn("attack_search is authoritative", result)
        self.assertIn('"missing_foundation": 3', result)
        self.assertIn('"experiments_without_results": 1', result)
        self.assertIn('"failed_evaluations": 1', result)
        self.assertIn('"ready_finding_reviews": 1', result)
        self.assertIn('"ready_report_reviews": 1', result)
        self.assertIn("Unrun accounting probe", result)
        self.assertIn("Profit objective", result)
        self.assertIn("Ready report", result)
        self.assertIn("/workspace/campaign/progress-reviews/prg-001.json", container.files)
        review = container.files["/workspace/campaign/progress-reviews/prg-001.json"]
        self.assertIn("Submit ready report-reviewed findings", review)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"progress_review": 1', state)
        self.assertIn("Campaign progress review", state)

    async def test_build_campaign_brief_persists_resume_artifacts(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "protocol_model",
            "title": "Vault protocol model",
            "content": "Vault, share token, and accounting surface are in scope.",
        })
        await _update_campaign(container, {
            "section": "value_flow",
            "title": "Deposit and redeem flow",
            "content": "Assets enter through deposit and leave through redeem.",
        })
        await _update_campaign(container, {
            "section": "invariant",
            "title": "Shares redeem proportionally",
            "content": "A user must not redeem more assets than their share fraction.",
        })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Donation sequence can skew share price",
            "content": "Attacker donates assets, deposits, then redeems.",
            "priority": "high",
        })
        await _create_experiment(container, {
            "title": "Donation sequence proof",
            "hypothesis_id": "hyp-001",
        })
        await _plan_attack_campaign(container, {
            "title": "Resume plan",
            "focus": "redeem",
        })

        result = await _build_campaign_brief(container, {
            "title": "Resume after context compaction",
            "focus": "redeem path",
            "max_items": 3,
        })

        self.assertIn('"brief_id": "brief-001"', result)
        self.assertIn('"tool": "run_experiment"', result)
        # Advisory tool: the resume brief defers scheduling to the controller.
        self.assertIn("attack_search is authoritative", result)
        self.assertIn("/workspace/campaign/brief.json", container.files)
        self.assertIn("/workspace/campaign/brief.md", container.files)
        brief = json.loads(container.files["/workspace/campaign/brief.json"])
        self.assertEqual(brief["id"], "brief-001")
        self.assertEqual(brief["suggested_next"]["tool"], "run_experiment")
        self.assertEqual(brief["latest_artifacts"]["plans"][0]["id"], "plan-001")
        self.assertEqual(
            brief["active_work"]["experiments_without_results"][0]["id"],
            "exp-001",
        )
        markdown = container.files["/workspace/campaign/brief.md"]
        self.assertIn("# Resume after context compaction", markdown)
        self.assertIn("## Latest Plan", markdown)
        self.assertIn("Donation sequence proof", markdown)
        # The resume doc tells the agent the controller, not the brief, schedules.
        self.assertIn("attack_search is authoritative", markdown)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"campaign_brief": 1', state)
        self.assertIn("Campaign resume brief", state)

    async def test_build_campaign_brief_suggests_explicit_actions_for_coverage_gaps(self):
        container = FakeContainer()
        for section, title in [
            ("protocol_model", "Vault model"),
            ("value_flow", "Vault value flow"),
            ("invariant", "Vault solvency invariant"),
        ]:
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": "Foundation artifact.",
            })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Rejected seed hypothesis",
            "content": "Foundation hypothesis already closed.",
            "status": "rejected",
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "summary": {"actions": 1, "observations": 0, "contracts": 1},
  "actions": [{
    "contract": "Oracle",
    "function": "updatePrice",
    "file": "/audit/src/Oracle.sol",
    "line": 44,
    "mutability": "nonpayable",
    "affordances": ["valuation_dependency", "market_or_router"],
    "modifiers": []
  }],
  "observations": []
}
"""
        await _update_campaign(container, {
            "section": "result",
            "title": "Action-space map",
            "content": "Action space as-001 was recorded.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
            "related_ids": ["as-001"],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Coverage review",
        })

        result = await _build_campaign_brief(container, {
            "record_result": False,
        })

        self.assertIn(
            '"tool": "source_slice then update_campaign or attack_search decision"',
            result,
        )
        brief = json.loads(container.files["/workspace/campaign/brief.json"])
        self.assertEqual(
            brief["suggested_next"]["tool"],
            "source_slice then update_campaign or attack_search decision",
        )

    async def test_review_attack_surface_coverage_flags_untested_levers(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "summary": {"actions": 4, "observations": 0, "contracts": 3},
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "mutability": "nonpayable",
      "affordances": ["value_in_or_mint", "token_or_native_transfer"],
      "modifiers": []
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 31,
      "mutability": "nonpayable",
      "affordances": ["value_out_or_burn", "token_or_native_transfer"],
      "modifiers": []
    },
    {
      "contract": "Oracle",
      "function": "updatePrice",
      "file": "/audit/src/Oracle.sol",
      "line": 44,
      "mutability": "nonpayable",
      "affordances": ["valuation_dependency", "market_or_router"],
      "modifiers": []
    },
    {
      "contract": "Router",
      "function": "execute",
      "file": "/audit/src/Router.sol",
      "line": 52,
      "mutability": "payable",
      "affordances": ["generic_execution", "external_call"],
      "modifiers": []
    }
  ],
  "observations": []
}
"""
        await _update_campaign(container, {
            "section": "result",
            "title": "Action-space map: /audit",
            "content": "Action space as-001 was recorded for later experiment design.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
            "related_ids": ["as-001"],
        })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Vault withdraw can exceed proportional assets",
            "content": "Test whether Vault::withdraw can redeem too much after a donation.",
            "priority": "high",
        })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Deposit baseline",
            "content": "Exercise Vault::deposit before measuring shares.",
            "related_ids": ["hyp-001"],
        })
        container.files["/workspace/experiments/exp-001/sequence.json"] = """
{"actions": [{"contract": "Router", "function": "execute"}]}
"""
        await _update_campaign(container, {
            "section": "result",
            "title": "Router sequence reproduced",
            "content": "The generated sequence was executed.",
            "evidence": ["/workspace/experiments/exp-001/sequence.json"],
            "related_ids": ["exp-001"],
        })

        result = await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Core surface review",
        })

        self.assertIn('"coverage_review_id": "cov-001"', result)
        self.assertIn('"high_attention_gaps": 1', result)
        self.assertIn('"hypothesized_not_experimented": 1', result)
        self.assertIn('"key": "Oracle::updatePrice"', result)
        self.assertIn('"key": "Vault::withdraw"', result)
        self.assertNotIn('"key": "Router::execute",\n      "contract"', result)
        self.assertIn("/workspace/campaign/coverage-reviews/cov-001.json", container.files)
        review = container.files["/workspace/campaign/coverage-reviews/cov-001.json"]
        self.assertIn('"coverage": "result_observed"', review)
        self.assertIn('"contract": "Router"', review)
        self.assertIn("Pick one high-attention uncovered lever", review)
        progress = await _review_campaign_progress(container, {
            "record_result": False,
        })
        self.assertIn('"coverage_high_attention_gaps": 1', progress)
        self.assertIn("Oracle::updatePrice", progress)
        plan = await _plan_attack_campaign(container, {
            "title": "Next core branch",
            "focus": "oracle",
        })
        self.assertIn('"plan_id": "plan-001"', plan)
        self.assertIn('"key": "Oracle::updatePrice"', plan)
        self.assertIn(
            '"recommended_next_tool": "compose_sequence_experiment with explicit actions or compose_invariant_harness with handler actions"',
            plan,
        )
        self.assertIn('"oracle_window_checks"', plan)
        self.assertIn("updatedAt/timestamp", plan)
        self.assertIn("missing fork context", plan)
        self.assertIn("/workspace/campaign/plans/plan-001.json", container.files)
        plan_artifact = container.files["/workspace/campaign/plans/plan-001.json"]
        self.assertIn("stop_or_mutate_condition", plan_artifact)
        progress_after_plan = await _review_campaign_progress(container, {
            "record_result": False,
        })
        self.assertIn('"latest_campaign_plans": 1', progress_after_plan)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"coverage_review": 1', state)
        self.assertIn('"campaign_plan": 1', state)
        self.assertIn("Attack-surface coverage review", state)
        self.assertIn("Attack campaign plan", state)

    async def test_plan_attack_campaign_is_advisory_not_a_scheduler(self):
        # The planner is advisory: it defers scheduling authority to
        # attack_search via controller_note, exposes its suggestions under an
        # explicitly advisory key (candidate_next_steps), and never emits a
        # competing required/next-action order.
        container = FakeContainer()
        for section, title in [
            ("protocol_model", "Vault model"),
            ("value_flow", "Vault value flow"),
            ("invariant", "Vault solvency invariant"),
        ]:
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": "Foundation artifact.",
            })
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Donation skews share price",
            "content": "Attacker donates, deposits, then redeems.",
            "priority": "high",
        })

        result = await _plan_attack_campaign(container, {"title": "Advisory plan"})
        plan = json.loads(result)

        self.assertEqual(
            plan["controller_note"],
            "Use attack_search for authoritative next_action and branch transitions.",
        )
        self.assertIn("candidate_next_steps", plan)
        self.assertTrue(plan["candidate_next_steps"])
        # No competing scheduler fields: the planner never issues a next_action.
        self.assertNotIn("next_actions", plan)
        self.assertNotIn("next_action", plan)
        self.assertNotIn("required_next_action", plan)
        self.assertNotIn("must_follow_next_action", plan)

        artifact = json.loads(
            container.files["/workspace/campaign/plans/plan-001.json"]
        )
        self.assertEqual(artifact["controller_note"], plan["controller_note"])
        self.assertIn("candidate_next_steps", artifact)
        self.assertNotIn("next_actions", artifact)
        self.assertNotIn("required_next_action", artifact)
        self.assertNotIn("must_follow_next_action", artifact)

    async def test_plan_attack_campaign_uses_amm_context_for_valuation_branch(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "value_flow",
            "title": "Oracle price controls borrowing power",
            "content": "The protocol reads market price before allowing value out.",
        })
        await _update_campaign(container, {
            "section": "invariant",
            "title": "Market price cannot be cheaply distorted for value out",
            "content": "Attacker-controlled pool state must not create profitable valuation drift.",
        })
        await _record_fork_context(container, {
            "title": "Mainnet oracle fork",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19_000_000,
            "pools": [{
                "label": "WETH/USDC",
                "pair": "0x0000000000000000000000000000000000000001",
            }],
            "oracles": [{
                "label": "ETH/USD feed",
                "address": "0x0000000000000000000000000000000000000002",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "title": "Oracle action map",
            "created_at": "2026-01-01T00:00:00+00:00",
            "summary": {"actions": 1, "observations": 0},
            "actions": [{
                "contract": "OracleAdapter",
                "function": "updatePrice",
                "file": "/audit/src/OracleAdapter.sol",
                "line": 57,
                "mutability": "nonpayable",
                "affordances": ["valuation_dependency", "market_or_router"],
                "modifiers": [],
            }],
            "observations": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Action-space map: oracle",
            "content": "Action space as-001 was recorded for planning.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
            "related_ids": ["as-001"],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Oracle coverage",
        })

        missing_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Oracle branch before economics",
            "record_result": False,
        }))
        missing_branch = missing_plan["branches"][0]
        self.assertIn(
            "missing AMM/economics estimate for price-moving branch",
            missing_branch["blockers"],
        )

        await _estimate_amm_economics(container, {
            "title": "WETH/USDC manipulation route",
            "pools": [{
                "label": "WETH/USDC",
                "reserve_in": "10000",
                "reserve_out": "20000",
                "amount_in": "1000",
                "fee_bps": 30,
                "token_in_decimals": 0,
                "token_out_decimals": 0,
                "token_in_symbol": "WETH",
                "token_out_symbol": "USDC",
                "token_in_price_usd": "2000",
                "token_out_price_usd": "1",
            }],
            "related_ids": ["as-001"],
        })
        ready_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Oracle branch after economics",
            "record_result": False,
        }))
        ready_branch = ready_plan["branches"][0]
        self.assertNotIn(
            "missing AMM/economics estimate",
            " ".join(ready_branch["blockers"]),
        )
        self.assertIn(
            "/workspace/campaign/economics/econ-001.json",
            ready_branch["source_artifacts"],
        )
        self.assertEqual(ready_branch["economics_context"]["kind"], "amm")
        self.assertEqual(
            ready_branch["economics_context"]["total_capital_usd"],
            "2000000",
        )
        self.assertNotEqual(
            ready_branch["economics_context"]["max_abs_price_change_bps"],
            "0",
        )

    async def test_plan_attack_campaign_uses_lending_health_context_for_credit_branch(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "value_flow",
            "title": "Lending collateral backs protocol debt",
            "content": "Borrowers lock collateral and receive debt; liquidation repays unhealthy debt.",
        })
        await _update_campaign(container, {
            "section": "invariant",
            "title": "Liquidations must not create bad debt",
            "content": "Collateral valuation, debt, and bonuses must keep the market solvent.",
        })
        await _record_fork_context(container, {
            "title": "Mainnet lending fork",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19_000_000,
            "contracts": [{
                "name": "LendingPool",
                "address": "0x0000000000000000000000000000000000000001",
            }],
            "tokens": [{
                "symbol": "WETH",
                "address": "0x0000000000000000000000000000000000000002",
            }],
            "actors": [{
                "role": "attacker",
                "address": "0x0000000000000000000000000000000000000003",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "title": "Lending action map",
            "created_at": "2026-01-01T00:00:00+00:00",
            "summary": {"actions": 1, "observations": 0},
            "actions": [{
                "contract": "LendingPool",
                "function": "liquidate",
                "file": "/audit/src/LendingPool.sol",
                "line": 88,
                "mutability": "nonpayable",
                "affordances": ["credit_or_liquidation"],
                "modifiers": [],
            }],
            "observations": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Action-space map: lending",
            "content": "Action space as-001 was recorded for planning.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
            "related_ids": ["as-001"],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Lending coverage",
        })

        missing_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Lending branch before economics",
            "record_result": False,
        }))
        missing_branch = missing_plan["branches"][0]
        self.assertEqual(
            missing_branch["target_actions"][0]["key"],
            "LendingPool::liquidate",
        )
        self.assertIn(
            "missing lending health estimate for credit/liquidation branch",
            missing_branch["blockers"],
        )
        self.assertIn(
            "run estimate_lending_health",
            " ".join(missing_branch["required_setup"]),
        )
        self.assertIn("liquidation_route_checks", missing_branch)
        self.assertIn(
            "close factor",
            " ".join(missing_branch["liquidation_route_checks"]),
        )

        await _estimate_lending_health(container, {
            "title": "Manipulated collateral liquidation",
            "positions": [{
                "label": "after oracle move",
                "collateral_amount_decimal": "2",
                "collateral_decimals": 18,
                "collateral_price_usd": "2000",
                "collateral_price_shift_bps": -3000,
                "liquidation_threshold_bps": 8000,
                "debt_amount_decimal": "2500",
                "debt_decimals": 6,
                "debt_price_usd": "1",
                "liquidation_bonus_bps": 500,
            }],
            "related_ids": ["as-001"],
        })
        ready_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Lending branch after economics",
            "record_result": False,
        }))
        ready_branch = ready_plan["branches"][0]
        self.assertGreater(
            ready_branch["priority_score"],
            missing_branch["priority_score"],
        )
        self.assertNotIn(
            "missing lending health estimate",
            " ".join(ready_branch["blockers"]),
        )
        self.assertIn(
            "/workspace/campaign/economics/econ-001.json",
            ready_branch["source_artifacts"],
        )
        self.assertEqual(
            ready_branch["economics_context"]["kind"],
            "lending_health",
        )
        self.assertEqual(
            ready_branch["economics_context"]["liquidatable_positions"],
            1,
        )
        self.assertEqual(
            ready_plan["branches"][0]["economics_context"]["total_shortfall_usd"],
            "260",
        )

    async def test_plan_attack_campaign_uses_flash_loan_context_for_callback_branch(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "value_flow",
            "title": "Flash borrower receives temporary liquidity",
            "content": "The provider transfers borrowed assets, calls back, and expects repayment plus fee.",
        })
        await _update_campaign(container, {
            "section": "invariant",
            "title": "Callback cannot move protected value before repayment",
            "content": "The callback must not leave the borrower or provider with an unaccounted value delta.",
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "title": "Flash callback action map",
            "created_at": "2026-01-01T00:00:00+00:00",
            "summary": {"actions": 1, "observations": 0},
            "actions": [{
                "contract": "FlashProvider",
                "function": "flashLoan",
                "file": "/audit/src/FlashProvider.sol",
                "line": 42,
                "mutability": "nonpayable",
                "affordances": ["callback_or_flashloan_surface", "external_call"],
                "modifiers": [],
            }],
            "observations": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Action-space map: flash provider",
            "content": "Action space as-001 was recorded for planning.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
            "related_ids": ["as-001"],
        })
        await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
            "title": "Flash callback coverage",
        })

        missing_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Flash branch before economics",
            "record_result": False,
        }))
        missing_branch = missing_plan["branches"][0]
        self.assertEqual(
            missing_branch["target_actions"][0]["key"],
            "FlashProvider::flashLoan",
        )
        self.assertIn("flash_loan_checks", missing_branch)
        self.assertIn(
            "run estimate_flash_loan",
            " ".join(missing_branch["required_setup"]),
        )

        await _estimate_flash_loan(container, {
            "title": "USDC callback liquidity",
            "assets": [{
                "symbol": "USDC",
                "asset": "0x0000000000000000000000000000000000000001",
                "provider": "0x0000000000000000000000000000000000000002",
                "amount_decimal": "100",
                "available_liquidity_decimal": "1000",
                "decimals": 6,
                "fee_bps": 9,
                "price_usd": "1",
            }],
            "related_ids": ["as-001"],
        })
        ready_plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Flash branch after economics",
            "record_result": False,
        }))
        ready_branch = ready_plan["branches"][0]
        self.assertGreater(
            ready_branch["priority_score"],
            missing_branch["priority_score"],
        )
        self.assertIn(
            "/workspace/campaign/economics/flash-001.json",
            ready_branch["source_artifacts"],
        )
        self.assertEqual(
            ready_branch["flash_loan_context"]["kind"],
            "flash_loan",
        )
        self.assertEqual(
            ready_branch["flash_loan_context"]["insufficient_liquidity"],
            0,
        )
        self.assertEqual(
            ready_branch["flash_loan_context"]["total_fee_usd"],
            "0.09",
        )
        self.assertIn(
            "review linked flash-loan estimate",
            " ".join(ready_branch["required_setup"]),
        )

    async def test_review_finding_evidence_records_ready_review(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Share inflation can drain vault",
            "content": "Donation before first deposit can skew share price.",
        })
        await _create_experiment(container, {
            "title": "Donation then redeem",
            "hypothesis_id": "hyp-001",
        })
        container.exec_result = (0, "Suite result: ok. 1 passed; 0 failed")
        await _run_experiment(container, {
            "command": "forge test --match-test testDonationRedeem -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )

        result = await _review_finding_evidence(container, {
            "title": "Share inflation drains vault",
            "severity": "high",
            "root_cause": "Initial share minting trusts donated assets.",
            "impact": "Unprivileged attacker can profit after flash-loan-funded donation.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Donate assets to empty vault",
                "Deposit minimal amount",
                "Redeem inflated shares",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "objective_evaluation": "eval-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validated": True,
            "capital_required": "Flash-loan-sized donation plus gas",
            **_exploitability_fields(),
            "trusted_role_required": False,
        })

        self.assertIn('"review_id": "fr-001"', result)
        self.assertIn('"ready": true', result)
        self.assertIn('"blocking_gaps": []', result)
        self.assertIn("/workspace/campaign/finding-reviews/fr-001.json", container.files)
        review = container.files["/workspace/campaign/finding-reviews/fr-001.json"]
        self.assertIn('"ready": true', review)
        self.assertIn('"checked_evidence_paths"', review)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"finding_review": 1', state)
        self.assertIn("Finding evidence review", state)

    async def test_review_finding_evidence_infers_affected_code_from_source_evidence(self):
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = "contract Vault { function skim() external {} }"
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Command: forge test\n"
            "Exit code: 0\n"
            "Log:\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped\n"
        )

        result = await _review_finding_evidence(container, {
            "title": "Vault skim can spend prefunded ETH",
            "severity": "low",
            "root_cause": "Public skim spends target funds.",
            "impact": "Protocol prefund loss.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": [
                "/audit/src/Vault.sol:1",
                "/workspace/campaign/results/res-001.log",
            ],
            "reproduction_steps": ["Run the passing replay."],
            "validated": True,
            "test_output": (
                "Command: forge test\n"
                "Exit code: 0\n"
                "Log:\n"
                "Suite result: ok. 1 passed; 0 failed; 0 skipped\n"
            ),
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertTrue(payload["ready"])
        self.assertIn("affected_code inferred", " ".join(payload["warnings"]))
        review = json.loads(container.files["/workspace/campaign/finding-reviews/fr-001.json"])
        self.assertEqual(
            review["candidate"]["affected_code"][0]["file"],
            "/audit/src/Vault.sol",
        )
        self.assertEqual(review["candidate"]["affected_code"][0]["lines"], "1")
        self.assertIn("/audit/src/Vault.sol:1", review["checked_evidence_paths"])

    async def test_review_finding_evidence_does_not_infer_generated_poc_as_affected_code(self):
        container = FakeContainer()
        container.files["/workspace/experiments/exp-001/ReentbotProSequence.t.sol"] = (
            "contract ReentbotProSequence {}"
        )
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Command: forge test\n"
            "Exit code: 0\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped\n"
        )

        result = await _review_finding_evidence(container, {
            "title": "Generated replay points at missing target source",
            "severity": "low",
            "root_cause": "The generated replay is not the affected protocol source.",
            "impact": "A report needs the live target source location.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": [
                "/workspace/experiments/exp-001/ReentbotProSequence.t.sol",
                "/workspace/campaign/results/res-001.log",
            ],
            "reproduction_steps": ["Run the generated replay."],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed; 0 skipped",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertFalse(payload["ready"])
        # Substring match accommodates the augmented gap string format:
        # "<key phrase> — <recovery hint with field shape>".
        self.assertIn(
            "missing affected code references",
            " ".join(payload["blocking_gaps"]),
        )
        review = json.loads(container.files["/workspace/campaign/finding-reviews/fr-001.json"])
        self.assertEqual(review["candidate"]["affected_code"], [])

    async def test_review_finding_evidence_warns_high_without_objective_or_minimization(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )

        result = await _review_finding_evidence(container, {
            "title": "High impact replay without objective proof",
            "severity": "high",
            "root_cause": "The replay reaches a suspicious accounting path.",
            "impact": "The candidate claims protocol loss but has no objective delta.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the replay.",
                "Observe the passing test.",
                "Inspect the log.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/SuspiciousReplay.t.sol",
            "validated": True,
            "capital_required": "Temporary capital plus gas",
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn(
            "lacks objective evaluation or preserved sequence minimization evidence",
            " ".join(parsed["warnings"]),
        )

    async def test_review_finding_evidence_labels_synthetic_precondition_for_high(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )

        result = await _review_finding_evidence(container, {
            "title": "Singleton action drains victim-approved tokens",
            "severity": "high",
            "root_cause": "The direct action path pulls tokens from calldata-controlled from.",
            "impact": "A victim allowance to the singleton would let the attacker mint to self.",
            "affected_code": [{"file": "src/actions/AaveSupply.sol", "lines": "73-131"}],
            "reproduction_steps": [
                "Victim approves the singleton action in the PoC setup.",
                "Attacker calls executeActionDirect with from=victim.",
                "The replay mints receipt tokens to the attacker.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "objective_evaluation": "eval-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/DirectActionAllowance.t.sol",
            "validated": True,
            "capital_required": "Victim allowance is required.",
            "preconditions": [
                "A victim must hold an ERC20 allowance to the singleton action contract."
            ],
            "precondition_provenance": [{
                "precondition": "Victim allowance to singleton action",
                "provenance": "synthetic_modeling_only",
                "evidence": (
                    "The PoC creates the allowance with vm.prank(victim); no live "
                    "allowance evidence or normal workflow creates it."
                ),
            }],
            "production_reachability": (
                "The direct action function exists, but the victim allowance "
                "precondition is created only inside the replay setup."
            ),
            "funds_at_risk": "Measured live funds at risk: $0.",
            "negative_controls": [
                "Without the synthetic victim approval to the singleton, transferFrom reverts."
            ],
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        joined = " ".join(parsed["warnings"])
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn("synthetic_modeling_only", joined)
        self.assertIn("zero measured funds at risk", joined)
        self.assertEqual(
            parsed["exploitability_review"]["exploitability_status"],
            "plausible_unproven",
        )
        self.assertEqual(parsed["exploitability_review"]["confidence"], "low")
        self.assertEqual(
            parsed["exploitability_review"]["exposure_status"],
            "measured_zero",
        )

    async def test_review_finding_evidence_warns_partial_probe_only_evidence(self):
        # A partial probe is setup/precondition evidence only; it can never be the
        # sole PoC for a medium/high/critical finding.
        container = FakeContainer()
        container.exec_result = (
            0,
            "[PASS] test_partial_probe_sequence()\nSuite result: ok. 1 passed; 0 failed",
        )
        await _run_experiment(container, {
            "command": "forge test --match-test test_partial_probe_sequence -vvv",
            "run_kind": "partial_probe",
            "experiment_id": "exp-001",
        })
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(
            state["sections"]["result"][0]["run_classification"]["run_kind"],
            "partial_probe",
        )

        result = await _review_finding_evidence(container, {
            "title": "Vault drain backed only by a partial probe",
            "severity": "medium",
            "root_cause": "The withdraw path skips the solvency check.",
            "impact": "An unprivileged caller could drain the vault.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the partial probe.",
                "Observe the preconditions hold.",
                "Inspect the snapshots.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "capital_required": "Flash-loaned principal plus gas",
            **_exploitability_fields(),
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn(
            "backed only by a partial probe",
            " ".join(parsed["warnings"]),
        )

    async def _generic_probe_run(self, container):
        """Compose+complete a generic_probe sequence and run it once.

        Returns after recording a poc_run whose run_classification carries
        probe_strength=generic_probe (the auto-generated after != before guard).
        """
        target = "0x1111111111111111111111111111111111111111"
        await _compose_sequence_experiment(container, {
            "title": "Drain vault",
            "objective": "attacker drains vault",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "expected_effect": "unauthorized value leaves the vault",
            }],
            "observations": [{
                "label": "vault assets",
                "contract": "Vault",
                "call": "totalAssets()(uint256)",
            }],
            "success_condition": "attacker balance increases",
        })
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": target},
            "objective_probe_strategy": "accounting_delta",
            "record_result": False,
        })
        sequence = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        # Sanity: completion produced a generic_probe objective probe.
        self.assertEqual(sequence["objective_probe"]["strength"], "generic_probe")
        container.exec_result = (
            0,
            "[PASS] test_sequence_experiment()\nSuite result: ok. 1 passed; 0 failed",
        )
        await _run_experiment(container, {
            "command": "forge test --match-test test_sequence_experiment -vvv",
            "experiment_id": "exp-001",
        })
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        run_result = state["sections"]["result"][0]
        self.assertEqual(
            run_result["run_classification"]["probe_strength"], "generic_probe"
        )
        self.assertTrue(
            run_result["run_classification"]["satisfies_experiment_run"]
        )

    async def test_review_finding_evidence_warns_generic_probe_only_evidence(self):
        # A generic_probe delta (after != before) is screening/setup evidence; it
        # cannot, by itself, validate a medium/high/critical finding.
        container = FakeContainer()
        await self._generic_probe_run(container)

        result = await _review_finding_evidence(container, {
            "title": "Vault drain backed only by a generic probe",
            "severity": "medium",
            "root_cause": "The withdraw path skips the solvency check.",
            "impact": "An unprivileged caller could drain the vault.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the completed sequence.",
                "Observe the generic accounting delta.",
                "Inspect the recorded log.",
            ],
            "campaign_ids": ["exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "capital_required": "Flash-loaned principal plus gas",
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn(
            "generic_probe is setup/context evidence, not objective impact proof",
            " ".join(parsed["warnings"]),
        )

    async def test_review_finding_evidence_generic_probe_passes_with_objective_eval(self):
        # generic_probe + a linked objective_evaluation: the stronger artifact
        # clears the generic-probe caveat.
        container = FakeContainer()
        await self._generic_probe_run(container)
        container.files["/workspace/campaign/comparisons/cmp-001.json"] = """
{
  "id": "cmp-001",
  "changed": [
    {"key": "attacker USDC", "before": "1000", "after": "1100", "delta": 100}
  ]
}
"""
        await _evaluate_objective(container, {
            "comparison": "/workspace/campaign/comparisons/cmp-001.json",
            "objectives": [{
                "match": "attacker USDC",
                "direction": "increase",
                "min_delta": "1",
                "unit": "USDC",
            }],
            "record_result": False,
        })

        result = await _review_finding_evidence(container, {
            "title": "Vault drain with a measured objective delta",
            "severity": "medium",
            "root_cause": "The withdraw path skips the solvency check.",
            "impact": "An unprivileged caller could drain the vault.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the completed sequence.",
                "Compare attacker balances before and after.",
                "Confirm eval-001 records positive attacker profit.",
            ],
            "campaign_ids": ["exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "objective_evaluation": "eval-001",
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "capital_required": "Flash-loaned principal plus gas",
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertNotIn(
            "generic_probe is setup/context evidence, not objective impact proof",
            " ".join(parsed["blocking_gaps"]),
        )

    async def test_review_finding_evidence_summarizes_sequence_minimization(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Reduced sequence preserves profit",
            "content": "A shorter withdraw path still preserves the objective marker.",
        })
        await _compose_sequence_experiment(container, {
            "title": "Minimize evidence sequence",
            "objective": "Find a minimal profitable replay.",
            "hypothesis_id": "hyp-001",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "deposit",
                    "args": ["amount"],
                },
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "args": ["amount"],
                },
            ],
            "success_condition": "OBJECTIVE_PASS appears when profit is preserved.",
        })
        container.exec_results = [
            (0, "baseline\nOBJECTIVE_PASS\nprofit=10\n"),
            (0, "drop deposit\nOBJECTIVE_PASS\nprofit=10\n"),
            (0, "remove approval\nprofit=0\n"),
        ]
        await _run_sequence_minimization(container, {
            "sequence": "exp-001",
            "baseline": {
                "command": "forge test --match-test test_sequence_experiment -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            },
            "variants": [{
                "variant_id": "drop-step-001",
                "command": "forge test --match-test test_drop_step_001 -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            }],
            "setup_checks": [{
                "check_id": "setup-approval",
                "kind": "approval",
                "target": "USDC->Vault",
                "change": "remove approval and rerun the preserved variant",
                "command": "forge test --match-test test_without_approval -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            }],
        })
        container.files["/workspace/campaign/comparisons/cmp-001.json"] = """
{
  "id": "cmp-001",
  "changed": [
    {"key": "attacker USDC", "before": "1000", "after": "1100", "delta": 100}
  ]
}
"""
        await _evaluate_objective(container, {
            "comparison": "/workspace/campaign/comparisons/cmp-001.json",
            "objectives": [{
                "match": "attacker USDC",
                "direction": "increase",
                "min_delta": "1",
                "unit": "USDC",
            }],
            "record_result": False,
        })

        result = await _review_finding_evidence(container, {
            "title": "Reduced sequence keeps attacker profit",
            "severity": "high",
            "root_cause": "Withdrawal accounting can be reached without the full setup sequence.",
            "impact": "Unprivileged attacker can preserve profit with fewer transaction steps.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the baseline sequence replay.",
                "Run the drop-step minimization variant.",
                "Confirm eval-001 records positive attacker profit.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "min-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/minimizations/min-001.json",
                "/workspace/campaign/minimizations/min-001/drop-step-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "sequence_minimization": "min-001",
            "objective_evaluation": "eval-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/ReducedSequence.t.sol",
            "validated": True,
            "capital_required": "Flash-loan-sized capital plus gas",
            **_exploitability_fields(),
            "trusted_role_required": False,
        })

        self.assertIn('"ready": true', result)
        review = json.loads(container.files["/workspace/campaign/finding-reviews/fr-001.json"])
        self.assertEqual(review["sequence_minimizations"][0]["id"], "min-001")
        self.assertEqual(
            review["sequence_minimizations"][0]["best_variant_id"],
            "drop-step-001",
        )
        self.assertEqual(
            review["sequence_minimizations"][0]["preserved_variants"],
            1,
        )
        self.assertEqual(
            review["sequence_minimizations"][0]["setup_checks_retained"],
            1,
        )
        self.assertEqual(
            review["sequence_minimizations"][0]["retained_setup_assumptions"][0]["kind"],
            "approval",
        )
        self.assertIn(
            "/workspace/campaign/minimizations/min-001.json",
            review["checked_evidence_paths"],
        )

    async def test_review_finding_evidence_warns_unresolved_route_composition(self):
        container = FakeContainer()
        sequence_path = "/workspace/experiments/exp-001-route/sequence.json"
        container.files[sequence_path] = json.dumps({
            "id": "exp-001",
            "route_composition_plan": {
                "strategy": "llm_route_composition_v1",
                "affordances": ["market_or_router", "valuation_dependency"],
                "routes": [{
                    "kind": "amm_or_valuation_route",
                    "title": "AMM/valuation route composition",
                    "affordances": ["market_or_router", "valuation_dependency"],
                    "missing_context": ["linked AMM economics estimate"],
                    "suggested_tools": ["estimate_amm_economics"],
                    "unwind_candidates": [{
                        "label": "pool unwind via WETH/USDC",
                        "pool": {"label": "WETH/USDC pool"},
                        "assets": [
                            {"symbol": "WETH"},
                            {"symbol": "USDC"},
                        ],
                    }],
                    "source_router_hints": [{
                        "action": "OracleAdapter::updatePrice",
                        "line": 59,
                        "target": "router",
                        "selector_hint": "swapExactTokensForTokens",
                        "path_terms": ["amountIn", "path", "deadline"],
                    }],
                    "evidence_prompts": [
                        "snapshot pool reserves, oracle freshness, route input/output, and valuation",
                    ],
                }],
            },
        })
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )

        result = await _review_finding_evidence(container, {
            "title": "Oracle route can skew collateral value",
            "severity": "high",
            "root_cause": "The collateral path trusts a spot route before minting debt.",
            "impact": "Unprivileged attacker can increase borrow capacity and profit.",
            "affected_code": [{"file": "src/Lending.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the composed route replay.",
                "Observe the manipulated borrow state.",
                "Confirm the attacker exits with profit.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": [
                sequence_path,
                "/workspace/campaign/results/res-001.log",
            ],
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/RouteReplay.t.sol",
            "validated": True,
            "capital_required": "Temporary swap capital plus gas.",
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertEqual(parsed["route_composition_count"], 1)
        self.assertIn(
            "route composition amm_or_valuation_route from exp-001 missing context",
            " ".join(parsed["warnings"]),
        )
        plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Review caveated route finding",
            "max_branches": 1,
            "record_result": False,
        }))
        branch = plan["branches"][0]
        self.assertEqual(branch["source"], "ready_finding_review")
        self.assertEqual(branch["recommended_next_tool"], "review_report_quality")

    async def test_review_finding_evidence_accepts_resolved_route_composition(self):
        container = FakeContainer()
        sequence_path = "/workspace/experiments/exp-001-route/sequence.json"
        container.files[sequence_path] = json.dumps({
            "id": "exp-001",
            "route_composition_plan": {
                "strategy": "llm_route_composition_v1",
                "affordances": ["market_or_router", "valuation_dependency"],
                "routes": [{
                    "kind": "amm_or_valuation_route",
                    "title": "AMM/valuation route composition",
                    "affordances": ["market_or_router", "valuation_dependency"],
                    "economics_context": {"kind": "amm", "total_capital_usd": 100000},
                    "missing_context": [],
                    "suggested_tools": [],
                    "source_artifacts": ["/workspace/campaign/economics/econ-001.json"],
                    "evidence_prompts": [
                        "snapshot pool reserves, oracle freshness, route input/output, and valuation",
                    ],
                }],
            },
        })
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )
        container.files["/workspace/campaign/economics/econ-001.json"] = (
            '{"id":"econ-001","kind":"amm"}\n'
        )

        result = await _review_finding_evidence(container, {
            "title": "Oracle route can skew collateral value",
            "severity": "high",
            "root_cause": (
                "The target values collateral from an oracle spot price after "
                "the attacker swaps through the pool route."
            ),
            "impact": (
                "The AMM pool reserve movement creates price impact and slippage, "
                "then the attacker can unwind while keeping borrow profit."
            ),
            "affected_code": [{"file": "src/Lending.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Snapshot pool reserves, oracle freshness, and target valuation before the route.",
                "Run the swap route and borrow step on the same fork block.",
                "Compare slippage, unwind output, and attacker profit in eval-001.",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001", "econ-001"],
            "evidence": [
                sequence_path,
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
                "/workspace/campaign/economics/econ-001.json",
            ],
            "objective_evaluation": "eval-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/RouteReplay.t.sol",
            "validated": True,
            "capital_required": "econ-001 models pool slippage, price impact, and unwind capital.",
            **_exploitability_fields(
                preconditions=[
                    (
                        "The attacker can trade through the live AMM route and "
                        "call the lending entrypoint with attacker-controlled "
                        "capital on the same fork block."
                    )
                ],
                precondition_provenance=[{
                    "precondition": "Live AMM route and public lending entrypoint",
                    "provenance": "observed_onchain",
                    "evidence": (
                        "econ-001 and the fork replay bind the AMM route, pool "
                        "reserve movement, oracle valuation, and public borrow step."
                    ),
                }],
                funds_at_risk=(
                    "econ-001 and eval-001 record nonzero borrow profit from "
                    "the route against deployed pool liquidity."
                ),
            ),
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        review = json.loads(container.files["/workspace/campaign/finding-reviews/fr-001.json"])
        self.assertEqual(review["route_compositions"][0]["routes"][0]["kind"], "amm_or_valuation_route")
        self.assertIn(sequence_path, review["checked_evidence_paths"])

    async def test_review_finding_evidence_warns_attack_graph_live_blockers(self):
        container = FakeContainer()
        sequence_path = "/workspace/experiments/exp-001-attack-graph/sequence.json"
        container.files[sequence_path] = json.dumps({
            "id": "exp-001",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "live_blockers": ["live exposure is gated"],
            }],
            "target_addresses": {
                "Vault": "0x1111111111111111111111111111111111111111",
            },
            "attack_graph_candidate": {
                "attack_graph_id": "ag-001",
                "attack_graph_path": "/workspace/campaign/attack-graphs/ag-001.json",
                "candidate_id": "agcand-001",
                "attack_key": "vault-withdraw",
                "action_key": "Vault::withdraw",
                "exposure": "gated",
                "live_status": "deployed",
                "target_address": "0x1111111111111111111111111111111111111111",
                "blockers": ["live exposure is gated"],
                "required_live_evidence": ["prove the attacker can satisfy the gate"],
            },
        })
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )

        result = await _review_finding_evidence(container, {
            "title": "Gated attack graph candidate cannot be high severity yet",
            "severity": "high",
            "root_cause": "The replay was generated from a gated attack graph branch.",
            "impact": "The claimed path would move vault assets if the gate were bypassed.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run the attack graph sequence replay.",
                "Attempt the gated withdraw call from an unprivileged attacker.",
                "Compare the objective evaluation output.",
            ],
            "campaign_ids": ["exp-001", "eval-001"],
            "evidence": [
                sequence_path,
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "objective_evaluation": "eval-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/GatedReplay.t.sol",
            "validated": True,
            "capital_required": "Temporary capital plus gas.",
            "trusted_role_required": False,
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertEqual(parsed["attack_graph_sequence_count"], 1)
        self.assertIn(
            "unresolved live blockers",
            " ".join(parsed["warnings"]),
        )
        self.assertIn("exposure is gated", " ".join(parsed["warnings"]))

    async def test_review_finding_evidence_blocks_failed_sequence_minimization(self):
        container = FakeContainer()
        container.files["/workspace/campaign/minimizations/min-001.json"] = """
{
  "id": "min-001",
  "summary": {
    "baseline_preserved": false,
    "preserved_variants": 0,
    "executed_variants": 0,
    "minimal_preserved_variant": null
  },
  "baseline": {
    "log_path": "/workspace/campaign/minimizations/min-001/baseline.log"
  },
  "variants": []
}
"""

        result = await _review_finding_evidence(container, {
            "title": "Failed reduced replay",
            "severity": "high",
            "root_cause": "Candidate root cause.",
            "impact": "Candidate impact.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42"}],
            "reproduction_steps": ["Run baseline", "Observe objective marker"],
            "campaign_ids": ["hyp-001", "exp-001", "min-001"],
            "evidence": ["/workspace/campaign/minimizations/min-001.json"],
            "sequence_minimization": "min-001",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "validated": True,
            "trusted_role_required": False,
        })

        self.assertIn('"ready": false', result)
        self.assertIn("baseline did not preserve objective evidence", result)

    async def test_review_finding_evidence_reports_blocking_gaps(self):
        container = FakeContainer()

        result = await _review_finding_evidence(container, {
            "title": "Admin can drain vault",
            "severity": "high",
            "root_cause": "Owner-only function transfers funds.",
            "impact": "Owner can transfer funds.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "10"}],
            "reproduction_steps": ["Owner calls sweep"],
            "campaign_ids": ["hyp-999"],
            "evidence": ["/workspace/campaign/results/missing.log"],
            "validated": True,
            "trusted_role_required": True,
        })

        parsed = json.loads(result)
        self.assertFalse(parsed["ready"])
        self.assertIn(
            "trusted-role caveat",
            " ".join(parsed["warnings"]),
        )
        self.assertIn("validated=true without test output", " ".join(parsed["blocking_gaps"]))
        self.assertIn("missing evidence files", " ".join(parsed["blocking_gaps"]))
        self.assertIn("/workspace/campaign/finding-reviews/fr-001.json", container.files)

    async def test_review_report_quality_records_ready_review(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Donation sequence inflates redemption",
            "content": "Donate, deposit, and redeem can increase attacker balance.",
        })
        await _create_experiment(container, {
            "title": "Donation redeem proof",
            "hypothesis_id": "hyp-001",
        })
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )
        await _review_finding_evidence(container, {
            "title": "Donation accounting drains vault",
            "severity": "high",
            "root_cause": "Share minting trusts donated assets before minting.",
            "impact": "Unprivileged attacker can profit after a donation sequence.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Donate assets",
                "Deposit minimal amount",
                "Redeem inflated shares",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validated": True,
            "objective_evaluation": "eval-001",
            "capital_required": "Flash-loan-sized donation plus gas",
            **_exploitability_fields(),
            "trusted_role_required": False,
        })

        result = await _review_report_quality(container, {
            "title": "Donation accounting lets attacker redeem more than deposited",
            "severity": "high",
            "summary": (
                "The vault prices newly minted shares using a balance that can "
                "be inflated by direct donations before the deposit."
            ),
            "root_cause": (
                "The deposit path uses the current token balance as pricing "
                "input, so donated assets influence shares minted for the next "
                "depositor."
            ),
            "impact": (
                "An unprivileged attacker can execute donate, deposit, and "
                "redeem to end with more assets than they started with."
            ),
            "attack_path": [
                "Attacker transfers assets directly into the vault without minting shares.",
                "Attacker deposits a minimal amount while the donated balance skews pricing.",
                "Attacker redeems the minted shares for more assets than the deposit amount.",
            ],
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run forge test --match-test testDonationRedeem -vvv.",
                "Observe the passing test and captured attacker balance delta.",
                "Inspect eval-001 to confirm the objective records positive profit.",
            ],
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validation": "Foundry PoC passes and records attacker profit.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": "Requires temporary donation capital; profit is measured in eval-001.",
            "assumptions": ["No privileged role is required.", "Token transfers are standard ERC20."],
            "limitations": ["None identified."],
            **_exploitability_fields(),
            "remediation": "Exclude unsolicited donations from share pricing or mint shares from pre-transfer assets.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "evidence_review": "fr-001",
            "objective_evaluation": "eval-001",
        })

        self.assertIn('"review_id": "rr-001"', result)
        self.assertIn('"ready": true', result)
        self.assertIn('"blocking_gaps": []', result)
        self.assertIn("/workspace/campaign/report-reviews/rr-001.json", container.files)
        review = container.files["/workspace/campaign/report-reviews/rr-001.json"]
        self.assertIn('"evidence_review"', review)
        self.assertIn('"ready": true', review)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"report_review": 1', state)
        self.assertIn("Report quality review", state)

    async def test_review_report_quality_inherits_affected_code_from_evidence_review(self):
        container = FakeContainer()
        await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Donation sequence inflates redemption",
            "content": "Donate, deposit, and redeem can increase attacker balance.",
        })
        await _create_experiment(container, {
            "title": "Donation redeem proof",
            "hypothesis_id": "hyp-001",
        })
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        await _review_finding_evidence(container, {
            "title": "Donation accounting drains vault",
            "severity": "low",
            "root_cause": "Share minting trusts donated assets before minting.",
            "impact": "Unprivileged attacker can profit after a donation sequence.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Donate assets",
                "Deposit minimal amount",
                "Redeem inflated shares",
            ],
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validated": True,
            "capital_required": "Temporary donation capital plus gas",
            "trusted_role_required": False,
        })

        result = json.loads(await _review_report_quality(container, {
            "title": "Donation accounting lets attacker redeem more than deposited",
            "severity": "low",
            "summary": (
                "The vault prices newly minted shares using a balance that can "
                "be inflated by direct donations before the deposit."
            ),
            "root_cause": (
                "The deposit path uses the current token balance as pricing "
                "input, so donated assets influence shares minted for the next "
                "depositor."
            ),
            "impact": (
                "An unprivileged attacker can execute donate, deposit, and "
                "redeem to end with more assets than they started with."
            ),
            "attack_path": [
                "Attacker transfers assets directly into the vault without minting shares.",
                "Attacker deposits while the donated balance skews pricing.",
                "Attacker redeems the minted shares for more assets.",
            ],
            "reproduction_steps": [
                "Run forge test --match-test testDonationRedeem -vvv.",
                "Observe the passing test and balance delta.",
                "Inspect the result log for the recorded profit.",
            ],
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validation": "Foundry PoC passes and records attacker profit.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": "Temporary donation capital is needed; the result log records profit.",
            "assumptions": ["No privileged role is required."],
            "limitations": ["None identified."],
            "remediation": "Exclude unsolicited donations from share pricing or price from pre-transfer assets.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "evidence_review": "fr-001",
            "record_result": False,
        }))

        self.assertTrue(result["ready"])
        self.assertIn(
            "affected_code inherited from linked evidence review",
            result["warnings"],
        )
        review = json.loads(container.files["/workspace/campaign/report-reviews/rr-001.json"])
        self.assertEqual(
            review["candidate"]["affected_code"],
            [{"file": "src/Vault.sol", "lines": "42-80"}],
        )

    async def test_review_report_quality_inherits_line_refs_inferred_from_evidence(self):
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = (
            "contract Vault { function skim() external {} }"
        )
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        await _review_finding_evidence(container, {
            "title": "Vault skim can spend prefunded ETH",
            "severity": "low",
            "root_cause": "The public skim path spends ETH held by the target.",
            "impact": "Any prefunded target balance can be burned or transferred.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": [
                "/audit/src/Vault.sol:1",
                "/workspace/campaign/results/res-001.log",
            ],
            "reproduction_steps": ["Run the replay."],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "record_result": False,
        })

        result = json.loads(await _review_report_quality(container, {
            "title": "Vault skim can consume prefunded target ETH",
            "severity": "low",
            "summary": (
                "The public skim path can spend value already sitting on the "
                "target when no protocol accounting requires that transfer."
            ),
            "root_cause": (
                "The skim implementation exposes a public value-moving path "
                "without binding the release to authorized protocol accounting."
            ),
            "impact": (
                "An unprivileged caller can consume prefunded ETH on the deployed "
                "target, causing direct loss of that target balance."
            ),
            "attack_path": [
                "Attacker identifies the prefunded deployed target.",
                "Attacker calls the public skim function.",
                "The target balance decreases without an authorized accounting claim.",
            ],
            "reproduction_steps": [
                "Run forge test --match-test testSkimPrefund -vvv.",
                "Observe the passing test and balance delta.",
                "Inspect the result log for the target balance decrease.",
            ],
            "proof_of_concept": "test/reentbot/SkimPrefund.t.sol",
            "validation": "Foundry PoC passes and records the target balance delta.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": "The loss is bounded by the live prefunded target balance.",
            "assumptions": ["The target has a non-zero live balance."],
            "limitations": ["Only prefunded balances are affected."],
            "remediation": "Gate the skim path or bind it to explicit accounting ownership.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "evidence_review": "fr-001",
            "record_result": False,
        }))

        self.assertTrue(result["ready"])
        review = json.loads(container.files["/workspace/campaign/report-reviews/rr-001.json"])
        affected = review["candidate"]["affected_code"][0]
        self.assertEqual(affected["file"], "/audit/src/Vault.sol")
        self.assertEqual(affected["lines"], "1")
        self.assertEqual(affected["source"], "inferred_from_evidence")

    async def test_review_report_quality_carries_sequence_minimization_review(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )
        container.files["/workspace/campaign/minimizations/min-001.json"] = json.dumps({
            "id": "min-001",
            "summary": {
                "baseline_preserved": True,
                "preserved_variants": 1,
                "executed_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
                "setup_checks_executed": 1,
                "setup_checks_preserved": 0,
                "setup_checks_retained": 1,
            },
            "baseline": {
                "log_path": "/workspace/campaign/minimizations/min-001/baseline.log",
            },
            "best_variant": {
                "id": "drop-step-001",
                "kind": "drop_step",
                "log_path": "/workspace/campaign/minimizations/min-001/drop-step-001.log",
            },
            "setup_reduction_summary": {
                "retained_setup": [{
                    "id": "setup-approval",
                    "kind": "approval",
                    "target": "USDC->Vault",
                    "change": "remove approval",
                    "status": "rejected",
                    "label": "approval: USDC->Vault (remove approval)",
                }],
            },
        })
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "ready": True,
            "sequence_minimizations": [{
                "id": "min-001",
                "path": "/workspace/campaign/minimizations/min-001.json",
                "baseline_preserved": True,
                "preserved_variants": 1,
                "executed_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
                "best_variant_id": "drop-step-001",
                "best_variant_log": "/workspace/campaign/minimizations/min-001/drop-step-001.log",
                "setup_checks_executed": 1,
                "setup_checks_retained": 1,
                "retained_setup_assumptions": [{
                    "id": "setup-approval",
                    "kind": "approval",
                    "target": "USDC->Vault",
                    "change": "remove approval",
                    "status": "rejected",
                    "label": "approval: USDC->Vault (remove approval)",
                }],
            }],
        })

        result = await _review_report_quality(container, {
            "title": "Reduced replay demonstrates donation accounting profit",
            "severity": "high",
            "summary": (
                "The final minimized replay demonstrates that donation-skewed "
                "share pricing is sufficient to create attacker profit."
            ),
            "root_cause": (
                "The deposit path prices shares from the live token balance, so "
                "unsolicited donations alter the next mint calculation."
            ),
            "impact": (
                "An unprivileged attacker can use the reduced transaction sequence "
                "to redeem more assets than they deposited."
            ),
            "attack_path": [
                "Attacker donates assets directly into the vault before minting shares.",
                "Attacker deposits a small amount while pricing uses the donated balance.",
                "Attacker redeems inflated shares to realize positive token profit.",
            ],
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run forge test --match-test testDropStep001 -vvv.",
                "Observe drop-step-001 preserving the objective profit marker.",
                "Inspect eval-001 to confirm the attacker balance increases.",
            ],
            "proof_of_concept": "test/reentbot/DropStep001.t.sol",
            "validation": "The minimized drop-step-001 replay passes and preserves profit.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": "Requires temporary donation capital; eval-001 records profit.",
            "assumptions": [
                "No privileged role is required.",
                "Token transfers are standard ERC20.",
                "The USDC->Vault approval remains required for the pull-based deposit.",
            ],
            "limitations": ["None identified."],
            **_exploitability_fields(),
            "remediation": "Exclude donated assets from share pricing or mint from pre-transfer assets.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001", "min-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "evidence_review": "fr-001",
            "objective_evaluation": "eval-001",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["sequence_minimization_count"], 1)
        self.assertEqual(parsed["setup_reduction_check_count"], 1)
        review = json.loads(container.files["/workspace/campaign/report-reviews/rr-001.json"])
        self.assertEqual(
            review["sequence_minimizations"][0]["best_variant_id"],
            "drop-step-001",
        )
        self.assertEqual(review["setup_reduction_check_count"], 1)
        self.assertEqual(
            review["sequence_minimizations"][0]["retained_setup_assumptions"][0]["kind"],
            "approval",
        )

    async def test_review_report_quality_warns_missing_route_composition_evidence(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "ready": True,
            "route_compositions": [{
                "sequence_id": "exp-001",
                "sequence_path": "/workspace/experiments/exp-001-route/sequence.json",
                "strategy": "llm_route_composition_v1",
                "route_count": 1,
                "routes": [{
                    "kind": "flash_loan_route",
                    "title": "Flash-loan/callback route composition",
                    "affordances": ["callback_or_flashloan_surface"],
                    "has_economics_context": True,
                    "missing_context": [],
                    "suggested_tools": [],
                    "evidence_prompts": [
                        "snapshot borrowed balance, premium, callback state, and repayment",
                    ],
                }],
            }],
        })

        result = await _review_report_quality(container, {
            "title": "Borrow path lets attacker extract protocol value",
            "severity": "high",
            "summary": (
                "The final report demonstrates that the borrow path can be "
                "reentered through external execution and leave measurable profit."
            ),
            "root_cause": (
                "The target records accounting state after an external execution "
                "path, so the protected balance can be changed before finalization."
            ),
            "impact": (
                "An unprivileged attacker can complete the transaction sequence "
                "and exit with more protocol assets than they started with."
            ),
            "attack_path": [
                "Attacker enters the borrow path with temporary external capital.",
                "The external execution path changes accounting before finalization.",
                "The attacker exits the sequence with measurable token profit.",
            ],
            "affected_code": [{"file": "src/Lending.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run forge test --match-test testBorrowPathProfit -vvv.",
                "Observe the passing replay and captured profit marker.",
                "Inspect eval-001 to confirm the attacker balance increases.",
            ],
            "proof_of_concept": "test/reentbot/BorrowPathProfit.t.sol",
            "validation": "The replay passes and preserves attacker profit.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": (
                "Requires temporary external capital and leaves measurable token "
                "profit after the final unwind."
            ),
            "assumptions": ["No privileged role is required."],
            "limitations": ["None identified."],
            "remediation": "Finalize accounting before external execution and add a guarded state transition.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "evidence_review": "fr-001",
            "objective_evaluation": "eval-001",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertEqual(parsed["route_composition_count"], 1)
        self.assertIn(
            "report does not describe route evidence for flash_loan_route",
            " ".join(parsed["warnings"]),
        )
        plan = json.loads(await _plan_attack_campaign(container, {
            "title": "Review caveated report route review",
            "max_branches": 1,
            "record_result": False,
        }))
        branch = plan["branches"][0]
        self.assertEqual(branch["source"], "ready_report_review")
        self.assertEqual(branch["recommended_next_tool"], "submit_finding")

    async def test_review_report_quality_warns_missing_minimized_variant_reference(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Suite result: ok. 1 passed; 0 failed\n"
        )
        container.files["/workspace/campaign/evaluations/eval-001.json"] = (
            '{"id":"eval-001","summary":{"passed":1}}\n'
        )
        container.files["/workspace/campaign/minimizations/min-001.json"] = json.dumps({
            "id": "min-001",
            "summary": {
                "baseline_preserved": True,
                "preserved_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
            },
            "baseline": {
                "log_path": "/workspace/campaign/minimizations/min-001/baseline.log",
            },
            "best_variant": {
                "id": "drop-step-001",
                "kind": "drop_step",
                "log_path": "/workspace/campaign/minimizations/min-001/drop-step-001.log",
            },
        })
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "ready": True,
            "sequence_minimizations": [{
                "id": "min-001",
                "path": "/workspace/campaign/minimizations/min-001.json",
                "baseline_preserved": True,
                "preserved_variants": 1,
                "minimal_preserved_variant": "drop-step-001",
                "best_variant_id": "drop-step-001",
            }],
        })

        result = await _review_report_quality(container, {
            "title": "Reduced replay demonstrates donation accounting profit",
            "severity": "high",
            "summary": (
                "The final report demonstrates that donation-skewed share pricing "
                "is sufficient to create attacker profit."
            ),
            "root_cause": (
                "The deposit path prices shares from the live token balance, so "
                "unsolicited donations alter the next mint calculation."
            ),
            "impact": (
                "An unprivileged attacker can use a reduced transaction sequence "
                "to redeem more assets than they deposited."
            ),
            "attack_path": [
                "Attacker donates assets directly into the vault before minting shares.",
                "Attacker deposits a small amount while pricing uses the donated balance.",
                "Attacker redeems inflated shares to realize positive token profit.",
            ],
            "affected_code": [{"file": "src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": [
                "Run forge test --match-test testDonationRedeem -vvv.",
                "Observe the passing replay and captured profit marker.",
                "Inspect eval-001 to confirm the attacker balance increases.",
            ],
            "proof_of_concept": "test/reentbot/DonationRedeem.t.sol",
            "validation": "The replay passes and preserves attacker profit.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": "Requires temporary donation capital; eval-001 records profit.",
            "assumptions": ["No privileged role is required.", "Token transfers are standard ERC20."],
            "limitations": ["None identified."],
            "remediation": "Exclude donated assets from share pricing or mint from pre-transfer assets.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001", "min-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "evidence_review": "fr-001",
            "objective_evaluation": "eval-001",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn(
            "does not reference minimized replay variant drop-step-001",
            " ".join(parsed["warnings"]),
        )

    async def test_review_report_quality_warns_vague_non_economic_impact(self):
        container = FakeContainer()
        self._seed_non_economic_minimization_review(container)

        result = await _review_report_quality(container, {
            "title": "Access disruption replay lacks exact state proof",
            "severity": "high",
            "summary": (
                "The final replay claims a high-impact permissionless access "
                "disruption, but the writeup only describes a generic disruption "
                "marker rather than the concrete protocol condition."
            ),
            "root_cause": (
                "The public function trusts caller-controlled inputs before "
                "checking the protocol authority boundary, so an unprivileged "
                "caller can reach protected behavior."
            ),
            "impact": (
                "An unprivileged caller can disrupt users after invoking the "
                "public function in the replay."
            ),
            "attack_path": [
                "The caller invokes the public management function without a role.",
                "The sequence reaches protected behavior through unchecked inputs.",
                "The drop-step-001 replay preserves the same disruption marker.",
            ],
            "affected_code": [{"file": "src/AccessController.sol", "lines": "40-92"}],
            "reproduction_steps": [
                "Run forge test --match-test testDropStep001 -vvv.",
                "Observe drop-step-001 preserving the access-disruption marker.",
                "Inspect the linked result log for the passing replay output.",
            ],
            "proof_of_concept": "test/reentbot/AccessDisruption.t.sol",
            "validation": "The minimized drop-step-001 replay passes.",
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": (
                "No direct token profit is claimed; validation only states that "
                "user access is disrupted."
            ),
            "assumptions": ["No privileged role is required."],
            "limitations": ["No direct profit is quantified."],
            "remediation": "Check the authority boundary before applying caller input.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "min-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/minimizations/min-001.json",
            ],
            "evidence_review": "fr-001",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertIn(
            "non-economic report should name the attacker-controlled actor",
            " ".join(parsed["warnings"]),
        )

    async def test_review_report_quality_accepts_non_economic_state_proof(self):
        container = FakeContainer()
        self._seed_non_economic_minimization_review(container)

        result = await _review_report_quality(container, {
            "title": "Unprivileged caller can lock withdrawals",
            "severity": "high",
            "summary": (
                "The minimized replay demonstrates that an unprivileged caller "
                "can flip the withdrawal-lock state without holding the guardian "
                "role."
            ),
            "root_cause": (
                "The management path applies the requested lock state before "
                "checking the guardian role, so the access-control boundary is "
                "enforced after the state transition."
            ),
            "impact": (
                "An unprivileged caller sets withdrawalsLocked from false to true, "
                "locking user withdrawals until a privileged actor intervenes."
            ),
            "attack_path": [
                "The caller invokes the public management function without a role.",
                "The unchecked path assigns withdrawalsLocked=true before authorization.",
                "The drop-step-001 replay preserves the unauthorized locked state.",
            ],
            "affected_code": [{"file": "src/AccessController.sol", "lines": "40-92"}],
            "reproduction_steps": [
                "Run forge test --match-test testDropStep001 -vvv.",
                "Observe drop-step-001 asserting withdrawalsLocked changes to true.",
                "Inspect the replay log for before/after lock-state assertions.",
            ],
            "proof_of_concept": "test/reentbot/AccessDisruption.t.sol",
            "validation": (
                "The minimized drop-step-001 replay passes and asserts the "
                "unauthorized state transition."
            ),
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "economic_analysis": (
                "No direct token profit is claimed; the replay snapshots prove "
                "withdrawalsLocked changes from false to true for an unprivileged "
                "caller."
            ),
            "assumptions": ["No privileged role is required."],
            "limitations": ["No direct profit is quantified."],
            **_exploitability_fields(
                funds_at_risk=(
                    "The replay demonstrates withdrawal availability for the "
                    "protocol user set can be locked by an unprivileged caller."
                )
            ),
            "remediation": "Check the guardian role before mutating withdrawal-lock state.",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "min-001"],
            "evidence": [
                "/workspace/campaign/results/res-001.log",
                "/workspace/campaign/minimizations/min-001.json",
            ],
            "evidence_review": "fr-001",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        self.assertEqual(parsed["sequence_minimization_count"], 1)

    async def test_review_report_quality_reports_warnings_for_presentation_gaps(self):
        container = FakeContainer()

        result = await _review_report_quality(container, {
            "title": "Bug",
            "severity": "high",
            "summary": "Bug.",
            "root_cause": "",
            "impact": "Loss.",
            "attack_path": ["Do it"],
            "affected_code": [{"file": "src/Vault.sol"}],
            "reproduction_steps": ["Run test"],
            "campaign_ids": ["hyp-999"],
            "evidence": ["/workspace/campaign/results/missing.log"],
            "test_output": "Suite result: fail. 0 passed; 1 failed",
        })

        parsed = json.loads(result)
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        joined = " ".join(parsed["warnings"])
        self.assertIn("summary is too short or generic", joined)
        self.assertIn("missing root cause", joined)
        self.assertIn("critical/high report is missing evidence review", joined)
        self.assertIn("missing evidence files", joined)
        self.assertIn("reports failing tests", joined)
        self.assertIn("/workspace/campaign/report-reviews/rr-001.json", container.files)

    async def test_create_experiment_writes_scaffold_and_campaign_entry(self):
        container = FakeContainer()

        result = await _create_experiment(container, {
            "title": "Manipulate spot price before borrow",
            "template": "fork_test",
            "hypothesis_id": "hyp-001",
            "notes": "Use a fork and assert bad debt or attacker PnL.",
        })

        self.assertIn("Created experiment exp-001", result)
        self.assertIn("/workspace/experiments/exp-001-manipulate-spot-price-before-borrow/README.md", container.files)
        self.assertIn("/workspace/experiments/exp-001-manipulate-spot-price-before-borrow/ReentbotProExperiment.t.sol", container.files)
        self.assertIn("vm.createFork", container.files[
            "/workspace/experiments/exp-001-manipulate-spot-price-before-borrow/ReentbotProExperiment.t.sol"
        ])
        self.assertIn("pragma solidity >=0.8.0 <0.9.0;", container.files[
            "/workspace/experiments/exp-001-manipulate-spot-price-before-borrow/ReentbotProExperiment.t.sol"
        ])
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "exp-001"', state)
        self.assertIn('"hyp-001"', state)

    async def test_create_experiment_can_skip_placeholder_scaffold(self):
        container = FakeContainer()

        result = await _create_experiment(container, {
            "title": "Custom manager accounting probe",
            "template": "accounting_probe",
            "write_scaffold_contract": False,
            "hypothesis_id": "hyp-001",
        })

        self.assertIn("Created experiment exp-001", result)
        self.assertIn(
            "/workspace/experiments/exp-001-custom-manager-accounting-probe/README.md",
            container.files,
        )
        self.assertNotIn(
            "/workspace/experiments/exp-001-custom-manager-accounting-probe/ReentbotProExperiment.t.sol",
            container.files,
        )
        self.assertIn(
            "No starter Solidity scaffold was written",
            container.files[
                "/workspace/experiments/exp-001-custom-manager-accounting-probe/README.md"
            ],
        )

    async def test_create_experiment_rejects_unapproved_target_dir(self):
        container = FakeContainer()

        result = await _create_experiment(container, {
            "title": "Bad target",
            "target_dir": "/tmp/reentbot",
        })

        self.assertIn("target_dir must be under", result)
        self.assertEqual(container.files, {})

    async def test_create_experiment_rejects_unknown_priority(self):
        container = FakeContainer()

        result = await _create_experiment(container, {
            "title": "Bad priority",
            "priority": "urgent",
        })

        self.assertIn("unknown campaign priority", result)
        self.assertEqual(container.files, {})

    async def test_run_experiment_records_result_and_full_log(self):
        container = FakeContainer()
        container.exec_result = (0, "PASS test_experiment")

        result = await _run_experiment(container, {
            "command": "forge test --match-test test_experiment -vvv",
            "working_dir": "/audit",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
            "interpretation": "Passing test means the scenario is reproducible.",
        })

        self.assertIn("PASS test_experiment", result)
        self.assertIn("Recorded campaign result: res-001 (observed)", result)
        self.assertIn("/workspace/campaign/results/res-001.log", container.files)
        self.assertIn("forge test --match-test", container.files[
            "/workspace/campaign/results/res-001.log"
        ])
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "res-001"', state)
        self.assertIn('"status": "observed"', state)
        self.assertIn('"exp-001"', state)

    async def test_run_experiment_uses_short_default_timeout_for_scripts(self):
        container = FakeContainer()
        container.exec_result = (124, "")

        await _run_experiment(container, {
            "command": "python3 roundtrip_math.py",
            "record_result": False,
        })

        command, _, timeout = container.exec_calls[0]
        self.assertIn("timeout --kill-after=5 90s", command)
        self.assertEqual(timeout, 100)

    async def test_run_experiment_keeps_longer_default_timeout_for_builds(self):
        container = FakeContainer()
        container.exec_result = (0, "compiled")

        await _run_experiment(container, {
            "command": "FOUNDRY_PROFILE=contract_USDY forge build",
            "record_result": False,
        })

        command, _, timeout = container.exec_calls[0]
        self.assertIn("timeout --kill-after=5 600s", command)
        self.assertEqual(timeout, 610)

    async def test_run_experiment_honors_explicit_timeout(self):
        container = FakeContainer()
        container.exec_result = (124, "")

        await _run_experiment(container, {
            "command": "python3 roundtrip_math.py",
            "timeout": 17,
            "record_result": False,
        })

        command, _, timeout = container.exec_calls[0]
        self.assertIn("timeout --kill-after=5 17s", command)
        self.assertEqual(timeout, 27)

    async def test_run_experiment_records_replay_followup_from_sequence_logs(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Vault replay",
            "objective": "Replay a value-moving vault sequence.",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
            }],
            "observations": [{
                "label": "total assets",
                "target": "Vault",
                "call": "totalAssets()(uint256)",
            }],
            "target_addresses": {
                "Vault": "0x0000000000000000000000000000000000001234",
            },
            "success_condition": "Vault assets decrease unexpectedly.",
        })
        container.exec_result = (
            0,
            "\n".join([
                "PASS test_sequence_experiment",
                "Logs:",
                "  before native Vault: 100",
                "  before total assets: 1000",
                "  after native Vault: 90",
                "  after total assets: 900",
            ]),
        )

        result = await _run_experiment(container, {
            "title": "Vault replay run",
            "command": "forge test --match-contract ReentbotProSequence -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })

        self.assertIn("Replay follow-up: /workspace/campaign/results/res-001.followup.json", result)
        self.assertIn("/workspace/campaign/results/res-001.followup.json", container.files)
        followup = json.loads(
            container.files["/workspace/campaign/results/res-001.followup.json"]
        )
        self.assertEqual(followup["summary"]["inline_snapshot_entries"], 4)
        self.assertEqual(followup["summary"]["snapshot_state_templates"], 2)
        self.assertEqual(followup["summary"]["assertion_suggestions"], 2)
        self.assertEqual(followup["summary"]["minimization_variants"], 1)
        self.assertIn("snapshot_state", followup["recommended_tools"])
        self.assertIn("compare_snapshots", followup["recommended_tools"])
        self.assertIn("evaluate_objective", followup["recommended_tools"])
        self.assertIn("run_sequence_minimization", followup["recommended_tools"])
        self.assertEqual(
            followup["sequence_minimization_plan"]["variants"][0]["kind"],
            "parameter_sweep",
        )
        self.assertEqual(
            followup["sequence_minimization_plan"]["setup_reduction"]["summary"]["pranks"],
            1,
        )
        self.assertEqual(
            followup["sequence_minimization_run_template"]["variants"][0]["command"],
            "forge test --match-test test_parameter_sweep_001 -vvv",
        )
        changed = {
            item["metric"]: item
            for item in followup["inline_comparison"]["changed"]
        }
        self.assertEqual(changed["native Vault"]["delta"], -10)
        self.assertEqual(changed["total assets"]["delta"], -100)
        suggestions = {
            item["metric"]: item
            for item in followup["objective_assertion_suggestions"]
        }
        self.assertEqual(suggestions["native Vault"]["direction"], "decrease")
        self.assertIn(
            "Replace TODO reads with live scaffold reads",
            suggestions["native Vault"]["foundry_assertion_snippet"],
        )
        self.assertIn(
            "assertLt(afterNative_Vault, beforeNative_Vault",
            suggestions["native Vault"]["foundry_assertion_snippet"],
        )
        self.assertIn(
            'assertEq(beforeNative_Vault - afterNative_Vault, 10, "native Vault delta changed");',
            suggestions["native Vault"]["foundry_assertion_snippet"],
        )
        before_input = followup["snapshot_state_inputs"]["before"]
        self.assertEqual(before_input["related_ids"], ["exp-001", "hyp-001"])
        self.assertEqual(
            before_input["eth_balances"][0]["address"],
            "0x0000000000000000000000000000000000001234",
        )
        self.assertEqual(
            before_input["calls"][0]["signature"],
            "totalAssets()(uint256)",
        )
        self.assertEqual(
            followup["compare_snapshots_input"]["related_ids"],
            ["exp-001", "hyp-001"],
        )
        self.assertEqual(
            followup["evaluate_objective_input"]["objectives"][0]["unit"],
            "raw",
        )
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn("/workspace/campaign/results/res-001.followup.json", state)

    async def test_run_experiment_diagnoses_blocked_run_for_planner_repair(self):
        container = FakeContainer()
        container.exec_result = (
            1,
            "\n".join([
                "Compiler run failed:",
                "Error (7576): Undeclared identifier.",
                "  --> test/ReentbotProSequence.t.sol:42:9",
            ]),
        )

        result = await _run_experiment(container, {
            "title": "Broken sequence replay",
            "command": "forge test --match-contract ReentbotProSequence -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })

        self.assertIn("Recorded campaign result: res-001 (blocked)", result)
        self.assertIn(
            "Experiment follow-up: /workspace/campaign/results/res-001.followup.json",
            result,
        )
        followup = json.loads(
            container.files["/workspace/campaign/results/res-001.followup.json"]
        )
        self.assertTrue(followup["summary"]["has_failure_diagnosis"])
        self.assertEqual(followup["summary"]["failure_kind"], "compile_error")
        self.assertEqual(followup["failure_diagnosis"]["kind"], "compile_error")
        self.assertEqual(
            followup["failure_diagnosis"]["recommended_next_tool"],
            "run_experiment",
        )
        self.assertIn(
            "Undeclared identifier",
            " ".join(followup["failure_diagnosis"]["evidence_lines"]),
        )
        self.assertIn(
            "placeholder argument variables",
            " ".join(followup["failure_diagnosis"]["compile_repair_hints"]),
        )

        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        self.assertEqual(
            progress["summary"]["blocked_results_without_decisions"],
            1,
        )
        self.assertEqual(
            progress["blocked_results_without_decisions"][0]["failure_diagnosis"]["kind"],
            "compile_error",
        )

        plan = json.loads(await _plan_attack_campaign(container, {
            "record_result": False,
        }))
        branch = plan["branches"][0]
        self.assertEqual(branch["source"], "blocked_result")
        self.assertEqual(branch["failure_diagnosis"]["kind"], "compile_error")
        self.assertEqual(branch["recommended_next_tool"], "run_experiment")
        self.assertIn(
            "fix imports",
            " ".join(branch["required_setup"]),
        )

    async def test_run_experiment_repairs_foundry_checksum_address_once(self):
        container = FakeContainer()
        path = "/audit/test/ReentbotProSequence.t.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[path] = f"contract T {{ address a = {bad}; }}\n"
        container.exec_results = [
            (
                1,
                "\n".join([
                    "Compiler run failed:",
                    "Error (9429): This looks like an address but has an invalid checksum.",
                    f"Correct checksummed address: \"{good}\"",
                    "  --> test/ReentbotProSequence.t.sol:1:26",
                ]),
            ),
            (0, "PASS test_sequence_experiment"),
        ]

        result = await _run_experiment(container, {
            "command": "forge test --match-contract ReentbotProSequence -vvv",
            "working_dir": "/audit",
            "record_result": False,
        })

        self.assertIn("[auto-repair]", result)
        self.assertIn("PASS test_sequence_experiment", result)
        self.assertIn(good, container.files[path])
        self.assertEqual(len(container.exec_calls), 2)

    async def test_run_experiment_does_not_repair_target_source_addresses(self):
        container = FakeContainer()
        path = "/audit/src/Vault.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[path] = f"contract Vault {{ address a = {bad}; }}\n"
        container.exec_result = (
            1,
            "\n".join([
                "Compiler run failed:",
                "Error (9429): This looks like an address but has an invalid checksum.",
                f"Correct checksummed address: \"{good}\"",
                "  --> src/Vault.sol:1:34",
            ]),
        )

        result = await _run_experiment(container, {
            "command": "forge test --match-contract ReentbotProSequence -vvv",
            "working_dir": "/audit",
            "record_result": False,
        })

        self.assertNotIn("[auto-repair]", result)
        self.assertIn(bad, container.files[path])
        self.assertEqual(len(container.exec_calls), 1)

    async def test_run_experiment_honors_string_false_auto_repair(self):
        container = FakeContainer()
        path = "/audit/test/ReentbotProSequence.t.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[path] = f"contract T {{ address a = {bad}; }}\n"
        container.exec_result = (
            1,
            "\n".join([
                "Compiler run failed:",
                "Error (9429): This looks like an address but has an invalid checksum.",
                f"Correct checksummed address: \"{good}\"",
                "  --> test/ReentbotProSequence.t.sol:1:26",
            ]),
        )

        result = await _run_experiment(container, {
            "command": "forge test --match-contract ReentbotProSequence -vvv",
            "working_dir": "/audit",
            "auto_repair": "false",
            "record_result": False,
        })

        self.assertNotIn("[auto-repair]", result)
        self.assertIn(bad, container.files[path])
        self.assertEqual(len(container.exec_calls), 1)

    async def test_run_sequence_minimization_records_preserved_variant(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Minimize vault replay",
            "objective": "Find the shortest sequence that preserves profit.",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "deposit",
                    "args": ["amount"],
                },
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "args": ["amount"],
                },
            ],
            "success_condition": "OBJECTIVE_PASS appears only when profit is preserved.",
        })
        container.exec_results = [
            (0, "baseline\nOBJECTIVE_PASS\nprofit=10\n"),
            (0, "prefix only\nprofit=0\n"),
            (0, "drop deposit\nOBJECTIVE_PASS\nprofit=10\n"),
            (0, "remove prank\nprofit=0\n"),
        ]

        result = await _run_sequence_minimization(container, {
            "title": "Vault replay minimization",
            "sequence": "exp-001",
            "baseline": {
                "command": "forge test --match-test test_sequence_experiment -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            },
            "variants": [
                {
                    "variant_id": "prefix-001",
                    "command": "forge test --match-test test_prefix_001 -vvv",
                    "expected_markers": ["OBJECTIVE_PASS"],
                },
                {
                    "variant_id": "drop-step-001",
                    "command": "forge test --match-test test_drop_step_001 -vvv",
                    "expected_markers": ["OBJECTIVE_PASS"],
                },
            ],
            "setup_checks": [{
                "check_id": "setup-prank-scope",
                "kind": "prank_scope",
                "target": "attacker",
                "change": "remove attacker prank and rerun the minimized replay",
                "command": "forge test --match-test test_setup_without_prank -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            }],
            "related_ids": ["hyp-001", "cmp-001", "eval-001"],
        })

        parsed = json.loads(result)
        self.assertEqual(parsed["minimization_id"], "min-001")
        self.assertEqual(parsed["summary"]["baseline_preserved"], True)
        self.assertEqual(parsed["summary"]["executed_variants"], 2)
        self.assertEqual(parsed["summary"]["preserved_variants"], 1)
        self.assertEqual(parsed["summary"]["minimal_preserved_variant"], "drop-step-001")
        self.assertEqual(parsed["summary"]["available_plan_variants"], 4)
        self.assertEqual(parsed["summary"]["requested_plan_variants"], 2)
        self.assertEqual(parsed["summary"]["untested_plan_variants"], 2)
        self.assertEqual(parsed["summary"]["unplanned_requested_variants"], 0)
        self.assertEqual(parsed["summary"]["setup_checks_executed"], 1)
        self.assertEqual(parsed["summary"]["setup_checks_retained"], 1)
        self.assertEqual(
            parsed["plan_coverage"]["untested_plan_variants"],
            ["drop-step-002", "parameter-sweep-001"],
        )
        self.assertEqual(
            parsed["setup_reduction_summary"]["retained_setup"][0]["kind"],
            "prank_scope",
        )
        self.assertEqual(parsed["best_variant"]["id"], "drop-step-001")
        self.assertEqual(parsed["best_variant"]["kind"], "drop_step")
        self.assertEqual(len(container.exec_calls), 4)
        self.assertIn("/workspace/campaign/minimizations/min-001.json", container.files)
        self.assertIn("/workspace/campaign/minimizations/min-001/baseline.log", container.files)
        self.assertIn("/workspace/campaign/minimizations/min-001/prefix-001.log", container.files)
        self.assertIn("/workspace/campaign/minimizations/min-001/drop-step-001.log", container.files)
        self.assertIn("/workspace/campaign/minimizations/min-001/setup-prank-scope.log", container.files)
        artifact = json.loads(
            container.files["/workspace/campaign/minimizations/min-001.json"]
        )
        self.assertEqual(artifact["variants"][0]["status"], "rejected")
        self.assertEqual(
            artifact["variants"][0]["missing_expected_markers"],
            ["OBJECTIVE_PASS"],
        )
        self.assertEqual(artifact["variants"][1]["status"], "preserved")
        self.assertEqual(artifact["setup_checks"][0]["status"], "rejected")
        self.assertEqual(artifact["setup_checks"][0]["setup_outcome"], "retained")
        self.assertEqual(artifact["related_ids"], ["exp-001", "hyp-001", "cmp-001", "eval-001"])
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"sequence_minimization": 1', state)
        self.assertIn('"id": "res-001"', state)
        self.assertIn("/workspace/campaign/minimizations/min-001.json", state)
        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        self.assertEqual(
            progress["summary"]["sequence_minimizations_without_review"],
            1,
        )
        self.assertEqual(
            progress["sequence_minimizations_without_review"][0]["id"],
            "min-001",
        )
        self.assertEqual(
            progress["sequence_minimizations_without_review"][0]["summary"][
                "setup_checks_retained"
            ],
            1,
        )
        self.assertEqual(
            progress["sequence_minimizations_without_review"][0]["summary"][
                "untested_plan_variants"
            ],
            2,
        )
        self.assertEqual(
            progress["sequence_minimizations_without_review"][0]["summary"][
                "retained_setup_assumptions"
            ][0]["kind"],
            "prank_scope",
        )
        await _build_campaign_brief(container, {
            "record_result": False,
        })
        brief = json.loads(container.files["/workspace/campaign/brief.json"])
        self.assertEqual(
            brief["latest_artifacts"]["sequence_minimizations"][0]["id"],
            "min-001",
        )
        self.assertEqual(
            brief["active_work"]["sequence_minimizations_without_review"][0]["id"],
            "min-001",
        )
        self.assertEqual(
            brief["suggested_next"]["tool"],
            "review_finding_evidence",
        )
        plan = json.loads(await _plan_attack_campaign(container, {
            "record_result": False,
        }))
        self.assertEqual(
            plan["branches"][0]["source"],
            "unreviewed_sequence_minimization",
        )
        self.assertEqual(
            plan["branches"][0]["recommended_next_tool"],
            "review_finding_evidence",
        )
        self.assertEqual(
            plan["branches"][0]["setup_reduction_context"][
                "setup_checks_retained"
            ],
            1,
        )
        self.assertIn(
            "challenge retained setup assumptions",
            " ".join(plan["branches"][0]["required_setup"]),
        )
        self.assertIn(
            "review untested minimization variants",
            " ".join(plan["branches"][0]["required_setup"]),
        )
        self.assertEqual(
            plan["branches"][0]["minimization_plan_context"][
                "untested_plan_variants"
            ],
            2,
        )
        self.assertIn(
            "mutate_hypothesis",
            plan["branches"][0]["stop_or_mutate_condition"],
        )

    async def test_run_sequence_minimization_skips_variants_when_baseline_fails(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Baseline fails",
            "objective": "Check baseline before variant runs.",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
            }],
            "success_condition": "OBJECTIVE_PASS proves impact.",
        })
        container.exec_results = [(0, "baseline did not reproduce\n")]

        result = await _run_sequence_minimization(container, {
            "sequence": "exp-001",
            "baseline": {
                "command": "forge test --match-test test_sequence_experiment -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            },
            "variants": [{
                "variant_id": "parameter-sweep-001",
                "command": "forge test --match-test test_parameter_sweep -vvv",
                "expected_markers": ["OBJECTIVE_PASS"],
            }],
        })

        parsed = json.loads(result)
        self.assertEqual(parsed["summary"]["baseline_preserved"], False)
        self.assertEqual(parsed["summary"]["executed_variants"], 0)
        self.assertEqual(parsed["summary"]["skipped_variants"], 1)
        self.assertIsNone(parsed["best_variant"])
        self.assertEqual(len(container.exec_calls), 1)
        artifact = json.loads(
            container.files["/workspace/campaign/minimizations/min-001.json"]
        )
        self.assertEqual(artifact["variants"][0]["status"], "skipped")
        self.assertEqual(
            artifact["variants"][0]["reason"],
            "baseline did not preserve expected markers",
        )

    async def test_run_campaign_fuzz_records_candidate_failure(self):
        container = FakeContainer()
        container.exec_result = (
            1,
            "\n".join([
                "Failing tests:",
                "Encountered 1 failing test in test/ReentbotProInvariant.t.sol",
                "[FAIL. Reason: invariant_campaignInvariant()]",
                "Call sequence:",
                "  Handler.deposit(1)",
                "  Handler.withdraw(2)",
                "Suite result: FAILED. 0 passed; 1 failed",
            ]),
        )

        result = await _run_campaign_fuzz(container, {
            "title": "Invariant handler campaign",
            "command": "forge test --match-contract ReentbotProInvariant -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
            "invariant_id": "inv-001",
        })

        self.assertIn('"fuzz_run_id": "fuzz-001"', result)
        self.assertIn('"outcome": "candidate_failure"', result)
        self.assertIn("Call sequence", result)
        self.assertIn("/workspace/campaign/fuzz-runs/fuzz-001.json", container.files)
        self.assertIn("/workspace/campaign/fuzz-runs/fuzz-001.log", container.files)
        fuzz_run = json.loads(
            container.files["/workspace/campaign/fuzz-runs/fuzz-001.json"]
        )
        self.assertTrue(fuzz_run["summary"]["candidate_failure"])
        self.assertEqual(fuzz_run["related_ids"], ["exp-001", "hyp-001", "inv-001"])
        progress = await _review_campaign_progress(container, {
            "record_result": False,
        })
        self.assertIn('"candidate_fuzz_failures": 1', progress)
        plan = await _plan_attack_campaign(container, {
            "record_result": False,
        })
        self.assertIn('"source": "candidate_fuzz_failure"', plan)
        self.assertIn('"recommended_next_tool": "summarize_trace or extract_call_sequence"', plan)
        brief = await _build_campaign_brief(container, {
            "record_result": False,
        })
        self.assertIn('"tool": "summarize_trace or extract_call_sequence"', brief)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"fuzz_run": 1', state)
        self.assertIn('"id": "res-001"', state)
        self.assertIn('"fuzz-001"', state)

    async def test_snapshot_state_records_probe_values(self):
        container = FakeContainer()
        container.exec_results = [
            (0, "100\n"),
            (0, "250\n"),
            (0, "0xabc\n"),
            (0, "42\n"),
        ]

        result = await _snapshot_state(container, {
            "title": "Before borrow",
            "rpc_url": "http://localhost:8545",
            "eth_balances": [{
                "label": "attacker",
                "address": "0x0000000000000000000000000000000000000001",
            }],
            "erc20_balances": [{
                "token_label": "USDC",
                "token": "0x0000000000000000000000000000000000000002",
                "account_label": "vault",
                "account": "0x0000000000000000000000000000000000000003",
            }],
            "storage_slots": [{
                "label": "slot0",
                "contract": "0x0000000000000000000000000000000000000004",
                "slot": "0",
            }],
            "calls": [{
                "label": "totalAssets",
                "target": "0x0000000000000000000000000000000000000005",
                "signature": "totalAssets()(uint256)",
            }],
            "related_ids": ["exp-001"],
        })

        self.assertIn('"snapshot_id": "snap-001"', result)
        self.assertIn("/workspace/campaign/snapshots/snap-001.json", container.files)
        snapshot = container.files["/workspace/campaign/snapshots/snap-001.json"]
        self.assertIn('"value": "100"', snapshot)
        self.assertIn('"value": "250"', snapshot)
        self.assertIn('"value": "0xabc"', snapshot)
        self.assertIn('"value": "42"', snapshot)
        self.assertIn("balanceOf(address)(uint256)", container.exec_calls[1][0])
        # The resolved endpoint runs the probes but its URL is redacted from the
        # stored snapshot, and an rpc_endpoint provenance summary is recorded.
        self.assertIn("--rpc-url http://localhost:8545", container.exec_calls[1][0])
        self.assertNotIn("http://localhost:8545", snapshot)
        self.assertIn("<rpc_url>", snapshot)
        self.assertIn('"rpc_endpoint"', snapshot)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "res-001"', state)
        self.assertIn("State snapshot: Before borrow", state)

    async def test_snapshot_state_rejects_empty_probe_set(self):
        container = FakeContainer()

        result = await _snapshot_state(container, {
            "title": "Empty snapshot",
        })

        self.assertIn("requires at least one probe", result)
        self.assertEqual(container.files, {})

    async def test_snapshot_state_rejects_non_object_probe(self):
        container = FakeContainer()

        result = await _snapshot_state(container, {
            "title": "Bad probe",
            "eth_balances": ["0x1"],
        })

        self.assertIn("eth_balances entries must be objects", result)
        self.assertEqual(container.files, {})

    async def test_compare_snapshots_records_numeric_delta(self):
        container = FakeContainer()
        container.files["/workspace/campaign/snapshots/snap-001.json"] = """
{
  "id": "snap-001",
  "title": "before",
  "probes": {
    "eth_balances": [
      {
        "label": "attacker",
        "address": "0x1",
        "ok": true,
        "value": "100"
      }
    ]
  }
}
"""
        container.files["/workspace/campaign/snapshots/snap-002.json"] = """
{
  "id": "snap-002",
  "title": "after",
  "probes": {
    "eth_balances": [
      {
        "label": "attacker",
        "address": "0x1",
        "ok": true,
        "value": "175"
      }
    ]
  }
}
"""

        result = await _compare_snapshots(container, {
            "before": "snap-001",
            "after": "snap-002",
            "related_ids": ["exp-001"],
        })

        self.assertIn('"comparison_id": "cmp-001"', result)
        self.assertIn('"delta": 75', result)
        self.assertIn("/workspace/campaign/comparisons/cmp-001.json", container.files)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "res-001"', state)
        self.assertIn("Snapshot comparison", state)

    async def test_compare_snapshots_rejects_paths_outside_snapshot_dir(self):
        container = FakeContainer()

        result = await _compare_snapshots(container, {
            "before": "/workspace/campaign/results/res-001.log",
            "after": "snap-002",
        })

        self.assertIn("absolute snapshot paths must be under", result)

    async def test_evaluate_objective_records_scaled_delta(self):
        container = FakeContainer()
        container.files["/workspace/campaign/comparisons/cmp-001.json"] = """
{
  "id": "cmp-001",
  "title": "attacker pnl",
  "changed": [
    {
      "key": "erc20:USDC:0xtoken:attacker:0xattacker",
      "kind": "erc20_balances",
      "before": "1000000",
      "after": "2500000",
      "delta": 1500000
    },
    {
      "key": "erc20:USDC:0xtoken:vault:0xvault",
      "kind": "erc20_balances",
      "before": "5000000",
      "after": "3500000",
      "delta": -1500000
    }
  ]
}
"""

        result = await _evaluate_objective(container, {
            "comparison": "cmp-001",
            "objectives": [{
                "label": "attacker USDC profit",
                "match": "attacker",
                "direction": "increase",
                "decimals": 6,
                "unit": "USDC",
                "price_usd": "1",
                "role": "attacker",
            }],
            "related_ids": ["exp-001", "hyp-001"],
        })

        self.assertIn('"evaluation_id": "eval-001"', result)
        self.assertIn('"delta": "1.5"', result)
        self.assertIn('"usd_delta": "1.5"', result)
        self.assertIn('"passed": true', result)
        self.assertIn("/workspace/campaign/evaluations/eval-001.json", container.files)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"evaluation": 1', state)
        self.assertIn("Objective evaluation", state)
        self.assertIn('"exp-001"', state)

    async def test_compare_snapshots_suggests_exact_key_objectives(self):
        container = FakeContainer()
        container.files["/workspace/campaign/snapshots/snap-001.json"] = json.dumps({
            "id": "snap-001",
            "probes": {
                "erc20_balances": [{
                    "token_label": "USDC",
                    "token": "0xtoken",
                    "account_label": "attacker",
                    "account": "0xattacker",
                    "ok": True,
                    "value": "1000000",
                }],
            },
        })
        container.files["/workspace/campaign/snapshots/snap-002.json"] = json.dumps({
            "id": "snap-002",
            "probes": {
                "erc20_balances": [{
                    "token_label": "USDC",
                    "token": "0xtoken",
                    "account_label": "attacker",
                    "account": "0xattacker",
                    "ok": True,
                    "value": "2500000",
                }],
            },
        })

        comparison = json.loads(await _compare_snapshots(container, {
            "before": "snap-001",
            "after": "snap-002",
            "record_result": False,
        }))
        objective = comparison["suggested_objectives"][0]
        self.assertEqual(
            objective["key"],
            "erc20:USDC:0xtoken:attacker:0xattacker",
        )
        self.assertEqual(objective["direction"], "increase")

        evaluation = json.loads(await _evaluate_objective(container, {
            "comparison": "cmp-001",
            "objectives": [{
                "label": "exact attacker key",
                "key": objective["key"],
                "direction": "increase",
                "decimals": 6,
                "unit": "USDC",
            }],
            "record_result": False,
        }))

        self.assertEqual(evaluation["summary"]["passed"], 1)
        self.assertEqual(evaluation["objectives"][0]["matches"][0]["delta"], "1.5")

    async def test_evaluate_objective_rejects_empty_objectives(self):
        container = FakeContainer()
        container.files["/workspace/campaign/comparisons/cmp-001.json"] = """
{
  "id": "cmp-001",
  "changed": [{
    "key": "erc20:USDC:0xtoken:attacker:0xattacker",
    "kind": "erc20_balances",
    "before": "0",
    "after": "1",
    "delta": 1
  }]
}
"""

        result = await _evaluate_objective(container, {
            "comparison": "cmp-001",
            "objectives": [],
        })

        self.assertIn("requires at least one objective", result)
        self.assertIn("Suggested objective examples", result)
        self.assertIn("erc20:USDC:0xtoken:attacker:0xattacker", result)

    async def test_record_fork_context_records_targets_and_validation(self):
        container = FakeContainer()
        container.exec_results = [
            (0, "1"),
            (0, "19000000"),
            (0, "0x6001600055"),
            (0, "0x6002600055"),
            (0, "1000000000000000000"),
            (0, "6"),
            (0, "USDC"),
        ]

        result = await _record_fork_context(container, {
            "title": "Mainnet vault fork context",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19000000,
            "rpc_url": "https://rpc.example/secret",
            "contracts": [{
                "label": "Vault",
                "address": "0x0000000000000000000000000000000000001000",
                "kind": "vault",
            }],
            "tokens": [{
                "symbol": "USDC",
                "address": "0x0000000000000000000000000000000000002000",
            }],
            "actors": [{
                "label": "attacker",
                "address": "0x000000000000000000000000000000000000a11c",
            }],
            "assumptions": ["Use a mainnet fork at block 19000000."],
            "related_ids": ["hyp-001"],
            "validate": True,
        })

        self.assertIn('"context_id": "fc-001"', result)
        self.assertIn('"code_present": true', result)
        self.assertIn('"parsed": 6', result)
        self.assertIn('"Vault"', result)
        self.assertIn('"USDC"', result)
        self.assertIn("/workspace/campaign/fork-contexts/fc-001.json", container.files)
        context = container.files["/workspace/campaign/fork-contexts/fc-001.json"]
        self.assertIn('"target_addresses"', context)
        self.assertIn("0x0000000000000000000000000000000000001000", context)
        self.assertNotIn("https://rpc.example/secret", context)
        self.assertIn("<rpc_url>", context)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"fork_context": 1', state)
        self.assertIn("Fork context", state)
        self.assertEqual(len(container.exec_calls), 7)

    async def test_record_fork_context_rejects_bad_collection_shape(self):
        container = FakeContainer()

        result = await _record_fork_context(container, {
            "title": "Bad context",
            "contracts": "not a list",
        })

        self.assertIn("contracts must be a list", result)
        self.assertEqual(container.files, {})

    async def test_estimate_amm_economics_records_manual_reserve_estimate(self):
        container = FakeContainer()

        result = await _estimate_amm_economics(container, {
            "title": "USDC price move",
            "pools": [{
                "label": "WETH/USDC",
                "reserve_in": "10000",
                "reserve_out": "20000",
                "amount_in": "1000",
                "fee_bps": 30,
                "token_in_decimals": 0,
                "token_out_decimals": 0,
                "token_in_symbol": "WETH",
                "token_out_symbol": "USDC",
                "token_in_price_usd": "2000",
                "token_out_price_usd": "1",
                "target_price_decrease_bps": 1000,
            }],
            "related_ids": ["hyp-001", "exp-001"],
        })

        self.assertIn('"economics_id": "econ-001"', result)
        self.assertIn('"amount_out_raw": 1813', result)
        self.assertIn('"capital_usd": "2000000"', result)
        self.assertIn('"target_price_decrease"', result)
        self.assertIn("/workspace/campaign/economics/econ-001.json", container.files)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"economics": 1', state)
        self.assertIn("AMM economics estimate", state)
        self.assertIn('"hyp-001"', state)

    async def test_estimate_amm_economics_records_route_sensitivity(self):
        container = FakeContainer()

        result = await _estimate_amm_economics(container, {
            "title": "Two-hop route",
            "pools": [
                {
                    "label": "A/B",
                    "reserve_in": "10000",
                    "reserve_out": "20000",
                    "amount_in": "1000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                    "token_in_symbol": "A",
                    "token_out_symbol": "B",
                },
                {
                    "label": "B/C",
                    "reserve_in": "20000",
                    "reserve_out": "10000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                    "token_in_symbol": "B",
                    "token_out_symbol": "C",
                },
            ],
            "sensitivity_multipliers": ["0.5", "1", "2"],
            "record_result": False,
        })

        parsed = json.loads(result)
        self.assertEqual(parsed["summary"]["legs"], 2)
        self.assertEqual(parsed["summary"]["final_amount_out_raw"], 828)
        self.assertEqual(parsed["summary"]["sensitivity_points"], 3)
        self.assertEqual(
            [row["multiplier"] for row in parsed["route_sensitivity"]],
            ["0.5", "1", "2"],
        )
        self.assertEqual(parsed["route_sensitivity"][1]["final_amount_out_raw"], 828)
        self.assertEqual(parsed["route_sensitivity"][1]["legs"][0]["amount_out_raw"], 1813)

    async def test_estimate_amm_economics_can_query_pair_reserves(self):
        container = FakeContainer()
        container.exec_results = [(0, "10000\n20000\n12345\n")]

        result = await _estimate_amm_economics(container, {
            "pools": [{
                "label": "Pair lookup",
                "pair": "0x0000000000000000000000000000000000000001",
                "token_in_index": 1,
                "amount_in": "1000",
                "fee_bps": 30,
                "token_in_decimals": 0,
                "token_out_decimals": 0,
            }],
            "rpc_url": "http://localhost:8545",
            "record_result": False,
        })

        self.assertIn('"economics_id": "econ-001"', result)
        self.assertIn('"reserve_in_raw": 20000', result)
        self.assertIn('"reserve_out_raw": 10000', result)
        self.assertIn("getReserves", container.exec_calls[0][0])
        self.assertIn("--rpc-url http://localhost:8545", container.exec_calls[0][0])

    async def test_estimate_amm_economics_rejects_empty_pools(self):
        container = FakeContainer()

        result = await _estimate_amm_economics(container, {
            "pools": [],
        })

        self.assertIn("requires at least one pool", result)

    async def test_estimate_flash_loan_records_fee_and_liquidity(self):
        container = FakeContainer()

        result = await _estimate_flash_loan(container, {
            "title": "USDC flash capital",
            "assets": [{
                "symbol": "USDC",
                "amount_decimal": "1000",
                "decimals": 6,
                "fee_bps": 9,
                "available_liquidity_decimal": "5000",
                "price_usd": "1",
            }],
            "related_ids": ["hyp-001", "econ-001"],
        })

        self.assertIn('"flash_loan_id": "flash-001"', result)
        self.assertIn('"amount": "1000"', result)
        self.assertIn('"fee": "0.9"', result)
        self.assertIn('"repayment": "1000.9"', result)
        self.assertIn('"liquidity_sufficient": true', result)
        self.assertIn('"total_fee_usd": "0.9"', result)
        self.assertIn("/workspace/campaign/economics/flash-001.json", container.files)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"flash_loan": 1', state)
        self.assertIn("Flash-loan estimate", state)
        self.assertIn('"econ-001"', state)

    async def test_estimate_flash_loan_can_query_provider_balance(self):
        container = FakeContainer()
        container.exec_results = [(0, "2500000000\n")]

        result = await _estimate_flash_loan(container, {
            "assets": [{
                "symbol": "USDC",
                "asset": "0x0000000000000000000000000000000000000001",
                "provider": "0x0000000000000000000000000000000000000002",
                "amount_decimal": "1000",
                "decimals": 6,
                "fee_bps": 5,
            }],
            "rpc_url": "http://localhost:8545",
            "record_result": False,
        })

        self.assertIn('"flash_loan_id": "flash-001"', result)
        self.assertIn('"available_liquidity": "2500"', result)
        self.assertIn('"liquidity_sufficient": true', result)
        self.assertIn("balanceOf(address)(uint256)", container.exec_calls[0][0])
        self.assertIn("--rpc-url http://localhost:8545", container.exec_calls[0][0])

    async def test_estimate_flash_loan_rejects_empty_assets(self):
        container = FakeContainer()

        result = await _estimate_flash_loan(container, {
            "assets": [],
        })

        self.assertIn("requires at least one asset", result)

    async def test_estimate_lending_health_records_liquidation_sensitivity(self):
        container = FakeContainer()

        result = await _estimate_lending_health(container, {
            "title": "Collateral price manipulation health",
            "positions": [
                {
                    "label": "before manipulation",
                    "collateral_amount_decimal": "2",
                    "collateral_decimals": 18,
                    "collateral_price_usd": "2000",
                    "liquidation_threshold_bps": 8000,
                    "debt_amount_decimal": "2500",
                    "debt_decimals": 6,
                    "debt_price_usd": "1",
                    "liquidation_bonus_bps": 500,
                },
                {
                    "label": "after collateral price drop",
                    "collateral_amount_decimal": "2",
                    "collateral_decimals": 18,
                    "collateral_price_usd": "2000",
                    "collateral_price_shift_bps": -3000,
                    "liquidation_threshold_bps": 8000,
                    "debt_amount_decimal": "2500",
                    "debt_decimals": 6,
                    "debt_price_usd": "1",
                    "liquidation_bonus_bps": 500,
                },
            ],
            "related_ids": ["hyp-001"],
        })

        parsed = json.loads(result)
        self.assertEqual(parsed["economics_id"], "econ-001")
        self.assertEqual(parsed["summary"]["liquidatable_positions"], 1)
        self.assertEqual(parsed["summary"]["min_health_factor"], "0.896")
        self.assertEqual(parsed["summary"]["total_shortfall_usd"], "260")
        self.assertEqual(parsed["positions"][0]["health_factor"], "1.28")
        self.assertEqual(
            parsed["positions"][0]["price_drop_to_liquidation_bps"],
            "2187.5",
        )
        self.assertTrue(parsed["positions"][1]["liquidatable"])
        self.assertEqual(parsed["positions"][1]["shortfall_usd"], "260")
        self.assertIn("/workspace/campaign/economics/econ-001.json", container.files)
        artifact = container.files["/workspace/campaign/economics/econ-001.json"]
        self.assertIn("Lending health-factor estimate", artifact)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"economics": 1', state)
        self.assertIn("Lending health estimate", state)

    async def test_estimate_lending_health_rejects_empty_positions(self):
        container = FakeContainer()

        result = await _estimate_lending_health(container, {
            "positions": [],
        })

        self.assertIn("requires at least one position", result)

    async def test_summarize_trace_records_calls_and_result(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = """
[PASS] test_attack_path() (gas: 123456)
Traces:
  ├─ [1234] Vault::deposit(100)
  │  ├─ [567] ERC20::transferFrom(attacker, vault, 100)
  │  └─ emit Transfer(from: attacker, to: vault, value: 100)
  ├─ [999] Vault::borrow(200)
  │  └─ [111] ERC20::transfer(attacker, 200)
  └─ [321] Oracle::latestAnswer()
Suite result: ok. 1 passed; 0 failed; 0 skipped
"""
        container.exec_results = [(0, "420\n")]

        result = await _summarize_trace(container, {
            "path": "/workspace/campaign/results/res-001.log",
            "title": "Attack path trace",
            "related_ids": ["exp-001", "res-001"],
        })

        self.assertIn('"trace_id": "trace-001"', result)
        self.assertIn('"call": "Vault::deposit"', result)
        self.assertIn('"call": "ERC20::transferFrom"', result)
        self.assertIn('"event": "Transfer"', result)
        self.assertIn("/workspace/campaign/traces/trace-001.json", container.files)
        summary = container.files["/workspace/campaign/traces/trace-001.json"]
        self.assertIn('"total": 5', summary)
        self.assertIn('"path": "/workspace/campaign/results/res-001.log"', summary)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"trace": 1', state)
        self.assertIn('"id": "res-001"', state)
        self.assertIn("Trace summary: Attack path trace", state)

    async def test_summarize_trace_rejects_unapproved_path(self):
        container = FakeContainer()

        result = await _summarize_trace(container, {
            "path": "/etc/passwd",
        })

        self.assertIn("trace path must be under", result)

    async def test_extract_call_sequence_matches_action_space(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = """
[FAIL] invariant_campaignInvariant()
Traces:
  ├─ [1234] Vault::deposit(100)
  │  ├─ [567] ERC20::transferFrom(attacker, vault, 100)
  ├─ [999] Vault::withdraw(150)
  └─ [321] Oracle::latestAnswer()
"""
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "mutability": "nonpayable",
      "affordances": ["value_in_or_mint"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "mutability": "nonpayable",
      "affordances": ["value_out_or_burn"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": []
}
"""

        result = await _extract_call_sequence(container, {
            "path": "/workspace/campaign/results/res-001.log",
            "title": "Invariant failure sequence",
            "action_space": "as-001",
            "related_ids": ["exp-001", "res-001"],
        })

        self.assertIn('"sequence_id": "seq-001"', result)
        self.assertIn('"steps": 2', result)
        self.assertIn('"contract": "Vault"', result)
        self.assertIn('"function": "deposit"', result)
        self.assertIn('"function": "withdraw"', result)
        self.assertNotIn('"contract": "ERC20"', result)
        self.assertIn("/workspace/campaign/sequences/seq-001.json", container.files)
        sequence = container.files["/workspace/campaign/sequences/seq-001.json"]
        self.assertIn('"action_space_path"', sequence)
        self.assertIn('"skipped_unmatched": 2', sequence)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"call_sequence": 1', state)
        self.assertIn("Extracted call sequence", state)

    async def test_extract_call_sequence_can_reduce_fuzz_run_log(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "mutability": "nonpayable",
      "affordances": ["value_in_or_mint"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "mutability": "nonpayable",
      "affordances": ["value_out_or_burn"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": []
}
"""
        container.exec_result = (
            1,
            "\n".join([
                "Failing tests:",
                "[FAIL. Reason: invariant_campaignInvariant()]",
                "Call sequence:",
                "  Handler.deposit(100)",
                "  Handler.withdraw(150)",
                "Suite result: FAILED. 0 passed; 1 failed",
            ]),
        )
        await _run_campaign_fuzz(container, {
            "title": "Invariant handler campaign",
            "command": "forge test --match-contract ReentbotProInvariant -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
            "invariant_id": "inv-001",
        })
        container.exec_result = (0, "")

        result = await _extract_call_sequence(container, {
            "fuzz_run": "fuzz-001",
            "title": "Reduced fuzz sequence",
            "action_space": "as-001",
            "related_ids": ["hyp-001"],
        })

        self.assertIn('"sequence_id": "seq-001"', result)
        self.assertIn('"fuzz_run": "/workspace/campaign/fuzz-runs/fuzz-001.json"', result)
        self.assertIn('"steps": 2', result)
        self.assertIn('"replay_steps": 2', result)
        self.assertIn('"matched": 2', result)
        self.assertIn('"contract": "Handler"', result)
        self.assertIn('"function": "deposit"', result)
        sequence = container.files["/workspace/campaign/sequences/seq-001.json"]
        self.assertIn('"fuzz_run_path"', sequence)
        self.assertIn('"reduction"', sequence)
        self.assertIn('"generated_harness_noise_filter_v1"', sequence)
        self.assertIn('/workspace/campaign/fuzz-runs/fuzz-001.log', sequence)
        self.assertIn('"fuzz-001"', sequence)
        progress = await _review_campaign_progress(container, {
            "record_result": False,
        })
        self.assertIn('"candidate_fuzz_failures": 0', progress)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"call_sequence": 1', state)
        self.assertIn("Fuzz run: /workspace/campaign/fuzz-runs/fuzz-001.json", state)

    async def test_extract_call_sequence_filters_generated_harness_noise_for_replay(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = """
Logs:
  ReentbotProSequence._snapshot(before)
  Vault.deposit(100)
  ReentbotProSequence._observeAfter()
  Vault.withdraw(150)
"""

        result = await _extract_call_sequence(container, {
            "path": "/workspace/campaign/results/res-001.log",
            "title": "Noisy sequence",
            "include_unmatched": True,
        })

        self.assertIn('"steps": 4', result)
        self.assertIn('"replay_steps": 2', result)
        self.assertIn('"removed_noise_steps": 2', result)
        sequence = json.loads(container.files["/workspace/campaign/sequences/seq-001.json"])
        self.assertEqual(
            sequence["reduction"]["kept_step_indices"],
            [2, 4],
        )
        self.assertEqual(sequence["reduction"]["summary"]["removed"], 2)

        compose_result = await _compose_sequence_experiment(container, {
            "title": "Replay noisy sequence",
            "objective": "Replay only value-moving calls.",
            "call_sequence": "seq-001",
        })

        self.assertIn('"experiment_id": "exp-001"', compose_result)
        workspace = "/workspace/experiments/exp-001-replay-noisy-sequence"
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("vault.deposit(100)", contract)
        self.assertIn("vault.withdraw(150)", contract)
        self.assertNotIn("ReentbotProSequence._snapshot", contract)
        plan = container.files[f"{workspace}/sequence.json"]
        self.assertIn('"function": "deposit"', plan)
        self.assertIn('"function": "withdraw"', plan)
        self.assertNotIn('"_snapshot"', plan)

    async def test_map_action_space_records_protocol_actions(self):
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Vault {
    IERC20 public asset;
    address public owner;

    event Deposited(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external onlyOwner {
        asset.transfer(msg.sender, amount);
    }

    function totalAssets() external view returns (uint256) {
        return 1;
    }
}
"""

        result = await _map_action_space(container, {
            "files": ["/audit/src/Vault.sol"],
            "related_ids": ["pm-001"],
        })

        self.assertIn('"action_space_id": "as-001"', result)
        self.assertIn('"function": "deposit"', result)
        self.assertIn('"function": "withdraw"', result)
        self.assertIn('"function": "totalAssets"', result)
        self.assertIn('"value_in_or_mint"', result)
        self.assertIn('"value_out_or_burn"', result)
        self.assertIn('"modifier": "onlyOwner"', result)
        self.assertIn("/workspace/campaign/action-spaces/as-001.json", container.files)
        action_space = container.files["/workspace/campaign/action-spaces/as-001.json"]
        self.assertIn('"actions": 4', action_space)
        self.assertIn('"observations": 3', action_space)
        self.assertIn('"role_gate_hints": 1', action_space)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"action_space": 1', state)
        self.assertIn("Action-space map", state)
        progress = await _review_campaign_progress(container, {
            "record_result": False,
        })
        self.assertIn('"action_spaces_without_coverage": 1', progress)

    async def test_map_action_space_limits_broad_instascope_roots(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [
                {"contract": "Top", "src": "/audit/src/Top_1111"},
                {"contract": "Bottom", "src": "/audit/src/Bottom_2222"},
            ],
        })
        container.files["/audit/src/Top_1111/Top.sol"] = """
pragma solidity ^0.8.20;
contract Top {
    function withdraw(uint256 amount) external {}
}
"""
        container.exec_result = (0, "/audit/src/Top_1111/Top.sol\n")

        # Isolate the discovery-scan behavior from the AST compile path so the
        # single-exec assertion stays meaningful.
        with mock.patch.dict(
            os.environ, {"REENTBOTPRO_DISABLE_AST_MAP": "1"}
        ):
            result = await _map_action_space(container, {
                "path": "/audit/src",
                "max_roots": 1,
                "record_result": False,
            })

        self.assertIn('"action_space_id": "as-001"', result)
        self.assertEqual(len(container.exec_calls), 1)
        self.assertIn("/audit/src/Top_1111", container.exec_calls[0][0])
        self.assertNotIn("/audit/src/Bottom_2222", container.exec_calls[0][0])
        action_space = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        self.assertEqual(action_space["source"]["profile_roots_limit"], 1)
        self.assertEqual(action_space["source"]["files_scanned"], 1)

    async def test_map_action_space_resolves_src_relative_files_under_src_root(self):
        container = FakeContainer()
        container.files["/audit/src/BridgeV2_c785/BridgeV2.sol"] = """
pragma solidity ^0.8.20;
contract BridgeV2 {
    function withdraw(uint256 amount) external {}
}
"""

        result = await _map_action_space(container, {
            "path": "/audit/src",
            "files": ["src/BridgeV2_c785/BridgeV2.sol"],
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["source"]["files_requested"], 1)
        self.assertEqual(payload["source"]["files_scanned"], 1)
        self.assertEqual(payload["source"]["read_errors"], [])
        self.assertIn("BridgeV2::withdraw", result)

    async def test_map_action_space_marks_requested_files_unreadable_as_invalid(self):
        container = FakeContainer()

        result = await _map_action_space(container, {
            "path": "/audit/src",
            "files": ["src/Missing.sol"],
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["status"], "invalid_empty_source")
        self.assertEqual(payload["source"]["files_requested"], 1)
        self.assertEqual(payload["source"]["files_scanned"], 0)
        self.assertEqual(payload["summary"]["actions"], 0)
        action_space = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        self.assertEqual(action_space["status"], "invalid_empty_source")
        self.assertEqual(action_space["source"]["files_scanned"], 0)

    async def test_map_action_space_scans_profile_nested_protocol_libs(self):
        container = FakeContainer()
        source_path = (
            "/audit/src/BoringOnChainQueue_7e5a/lib/boring-vault/src/"
            "BoringOnChainQueue.sol"
        )
        container.files[source_path] = """
pragma solidity ^0.8.20;
contract BoringOnChainQueue {
    function requestOnChainWithdrawWithPermit(uint256 shares, uint256 assets) external {}
    function solveOnChainWithdraws(uint256[] calldata requestIds) external {}
}
"""
        container.files[
            "/audit/src/BoringOnChainQueue_7e5a/lib/openzeppelin/contracts/Ownable.sol"
        ] = """
pragma solidity ^0.8.20;
contract Ownable {
    function transferOwnership(address owner) external {}
}
"""
        container.files["/audit/src/BoringOnChainQueue_7e5a/test/Queue.t.sol"] = """
pragma solidity ^0.8.20;
contract QueueTest {
    function fakeExploit() external {}
}
"""
        container.exec_result = (
            0,
            "\n".join([
                source_path,
                "/audit/src/BoringOnChainQueue_7e5a/lib/openzeppelin/contracts/Ownable.sol",
                "/audit/src/BoringOnChainQueue_7e5a/test/Queue.t.sol",
            ]) + "\n",
        )

        result = await _map_action_space(container, {
            "path": "/audit/src/BoringOnChainQueue_7e5a",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["summary"]["actions"], 2)
        self.assertIn("BoringOnChainQueue::requestOnChainWithdrawWithPermit", result)
        self.assertIn("BoringOnChainQueue::solveOnChainWithdraws", result)
        self.assertNotIn("Ownable::transferOwnership", result)
        self.assertNotIn("QueueTest::fakeExploit", result)

    async def test_map_action_space_groups_duplicate_signature_families(self):
        container = FakeContainer()
        source = """
pragma solidity ^0.8.20;
contract Market {
    function redeem(uint256 amount) external returns (uint256) {
        return amount;
    }
}
"""
        container.files["/audit/src/Market_a111/Market.sol"] = source
        container.files["/audit/src/Market_b222/Market.sol"] = source

        result = await _map_action_space(container, {
            "files": [
                "/audit/src/Market_a111/Market.sol",
                "/audit/src/Market_b222/Market.sol",
            ],
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["summary"]["actions"], 2)
        self.assertEqual(payload["summary"]["action_signature_groups"], 1)
        self.assertEqual(payload["action_families"][0]["key"], "Market::redeem")
        self.assertEqual(payload["action_families"][0]["count"], 2)
        action_space = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        self.assertEqual(action_space["action_families"][0]["count"], 2)

    async def test_map_action_space_ignores_contract_words_inside_comments(self):
        container = FakeContainer()
        container.files["/audit/src/Messenger.sol"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @notice The Messenger contract is an OApp that routes OFT messages across chains.
 * @dev This function allows registering with a pre-existing OFT contract instead of creating a new one.
 */
contract Messenger is Base {
    function send(bytes calldata message) external payable {
        message;
    }
}

/// @dev OFTAdapter is a contract that adapts an ERC-20 token.
abstract contract MintBurnAdapter is Base {
    address public token;

    function approvalRequired() external pure returns (bool) {
        return true;
    }
}
"""

        result = await _map_action_space(container, {
            "files": ["/audit/src/Messenger.sol"],
            "record_result": False,
        })

        self.assertIn('"contract": "Messenger"', result)
        self.assertIn('"contract": "MintBurnAdapter"', result)
        self.assertNotIn('"contract": "is"', result)
        self.assertNotIn('"contract": "that"', result)

    async def test_map_action_space_rejects_unapproved_path(self):
        container = FakeContainer()

        result = await _map_action_space(container, {
            "files": ["/tmp/Vault.sol"],
        })

        self.assertIn("action source paths must be under", result)

    async def test_signature_input_without_verification_stays_public_reachable(self):
        reachability = _classify_action_reachability({
            "visibility": "external",
            "modifiers": [],
            "affordances": ["state_changing_entrypoint", "signature_input"],
            "hints": {"authorization_checks": []},
        })

        self.assertEqual(reachability["kind"], "public")
        self.assertTrue(reachability["attacker_reachable"])

    async def test_signature_verification_affordance_is_signature_gated(self):
        reachability = _classify_action_reachability({
            "visibility": "external",
            "modifiers": [],
            "affordances": ["state_changing_entrypoint", "signature_gate"],
            "hints": {
                "authorization_checks": [{
                    "line": 12,
                    "text": "address signer = ECDSA.recover(digest, signature);",
                }],
            },
        })

        self.assertEqual(reachability["kind"], "signature_gated")
        self.assertEqual(
            reachability["attacker_reachable"],
            "requires_valid_signature",
        )

    async def test_attack_graph_deprioritizes_proxy_delegate_helper_names(self):
        helper_score = _attack_graph_candidate_score({
            "action_key": "CErc20Delegator::delegateToImplementation",
            "contract": "CErc20Delegator",
            "function": "delegateToImplementation",
            "exposure": "exposed",
            "live_status": "deployed",
            "reachability": {"kind": "public"},
            "target_binding": {
                "kind": "active_proxy",
                "economically_significant_hint": True,
            },
            "affordances": ["generic_execution", "delegatecall"],
        }, "")
        redeem_score = _attack_graph_candidate_score({
            "action_key": "CErc20Delegator::redeem",
            "contract": "CErc20Delegator",
            "function": "redeem",
            "exposure": "exposed",
            "live_status": "deployed",
            "reachability": {"kind": "public"},
            "target_binding": {
                "kind": "active_proxy",
                "economically_significant_hint": True,
            },
            "affordances": ["value_out_or_burn", "token_or_native_transfer"],
        }, "")

        self.assertLess(helper_score, redeem_score)

    async def test_map_live_reachability_classifies_public_and_gated_actions(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [{
                "profile": "contract_Vault_abcd",
                "contract": "Vault",
                "address": "0x1111111111111111111111111111111111111111",
                "src": "/audit/src/Vault_abcd",
                "priority_score": 10,
                "tags": ["vault/accounting", "deployed-address"],
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 2, "observations": 0, "contracts": 1},
            "actions": [
                {
                    "contract": "Vault",
                    "function": "deposit",
                    "file": "/audit/src/Vault_abcd/Vault.sol",
                    "line": 10,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                    "affordances": ["value_in_or_mint", "token_or_native_transfer"],
                    "modifiers": [],
                    "hints": {},
                },
                {
                    "contract": "Vault",
                    "function": "withdraw",
                    "file": "/audit/src/Vault_abcd/Vault.sol",
                    "line": 20,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                    "affordances": ["value_out_or_burn", "modifier_gated"],
                    "modifiers": ["onlyOwner"],
                    "hints": {"role_gates": [{"line": 20, "text": "onlyOwner"}]},
                },
                {
                    "contract": "Vault",
                    "function": "sweep",
                    "file": "/audit/src/Vault_abcd/Vault.sol",
                    "line": 30,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [],
                    "affordances": ["value_out_or_burn", "modifier_gated"],
                    "modifiers": ["requiresAuth"],
                    "hints": {},
                },
            ],
            "observations": [],
        })

        result = await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": False,
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["live_reachability_id"], "lr-001")
        exposures = payload["profiles"][0]["action_exposures"]
        by_key = {item["action_key"]: item for item in exposures}
        top_by_key = {item["action_key"]: item for item in payload["top_exposures"]}
        self.assertEqual(payload["summary"]["target_bindings"], {"unprobed": 1})
        self.assertEqual(payload["profiles"][0]["target_binding"]["kind"], "unprobed")
        self.assertEqual(top_by_key["Vault::deposit"]["reachability"]["kind"], "public")
        self.assertEqual(by_key["Vault::withdraw"]["reachability"]["kind"], "role_gated")
        self.assertEqual(by_key["Vault::withdraw"]["exposure"], "gated")
        self.assertEqual(by_key["Vault::sweep"]["reachability"]["kind"], "role_gated")
        self.assertEqual(by_key["Vault::sweep"]["exposure"], "gated")
        self.assertIn("/workspace/campaign/live-reachability/lr-001.json", container.files)

    async def test_inventory_live_targets_records_bounded_probe_artifact(self):
        container = FakeContainer()
        container.exec_result = (
            0,
            "\n".join([
                "code=0x60006000",
                "native_balance=10",
                "eip1967_impl=0x0000000000000000000000002222222222222222222222222222222222222222",
                "eip1967_admin=0x0000000000000000000000003333333333333333333333333333333333333333",
                "owner=0x0000000000000000000000000000000000000001",
                "paused=false",
                "asset=0x0000000000000000000000000000000000000002",
                "total_assets=1000",
            ]),
        )

        result = await _inventory_live_targets(container, {
            "targets": [{
                "label": "Vault",
                "contract": "Vault",
                "address": "0x1111111111111111111111111111111111111111",
            }],
            "rpc_url": "http://rpc.test",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["inventory_id"], "linv-001")
        self.assertEqual(payload["summary"]["code_present"], 1)
        self.assertEqual(payload["summary"]["live_deployed_targets"], 1)
        self.assertEqual(payload["summary"]["economically_significant_targets"], 1)
        self.assertEqual(payload["targets"][0]["target_binding"]["kind"], "active_proxy")
        self.assertEqual(payload["targets"][0]["values"]["total_assets"], "1000")
        self.assertIn("/workspace/campaign/live-inventory/linv-001.json", container.files)

    async def test_inventory_live_targets_records_related_call_target(self):
        container = FakeContainer()
        pool_impl = "0x1111111111111111111111111111111111111111"
        provider = "0x2222222222222222222222222222222222222222"
        live_pool = "0x3333333333333333333333333333333333333333"
        container.exec_result = (
            0,
            "\n".join([
                "code=0x60006000",
                "native_balance=0",
                f"addresses_provider={provider}",
                f"provider_get_pool={live_pool}",
                "get_reserves_list=[]",
                "get_reserves_count=0",
            ]),
        )

        result = await _inventory_live_targets(container, {
            "targets": [{
                "label": "Pool implementation",
                "contract": "PoolImplementation",
                "address": pool_impl,
            }],
            "rpc_url": "http://rpc.test",
            "record_result": False,
        })

        payload = json.loads(result)
        binding = payload["targets"][0]["target_binding"]
        self.assertEqual(binding["kind"], "deployed_implementation_or_template")
        self.assertEqual(binding["recommended_call_target"], live_pool)
        self.assertIn("related live target", binding["normalization_reason"])
        self.assertEqual(
            binding["related_live_targets"][0]["relation"],
            "pool",
        )

    async def test_inventory_live_targets_infers_selected_branch_targets(self):
        container = FakeContainer()
        container.files[_CAMPAIGN_STATE_PATH] = json.dumps({
            "schema_version": 1,
            "counters": {},
            "sections": {},
            "attack_search": {
                "current": {
                    "selected_branch_id": "br-001",
                    "branches": [{
                        "id": "br-001",
                        "title": "Live queue target",
                        "status": "needs_inventory",
                        "next_tool": "inventory_live_targets",
                        "required_args": {
                            "inventory_live_targets": {
                                "title": "Required branch inventory",
                                "targets": [{
                                    "label": "Queue",
                                    "contract": "Queue",
                                    "address": "0x1111111111111111111111111111111111111111",
                                }],
                                "related_ids": ["ag-001", "agcand-001"],
                            },
                        },
                    }],
                },
            },
        })

        result = await _inventory_live_targets(container, {
            "execute_probes": False,
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["summary"]["targets"], 1)
        self.assertEqual(payload["targets"][0]["contract"], "Queue")
        self.assertEqual(
            payload["inferred_from_attack_search"]["branch_id"],
            "br-001",
        )
        artifact = json.loads(
            container.files["/workspace/campaign/live-inventory/linv-001.json"]
        )
        self.assertEqual(artifact["title"], "Required branch inventory")
        self.assertEqual(artifact["related_ids"], ["ag-001", "agcand-001"])

    async def test_inventory_live_targets_rejects_bad_shapes_and_caps_targets(self):
        container = FakeContainer()

        bad_concurrency = await _inventory_live_targets(container, {
            "targets": [{
                "address": "0x1111111111111111111111111111111111111111",
            }],
            "probe_concurrency": "fast",
            "record_result": False,
        })
        self.assertIn("probe_concurrency must be an integer", bad_concurrency)

        bad_selectors = await _inventory_live_targets(container, {
            "targets": [{
                "address": "0x1111111111111111111111111111111111111111",
                "selectors": "0x12345678",
            }],
            "record_result": False,
        })
        self.assertIn("selectors must be a list", bad_selectors)

        too_many = await _inventory_live_targets(container, {
            "targets": [
                {"address": f"0x{index:040x}"}
                for index in range(1, 52)
            ],
            "record_result": False,
        })
        self.assertIn("accepts at most 50 targets", too_many)

    async def test_map_live_reachability_groups_profile_families(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [
                {
                    "profile": "contract_Market_a111",
                    "contract": "Market",
                    "address": "0x1111111111111111111111111111111111111111",
                    "src": "/audit/src/Market_a111",
                },
                {
                    "profile": "contract_Market_b222",
                    "contract": "Market",
                    "address": "0x2222222222222222222222222222222222222222",
                    "src": "/audit/src/Market_b222",
                },
            ],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Market",
                "function": "redeem",
                "file": "/audit/src/Market_a111/Market.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_out_or_burn"],
                "modifiers": [],
            }],
            "observations": [],
        })

        result = await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": False,
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["summary"]["profile_families"], 1)
        self.assertEqual(payload["profile_families"][0]["contract"], "Market")
        self.assertEqual(payload["profile_families"][0]["profiles"], 2)
        reachability = json.loads(
            container.files["/workspace/campaign/live-reachability/lr-001.json"]
        )
        self.assertEqual(reachability["profile_families"][0]["profiles"], 2)

    async def test_map_live_reachability_marks_imported_interface_only_actions(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [{
                "profile": "contract_LimitOrder_f0bc",
                "contract": "LimitOrder",
                "address": "0x1111111111111111111111111111111111111111",
                "src": "/audit/src/LimitOrder_f0bc",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "ITokenManager",
                "contract_kind": "interface",
                "function": "redeemWithAttestation",
                "file": "/audit/src/LimitOrder_f0bc/interfaces/ITokenManager.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [],
                "affordances": ["value_out_or_burn", "signed_authorization"],
                "modifiers": [],
            }],
            "observations": [],
        })

        payload = json.loads(await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": False,
            "record_result": False,
        }))

        exposure = payload["profiles"][0]["action_exposures"][0]
        self.assertEqual(exposure["exposure"], "source_interface_only")
        self.assertEqual(exposure["source_relation"]["kind"], "source_interface_only")
        self.assertLess(exposure["priority_score"], 3)

    async def test_map_live_reachability_marks_flattened_dependency_actions_artifact_only(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [{
                "profile": "contract_Teller_f0bc",
                "contract": "Teller",
                "address": "0x1111111111111111111111111111111111111111",
                "src": "/audit/src/Teller_f0bc",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "contracts": [
                {
                    "name": "WETH",
                    "kind": "contract",
                    "bases": [],
                    "file": "/audit/src/Teller_f0bc/Teller.flattened.sol",
                },
                {
                    "name": "Teller",
                    "kind": "contract",
                    "bases": ["Auth"],
                    "file": "/audit/src/Teller_f0bc/Teller.flattened.sol",
                },
            ],
            "actions": [
                {
                    "contract": "WETH",
                    "contract_kind": "contract",
                    "function": "withdraw",
                    "file": "/audit/src/Teller_f0bc/Teller.flattened.sol",
                    "line": 40,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "wad", "raw": "uint256 wad"}],
                    "affordances": ["value_out_or_burn"],
                    "modifiers": [],
                },
                {
                    "contract": "Teller",
                    "contract_kind": "contract",
                    "function": "deposit",
                    "file": "/audit/src/Teller_f0bc/Teller.flattened.sol",
                    "line": 80,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                    "affordances": ["value_in_or_mint"],
                    "modifiers": [],
                },
            ],
            "observations": [],
        })

        payload = json.loads(await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": False,
            "record_result": False,
        }))

        by_key = {
            item["action_key"]: item
            for item in payload["profiles"][0]["action_exposures"]
        }
        self.assertEqual(by_key["WETH::withdraw"]["exposure"], "source_artifact_only")
        self.assertEqual(
            by_key["WETH::withdraw"]["source_relation"]["kind"],
            "source_dependency_only",
        )
        self.assertEqual(
            by_key["Teller::deposit"]["source_relation"]["kind"],
            "profile_contract",
        )
        self.assertEqual(payload["summary"]["source_artifact_actions"], 1)

    async def test_map_live_reachability_allows_inherited_base_actions(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [{
                "profile": "contract_Child_a111",
                "contract": "Child",
                "address": "0x1111111111111111111111111111111111111111",
                "src": "/audit/src/Child_a111",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "contracts": [
                {
                    "name": "BaseVault",
                    "kind": "contract",
                    "bases": [],
                    "file": "/audit/src/Child_a111/Child.sol",
                },
                {
                    "name": "Child",
                    "kind": "contract",
                    "bases": ["BaseVault"],
                    "file": "/audit/src/Child_a111/Child.sol",
                },
            ],
            "actions": [{
                "contract": "BaseVault",
                "contract_kind": "contract",
                "function": "withdraw",
                "file": "/audit/src/Child_a111/Child.sol",
                "line": 12,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_out_or_burn"],
                "modifiers": [],
            }],
            "observations": [],
        })

        payload = json.loads(await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": False,
            "record_result": False,
        }))

        exposure = payload["profiles"][0]["action_exposures"][0]
        self.assertEqual(exposure["source_relation"]["kind"], "inherited_base")
        self.assertEqual(exposure["source_relation"]["executable_source"], True)
        self.assertEqual(exposure["exposure"], "source_public_live_unknown")

    async def test_map_live_reachability_uses_authority_can_call_for_requires_auth(self):
        container = FakeContainer()
        container.exec_results = [
            (
                0,
                "\n".join([
                    "code=0x60006000",
                    "authority=0x2222222222222222222222222222222222222222",
                ]),
            ),
            (0, "authority_can_call_1=true"),
        ]
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [{
                "profile": "contract_Teller_f0bc",
                "contract": "Teller",
                "address": "0x1111111111111111111111111111111111111111",
                "src": "/audit/src/Teller_f0bc",
            }],
        })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Teller",
                "contract_kind": "contract",
                "function": "deposit",
                "file": "/audit/src/Teller_f0bc/Teller.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_in_or_mint", "modifier_gated"],
                "modifiers": ["requiresAuth"],
                "hints": {},
            }],
            "observations": [],
        })

        payload = json.loads(await _map_live_reachability(container, {
            "action_space": "as-001",
            "execute_probes": True,
            "rpc_url": "http://rpc.test",
            "record_result": False,
        }))

        exposure = payload["profiles"][0]["action_exposures"][0]
        self.assertEqual(exposure["exposure"], "exposed")
        self.assertEqual(exposure["reachability"]["kind"], "public_authorized")
        self.assertEqual(exposure["reachability"]["authority_attacker_can_call"], True)
        self.assertEqual(exposure["authority_probe"]["attacker_can_call"], True)
        reachability_artifact = json.loads(
            container.files["/workspace/campaign/live-reachability/lr-001.json"]
        )
        self.assertTrue(
            reachability_artifact["profiles"][0]["probe"]["authority_probe"]["decisions"]
        )
        self.assertEqual(len(container.exec_calls), 2)
        self.assertIn("timeout 8s cast call", container.exec_calls[1][0])

    def test_authority_probe_command_bounds_and_deduplicates_selector_calls(self):
        command = _authority_probe_command(
            target="0x1111111111111111111111111111111111111111",
            authority="0x2222222222222222222222222222222222222222",
            rpc_url="https://rpc.example",
            actions=[
                {
                    "contract": "Queue",
                    "function": "solve",
                    "parameters": [{"raw": "uint256 amount"}],
                },
                {
                    "contract": "Queue",
                    "function": "solve",
                    "parameters": [{"raw": "uint256 amount"}],
                },
                {
                    "contract": "Queue",
                    "function": "cancel",
                    "parameters": [],
                },
            ],
        )

        self.assertIn("timeout 8s cast call", command)
        self.assertEqual(command.count("solve(uint256)"), 1)
        self.assertEqual(command.count("cancel()"), 1)
        # The concrete endpoint is used; the old global-RPC guard is gone.
        self.assertIn("--rpc-url https://rpc.example", command)
        self.assertNotIn("__NO_ETH_RPC_URL__", command)
        self.assertNotIn("ETH_RPC_URL", command)

    async def test_map_live_reachability_runs_bounded_probe_batch(self):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [
                {
                    "profile": "contract_Market_a111",
                    "contract": "Market",
                    "address": "0x1111111111111111111111111111111111111111",
                    "src": "/audit/src/Market_a111",
                },
                {
                    "profile": "contract_Market_b222",
                    "contract": "Market",
                    "address": "0x2222222222222222222222222222222222222222",
                    "src": "/audit/src/Market_b222",
                },
            ],
        })
        probe_output = "\n".join([
            "code=0x60006000",
            "native_balance=0",
            "eip1967_impl=0x",
            "eip1967_admin=0x",
        ])
        container.exec_results = [(0, probe_output), (0, probe_output)]

        result = await _map_live_reachability(container, {
            "execute_probes": True,
            "probe_concurrency": 2,
            "rpc_url": "http://rpc.test",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["summary"]["probed"], 2)
        self.assertEqual(payload["summary"]["code_present"], 2)
        self.assertEqual(payload["summary"]["probe_concurrency"], 2)
        self.assertEqual(len(container.exec_calls), 2)
        reachability = json.loads(
            container.files["/workspace/campaign/live-reachability/lr-001.json"]
        )
        self.assertEqual(reachability["probe_concurrency"], 2)

    async def test_build_attack_graph_creates_required_action_skeletons(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Vault",
                "function": "deposit",
                "file": "/audit/src/Vault.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_in_or_mint", "token_or_native_transfer"],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Vault",
                "address": "0x1111111111111111111111111111111111111111",
                "action_exposures": [{
                    "action_key": "Vault::deposit",
                    "action_uid": "/audit/src/Vault.sol:Vault::deposit:10",
                    "contract": "Vault",
                    "function": "deposit",
                    "signature": "deposit(uint256)",
                    "file": "/audit/src/Vault.sol",
                    "line": 10,
                    "target_address": "0x1111111111111111111111111111111111111111",
                    "affordances": ["value_in_or_mint", "token_or_native_transfer"],
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                    "reachability": {"kind": "public", "attacker_reachable": True},
                    "live_status": "deployed",
                    "exposure": "exposed",
                }],
            }],
        })

        result = await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["attack_graph_id"], "ag-001")
        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["action_key"], "Vault::deposit")
        self.assertEqual(candidate["actions"][0]["target"], "0x1111111111111111111111111111111111111111")
        self.assertEqual(candidate["candidate_id"], "agcand-001")
        self.assertEqual(candidate["actions"][0]["live_status"], "deployed")
        self.assertIn("/workspace/campaign/attack-graphs/ag-001.json", container.files)

    async def test_build_attack_graph_prioritizes_active_proxy_binding(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        proxy = "0x1111111111111111111111111111111111111111"
        implementation = "0x2222222222222222222222222222222222222222"

        def exposure(address, binding_kind):
            return {
                "action_key": "Vault::withdraw",
                "action_uid": f"/audit/src/Vault.sol:Vault::withdraw:{address[-4:]}",
                "contract": "Vault",
                "function": "withdraw",
                "signature": "withdraw(uint256)",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "target_address": address,
                "affordances": ["value_out_or_burn", "token_or_native_transfer"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "reachability": {"kind": "public", "attacker_reachable": True},
                "live_status": "deployed",
                "exposure": "exposed",
                "target_binding": {
                    "kind": binding_kind,
                    "live_deployed": True,
                    "economic_priority": "high" if binding_kind == "active_proxy" else "low",
                    "economically_significant_hint": binding_kind == "active_proxy",
                    "reasons": ["test binding"],
                },
            }

        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Vault",
                "address": proxy,
                "action_exposures": [
                    exposure(implementation, "deployed_implementation_or_template"),
                    exposure(proxy, "active_proxy"),
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["target_address"], proxy)
        self.assertEqual(candidate["target_binding"]["kind"], "active_proxy")

    async def test_build_attack_graph_prioritizes_release_over_ingress_only_paths(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 2, "observations": 0, "contracts": 1},
            "actions": [],
            "observations": [],
        })
        address = "0x1111111111111111111111111111111111111111"
        base_exposure = {
            "contract": "Bridge",
            "signature": "",
            "file": "/audit/src/Bridge.sol",
            "target_address": address,
            "reachability": {"kind": "public", "attacker_reachable": True},
            "live_status": "deployed",
            "exposure": "exposed",
            "parameters": [{"name": "amount", "raw": "uint256 amount"}],
        }
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Bridge",
                "address": address,
                "action_exposures": [
                    {
                        **base_exposure,
                        "action_key": "Bridge::sendNative",
                        "action_uid": "/audit/src/Bridge.sol:Bridge::sendNative:10",
                        "function": "sendNative",
                        "line": 10,
                        "signature": "sendNative(uint256)",
                        "affordances": [
                            "accepts_native_value",
                            "value_in_or_mint",
                            "token_or_native_transfer",
                            "cross_domain_or_message",
                        ],
                    },
                    {
                        **base_exposure,
                        "action_key": "Bridge::relay",
                        "action_uid": "/audit/src/Bridge.sol:Bridge::relay:40",
                        "function": "relay",
                        "line": 40,
                        "signature": "relay(bytes)",
                        "affordances": [
                            "value_out_or_burn",
                            "token_or_native_transfer",
                            "cross_domain_or_message",
                        ],
                    },
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidates = payload["candidate_chains"]
        self.assertEqual(candidates[0]["candidate_kind"], "economic_chain")
        self.assertEqual(candidates[0]["mechanism"], "bridge_message_accounting")
        self.assertEqual(candidates[0]["actions"][0]["function"], "sendNative")
        self.assertEqual(candidates[0]["actions"][-1]["function"], "relay")
        relay_candidate = next(
            item for item in candidates if item["action_key"] == "Bridge::relay"
        )
        self.assertEqual(relay_candidate["direction_hint"], "outbound_or_release")
        send_candidate = next(
            item for item in candidates if item["action_key"] == "Bridge::sendNative"
        )
        self.assertEqual(send_candidate["direction_hint"], "inbound_value_entry")
        self.assertIn("over-crediting", " ".join(send_candidate["planning_notes"]))
        self.assertIn(
            "actually transfers",
            send_candidate["actions"][0]["expected_effect"],
        )

    async def test_build_attack_graph_prefers_vault_economic_chain_over_single_redeem(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        address = "0x1111111111111111111111111111111111111111"

        def exposure(function, affordances, line):
            return {
                "action_key": f"Vault::{function}",
                "action_uid": f"/audit/src/Vault.sol:Vault::{function}:{line}",
                "contract": "Vault",
                "function": function,
                "signature": f"{function}(uint256)",
                "file": "/audit/src/Vault.sol",
                "line": line,
                "target_address": address,
                "affordances": affordances,
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "reachability": {"kind": "public", "attacker_reachable": True},
                "live_status": "deployed",
                "exposure": "exposed",
            }

        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Vault",
                "address": address,
                "action_exposures": [
                    exposure("deposit", ["value_in_or_mint", "token_or_native_transfer"], 10),
                    exposure("redeem", ["value_out_or_burn", "token_or_native_transfer"], 30),
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["candidate_kind"], "economic_chain")
        self.assertEqual(candidate["mechanism"], "vault_share_inflation")
        self.assertEqual(candidate["actions"][0]["function"], "deposit")
        self.assertEqual(candidate["actions"][1]["action_key"], "external::donateAssetToAccountingTarget")
        self.assertEqual(candidate["actions"][2]["function"], "redeem")
        self.assertIn("inventory_live_targets", candidate["recommended_next_tool"])

    async def test_build_attack_graph_classifies_staking_chain_separately_from_vault(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        address = "0x1111111111111111111111111111111111111111"

        def exposure(function, affordances, line):
            return {
                "action_key": f"StakingRewards::{function}",
                "action_uid": f"/audit/src/StakingRewards.sol:StakingRewards::{function}:{line}",
                "contract": "StakingRewards",
                "function": function,
                "signature": f"{function}(uint256)",
                "file": "/audit/src/StakingRewards.sol",
                "line": line,
                "target_address": address,
                "affordances": affordances,
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "reachability": {"kind": "public", "attacker_reachable": True},
                "live_status": "deployed",
                "exposure": "exposed",
            }

        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "StakingRewards",
                "address": address,
                "action_exposures": [
                    exposure("stake", ["value_in_or_mint"], 10),
                    exposure("unstake", ["value_out_or_burn"], 30),
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["candidate_kind"], "economic_chain")
        self.assertEqual(candidate["mechanism"], "staking_delegation_accounting")
        self.assertEqual([action["function"] for action in candidate["actions"]], ["stake", "unstake"])
        self.assertNotIn("external::donateAssetToAccountingTarget", json.dumps(candidate["actions"]))

    async def test_build_attack_graph_does_not_promote_gated_economic_extraction(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        address = "0x1111111111111111111111111111111111111111"
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Vault",
                "address": address,
                "action_exposures": [
                    {
                        "action_key": "Vault::deposit",
                        "action_uid": "/audit/src/Vault.sol:Vault::deposit:10",
                        "contract": "Vault",
                        "function": "deposit",
                        "target_address": address,
                        "affordances": ["value_in_or_mint"],
                        "reachability": {"kind": "public", "attacker_reachable": True},
                        "live_status": "deployed",
                        "exposure": "exposed",
                    },
                    {
                        "action_key": "Vault::redeem",
                        "action_uid": "/audit/src/Vault.sol:Vault::redeem:30",
                        "contract": "Vault",
                        "function": "redeem",
                        "target_address": address,
                        "affordances": ["value_out_or_burn", "modifier_gated"],
                        "reachability": {"kind": "role_gated", "attacker_reachable": False},
                        "live_status": "deployed",
                        "exposure": "gated",
                    },
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        self.assertFalse(
            any(
                item.get("candidate_kind") == "economic_chain"
                for item in payload["candidate_chains"]
            )
        )

    async def test_build_attack_graph_adds_queue_request_settlement_chain(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        address = "0x1111111111111111111111111111111111111111"

        def exposure(function, affordances, line, *, gated=False):
            return {
                "action_key": f"BoringOnChainQueue::{function}",
                "action_uid": f"/audit/src/Queue.sol:BoringOnChainQueue::{function}:{line}",
                "contract": "BoringOnChainQueue",
                "function": function,
                "signature": f"{function}(uint256)",
                "file": "/audit/src/Queue.sol",
                "line": line,
                "target_address": address,
                "affordances": affordances,
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "reachability": (
                    {"kind": "role_gated", "attacker_reachable": False}
                    if gated else {"kind": "public", "attacker_reachable": True}
                ),
                "live_status": "deployed",
                "exposure": "gated" if gated else "exposed",
            }

        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "BoringOnChainQueue",
                "address": address,
                "action_exposures": [
                    exposure(
                        "requestOnChainWithdrawWithPermit",
                        ["signed_authorization", "token_or_native_transfer"],
                        10,
                    ),
                    exposure(
                        "cancelOnChainWithdraw",
                        ["signed_authorization"],
                        20,
                    ),
                    exposure(
                        "solveOnChainWithdraws",
                        ["value_out_or_burn", "token_or_native_transfer"],
                        30,
                        gated=True,
                    ),
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidate = next(
            item for item in payload["candidate_chains"]
            if item.get("mechanism") == "queue_solver_accounting"
        )
        self.assertEqual(candidate["candidate_kind"], "economic_chain")
        self.assertEqual(
            [action["function"] for action in candidate["actions"]],
            [
                "requestOnChainWithdrawWithPermit",
                "cancelOnChainWithdraw",
                "solveOnChainWithdraws",
            ],
        )
        self.assertEqual(candidate["actions"][-1]["actor"], "authorized solver/keeper")
        self.assertIn("production solver/keeper", " ".join(candidate["blockers"]))
        self.assertIn("request id", " ".join(candidate["required_live_evidence"]))

    async def test_build_attack_graph_collapses_duplicate_gated_clones(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        addresses = [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ]
        exposure = {
            "action_key": "Vault::sweep",
            "contract": "Vault",
            "function": "sweep",
            "signature": "sweep()",
            "affordances": [
                "value_out_or_burn",
                "generic_execution",
                "delegatecall",
                "credit_or_liquidation",
                "valuation_dependency",
            ],
            "reachability": {"kind": "role_gated", "attacker_reachable": False},
            "live_status": "deployed",
            "exposure": "gated",
        }
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [
                {
                    "contract": "Vault",
                    "address": address,
                    "action_exposures": [{
                        **exposure,
                        "action_uid": f"/audit/src/Vault.sol:Vault::sweep:{index}",
                        "line": index,
                        "target_address": address,
                    }],
                }
                for index, address in enumerate(addresses, start=1)
            ],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidates = [
            item for item in payload["candidate_chains"]
            if item["action_key"] == "Vault::sweep"
        ]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["duplicate_count"], 2)
        self.assertEqual(candidates[0]["similar_targets"], [addresses[1]])

    async def test_build_attack_graph_adds_lending_exchange_rate_chain_candidate(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 0, "observations": 0, "contracts": 0},
            "actions": [],
            "observations": [],
        })
        market_a = "0x1111111111111111111111111111111111111111"
        market_b = "0x2222222222222222222222222222222222222222"
        controller = "0x3333333333333333333333333333333333333333"

        def exposure(contract, function, address, affordances):
            return {
                "action_key": f"{contract}::{function}",
                "action_uid": f"/audit/src/{contract}.sol:{contract}::{function}:10",
                "contract": contract,
                "function": function,
                "signature": f"{function}()",
                "file": f"/audit/src/{contract}.sol",
                "line": 10,
                "target_address": address,
                "affordances": affordances,
                "parameters": [],
                "reachability": {"kind": "public", "attacker_reachable": True},
                "live_status": "deployed",
                "exposure": "exposed",
            }

        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [
                {
                    "contract": "CErc20Delegator",
                    "address": market_a,
                    "action_exposures": [
                        exposure("CErc20Delegator", "mint", market_a, ["value_in_or_mint"]),
                        exposure("CErc20Delegator", "redeem", market_a, ["value_out_or_burn"]),
                        exposure("CErc20Delegator", "exchangeRateCurrent", market_a, ["valuation_dependency"]),
                    ],
                },
                {
                    "contract": "CErc20Delegator",
                    "address": market_b,
                    "action_exposures": [
                        exposure("CErc20Delegator", "borrow", market_b, ["credit_or_liquidation", "value_out_or_burn"]),
                    ],
                },
                {
                    "contract": "Unitroller",
                    "address": controller,
                    "action_exposures": [
                        exposure("Unitroller", "enterMarkets", controller, ["credit_or_liquidation"]),
                    ],
                },
            ],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["action_key"], "Lending::exchangeRateCollateralInflation")
        self.assertEqual(candidate["candidate_kind"], "economic_pattern")
        self.assertEqual(candidate["market_inventory"]["collateral_market"], market_a)
        self.assertEqual(candidate["market_inventory"]["borrow_market"], market_b)
        self.assertIn("external::donateUnderlyingToMarket", json.dumps(candidate["actions"]))

        workbench = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))
        self.assertEqual(workbench["mechanism"], "lending")
        persisted = json.loads(
            container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
        )
        self.assertIn("market_inventory", json.dumps(persisted))
        self.assertIn("borrow_capacity_and_unwind", json.dumps(persisted))
        sequence = json.loads(await _compose_sequence_experiment(
            container,
            workbench["compose_sequence_experiment_args"],
        ))
        self.assertEqual(sequence["target_addresses"]["CollateralMarket"], market_a)
        self.assertEqual(sequence["target_addresses"]["BorrowMarket"], market_b)
        scaffold_path = (
            "/workspace/experiments/exp-001-test-lending-exchange-rate-collateral-inflation-chain/"
            "ReentbotProSequence.t.sol"
        )
        scaffold = container.files[scaffold_path]
        self.assertIn("IReentbotProCollateralMarket", scaffold)
        self.assertIn("IReentbotProBorrowMarket", scaffold)

    async def test_build_attack_graph_source_only_mode_uses_only_action_space(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": [
                    "value_out_or_burn",
                    "token_or_native_transfer",
                    "state_mutating_entrypoint",
                ],
                "modifiers": [],
            }],
            "observations": [],
        })

        result = await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "record_result": False,
        })

        payload = json.loads(result)
        self.assertEqual(payload["mode"], "source_only")
        self.assertTrue(payload["needs_live_context"])
        candidate = payload["candidate_chains"][0]
        self.assertEqual(candidate["action_key"], "Vault::withdraw")
        self.assertEqual(candidate["exposure"], "source_only")
        self.assertEqual(candidate["reachability"], "needs_live_context")
        self.assertIn("live reachability not mapped", candidate["blockers"])
        self.assertIn("target address not bound", candidate["blockers"])
        self.assertNotIn("target_address", candidate)
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        self.assertEqual(artifact["mode"], "source_only")
        self.assertIsNone(artifact["live_reachability_path"])
        self.assertEqual(artifact["all_candidate_count"], 1)

    async def test_build_attack_graph_source_only_preserves_renamed_and_bland_actions(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [
                {
                    # Renamed function (no known vocabulary) carrying only
                    # structural labels still becomes a candidate.
                    "contract": "Ledger",
                    "function": "zorp",
                    "file": "/audit/src/Ledger.sol",
                    "line": 12,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "id", "raw": "uint256 id"}],
                    "affordances": ["mapping_state_write", "state_mutating_entrypoint"],
                    "modifiers": [],
                },
                {
                    # Bare external/non-view entrypoint with no structural risk:
                    # diverted to the low_signal_entrypoints frontier, not a
                    # candidate.
                    "contract": "Ledger",
                    "function": "qux",
                    "file": "/audit/src/Ledger.sol",
                    "line": 40,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [],
                    "affordances": [],
                    "modifiers": [],
                },
            ],
            "observations": [],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "max_candidates": 1,
            "record_result": False,
        }))

        # The renamed-but-structural action is the sole candidate; the bare
        # entrypoint never competes for the top list.
        self.assertEqual(len(payload["candidate_chains"]), 1)
        self.assertEqual(payload["candidate_chains"][0]["action_key"], "Ledger::zorp")
        self.assertIn("accounting", payload["candidate_chains"][0]["objective"])
        # all_candidates still counts the diverted bare entrypoint.
        self.assertEqual(payload["summary"]["all_candidates"], 2)
        candidate_keys = [item["action_key"] for item in payload["candidate_chains"]]
        self.assertNotIn("Ledger::qux", candidate_keys)

        # The bare entrypoint is preserved in the artifact's terminal
        # low_signal_entrypoints bucket, not erased and not promoted into the
        # mutator/novelty buckets.
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        self.assertEqual(artifact["all_candidate_count"], 2)
        frontier = artifact["frontier"]
        low_signal_keys = [
            item["action_key"] for item in frontier["low_signal_entrypoints"]
        ]
        self.assertIn("Ledger::qux", low_signal_keys)
        self.assertEqual(payload["frontier_summary"]["low_signal_entrypoints"], 1)
        self.assertEqual(payload["frontier_summary"]["omitted_by_truncation"], 0)
        self.assertNotIn("Ledger::qux", [
            item["action_key"] for item in frontier.get("unlabeled_state_mutators", [])
        ])

    # ── source-only candidate scoring ────────────────────────────────────────
    # The affordance sets below are exactly what the action-space parser emits
    # for the noted Solidity (verified via _iter_function_units); the assertions
    # pin _source_only_candidate_score / _source_only_candidate_priority so a
    # no-op external function can never become a critical generic-invariant
    # candidate while structurally risky functions still surface.

    async def test_source_only_candidate_score_bare_entrypoint_is_low_signal(self):
        # function ping() external {}  →  ["state_changing_entrypoint"]
        action = {"visibility": "external", "affordances": ["state_changing_entrypoint"]}
        score, reasons = _source_only_candidate_score(action)
        self.assertLessEqual(score, 2)
        self.assertEqual(reasons, ["bare_entrypoint"])
        self.assertEqual(
            _source_only_candidate_priority(score, {"state_changing_entrypoint"}),
            "low",
        )
        self.assertFalse(_source_only_allows_critical({"state_changing_entrypoint"}))

    async def test_source_only_candidate_score_first_party_source_alone_stays_weak(self):
        # First-party source + the non-view roll-up are context, not risk.
        action = {
            "visibility": "external",
            "file": "/audit/src/Vault.sol",
            "affordances": ["state_changing_entrypoint"],
        }
        score, reasons = _source_only_candidate_score(action)
        self.assertEqual(score, 1)
        self.assertEqual(reasons, ["bare_entrypoint"])
        self.assertNotEqual(
            _source_only_candidate_priority(score, {"state_changing_entrypoint"}),
            "critical",
        )

    async def test_source_only_candidate_score_dynamic_call_target_is_surfaced(self):
        # function z(address t, bytes calldata d) external {
        #     (bool ok,) = t.call(d); require(ok); }
        affordances = {
            "dynamic_call_target",
            "external_boundary_crossing",
            "external_call",
            "state_changing_entrypoint",
        }
        score, reasons = _source_only_candidate_score(
            {"affordances": sorted(affordances)}
        )
        self.assertIn("dynamic_call_target+5", reasons)
        self.assertIn("external_boundary_crossing+3", reasons)
        self.assertGreaterEqual(score, 6)
        self.assertIn(
            _source_only_candidate_priority(score, affordances), {"high", "critical"}
        )
        self.assertTrue(_source_only_allows_critical(affordances))

    async def test_source_only_candidate_score_mapping_and_aggregate_writes(self):
        # function f(uint256 a) external { m[msg.sender] += a; total += a; }
        affordances = {
            "aggregate_state_update",
            "mapping_state_write",
            "user_claim_or_obligation_update",
            "state_changing_entrypoint",
            "state_mutating_entrypoint",
        }
        score, reasons = _source_only_candidate_score(
            {"affordances": sorted(affordances)}
        )
        self.assertIn("mapping_state_write+3", reasons)
        self.assertIn("aggregate_state_update+3", reasons)
        self.assertIn("mapping_and_aggregate+2", reasons)
        priority = _source_only_candidate_priority(score, affordances)
        self.assertIn(priority, {"medium", "high"})

    async def test_source_only_candidate_score_authorization_binding(self):
        # function q(address user, uint256 amount) external {
        #     require(ok[msg.sender]); balance[user] -= amount; }
        affordances = {
            "authorization_condition",
            "mapping_state_write",
            "sender_or_role_checked",
            "user_claim_or_obligation_update",
            "state_changing_entrypoint",
            "state_mutating_entrypoint",
        }
        score, reasons = _source_only_candidate_score(
            {"affordances": sorted(affordances)}
        )
        self.assertIn("authorization_condition+3", reasons)
        self.assertIn("mapping_state_write+3", reasons)
        self.assertGreaterEqual(score, 6)
        self.assertNotEqual(
            _source_only_candidate_priority(score, affordances), "low"
        )

    async def test_source_only_candidate_priority_critical_needs_strong_signal(self):
        # Dynamic call + real mutation reaches critical (still PoC-gated downstream).
        strong = {
            "dynamic_call_target",
            "external_boundary_crossing",
            "mapping_state_write",
            "aggregate_state_update",
        }
        strong_score, _ = _source_only_candidate_score({"affordances": sorted(strong)})
        self.assertGreaterEqual(strong_score, 10)
        self.assertEqual(
            _source_only_candidate_priority(strong_score, strong), "critical"
        )
        # The same score band without a critical-gate signal caps at high.
        weak = {
            "mapping_state_write",
            "aggregate_state_update",
            "user_claim_or_obligation_update",
        }
        weak_score, _ = _source_only_candidate_score({"affordances": sorted(weak)})
        self.assertGreaterEqual(weak_score, 10)
        self.assertEqual(_source_only_candidate_priority(weak_score, weak), "high")

    async def test_source_only_attack_graph_candidates_diverts_bare_entrypoints(self):
        action_space = {
            "actions": [
                {
                    "contract": "M",
                    "function": "strong",
                    "file": "/audit/src/M.sol",
                    "line": 1,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "affordances": ["mapping_state_write", "state_mutating_entrypoint"],
                    "parameters": [],
                },
                {
                    "contract": "M",
                    "function": "noop",
                    "file": "/audit/src/M.sol",
                    "line": 2,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "affordances": ["state_changing_entrypoint"],
                    "parameters": [],
                },
            ],
        }
        candidates, low_signal = _source_only_attack_graph_candidates(
            action_space, None, "", "/workspace/campaign/action-spaces/as-001.json", ""
        )
        self.assertEqual({c["action_key"] for c in candidates}, {"M::strong"})
        strong = candidates[0]
        self.assertIn("mapping_state_write+3", strong["score_reasons"])
        self.assertEqual(len(low_signal), 1)
        low_entry = next(iter(low_signal.values()))
        self.assertEqual(low_entry["action_key"], "M::noop")
        self.assertEqual(low_entry["frontier_reason"], "low_signal_entrypoints")
        self.assertEqual(low_entry["priority"], "low")
        self.assertTrue(low_entry["title"].startswith("Low-signal source entrypoint"))

    async def test_build_attack_graph_source_only_no_op_is_low_signal_not_critical(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [
                {
                    # Funds leave — genuinely risky, stays a candidate.
                    "contract": "Vault",
                    "function": "withdraw",
                    "file": "/audit/src/Vault.sol",
                    "line": 20,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                    "affordances": [
                        "value_out_or_burn",
                        "token_or_native_transfer",
                        "state_mutating_entrypoint",
                    ],
                    "modifiers": [],
                },
                {
                    # Attacker-chosen dynamic call target — structurally risky.
                    "contract": "Vault",
                    "function": "z",
                    "file": "/audit/src/Vault.sol",
                    "line": 35,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [
                        {"name": "t", "raw": "address t"},
                        {"name": "d", "raw": "bytes calldata d"},
                    ],
                    "affordances": [
                        "dynamic_call_target",
                        "external_boundary_crossing",
                        "external_call",
                        "state_changing_entrypoint",
                    ],
                    "modifiers": [],
                },
                {
                    # function ping() external {}  — no structural risk.
                    "contract": "Vault",
                    "function": "ping",
                    "file": "/audit/src/Vault.sol",
                    "line": 50,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [],
                    "affordances": ["state_changing_entrypoint"],
                    "modifiers": [],
                },
            ],
            "observations": [],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "record_result": False,
        }))

        candidate_keys = [item["action_key"] for item in payload["candidate_chains"]]
        self.assertIn("Vault::withdraw", candidate_keys)
        # The structurally risky dynamic-call function still surfaces.
        self.assertIn("Vault::z", candidate_keys)
        # The no-op never competes for the top candidate list.
        self.assertNotIn("Vault::ping", candidate_keys)
        # No candidate is a critical no-op generic-invariant probe.
        for candidate in payload["candidate_chains"]:
            self.assertNotEqual(
                (candidate["action_key"], candidate.get("priority")),
                ("Vault::ping", "critical"),
            )
        dynamic = next(
            c for c in payload["candidate_chains"] if c["action_key"] == "Vault::z"
        )
        self.assertIn(dynamic["priority"], {"high", "critical"})

        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        low_signal = artifact["frontier"]["low_signal_entrypoints"]
        ping_entry = next(
            item for item in low_signal if item["action_key"] == "Vault::ping"
        )
        self.assertEqual(ping_entry["priority"], "low")
        self.assertLessEqual(ping_entry["priority_score"], 2)
        self.assertEqual(payload["frontier_summary"]["low_signal_entrypoints"], 1)

    async def test_build_attack_graph_reachability_aware_requires_live_when_explicit(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })

        result = await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "reachability_aware",
            "record_result": False,
        })

        self.assertTrue(result.startswith("Error:"))
        self.assertIn("reachability_aware", result)
        self.assertIn("live-reachability", result)

    async def test_build_attack_graph_auto_falls_back_to_source_only_without_live(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Vault",
                "function": "deposit",
                "file": "/audit/src/Vault.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_in_or_mint"],
                "modifiers": [],
            }],
            "observations": [],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "record_result": False,
        }))

        self.assertEqual(payload["mode"], "source_only")
        self.assertTrue(payload["needs_live_context"])
        self.assertTrue(payload["candidate_chains"])
        self.assertEqual(
            payload["candidate_chains"][0]["exposure"],
            "source_only",
        )

    async def test_build_attack_graph_auto_falls_back_to_source_only_with_empty_live(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": ["value_out_or_burn", "state_mutating_entrypoint"],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "mode": "auto",
            "record_result": False,
        }))

        self.assertEqual(payload["mode"], "source_only")
        self.assertTrue(payload["needs_live_context"])
        self.assertTrue(payload["candidate_chains"])
        self.assertEqual(payload["candidate_chains"][0]["exposure"], "source_only")
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        self.assertIsNone(artifact["live_reachability_path"])

    async def test_build_attack_graph_reachability_aware_preserves_low_score_in_frontier(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [{
                "contract": "Vault",
                "address": "0x1111111111111111111111111111111111111111",
                "action_exposures": [
                    {
                        "action_key": "Vault::withdraw",
                        "contract": "Vault",
                        "function": "withdraw",
                        "signature": "withdraw(uint256)",
                        "file": "/audit/src/Vault.sol",
                        "line": 20,
                        "target_address": "0x1111111111111111111111111111111111111111",
                        "affordances": ["value_out_or_burn", "token_or_native_transfer"],
                        "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                        "reachability": {"kind": "public", "attacker_reachable": True},
                        "live_status": "deployed",
                        "exposure": "exposed",
                    },
                    {
                        # Source-interface-only stub scores below the candidate
                        # floor; it must be preserved in the frontier, not dropped.
                        "action_key": "IFaucet::config",
                        "contract": "IFaucet",
                        "function": "config",
                        "signature": "config()",
                        "file": "/audit/src/IFaucet.sol",
                        "line": 5,
                        "target_address": "0x2222222222222222222222222222222222222222",
                        "affordances": ["configuration"],
                        "parameters": [],
                        "reachability": {"kind": "public"},
                        "live_status": "unknown",
                        "exposure": "source_interface_only",
                    },
                ],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "lr-001",
            "record_result": False,
        }))

        self.assertEqual(payload["mode"], "reachability_aware")
        top_keys = [item["action_key"] for item in payload["candidate_chains"]]
        self.assertIn("Vault::withdraw", top_keys)
        self.assertNotIn("IFaucet::config", top_keys)
        self.assertGreaterEqual(payload["frontier_summary"]["omitted_by_score"], 1)

        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        low_score_keys = [
            item["action_key"] for item in artifact["frontier"]["omitted_by_score"]
        ]
        self.assertIn("IFaucet::config", low_score_keys)
        self.assertEqual(artifact["all_candidate_count"], 2)

    async def test_build_attack_graph_preserve_frontier_false_skips_frontier(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [
                {
                    "contract": "Ledger",
                    "function": f"act{index}",
                    "file": "/audit/src/Ledger.sol",
                    "line": 10 + index,
                    "visibility": "external",
                    "mutability": "nonpayable",
                    "parameters": [],
                    "affordances": ["state_mutating_entrypoint", "mapping_state_write"],
                    "modifiers": [],
                }
                for index in range(3)
            ],
            "observations": [],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "max_candidates": 1,
            "preserve_frontier": False,
            "record_result": False,
        }))

        self.assertEqual(payload["frontier_summary"], {"preserved": False})
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        self.assertEqual(artifact["frontier"], {})
        # Omitted candidates are still counted even when the frontier is skipped.
        self.assertEqual(artifact["all_candidate_count"], 3)

    async def test_attack_search_recommends_source_only_attack_graph_without_live_reachability(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Source maps",
            "content": (
                "Protocol graph and action space are available; live reachability "
                "is not mapped yet."
            ),
            "evidence": [
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/action-spaces/as-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branches = {
            branch["next_tool"]: branch for branch in result["active_branches"]
        }
        self.assertIn("build_attack_graph", branches)
        source_only = branches["build_attack_graph"]
        self.assertEqual(source_only["source"], "missing_attack_graph_source_only")
        self.assertEqual(
            source_only["required_args"]["build_attack_graph"]["mode"],
            "source_only",
        )
        # Live reachability mapping stays the higher-priority next action when
        # protocol/action context exists; the source-only graph is additive.
        self.assertIn("map_live_reachability", branches)
        self.assertEqual(result["next_action"]["tool"], "map_live_reachability")

    async def test_build_attack_graph_consumes_state_transition_model(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Bland",
                "function": "x",
                "file": "/audit/src/Bland.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [],
                "affordances": ["mapping_state_write", "state_mutating_entrypoint"],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = json.dumps({
            "state_transition_model_id": "stm-001",
            "id": "stm-001",
            "candidate_invariants": [{
                "id": "inv-001",
                "kind": "conservation",
                "statement": "Per-user claim must not exceed aggregate resource.",
                "falsification_ideas": [
                    "Increase user claim without increasing aggregate.",
                ],
                "candidate_observations": [{"contract": "Bland", "function": "x"}],
            }],
            "entrypoints": [{"contract": "Bland", "function": "x", "line": 10}],
            "experiment_prompts": [{
                "title": "Falsify conservation in Bland",
                "target_actions": ["Bland.x"],
                "objective": (
                    "Try to falsify: Per-user claim must not exceed aggregate "
                    "resource."
                ),
                "probe_strategy": "accounting_delta",
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": (
                "/workspace/campaign/state-transition-models/stm-001.json"
            ),
            "record_result": False,
        }))

        generic = [
            candidate
            for candidate in payload["candidate_chains"]
            if candidate.get("candidate_kind") == "generic_invariant"
        ]
        self.assertEqual(len(generic), 1)
        candidate = generic[0]
        self.assertEqual(candidate["attack_key"], "stm:stm-001:inv-001")
        self.assertEqual(candidate["mechanism"], "generic_state_transition")
        self.assertEqual(candidate["invariant"]["id"], "inv-001")
        self.assertEqual(candidate["invariant"]["source"], "generic")
        self.assertEqual(
            candidate["source"],
            {
                "kind": "state_transition_model",
                "state_transition_model": (
                    "/workspace/campaign/state-transition-models/stm-001.json"
                ),
                "invariant_id": "inv-001",
            },
        )
        self.assertIn(
            "Per-user claim must not exceed aggregate resource.",
            candidate["objective"],
        )
        # The invariant resolved to the action-space entrypoint via the matching
        # experiment prompt / entrypoint, so a concrete action skeleton is bound.
        self.assertEqual(candidate["actions"][0]["action_key"], "Bland::x")
        self.assertNotIn(
            "state-transition model invariant has no matched action-space "
            "entrypoint",
            candidate["blockers"],
        )
        # The invariant's own candidate_observations are preserved.
        self.assertIn(
            {"contract": "Bland", "function": "x"}, candidate["observations"]
        )
        # Response + artifact carry the state-transition-model locator.
        self.assertEqual(
            payload["state_transition_model"],
            {
                "path": "/workspace/campaign/state-transition-models/stm-001.json",
                "candidate_count": 1,
            },
        )
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        self.assertEqual(
            artifact["state_transition_model"],
            {
                "path": "/workspace/campaign/state-transition-models/stm-001.json",
                "model_id": "stm-001",
                "candidate_count": 1,
            },
        )
        self.assertEqual(
            payload["summary"]["generic_invariant_candidates"], 1
        )

    async def test_build_attack_graph_state_transition_model_id_ref_and_frontier(self):
        container = FakeContainer()
        # A high-value source-only action outranks the generic invariant, so with
        # max_candidates=1 the invariant candidate is preserved in the frontier's
        # dedicated generic_invariant_candidates bucket rather than dropped.
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "affordances": [
                    "value_out_or_burn",
                    "token_or_native_transfer",
                    "state_mutating_entrypoint",
                ],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = json.dumps({
            "state_transition_model_id": "stm-001",
            "id": "stm-001",
            "candidate_invariants": [{
                "id": "inv-001",
                "kind": "rounding",
                "statement": "Rounding must not favor the caller.",
                "contract": "Other",
                "function": "compute",
                "candidate_observations": [],
            }],
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "max_candidates": 1,
            # Resolve the model by bare id, exercising the id loader path.
            "state_transition_model": "stm-001",
            "record_result": False,
        }))

        top_kinds = [
            candidate.get("candidate_kind")
            for candidate in payload["candidate_chains"]
        ]
        self.assertNotIn("generic_invariant", top_kinds)
        artifact = json.loads(
            container.files["/workspace/campaign/attack-graphs/ag-001.json"]
        )
        frontier_keys = [
            ref.get("attack_key")
            for ref in artifact["frontier"]["generic_invariant_candidates"]
        ]
        self.assertIn("stm:stm-001:inv-001", frontier_keys)
        self.assertEqual(
            payload["frontier_summary"]["generic_invariant_candidates"], 1
        )
        # An unmatched invariant keeps the no-entrypoint blocker and a lower score.
        invariant_candidate = next(
            candidate
            for candidate in _state_transition_model_attack_candidates(
                json.loads(
                    container.files[
                        "/workspace/campaign/state-transition-models/stm-001.json"
                    ]
                ),
                action_space=json.loads(
                    container.files["/workspace/campaign/action-spaces/as-001.json"]
                ),
                protocol_graph=None,
                source_path="/workspace/campaign/state-transition-models/stm-001.json",
                mode="source_only",
            )
        )
        # No entrypoint resolved, so the empty actions list is elided like any
        # other empty candidate field.
        self.assertEqual(invariant_candidate.get("actions", []), [])
        self.assertIn(
            "state-transition model invariant has no matched action-space "
            "entrypoint",
            invariant_candidate["blockers"],
        )

    async def test_build_attack_graph_generic_invariant_survives_protocol_lens(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Vault",
                "function": "redeem",
                "file": "/audit/src/Vault.sol",
                "line": 30,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [],
                "affordances": ["value_out_or_burn"],
                "modifiers": [],
            }],
            "observations": [],
        })
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = json.dumps({
            "state_transition_model_id": "stm-001",
            "id": "stm-001",
            "candidate_invariants": [{
                "id": "inv-001",
                "kind": "conservation",
                "statement": "Shares and assets must stay conserved.",
                "contract": "Vault",
                "function": "redeem",
                "candidate_observations": [],
            }],
            # A vault lens coexists; it must annotate, not replace or outrank the
            # generic invariant candidate.
            "lenses": {"vault_like": {"evidence": [], "note": "optional"}},
        })

        payload = json.loads(await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": "stm-001",
            "record_result": False,
        }))

        generic = [
            candidate
            for candidate in payload["candidate_chains"]
            if candidate.get("candidate_kind") == "generic_invariant"
        ]
        self.assertEqual(len(generic), 1)
        # The lens appears only as a metadata planning note, never as a separate
        # candidate kind or a score driver.
        lens_notes = [
            note for note in generic[0]["planning_notes"] if "lenses" in note
        ]
        self.assertTrue(lens_notes)
        self.assertIn("vault_like", lens_notes[0])
        kinds = {
            candidate.get("candidate_kind")
            for candidate in payload["candidate_chains"]
        }
        self.assertLessEqual(kinds, {"generic_invariant", "source_only"})

    async def test_build_attack_graph_invalid_state_transition_model_errors(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })

        missing = await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": (
                "/workspace/campaign/state-transition-models/stm-999.json"
            ),
            "record_result": False,
        })
        self.assertTrue(missing.startswith("Error:"))
        self.assertIn("state_transition_model", missing)

        bad_path = await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": "/etc/passwd",
            "record_result": False,
        })
        self.assertTrue(bad_path.startswith("Error:"))
        self.assertIn("state-transition-models", bad_path)

    async def test_attack_search_recommends_attack_graph_with_state_transition_model(
        self,
    ):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = json.dumps({"id": "stm-001", "candidate_invariants": []})
        await _update_campaign(container, {
            "section": "result",
            "title": "Source maps",
            "content": "Action space, protocol graph, and state model are available.",
            "evidence": [
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/state-transition-models/stm-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branches = {
            branch["next_tool"]: branch for branch in result["active_branches"]
        }
        self.assertIn("build_attack_graph", branches)
        required = branches["build_attack_graph"]["required_args"][
            "build_attack_graph"
        ]
        self.assertEqual(
            required["state_transition_model"],
            "/workspace/campaign/state-transition-models/stm-001.json",
        )
        self.assertIn(
            "state_transition_model",
            branches["build_attack_graph"]["instructions"],
        )

    async def _record_foundation(self, container):
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })

    def _bland_action_space(self):
        return json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Bland",
                "function": "x",
                "file": "/audit/src/Bland.sol",
                "line": 10,
                "visibility": "external",
                "mutability": "nonpayable",
                "parameters": [],
                "affordances": ["mapping_state_write", "state_mutating_entrypoint"],
                "modifiers": [],
            }],
            "observations": [],
        })

    def _bland_state_transition_model(self):
        return json.dumps({
            "state_transition_model_id": "stm-001",
            "id": "stm-001",
            "candidate_invariants": [{
                "id": "inv-001",
                "kind": "conservation",
                "statement": "Per-user claim must not exceed aggregate resource.",
                "falsification_ideas": [
                    "Increase user claim without increasing aggregate.",
                ],
                "candidate_observations": [{"contract": "Bland", "function": "x"}],
            }],
            "entrypoints": [{"contract": "Bland", "function": "x", "line": 10}],
            "experiment_prompts": [{
                "title": "Falsify conservation in Bland",
                "target_actions": ["Bland.x"],
                "objective": (
                    "Try to falsify: Per-user claim must not exceed aggregate "
                    "resource."
                ),
                "probe_strategy": "accounting_delta",
            }],
        })

    async def test_attack_search_recommends_extract_state_transition_model_when_missing(
        self,
    ):
        # A: action space exists but no state-transition model -> extract is
        # recommended (generic-first), carrying the action-space arg and the map
        # toolset (also covers F for the extract branch).
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps(
            {"id": "pg-001", "nodes": [], "edges": []}
        )
        await _update_campaign(container, {
            "section": "result",
            "title": "Source maps",
            "content": "Action space and protocol graph available; no model yet.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branches = {
            branch["next_tool"]: branch for branch in result["active_branches"]
        }
        self.assertIn("extract_state_transition_model", branches)
        extract = branches["extract_state_transition_model"]
        self.assertEqual(extract["source"], "missing_state_transition_model")
        self.assertEqual(extract["status"], "needs_mapping")
        self.assertEqual(extract["required_toolsets"], ["map"])
        self.assertEqual(
            extract["required_args"]["extract_state_transition_model"]["action_space"],
            "/workspace/campaign/action-spaces/as-001.json",
        )

    async def test_attack_search_recommends_rebuild_when_graph_skips_model(self):
        # B: action space + a model with invariants exist, an attack graph exists
        # but did not consume the model -> recommend a build_attack_graph rebuild
        # that passes the model (map toolset).
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = self._bland_state_transition_model()
        # A pre-existing attack graph with no state_transition_model locator.
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [],
            "nodes": [],
            "edges": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps and graph",
            "content": "Action space, model, and a model-blind attack graph exist.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/state-transition-models/stm-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        rebuilds = [
            branch for branch in result["active_branches"]
            if branch["source"] == "attack_graph_without_state_transition_model"
        ]
        self.assertEqual(len(rebuilds), 1)
        rebuild = rebuilds[0]
        self.assertEqual(rebuild["next_tool"], "build_attack_graph")
        self.assertEqual(rebuild["status"], "needs_mapping")
        self.assertEqual(rebuild["required_toolsets"], ["map"])
        required = rebuild["required_args"]["build_attack_graph"]
        self.assertEqual(
            required["state_transition_model"],
            "/workspace/campaign/state-transition-models/stm-001.json",
        )
        self.assertEqual(required["mode"], "source_only")
        self.assertTrue(required["preserve_frontier"])
        # A is mutually exclusive: a model already exists, so do not re-extract.
        tools = {branch["next_tool"] for branch in result["active_branches"]}
        self.assertNotIn("extract_state_transition_model", tools)

    async def test_attack_search_surfaces_generic_invariant_branch_from_graph(self):
        # C + D: a graph that consumed the model surfaces a branch carrying the
        # invariant id and generic_state_transition mechanism; lacking live
        # context, it routes to map_live_reachability (map toolset).
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = self._bland_state_transition_model()
        await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": (
                "/workspace/campaign/state-transition-models/stm-001.json"
            ),
            "record_result": False,
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps and graph",
            "content": "Action space, model, and a model-aware attack graph exist.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/state-transition-models/stm-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        invariant_branches = [
            branch for branch in result["active_branches"]
            if branch.get("generic_invariant")
        ]
        self.assertEqual(len(invariant_branches), 1)
        branch = invariant_branches[0]
        self.assertEqual(branch["source"], "attack_graph_state_model")
        self.assertEqual(branch["invariant_id"], "inv-001")
        self.assertEqual(branch["invariant_kind"], "conservation")
        self.assertEqual(branch["mechanism"], "generic_state_transition")
        self.assertIn(
            "Per-user claim must not exceed aggregate resource.",
            branch["invariant_statement"],
        )
        self.assertEqual(
            branch["state_transition_model"],
            "/workspace/campaign/state-transition-models/stm-001.json",
        )
        self.assertIn("stm:stm-001:inv-001", branch["attack_keys"])
        # D: no live reachability -> prefer mapping live reachability, map toolset.
        self.assertEqual(branch["next_tool"], "map_live_reachability")
        self.assertEqual(branch["required_toolsets"], ["map"])
        # The durable dossier carries the same locator for a recovering agent.
        await _attack_search(container, {
            "action": "select",
            "branch_id": branch["id"],
            "record_result": False,
        })
        dossier = json.loads(
            container.files[
                f"/workspace/campaign/branch-dossiers/{branch['id']}.json"
            ]
        )
        self.assertTrue(dossier["generic_invariant"])
        self.assertEqual(dossier["invariant_id"], "inv-001")
        self.assertEqual(dossier["mechanism"], "generic_state_transition")
        self.assertEqual(
            dossier["state_transition_model"],
            "/workspace/campaign/state-transition-models/stm-001.json",
        )

    async def test_attack_search_parks_generic_invariant_after_empty_live_map(self):
        # If live reachability was attempted but did not bind any deployed
        # target, source-only generic invariants must not advance into workbench
        # or sequence composition. Preserve the branch as parked planning
        # context until the agent records deployment/fork context or mutates it.
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = self._bland_state_transition_model()
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })
        await _build_attack_graph(container, {
            "action_space": "as-001",
            "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
            "mode": "auto",
            "state_transition_model": (
                "/workspace/campaign/state-transition-models/stm-001.json"
            ),
            "record_result": False,
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps and graph",
            "content": (
                "Action space, empty live reachability, model, and model-aware "
                "attack graph exist."
            ),
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/state-transition-models/stm-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        invariant_branches = [
            branch for branch in result["active_branches"]
            if branch.get("generic_invariant")
        ]
        self.assertEqual(len(invariant_branches), 1)
        branch = invariant_branches[0]
        self.assertEqual(branch["source"], "attack_graph_state_model")
        self.assertEqual(branch["status"], "parked_needs_live_context")
        self.assertEqual(branch["next_tool"], "record_fork_context or update_campaign")
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertIn("live reachability", branch["parking_reason"])
        self.assertIn("deployment metadata", branch["recommended_budget"])
        self.assertNotIn(
            branch["next_tool"],
            {
                "prepare_fork_exploit_workbench",
                "compose_sequence_experiment",
                "complete_sequence_experiment",
                "run_experiment",
            },
        )
        self.assertTrue(
            any(
                "deployment" in evidence and "target" in evidence
                for evidence in branch["required_evidence"]
            )
        )

    async def test_attack_search_uses_source_only_graph_after_empty_live_map(self):
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "summary": {"nodes": 1, "edges": 0},
            "hotspots": [],
        })
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps",
            "content": "Source maps and empty live reachability are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        self.assertFalse([
            item for item in result["active_branches"]
            if item["source"] == "missing_attack_graph"
        ])
        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "missing_attack_graph_source_only"
        )
        required = branch["required_args"]["build_attack_graph"]
        self.assertEqual(required["mode"], "source_only")
        self.assertNotIn("live_reachability", required)

    async def test_attack_search_parks_source_only_frontier_after_empty_live_map(self):
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files[
            "/workspace/campaign/live-reachability/lr-001.json"
        ] = json.dumps({
            "id": "lr-001",
            "summary": {
                "exposed_actions": 0,
                "live_deployed_profiles": 0,
                "code_present": 0,
                "profiles_with_actions": 0,
                "source_artifact_actions": 0,
                "target_bindings": {},
            },
            "actions": [],
            "exposures": [],
            "profiles": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "mode": "source_only",
            "candidate_chains": [],
            "frontier": {
                "omitted_by_score": [{
                    "attack_key": "source:Vault:skim:12",
                    "action_key": "Vault::skim",
                    "contract": "Vault",
                    "function": "skim",
                    "title": "Frontier lead: Vault::skim",
                    "exposure": "source_only",
                    "blockers": [
                        "live reachability not mapped",
                        "target address not bound",
                    ],
                    "affordances": [
                        "mapping_state_write",
                        "external_boundary_crossing",
                    ],
                    "priority_score": 1,
                    "frontier_reason": "omitted_by_score",
                }],
                "unlabeled_state_mutators": [{
                    "attack_key": "source:Vault:skim:12",
                }],
            },
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Source-only maps and graph",
            "content": "Source maps, empty live reachability, and graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "attack_graph_frontier"
        )
        self.assertEqual(branch["status"], "parked_needs_live_context")
        self.assertEqual(branch["next_tool"], "record_fork_context or update_campaign")
        self.assertEqual(branch["required_toolsets"], ["core"])
        self.assertIn("live reachability", branch["parking_reason"])
        self.assertNotEqual(branch["next_tool"], "map_live_reachability")

    async def test_attack_search_evidence_outranks_state_model_candidates(self):
        # D (strict ordering): a needs_evidence branch still wins the next_action
        # over an extract_state_transition_model candidate.
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        await _update_campaign(container, {
            "section": "result",
            "title": "Source maps",
            "content": "Action space available; no model yet.",
            "evidence": ["/workspace/campaign/action-spaces/as-001.json"],
        })
        await _update_campaign(container, {
            "section": "experiment",
            "title": "Donation redeem fork replay",
            "content": "Run a Foundry fork test and measure attacker balance.",
            "related_ids": ["hyp-001"],
        })
        container.exec_result = (
            0,
            "[PASS] test_donation_redeem_profit() (gas: 123)\n"
            "Suite result: ok. 1 passed; 0 failed; 0 skipped\n",
        )
        await _run_experiment(container, {
            "title": "Donation redeem fork replay",
            "command": "forge test --match-test test_donation_redeem_profit -vvv",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        # The extract candidate is present but strictly outranked by evidence.
        tools = {branch["next_tool"] for branch in result["active_branches"]}
        self.assertIn("extract_state_transition_model", tools)
        self.assertEqual(result["next_action"]["status"], "needs_evidence")

    async def test_attack_search_does_not_reextract_model_used_by_graph(self):
        # E (no loop): a model exists and the latest attack graph consumed it ->
        # neither extraction nor a model rebuild is recommended.
        container = FakeContainer()
        await self._record_foundation(container)
        container.files["/workspace/campaign/action-spaces/as-001.json"] = (
            self._bland_action_space()
        )
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = self._bland_state_transition_model()
        await _build_attack_graph(container, {
            "action_space": "as-001",
            "mode": "source_only",
            "state_transition_model": (
                "/workspace/campaign/state-transition-models/stm-001.json"
            ),
            "record_result": False,
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps and graph",
            "content": "Action space, model, and a model-aware attack graph exist.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/state-transition-models/stm-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        tools = {branch["next_tool"] for branch in result["active_branches"]}
        sources = {branch["source"] for branch in result["active_branches"]}
        self.assertNotIn("extract_state_transition_model", tools)
        self.assertNotIn("attack_graph_without_state_transition_model", sources)
        # Positive control: the consumed model still produced a generic branch.
        self.assertTrue(
            any(branch.get("generic_invariant") for branch in result["active_branches"])
        )

    async def test_prepare_fork_exploit_workbench_infers_vault_adapter(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "vault-redeem",
                "title": "Test live-reachable Vault::redeem",
                "priority": "critical",
                "priority_score": 24,
                "action_key": "Vault::redeem",
                "contract": "Vault",
                "function": "redeem",
                "target_address": "0x1111111111111111111111111111111111111111",
                "exposure": "exposed",
                "live_status": "deployed",
                "objective": "redeem must not release more assets than shares justify",
                "affordances": ["value_out_or_burn", "token_or_native_transfer"],
                "actions": [{
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "redeem",
                    "target": "0x1111111111111111111111111111111111111111",
                    "args": ["shares"],
                    "expected_effect": "unauthorized value leaves the vault",
                }],
            }],
        })

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))

        self.assertEqual(result["workbench_id"], "fw-001")
        self.assertEqual(result["mechanism"], "vault")
        self.assertEqual(result["target"]["address"], "0x1111111111111111111111111111111111111111")
        self.assertIn("attacker asset profit", json.dumps(result["objective_templates"]))
        self.assertEqual(
            result["compose_sequence_experiment_args"]["candidate_id"],
            "agcand-001",
        )
        workbench = json.loads(
            container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
        )
        self.assertEqual(workbench["mechanism"], "vault")
        self.assertIn("asset()(address)", json.dumps(workbench))
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["sections"]["experiment"][0]["id"], "fw-001")
        self.assertIn("Template: fork_workbench", state["sections"]["experiment"][0]["content"])

    async def test_prepare_fork_exploit_workbench_infers_lending_adapter(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "cether-liquidation",
                "title": "Test live-reachable CEther::liquidateBorrow",
                "priority": "high",
                "priority_score": 20,
                "action_key": "CEther::liquidateBorrow",
                "contract": "CEther",
                "function": "liquidateBorrow",
                "target_address": "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9",
                "exposure": "exposed",
                "live_status": "deployed",
                "objective": "liquidation must not seize more collateral than formula permits",
                "affordances": ["credit_or_liquidation", "accepts_native_value"],
                "actions": [{
                    "actor": "attacker",
                    "contract": "CEther",
                    "function": "liquidateBorrow",
                    "target": "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9",
                    "args": ["borrower", "cTokenCollateral"],
                    "expected_effect": "unfair liquidation value",
                }],
            }],
        })

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))

        self.assertEqual(result["mechanism"], "lending")
        workbench = json.loads(
            container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
        )
        self.assertIn("borrowBalanceStored", json.dumps(workbench))
        self.assertIn("expected seize tokens", json.dumps(workbench))

    async def test_lending_workbench_carries_liquidation_playbook(self):
        # The permanent prompt no longer spells out the liquidation checklist
        # (close factor, repay asset, seize tokens, ...). That mechanism-specific
        # playbook must still surface where the mechanism is actually known —
        # the prepare_fork_exploit_workbench output and the README the agent
        # reads — which is the branch/tool surface the compressed prompt
        # delegates to.
        container = FakeContainer()
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "cether-liquidation",
                "title": "Test live-reachable CEther::liquidateBorrow",
                "priority": "high",
                "priority_score": 20,
                "action_key": "CEther::liquidateBorrow",
                "contract": "CEther",
                "function": "liquidateBorrow",
                "target_address": "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9",
                "exposure": "exposed",
                "live_status": "deployed",
                "objective": "liquidation must not seize more collateral than formula permits",
                "affordances": ["credit_or_liquidation", "accepts_native_value"],
                "actions": [{
                    "actor": "attacker",
                    "contract": "CEther",
                    "function": "liquidateBorrow",
                    "target": "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9",
                    "args": ["borrower", "cTokenCollateral"],
                    "expected_effect": "unfair liquidation value",
                }],
            }],
        })

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))
        self.assertEqual(result["mechanism"], "lending")

        workbench_blob = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/workbench.json"
        ]
        readme = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/README.md"
        ]
        # The detailed mechanism guidance lives in the branch surface, not the
        # permanent prompt.
        self.assertIn("close factor", workbench_blob)
        self.assertIn("seize tokens", workbench_blob)
        # The README the agent reads carries the same mechanism-specific setup.
        self.assertIn("close factor", readme)

    async def test_prepare_fork_exploit_workbench_infers_bridge_staking_and_generic_adapters(self):
        cases = [
            (
                "bridge_message_accounting",
                "Bridge",
                "Bridge::relay",
                ["cross_domain_or_message", "value_out_or_burn"],
                "bridge",
                "message_path_binding",
            ),
            (
                "staking_delegation_accounting",
                "StakingVault",
                "StakingVault::unstake",
                ["value_out_or_burn"],
                "staking",
                "stake_entitlement_binding",
            ),
            (
                "generic_execution",
                "Executor",
                "Executor::execute",
                ["generic_execution", "delegatecall"],
                "generic_execution",
                "callee_and_selector_binding",
            ),
            (
                "queue_solver_accounting",
                "BoringOnChainQueue",
                "BoringOnChainQueue::solveOnChainWithdraws",
                ["value_out_or_burn"],
                "queue_solver",
                "solver_consent_and_allowance",
            ),
        ]
        for mechanism, contract, action_key, affordances, expected, setup_kind in cases:
            container = FakeContainer()
            container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
                "id": "ag-001",
                "candidate_chains": [{
                    "candidate_id": "agcand-001",
                    "attack_key": action_key.lower(),
                    "title": f"Test live-reachable {action_key}",
                    "priority": "high",
                    "priority_score": 20,
                    "action_key": action_key,
                    "contract": contract,
                    "function": action_key.split("::", 1)[1],
                    "target_address": "0x1111111111111111111111111111111111111111",
                    "exposure": "exposed",
                    "live_status": "deployed",
                    "mechanism": mechanism,
                    "objective": "Prove or reject the mechanism-specific exploit path.",
                    "affordances": affordances,
                    "actions": [{
                        "actor": "attacker",
                        "contract": contract,
                        "function": action_key.split("::", 1)[1],
                        "target": "0x1111111111111111111111111111111111111111",
                        "args": ["payload"],
                        "expected_effect": "measurable unauthorized state transition",
                    }],
                }],
            })

            result = json.loads(await _prepare_fork_exploit_workbench(container, {
                "attack_graph": "ag-001",
                "candidate_id": "agcand-001",
                "record_result": False,
            }))

            self.assertEqual(result["mechanism"], expected)
            persisted = json.loads(
                container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
            )
            self.assertIn(setup_kind, json.dumps(persisted))
            if expected == "queue_solver":
                self.assertIn("provider_safe_event_reconstruction", json.dumps(persisted))

    async def test_prepare_fork_exploit_workbench_prefers_candidate_mechanism_over_override(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "economic:queue_solver:0x1111111111111111111111111111111111111111",
                "title": "Test queue request-to-settlement accounting",
                "priority": "critical",
                "priority_score": 40,
                "action_key": "QueueSolver::BoringOnChainQueue",
                "contract": "BoringOnChainQueue",
                "target_address": "0x1111111111111111111111111111111111111111",
                "mechanism": "queue_solver_accounting",
                "objective": "Queued requests must not settle for excess value.",
                "actions": [{
                    "actor": "attacker",
                    "contract": "BoringOnChainQueue",
                    "function": "requestOnChainWithdrawWithPermit",
                    "target": "0x1111111111111111111111111111111111111111",
                    "action_key": "BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                    "expected_effect": "create a queued claim",
                }],
            }],
        })

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "mechanism": "vault",
            "record_result": False,
        }))

        self.assertEqual(result["mechanism"], "queue_solver")
        persisted = json.loads(
            container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
        )
        self.assertIn("queue nonce", json.dumps(persisted))

    def test_infer_fork_workbench_mechanism_unknown_candidate_is_generic(self):
        # A bland access-control candidate with no economic/execution vocabulary
        # must not be coerced into vault assumptions.
        candidate = {
            "title": "Registry::finalizeEntry caller bypass",
            "contract": "Registry",
            "function": "finalizeEntry",
            "objective": (
                "only the entry creator may finalize an entry; a third party must "
                "not finalize another account's entry"
            ),
            "affordances": ["unauthorized_caller"],
            "actions": [{
                "actor": "attacker",
                "contract": "Registry",
                "function": "finalizeEntry",
                "args": ["entryId"],
                "expected_effect": "finalize an entry the attacker did not create",
            }],
        }
        self.assertEqual(
            _infer_fork_workbench_mechanism(candidate, None, "auto"),
            "generic_state_transition",
        )

    def test_infer_fork_workbench_mechanism_respects_explicit_overrides(self):
        candidate = {
            "title": "Registry::finalizeEntry caller bypass",
            "contract": "Registry",
            "function": "finalizeEntry",
            "objective": "a third party must not finalize another account's entry",
        }
        self.assertEqual(
            _infer_fork_workbench_mechanism(candidate, None, "vault"),
            "vault",
        )
        self.assertEqual(
            _infer_fork_workbench_mechanism(candidate, None, "generic_execution"),
            "generic_execution",
        )
        self.assertEqual(
            _infer_fork_workbench_mechanism(candidate, None, "generic_state_transition"),
            "generic_state_transition",
        )

    def test_infer_fork_workbench_mechanism_vault_terms_still_vault(self):
        candidate = {
            "title": "Vault redemption rounding",
            "contract": "Vault",
            "function": "redeem",
            "objective": "deposit and redeem shares must not let an attacker drain the vault",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "redeem",
                "args": ["shares"],
                "expected_effect": "redeem more assets than shares justify",
            }],
        }
        self.assertEqual(
            _infer_fork_workbench_mechanism(candidate, None, "auto"),
            "vault",
        )

    def test_fork_workbench_adapter_unknown_fallback_is_generic_not_vault(self):
        target = {
            "label": "Registry",
            "address": "0x1111111111111111111111111111111111111111",
            "concrete": True,
        }
        candidate = {
            "contract": "Registry",
            "function": "finalizeEntry",
            "objective": "a third party must not finalize another account's entry",
        }
        # An unmatched mechanism string must fall through to the generic
        # state-transition adapter, never the vault adapter.
        fallback = _fork_workbench_adapter(
            "totally_unknown_mechanism",
            candidate,
            target=target,
            fork_context=None,
        )
        self.assertEqual(fallback["mechanism"], "generic_state_transition")
        self.assertNotIn("totalAssets", json.dumps(fallback))
        self.assertNotIn("previewRedeem", json.dumps(fallback))
        # The explicit dispatch must reach the same adapter.
        explicit = _fork_workbench_adapter(
            "generic_state_transition",
            candidate,
            target=target,
            fork_context=None,
        )
        self.assertEqual(explicit, fallback)
        # Vault still routes to the vault adapter (with its share accounting).
        vault = _fork_workbench_adapter(
            "vault",
            candidate,
            target=target,
            fork_context=None,
        )
        self.assertEqual(vault["mechanism"], "vault")
        self.assertIn("totalAssets", json.dumps(vault))

    def test_generic_state_transition_adapter_makes_no_vault_assumptions(self):
        target = {
            "label": "Registry",
            "address": "0x1111111111111111111111111111111111111111",
            "concrete": True,
        }
        candidate = {
            "contract": "Registry",
            "function": "finalizeEntry",
            "objective": "a third party must not finalize another account's entry",
        }
        adapter = _generic_state_transition_workbench_adapter(
            candidate,
            target=target,
            fork_context=None,
        )
        self.assertEqual(adapter["mechanism"], "generic_state_transition")
        dumped = json.dumps(adapter)
        for vault_term in ("asset()(address)", "totalAssets", "previewRedeem", "share"):
            self.assertNotIn(vault_term, dumped)
        setup_kinds = {item["kind"] for item in adapter["setup_tasks"]}
        self.assertEqual(
            setup_kinds,
            {"target_binding", "actor_identification", "asset_seeding", "authorization_precondition"},
        )
        # Without identified assets the asset-seeding task must refuse to assume
        # balances and surface a missing-objective blocker instead.
        asset_seeding = next(
            item for item in adapter["setup_tasks"] if item["kind"] == "asset_seeding"
        )
        self.assertIn("No assets were identified", asset_seeding["prompt"])
        self.assertTrue(
            any("Add at least one" in check for check in adapter["blocker_checks"])
        )
        roles = {item["role"] for item in adapter["objective_templates"]}
        self.assertIn("state_transition", roles)

    async def test_prepare_fork_exploit_workbench_infers_generic_state_transition(self):
        container = FakeContainer()
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "registry-finalize",
                "title": "Registry::finalizeEntry caller bypass",
                "priority": "high",
                "priority_score": 18,
                "action_key": "Registry::finalizeEntry",
                "contract": "Registry",
                "function": "finalizeEntry",
                "target_address": "0x1111111111111111111111111111111111111111",
                "exposure": "exposed",
                "live_status": "deployed",
                "objective": (
                    "only the entry creator may finalize an entry; a third party "
                    "must not finalize another account's entry"
                ),
                "affordances": ["unauthorized_caller"],
                "actions": [{
                    "actor": "attacker",
                    "contract": "Registry",
                    "function": "finalizeEntry",
                    "target": "0x1111111111111111111111111111111111111111",
                    "args": ["entryId"],
                    "expected_effect": "finalize an entry the attacker did not create",
                }],
            }],
        })

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))

        self.assertEqual(result["mechanism"], "generic_state_transition")
        workbench = json.loads(
            container.files["/workspace/campaign/fork-workbenches/fw-001/workbench.json"]
        )
        self.assertEqual(workbench["mechanism"], "generic_state_transition")
        dumped = json.dumps(workbench)
        self.assertNotIn("asset()(address)", dumped)
        self.assertNotIn("totalAssets", dumped)
        self.assertNotIn("previewRedeem", dumped)

        readme = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/README.md"
        ].lower()
        self.assertIn("generic invariant", readme)
        for banned in ("vault", "share", "totalassets"):
            self.assertNotIn(banned, readme)

    def _write_stm_workbench_files(
        self,
        container,
        *,
        invariant,
        lenses=None,
        candidate_source=None,
        candidate_invariant=None,
    ):
        """Write an stm-001 model artifact plus an ag-001 attack graph carrying one
        generic_invariant candidate keyed to the invariant."""
        contract = invariant.get("contract") or "Registry"
        function = invariant.get("function") or "finalizeEntry"
        model = {
            "state_transition_model_id": "stm-001",
            "id": "stm-001",
            "candidate_invariants": [invariant],
            "entrypoints": [{"contract": contract, "function": function, "line": 10}],
            "experiment_prompts": [{
                "title": f"Falsify {invariant['kind']} in {contract}.{function}",
                "target_actions": [f"{contract}.{function}"],
                "objective": f"Try to falsify: {invariant['statement']}",
                "probe_strategy": "custom",
                "required_setup": ["Prepare attacker and victim identities."],
            }],
        }
        if lenses is not None:
            model["lenses"] = lenses
        container.files[
            "/workspace/campaign/state-transition-models/stm-001.json"
        ] = json.dumps(model)
        candidate = {
            "candidate_id": "agcand-001",
            "attack_key": f"stm:stm-001:{invariant['id']}",
            "title": f"Invariant probe: {invariant['statement']}",
            "priority": "high",
            "priority_score": 8,
            "candidate_kind": "generic_invariant",
            "mechanism": "generic_state_transition",
            "action_key": f"{contract}::{function}",
            "contract": contract,
            "function": function,
            "target_address": "0x1111111111111111111111111111111111111111",
            "exposure": "exposed",
            "live_status": "deployed",
            "objective": f"Falsify invariant: {invariant['statement']}",
            "actions": [{
                "actor": "attacker",
                "contract": contract,
                "function": function,
                "target": "0x1111111111111111111111111111111111111111",
                "args": ["entryId"],
                "expected_effect": "exercise the transition the invariant forbids",
            }],
        }
        if candidate_invariant is not None:
            candidate["invariant"] = candidate_invariant
        if candidate_source is not None:
            candidate["source"] = candidate_source
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [candidate],
        })

    async def test_prepare_fork_exploit_workbench_accepts_state_transition_model(self):
        # Passing the optional arg is accepted and threads model-derived guidance
        # into the workbench. (The schema surface is pinned in test_tool_registry.)
        container = FakeContainer()
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "authorization_binding",
                "statement": "Only the entry creator may finalize an entry.",
                "contract": "Registry",
                "function": "finalizeEntry",
                "falsification_ideas": ["Finalize an entry you did not create."],
                "candidate_observations": [
                    "custom: assert the victim entry status changes while only the "
                    "attacker authorized the call",
                ],
            },
            candidate_invariant={"id": "inv-001"},
        )

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "stm-001",
            "record_result": False,
        }))

        self.assertEqual(result["mechanism"], "generic_state_transition")
        self.assertEqual(result["model_guidance"]["invariant_id"], "inv-001")

    async def test_prepare_fork_exploit_workbench_consumes_matched_invariant(self):
        container = FakeContainer()
        statement = "Only the entry creator may finalize an entry."
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "authorization_binding",
                "statement": statement,
                "contract": "Registry",
                "function": "finalizeEntry",
                "falsification_ideas": ["Finalize an entry you did not create."],
                "candidate_observations": [
                    "custom: assert the victim entry status changes while only the "
                    "attacker authorized the call",
                ],
            },
            candidate_source={
                "kind": "state_transition_model",
                "state_transition_model": (
                    "/workspace/campaign/state-transition-models/stm-001.json"
                ),
                "invariant_id": "inv-001",
            },
        )

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "stm-001",
            "record_result": False,
        }))

        guidance = result["model_guidance"]
        self.assertEqual(guidance["invariant_id"], "inv-001")
        self.assertEqual(guidance["kind"], "authorization_binding")
        self.assertEqual(guidance["statement"], statement)
        # The invariant statement drives the lead objective and the success
        # condition the agent will assert against.
        self.assertIn(statement, json.dumps(result["objective_templates"]))
        self.assertEqual(
            result["objective_templates"][0]["role"], "invariant_falsification"
        )
        compose = result["compose_sequence_experiment_args"]
        self.assertEqual(compose["mechanism"], "generic_state_transition")
        self.assertEqual(compose["invariant_id"], "inv-001")
        self.assertIn(statement, compose["success_condition"])
        self.assertTrue(any(
            isinstance(obs, dict)
            and obs.get("source") == "state_transition_model_invariant"
            for obs in compose["observations"]
        ))
        # A model experiment prompt's setup became a workbench setup task.
        workbench = json.loads(
            container.files[
                "/workspace/campaign/fork-workbenches/fw-001/workbench.json"
            ]
        )
        self.assertEqual(workbench["model_guidance"]["invariant_id"], "inv-001")
        self.assertIn(
            "model_experiment_setup",
            {task["kind"] for task in workbench["setup_tasks"]},
        )
        readme = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/README.md"
        ]
        self.assertIn("## Model Guidance", readme)
        self.assertIn("inv-001", readme)
        self.assertIn(statement, readme)
        self.assertIn(
            "/workspace/campaign/state-transition-models/stm-001.json", readme
        )

    async def test_prepare_fork_exploit_workbench_loads_model_from_candidate_source(self):
        # No explicit arg: the candidate's own source.state_transition_model is the
        # fallback locator and still produces model guidance.
        container = FakeContainer()
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "state_machine",
                "statement": "Finalization must not run twice for one entry.",
                "contract": "Registry",
                "function": "finalizeEntry",
                "falsification_ideas": ["Call finalize twice on the same entry."],
                "candidate_observations": [],
            },
            candidate_source={
                "kind": "state_transition_model",
                "state_transition_model": (
                    "/workspace/campaign/state-transition-models/stm-001.json"
                ),
                "invariant_id": "inv-001",
            },
        )

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        }))

        self.assertEqual(result["model_guidance"]["invariant_id"], "inv-001")
        self.assertEqual(result["model_guidance"]["kind"], "state_machine")
        self.assertEqual(
            result["compose_sequence_experiment_args"]["invariant_id"], "inv-001"
        )

    async def test_prepare_fork_exploit_workbench_invalid_state_transition_model_errors(
        self,
    ):
        container = FakeContainer()
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "authorization_binding",
                "statement": "Only the entry creator may finalize an entry.",
                "contract": "Registry",
                "function": "finalizeEntry",
                "candidate_observations": [],
            },
            candidate_invariant={"id": "inv-001"},
        )

        missing = await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "stm-999",
            "record_result": False,
        })
        self.assertTrue(missing.startswith("Error:"))
        self.assertIn("state_transition_model", missing)

        bad_path = await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "/etc/passwd",
            "record_result": False,
        })
        self.assertTrue(bad_path.startswith("Error:"))
        self.assertIn("state-transition-models", bad_path)

    async def test_prepare_fork_exploit_workbench_generic_invariant_stays_generic(self):
        # A generic invariant with no protocol lens must not regress to vault
        # assumptions: no vault/share/totalAssets terms appear anywhere.
        container = FakeContainer()
        statement = (
            "Only the authorized caller may consume another account's entry; the "
            "signed/role-checked subject must equal the account whose state changes."
        )
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "authorization_binding",
                "statement": statement,
                "contract": "Registry",
                "function": "finalizeEntry",
                "falsification_ideas": [
                    "Authorize yourself but pass another account; check whose state "
                    "changes.",
                ],
                "candidate_observations": [
                    "custom: assert the victim entry status changes while only the "
                    "attacker authorized the call",
                ],
            },
            candidate_source={
                "kind": "state_transition_model",
                "state_transition_model": (
                    "/workspace/campaign/state-transition-models/stm-001.json"
                ),
                "invariant_id": "inv-001",
            },
        )

        result = await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "stm-001",
            "record_result": False,
        })
        parsed = json.loads(result)
        self.assertEqual(parsed["mechanism"], "generic_state_transition")
        self.assertEqual(parsed["model_guidance"]["invariant_id"], "inv-001")

        workbench = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/workbench.json"
        ]
        readme = container.files[
            "/workspace/campaign/fork-workbenches/fw-001/README.md"
        ]
        for banned in ("vault", "share", "totalassets"):
            self.assertNotIn(banned, result.lower())
            self.assertNotIn(banned, workbench.lower())
            self.assertNotIn(banned, readme.lower())

    async def test_prepare_fork_exploit_workbench_vault_lens_adds_notes_only(self):
        # A vault_like lens in the model annotates but never replaces the generic
        # invariant objective.
        container = FakeContainer()
        statement = "Per-account credit must stay consistent with the aggregate total."
        self._write_stm_workbench_files(
            container,
            invariant={
                "id": "inv-001",
                "kind": "conservation",
                "statement": statement,
                "contract": "Registry",
                "function": "finalizeEntry",
                "falsification_ideas": ["Increase a credit without moving the total."],
                "candidate_observations": [],
            },
            lenses={"vault_like": {"evidence": [], "note": "optional"}},
            candidate_source={
                "kind": "state_transition_model",
                "state_transition_model": (
                    "/workspace/campaign/state-transition-models/stm-001.json"
                ),
                "invariant_id": "inv-001",
            },
        )

        result = json.loads(await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "state_transition_model": "stm-001",
            "record_result": False,
        }))

        # The generic invariant objective remains present and leads the list.
        self.assertEqual(result["mechanism"], "generic_state_transition")
        self.assertEqual(
            result["objective_templates"][0]["label"],
            f"Falsify invariant: {statement}",
        )
        self.assertIn(statement, json.dumps(result["objective_templates"]))
        # The lens is recorded only as an annotation note.
        lens_notes = result["model_guidance"]["lens_notes"]
        self.assertTrue(any("vault_like" in note for note in lens_notes))

    async def test_attack_search_routes_attack_graph_candidate_to_sequence_materialization(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "vault-withdraw",
                "title": "Test live-reachable Vault::withdraw",
                "priority": "critical",
                "priority_score": 24,
                "action_key": "Vault::withdraw",
                "contract": "Vault",
                "function": "withdraw",
                "target_address": "0x1111111111111111111111111111111111111111",
                "exposure": "exposed",
                "live_status": "deployed",
                "objective": "Vault::withdraw must not release unauthorized value.",
                "actions": [{
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "target": "0x1111111111111111111111111111111111111111",
                    "args": ["amount"],
                    "expected_effect": "unauthorized value leaves the vault",
                }],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                    "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                },
            }],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, and attack graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        self.assertEqual(result["next_action"]["tool"], "inventory_live_targets")
        self.assertEqual(result["next_action"]["status"], "needs_inventory")
        self.assertEqual(
            result["next_action"]["required_args"]["inventory_live_targets"]["targets"][0]["address"],
            "0x1111111111111111111111111111111111111111",
        )
        branch = next(
            item for item in result["active_branches"]
            if item["source"] == "attack_graph_candidate"
        )
        self.assertEqual(branch["next_tool"], "inventory_live_targets")
        inventory_args = branch["required_args"]["inventory_live_targets"]
        await _inventory_live_targets(container, {
            **inventory_args,
            "execute_probes": False,
        })
        inventory_planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertEqual(
            inventory_planned["next_action"]["tool"],
            "prepare_fork_exploit_workbench",
        )
        branch = next(
            item for item in inventory_planned["active_branches"]
            if item["source"] == "attack_graph_candidate"
        )
        self.assertEqual(branch["next_tool"], "prepare_fork_exploit_workbench")
        workbench_args = branch["required_args"]["prepare_fork_exploit_workbench"]
        self.assertEqual(workbench_args["attack_graph"], "/workspace/campaign/attack-graphs/ag-001.json")
        self.assertEqual(workbench_args["candidate_id"], "agcand-001")

        await _prepare_fork_exploit_workbench(container, {
            **workbench_args,
            "record_result": False,
        })
        planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertEqual(planned["next_action"]["tool"], "compose_sequence_experiment")
        planned_branch = next(
            item for item in planned["active_branches"]
            if item["source"] == "attack_graph_candidate"
        )
        required_args = planned_branch["required_args"]["compose_sequence_experiment"]
        self.assertEqual(required_args["attack_graph"], "/workspace/campaign/attack-graphs/ag-001.json")
        self.assertEqual(required_args["candidate_id"], "agcand-001")
        self.assertEqual(required_args["target_addresses"]["Vault"], "0x1111111111111111111111111111111111111111")
        self.assertIn("success_condition", required_args)
        self.assertIn("setup", required_args)

        await _compose_sequence_experiment(container, required_args)
        refreshed = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        # A non-runnable sequence scaffold now routes to the deterministic
        # completion tool, not a hand-written write_file. The composed step binds
        # the Vault target, so it has an executable subset and routes to a partial
        # probe (mode=partial_probe) rather than plain concretization.
        self.assertEqual(
            refreshed["next_action"]["tool"], "complete_sequence_experiment"
        )
        self.assertEqual(refreshed["next_action"]["status"], "needs_partial_probe")
        self.assertIn("exp-001", refreshed["next_action"]["related_ids"])
        completion_args = refreshed["next_action"]["required_args"][
            "complete_sequence_experiment"
        ]
        self.assertEqual(completion_args["sequence"], "exp-001")
        self.assertEqual(completion_args["mode"], "partial_probe")
        self.assertEqual(
            completion_args["target_addresses"]["Vault"],
            "0x1111111111111111111111111111111111111111",
        )
        refreshed_branch = next(
            item for item in refreshed["active_branches"]
            if item["source"] == "attack_graph_candidate"
        )
        self.assertTrue(
            any(
                path.endswith("/sequence.json")
                for path in refreshed_branch.get("evidence", [])
            )
        )

    async def test_attack_search_reranks_attack_graph_candidates_with_inventory(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        action_space_path = "/workspace/campaign/action-spaces/as-001.json"
        live_path = "/workspace/campaign/live-reachability/lr-001.json"
        protocol_graph_path = "/workspace/campaign/protocol-graphs/pg-001.json"
        attack_graph_path = "/workspace/campaign/attack-graphs/ag-001.json"
        inventory_path = "/workspace/campaign/live-inventory/linv-001.json"
        no_code = "0x1111111111111111111111111111111111111111"
        active_proxy = "0x2222222222222222222222222222222222222222"
        container.files[action_space_path] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files[live_path] = json.dumps({"id": "lr-001", "profiles": []})
        container.files[protocol_graph_path] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files[attack_graph_path] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [
                {
                    "candidate_id": "agcand-001",
                    "attack_key": "vault:no-code",
                    "title": "No-code implementation-looking target",
                    "priority": "critical",
                    "priority_score": 34,
                    "action_key": "Vault::withdraw",
                    "contract": "Vault",
                    "function": "withdraw",
                    "target_address": no_code,
                    "actions": [{
                        "actor": "attacker",
                        "contract": "Vault",
                        "function": "withdraw",
                        "target": no_code,
                        "args": ["amount"],
                        "action_key": "Vault::withdraw",
                        "affordances": ["value_out_or_burn"],
                    }],
                    "source": {
                        "action_space": action_space_path,
                        "live_reachability": live_path,
                    },
                },
                {
                    "candidate_id": "agcand-002",
                    "attack_key": "vault:active-proxy",
                    "title": "Active proxy economic target",
                    "priority": "high",
                    "priority_score": 22,
                    "action_key": "Vault::redeem",
                    "contract": "Vault",
                    "function": "redeem",
                    "target_address": active_proxy,
                    "actions": [{
                        "actor": "attacker",
                        "contract": "Vault",
                        "function": "redeem",
                        "target": active_proxy,
                        "args": ["shares"],
                        "action_key": "Vault::redeem",
                        "affordances": ["value_out_or_burn"],
                    }],
                    "source": {
                        "action_space": action_space_path,
                        "live_reachability": live_path,
                    },
                },
            ],
        })
        container.files[inventory_path] = json.dumps({
            "id": "linv-001",
            "targets": [
                {
                    "label": "NoCodeVault",
                    "contract": "Vault",
                    "address": no_code,
                    "probe": {
                        "executed": True,
                        "rpc_available": True,
                        "code_present": False,
                        "values": {"code_size_bytes": "0"},
                    },
                    "target_binding": {
                        "kind": "no_code",
                        "live_deployed": False,
                        "economic_priority": "none",
                        "economically_significant_hint": False,
                    },
                },
                {
                    "label": "ActiveProxyVault",
                    "contract": "Vault",
                    "address": active_proxy,
                    "probe": {
                        "executed": True,
                        "rpc_available": True,
                        "code_present": True,
                        "values": {
                            "eip1967_impl": "0x3333333333333333333333333333333333333333",
                            "total_assets": "1000000000000000000000",
                        },
                    },
                    "target_binding": {
                        "kind": "active_proxy",
                        "live_deployed": True,
                        "economic_priority": "high",
                        "economically_significant_hint": True,
                    },
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Maps and inventory",
            "content": "Attack graph and live inventory are available.",
            "evidence": [
                action_space_path,
                live_path,
                protocol_graph_path,
                attack_graph_path,
                inventory_path,
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        self.assertEqual(result["next_action"]["branch_title"], "Active proxy economic target")
        active_branch = next(
            item for item in result["active_branches"]
            if item["title"] == "Active proxy economic target"
        )
        no_code_branch = next(
            item for item in result["active_branches"]
            if item["title"] == "No-code implementation-looking target"
        )
        self.assertGreater(
            active_branch["priority_score"],
            no_code_branch["priority_score"],
        )
        self.assertEqual(
            active_branch["inventory_context"]["matched_targets"][0]["target_binding"]["kind"],
            "active_proxy",
        )
        self.assertEqual(
            no_code_branch["next_tool"],
            "attack_search action=decision or mutate_hypothesis",
        )
        self.assertEqual(
            no_code_branch["inventory_context"]["hard_blockers"][0]["target_binding"],
            "no_code",
        )

    async def test_attack_search_queues_related_live_target_alias_from_inventory(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        original = "0x1111111111111111111111111111111111111111"
        live_pool = "0x2222222222222222222222222222222222222222"
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": f"pool-liquidation:{original.lower()}",
                "title": "Test Pool liquidation on profiled address",
                "priority": "critical",
                "priority_score": 30,
                "action_key": "Pool::liquidationCall",
                "contract": "Pool",
                "function": "liquidationCall",
                "target_address": original,
                "actions": [{
                    "actor": "attacker",
                    "contract": "Pool",
                    "function": "liquidationCall",
                    "target": original,
                    "action_key": "Pool::liquidationCall",
                    "affordances": ["credit_or_liquidation"],
                }],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                    "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                },
            }],
        })
        container.files["/workspace/campaign/live-inventory/linv-001.json"] = json.dumps({
            "id": "linv-001",
            "targets": [{
                "label": "PoolImplementation",
                "contract": "Pool",
                "address": original,
                "probe": {
                    "executed": True,
                    "rpc_available": True,
                    "code_present": True,
                    "values": {
                        "addresses_provider": "0x3333333333333333333333333333333333333333",
                        "provider_get_pool": live_pool,
                        "get_reserves_list": "[]",
                    },
                },
                "target_binding": {
                    "kind": "deployed_implementation_or_template",
                    "binding_kind": "deployed_implementation_or_template",
                    "live_deployed": True,
                    "economic_priority": "low",
                    "economically_significant_hint": False,
                    "recommended_call_target": live_pool,
                    "normalization_reason": "provider resolves live Pool proxy",
                    "related_live_targets": [{
                        "relation": "pool",
                        "address": live_pool,
                        "source": "ADDRESSES_PROVIDER().getPool()",
                        "audit_relevance": "call_target_candidate",
                    }],
                },
            }],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Inventory with related target",
            "content": "Attack graph and inventory are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
                "/workspace/campaign/live-inventory/linv-001.json",
            ],
        })

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        alias_branch = next(
            item for item in result["active_branches"]
            if item["source"] == "attack_graph_related_live_target"
        )
        self.assertEqual(alias_branch["next_tool"], "inventory_live_targets")
        self.assertEqual(
            alias_branch["required_args"]["inventory_live_targets"]["targets"][0]["address"],
            live_pool,
        )
        self.assertEqual(alias_branch["target_actions"][0]["target"], live_pool)
        self.assertEqual(result["next_action"]["branch_id"], alias_branch["id"])

    async def test_attack_search_keeps_workbenches_candidate_specific(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        first = "0x1111111111111111111111111111111111111111"
        second = "0x2222222222222222222222222222222222222222"
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })

        def queue_candidate(candidate_id, address):
            return {
                "candidate_id": candidate_id,
                "attack_key": f"economic:queue_solver:{address.lower()}",
                "title": "Test queue request-to-settlement accounting",
                "priority": "critical",
                "priority_score": 40,
                "action_key": "QueueSolver::BoringOnChainQueue",
                "contract": "BoringOnChainQueue",
                "target_address": address,
                "mechanism": "queue_solver_accounting",
                "objective": "Queued requests must not settle for excess value.",
                "actions": [
                    {
                        "actor": "attacker",
                        "contract": "BoringOnChainQueue",
                        "function": "requestOnChainWithdrawWithPermit",
                        "target": address,
                        "action_key": "BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                        "expected_effect": "create a queued claim",
                    },
                    {
                        "actor": "authorized solver/keeper",
                        "contract": "BoringOnChainQueue",
                        "function": "solveOnChainWithdraws",
                        "target": address,
                        "action_key": "BoringOnChainQueue::solveOnChainWithdraws",
                        "expected_effect": "settle the queued claim",
                    },
                ],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                    "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                },
            }

        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [
                queue_candidate("agcand-001", first),
                queue_candidate("agcand-002", second),
            ],
        })
        container.files["/workspace/campaign/live-inventory/linv-001.json"] = json.dumps({
            "id": "linv-001",
            "targets": [
                {"label": "first", "address": first},
                {"label": "second", "address": second},
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, attack graph, and inventory are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
                "/workspace/campaign/live-inventory/linv-001.json",
            ],
        })
        await _prepare_fork_exploit_workbench(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "record_result": False,
        })

        planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))

        second_branch = next(
            item for item in planned["active_branches"]
            if item.get("attack_keys") == [f"economic:queue_solver:{second.lower()}"]
        )
        self.assertEqual(second_branch["next_tool"], "prepare_fork_exploit_workbench")
        self.assertEqual(
            second_branch["required_args"]["prepare_fork_exploit_workbench"]["candidate_id"],
            "agcand-002",
        )
        self.assertEqual(
            second_branch["required_args"]["prepare_fork_exploit_workbench"]["mechanism"],
            "queue_solver",
        )
        compose_args = second_branch["required_args"]["compose_sequence_experiment"]
        self.assertEqual(compose_args["candidate_id"], "agcand-002")
        self.assertEqual(compose_args["target_addresses"]["BoringOnChainQueue"], second)
        self.assertNotIn("setup", compose_args)

    async def test_attack_search_supersedes_same_target_child_branches_after_parent_decision(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        target = "0x1111111111111111111111111111111111111111"
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [
                {
                    "candidate_id": "agcand-001",
                    "attack_key": f"economic:queue_solver:{target.lower()}",
                    "title": "Test queue request-to-settlement accounting",
                    "priority": "critical",
                    "priority_score": 40,
                    "action_key": "QueueSolver::BoringOnChainQueue",
                    "contract": "BoringOnChainQueue",
                    "target_address": target,
                    "mechanism": "queue_solver_accounting",
                    "objective": "Queued requests must not settle for excess value.",
                    "actions": [
                        {
                            "actor": "attacker",
                            "contract": "BoringOnChainQueue",
                            "function": "requestOnChainWithdrawWithPermit",
                            "target": target,
                            "action_key": "BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                            "expected_effect": "create a queued claim",
                        },
                        {
                            "actor": "authorized solver/keeper",
                            "contract": "BoringOnChainQueue",
                            "function": "solveOnChainWithdraws",
                            "target": target,
                            "action_key": "BoringOnChainQueue::solveOnChainWithdraws",
                            "expected_effect": "settle the queued claim",
                        },
                    ],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
                {
                    "candidate_id": "agcand-002",
                    "attack_key": f"{target.lower()}:BoringOnChainQueue::requestOnChainWithdrawWithPermit:exposed",
                    "title": "Test live-reachable BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                    "priority": "high",
                    "priority_score": 28,
                    "action_key": "BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                    "contract": "BoringOnChainQueue",
                    "function": "requestOnChainWithdrawWithPermit",
                    "target_address": target,
                    "objective": "Request creation must not release value.",
                    "actions": [{
                        "actor": "attacker",
                        "contract": "BoringOnChainQueue",
                        "function": "requestOnChainWithdrawWithPermit",
                        "target": target,
                        "action_key": "BoringOnChainQueue::requestOnChainWithdrawWithPermit",
                        "expected_effect": "create a queued claim",
                    }],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
                {
                    "candidate_id": "agcand-003",
                    "attack_key": f"{target.lower()}:BoringOnChainQueue::withdraw:exposed",
                    "title": "Test unrelated withdraw on same dead target",
                    "priority": "high",
                    "priority_score": 25,
                    "action_key": "BoringOnChainQueue::withdraw",
                    "contract": "BoringOnChainQueue",
                    "function": "withdraw",
                    "target_address": target,
                    "objective": "Withdraw must not release excess value.",
                    "actions": [{
                        "actor": "attacker",
                        "contract": "BoringOnChainQueue",
                        "function": "withdraw",
                        "target": target,
                        "action_key": "BoringOnChainQueue::withdraw",
                        "expected_effect": "release value",
                    }],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, and attack graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        parent = next(
            item for item in planned["active_branches"]
            if item["key"].startswith("attack_graph:economic:queue_solver")
        )
        child_key = (
            "attack_graph:"
            f"{target.lower()}:BoringOnChainQueue::requestOnChainWithdrawWithPermit:exposed"
        )
        sibling_key = (
            "attack_graph:"
            f"{target.lower()}:BoringOnChainQueue::withdraw:exposed"
        )
        self.assertTrue(any(item["key"] == child_key for item in planned["active_branches"]))
        self.assertTrue(any(item["key"] == sibling_key for item in planned["active_branches"]))

        decided = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": parent["id"],
            "decision_status": "rejected",
            "decision": "The target binding points at a dormant implementation, not the live economic target.",
            "failed_assumption": "The selected address is the live target.",
            "impact_assessment": "No unprivileged value release.",
            "record_result": False,
        }))

        child = next(item for item in decided["terminal_branches"] if item["key"] == child_key)
        self.assertEqual(child["status"], "superseded")
        self.assertTrue(child["terminal_decision"])
        self.assertEqual(child["decision_id"], decided["decision_id"])
        sibling = next(
            item for item in decided["terminal_branches"]
            if item["key"] == sibling_key
        )
        self.assertEqual(sibling["status"], "superseded")
        self.assertEqual(sibling["decision_id"], decided["decision_id"])

    async def test_attack_search_supersedes_same_clone_family_after_mechanism_decision(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        first = "0x1111111111111111111111111111111111111111"
        second = "0x2222222222222222222222222222222222222222"
        clone_family = "code:abc123:public:reward_controller::claim_reward"
        for path, payload in (
            ("/workspace/campaign/action-spaces/as-001.json", {"id": "as-001", "actions": []}),
            ("/workspace/campaign/live-reachability/lr-001.json", {"id": "lr-001", "profiles": []}),
            ("/workspace/campaign/protocol-graphs/pg-001.json", {"id": "pg-001", "nodes": []}),
        ):
            container.files[path] = json.dumps(payload)
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [
                {
                    "candidate_id": "agcand-001",
                    "attack_key": f"{first.lower()}:RewardsController::claimRewards:exposed",
                    "title": "First reward clone claim",
                    "priority": "high",
                    "priority_score": 30,
                    "action_key": "RewardsController::claimRewards",
                    "contract": "RewardsController",
                    "function": "claimRewards",
                    "target_address": first,
                    "clone_family_keys": [clone_family],
                    "actions": [{
                        "actor": "attacker",
                        "contract": "RewardsController",
                        "function": "claimRewards",
                        "target": first,
                        "action_key": "RewardsController::claimRewards",
                        "expected_effect": "claim rewards",
                    }],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
                {
                    "candidate_id": "agcand-002",
                    "attack_key": f"{second.lower()}:RewardsController::claimRewards:exposed",
                    "title": "Second reward clone claim",
                    "priority": "high",
                    "priority_score": 29,
                    "action_key": "RewardsController::claimRewards",
                    "contract": "RewardsController",
                    "function": "claimRewards",
                    "target_address": second,
                    "clone_family_keys": [clone_family],
                    "actions": [{
                        "actor": "attacker",
                        "contract": "RewardsController",
                        "function": "claimRewards",
                        "target": second,
                        "action_key": "RewardsController::claimRewards",
                        "expected_effect": "claim rewards",
                    }],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, and attack graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        first_branch = next(
            item for item in planned["active_branches"]
            if item["title"] == "First reward clone claim"
        )

        decided = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": first_branch["id"],
            "decision_status": "rejected",
            "decision": "The same authorization gate prevents unprivileged reward claims across this clone family.",
            "failed_assumption": "Attacker can bypass the same gate.",
            "impact_assessment": "No attacker profit.",
            "record_result": False,
        }))

        second_branch = next(
            item for item in decided["terminal_branches"]
            if item["title"] == "Second reward clone claim"
        )
        self.assertEqual(second_branch["status"], "superseded")
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertIn(
            clone_family,
            state["attack_search"]["decided_clone_family_keys"],
        )

    async def test_attack_search_supersedes_same_target_semantic_action_family(self):
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        target = "0x2222222222222222222222222222222222222222"
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [],
            "observations": [],
        })
        container.files["/workspace/campaign/live-reachability/lr-001.json"] = json.dumps({
            "id": "lr-001",
            "profiles": [],
        })
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = json.dumps({
            "id": "pg-001",
            "nodes": [],
            "edges": [],
        })

        def rewards_candidate(candidate_id: str, function: str, score: int) -> dict:
            action_key = f"RewardsController::{function}"
            return {
                "candidate_id": candidate_id,
                "attack_key": f"{target.lower()}:{action_key}:exposed",
                "title": f"Test live-reachable {action_key}",
                "priority": "high",
                "priority_score": score,
                "action_key": action_key,
                "contract": "RewardsController",
                "function": function,
                "target_address": target,
                "objective": "Rewards calls must not release unauthorized rewards.",
                "actions": [{
                    "actor": "attacker",
                    "contract": "RewardsController",
                    "function": function,
                    "target": target,
                    "action_key": action_key,
                    "expected_effect": "attempt reward release",
                }],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                    "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                },
            }

        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "candidate_chains": [
                rewards_candidate("agcand-001", "claimRewards", 30),
                rewards_candidate("agcand-002", "claimAllRewardsToSelf", 29),
                rewards_candidate("agcand-003", "claimRewardsOnBehalf", 28),
                {
                    "candidate_id": "agcand-004",
                    "attack_key": f"{target.lower()}:RewardsController::setClaimer:exposed",
                    "title": "Test live-reachable RewardsController::setClaimer",
                    "priority": "high",
                    "priority_score": 27,
                    "action_key": "RewardsController::setClaimer",
                    "contract": "RewardsController",
                    "function": "setClaimer",
                    "target_address": target,
                    "objective": "Claimer assignment must not be attacker controlled.",
                    "actions": [{
                        "actor": "attacker",
                        "contract": "RewardsController",
                        "function": "setClaimer",
                        "target": target,
                        "action_key": "RewardsController::setClaimer",
                        "expected_effect": "assign attacker as claimer",
                    }],
                    "source": {
                        "action_space": "/workspace/campaign/action-spaces/as-001.json",
                        "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                        "protocol_graph": "/workspace/campaign/protocol-graphs/pg-001.json",
                    },
                },
            ],
        })
        await _update_campaign(container, {
            "section": "result",
            "title": "Reachability artifacts",
            "content": "Action space, live reachability, and attack graph are available.",
            "evidence": [
                "/workspace/campaign/action-spaces/as-001.json",
                "/workspace/campaign/live-reachability/lr-001.json",
                "/workspace/campaign/protocol-graphs/pg-001.json",
                "/workspace/campaign/attack-graphs/ag-001.json",
            ],
        })

        planned = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        claim_branch = next(
            item for item in planned["active_branches"]
            if item["key"].endswith("RewardsController::claimRewards:exposed")
        )

        decided = json.loads(await _attack_search(container, {
            "action": "decision",
            "branch_id": claim_branch["id"],
            "decision_status": "rejected",
            "decision": (
                "Source and live probes bind direct reward claims to msg.sender; "
                "there is no unauthorized release and no attacker profit."
            ),
            "failed_assumption": "Claim variants could redirect another user's rewards.",
            "impact_assessment": "Same self-claim mechanism has no balance delta.",
            "record_result": False,
        }))

        terminal_keys = {item["key"]: item for item in decided["terminal_branches"]}
        self.assertEqual(
            terminal_keys[
                f"attack_graph:{target.lower()}:RewardsController::claimAllRewardsToSelf:exposed"
            ]["status"],
            "superseded",
        )
        self.assertEqual(
            terminal_keys[
                f"attack_graph:{target.lower()}:RewardsController::claimRewardsOnBehalf:exposed"
            ]["status"],
            "superseded",
        )
        self.assertTrue(any(
            item["key"] == (
                f"attack_graph:{target.lower()}:RewardsController::setClaimer:exposed"
            )
            for item in decided["active_branches"]
        ))
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        decided_families = state["attack_search"]["decided_action_family_keys"]
        self.assertIn(
            f"{target.lower()}:reward_controller::claim_reward",
            decided_families,
        )

    async def test_compose_sequence_experiment_materializes_attack_graph_candidate(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 26,
                "affordances": ["value_out_or_burn"],
                "mutability": "nonpayable",
                "parameters": [{"raw": "uint256 amount", "name": "amount"}],
            }],
            "observations": [],
        })
        container.files["/workspace/campaign/attack-graphs/ag-001.json"] = json.dumps({
            "id": "ag-001",
            "title": "Reachability-aware attack graph",
            "candidate_chains": [{
                "candidate_id": "agcand-001",
                "attack_key": "vault-withdraw",
                "title": "Test live-reachable Vault::withdraw",
                "priority": "critical",
                "priority_score": 24,
                "action_key": "Vault::withdraw",
                "contract": "Vault",
                "function": "withdraw",
                "target_address": "0x1111111111111111111111111111111111111111",
                "exposure": "exposed",
                "live_status": "deployed",
                "affordances": ["value_out_or_burn"],
                "objective": "Vault::withdraw must not release unauthorized value.",
                "required_live_evidence": [
                    "fork block and deployed target address",
                    "before/after balances or protocol accounting objective",
                ],
                "actions": [{
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "target": "0x1111111111111111111111111111111111111111",
                    "args": ["amount"],
                    "expected_effect": "unauthorized value leaves the vault",
                    "reachability": {"kind": "public", "attacker_reachable": True},
                }],
                "source": {
                    "action_space": "/workspace/campaign/action-spaces/as-001.json",
                    "live_reachability": "/workspace/campaign/live-reachability/lr-001.json",
                },
            }],
        })

        result = await _compose_sequence_experiment(container, {
            "attack_graph": "ag-001",
            "candidate_id": "agcand-001",
            "fork_block": 19000000,
        })

        parsed = json.loads(result)
        self.assertEqual(parsed["attack_graph"], "/workspace/campaign/attack-graphs/ag-001.json")
        self.assertEqual(parsed["attack_graph_candidate"]["candidate_id"], "agcand-001")
        self.assertEqual(parsed["replay_validation"]["source"], "attack_graph_candidate")
        self.assertEqual(parsed["target_addresses"]["Vault"], "0x1111111111111111111111111111111111111111")
        workspace = "/workspace/experiments/exp-001-test-live-reachable-vault-withdraw"
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        self.assertEqual(sequence["attack_graph_candidate"]["attack_key"], "vault-withdraw")
        self.assertEqual(sequence["fork"]["fork_block"], 19000000)
        self.assertIn("attack_graph_candidate", sequence["scaffold"]["planning_context"])
        self.assertEqual(len(sequence["steps"]), 1)
        self.assertTrue(sequence["steps"][0]["executable"])
        self.assertEqual(sequence["steps"][0]["readiness"], "executable")
        self.assertFalse(sequence["scaffold_quality"]["runnable"])
        self.assertTrue(sequence["scaffold_quality"]["requires_manual_assertions"])
        # The executable step is concrete, but the objective hook is still a
        # placeholder: requires_manual_assertions is driven by the missing
        # objective assertion, not by the presence of TODO scaffolding.
        assertion_gaps = " ".join(sequence["scaffold_quality"]["assertion_gaps"])
        self.assertIn("no executable objective assertion", assertion_gaps)
        self.assertNotIn("placeholder objective assertion", assertion_gaps)
        self.assertEqual(sequence["scaffold_quality"]["proof_readiness"], "partial")
        self.assertEqual(sequence["scaffold_quality"]["executable_sequence_calls"], 1)
        self.assertIn(f"{workspace}/foundry.toml", parsed["files"])
        self.assertIn(f"{workspace}/lib/forge-std/src/Test.sol", parsed["files"])
        self.assertIn("[profile.default]", container.files[f"{workspace}/foundry.toml"])
        self.assertIn("contract Test", container.files[
            f"{workspace}/lib/forge-std/src/Test.sol"
        ])
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Attack Graph Candidate", readme)
        self.assertIn("Required live evidence", readme)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("function _assertPreconditions() internal", contract)
        self.assertIn("assertGt(vaultAddress.code.length, 0", contract)
        self.assertIn("_assertPreconditions();", contract)

    async def test_map_action_space_records_economic_callback_and_router_hints(self):
        container = FakeContainer()
        container.files["/audit/src/FlashBorrower.sol"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMinimum,
        address[] calldata path,
        address recipient,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract FlashBorrower {
    uint256 public flashLoanPremiumBps = 9;
    uint256 public closeFactorBps = 5000;
    IRouter public router;

    function executeOperation(address asset, uint256 amount) external returns (bytes32) {
        uint256 premium = amount * flashLoanPremiumBps / 10_000;
        uint256 repayAmount = amount + premium;
        repayAmount;
        return keccak256("executeOperation(address,uint256,uint256,address,bytes)");
    }

    function liquidate(address borrower, uint256 debt) external {
        uint256 closeFactor = closeFactorBps;
        borrower;
        debt;
        closeFactor;
    }

    function rebalance(uint256 amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, 1, path, address(this), block.timestamp);
    }

    function exactSingle(uint256 amountIn, uint256 minOut, address tokenIn, address tokenOut) external {
        router.exactInputSingle(ExactInputSingleParams({tokenIn: tokenIn, tokenOut: tokenOut, fee: 3000, recipient: msg.sender, deadline: block.timestamp, amountIn: amountIn, amountOutMinimum: minOut, sqrtPriceLimitX96: 0}));
    }
}
"""

        result = await _map_action_space(container, {
            "files": ["/audit/src/FlashBorrower.sol"],
            "record_result": False,
        })

        self.assertIn('"economic_parameter_hints"', result)
        self.assertIn('"callback_surface_hints"', result)
        self.assertIn('"router_call_hints"', result)
        self.assertIn("flashLoanPremiumBps", result)
        self.assertIn("executeOperation(address,uint256,uint256,address,bytes)", result)
        self.assertIn("swapExactTokensForTokens", result)
        action_space = json.loads(container.files["/workspace/campaign/action-spaces/as-001.json"])
        execute_action = next(
            item for item in action_space["actions"]
            if item["function"] == "executeOperation"
        )
        self.assertIn(
            "executeOperation(address,uint256,uint256,address,bytes)",
            {
                item.get("selector_hint")
                for item in execute_action["hints"]["callback_surfaces"]
            },
        )
        rebalance_action = next(
            item for item in action_space["actions"]
            if item["function"] == "rebalance"
        )
        router_hint = rebalance_action["hints"]["router_calls"][0]
        self.assertIn(
            "swapExactTokensForTokens",
            {
                item.get("selector_hint")
                for item in rebalance_action["hints"]["router_calls"]
            },
        )
        self.assertIn(
            "path",
            {
                term
                for item in rebalance_action["hints"]["router_calls"]
                for term in item.get("path_terms") or []
            },
        )
        self.assertEqual(router_hint["approval_spender"], "router")
        self.assertEqual(
            router_hint["calldata_roles"]["amount_in"],
            "amountIn",
        )
        self.assertEqual(router_hint["calldata_roles"]["min_output"], "1")
        self.assertEqual(router_hint["calldata_roles"]["recipient"], "address(this)")
        self.assertEqual(router_hint["calldata_roles"]["deadline"], "block.timestamp")
        self.assertIn("amountOutMinimum", router_hint["path_terms"])
        self.assertIn("recipient", router_hint["path_terms"])
        self.assertIn("deadline", router_hint["path_terms"])
        self.assertTrue(
            any("slippage" in item for item in router_hint["validation_prompts"])
        )
        exact_single_action = next(
            item for item in action_space["actions"]
            if item["function"] == "exactSingle"
        )
        exact_hint = exact_single_action["hints"]["router_calls"][0]
        self.assertEqual(exact_hint["selector_hint"], "exactInputSingle")
        self.assertEqual(exact_hint["calldata_roles"]["token_in"], "tokenIn")
        self.assertEqual(exact_hint["calldata_roles"]["token_out"], "tokenOut")
        self.assertEqual(exact_hint["calldata_roles"]["fee"], "3000")
        self.assertEqual(exact_hint["calldata_roles"]["min_output"], "minOut")
        self.assertIn("sqrtPriceLimitX96", exact_hint["path_terms"])

    async def test_map_protocol_graph_feeds_planner_without_taxonomy(self):
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IOracle {
    function price() external view returns (uint256);
}

interface IRouter {
    function exactInput(bytes calldata path) external returns (uint256);
}

interface IBridge {
    function sendMessage(bytes32 message) external;
}

contract Vault {
    event Withdraw(address indexed account, uint256 amount);

    IERC20 public asset;
    IOracle public oracle;
    IRouter public router;
    IBridge public bridge;
    address public owner;
    mapping(address => uint256) public shares;
    mapping(bytes32 => bool) public consumedMessages;
    uint256 public totalDebt;
    uint256 public liquidationThresholdBps = 8000;
    uint256 public flashLoanPremiumBps = 9;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        asset.transfer(msg.sender, amount);
        emit Withdraw(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        uint256 threshold = liquidationThresholdBps;
        require(oracle.price() * shares[msg.sender] * threshold / 10_000 >= amount, "collateral");
        totalDebt += amount;
    }

    function swapThroughRouter(bytes calldata path) external {
        uint256 out = router.exactInput(path);
        totalDebt += out;
    }

    function finalizeMessage(bytes32 message, bytes calldata signature) external {
        require(!consumedMessages[message], "replay");
        require(msg.sender == owner || signature.length > 0, "auth");
        consumedMessages[message] = true;
        bridge.sendMessage(message);
    }

    function onFlashLoan(address initiator, uint256 amount) external returns (bytes32) {
        require(msg.sender == address(router), "callback");
        uint256 premium = amount * flashLoanPremiumBps / 10_000;
        totalDebt += premium;
        asset.transfer(initiator, amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function updateOracle(IOracle nextOracle) external onlyOwner {
        oracle = nextOracle;
    }
}
"""

        result = await _map_protocol_graph(container, {
            "files": ["/audit/src/Vault.sol"],
            "related_ids": ["pm-001"],
        })

        self.assertIn('"protocol_graph_id": "pg-001"', result)
        self.assertIn('"asset_hints"', result)
        self.assertIn('"accounting_state"', result)
        self.assertIn('"external_dependencies"', result)
        self.assertIn('"trust_boundary_edges"', result)
        self.assertIn('"event_hints"', result)
        self.assertIn('"state_mutation_hints"', result)
        self.assertIn('"oracle_edges"', result)
        self.assertIn('"router_edges"', result)
        self.assertIn('"bridge_edges"', result)
        self.assertIn('"callback_edges"', result)
        self.assertIn('"authorization_edges"', result)
        self.assertIn('"cross_contract_edges"', result)
        self.assertIn('"economic_parameter_edges"', result)
        self.assertIn("Vault::withdraw", result)
        self.assertIn("Vault::borrow", result)
        self.assertIn("Vault::swapThroughRouter", result)
        self.assertIn("Vault::finalizeMessage", result)
        self.assertIn("references_asset_hint", result)
        self.assertIn("emits_event", result)
        self.assertIn("has_state_mutation_hint", result)
        self.assertIn("depends_on_valuation", result)
        self.assertIn("reads_oracle_input", result)
        self.assertIn("routes_through_router", result)
        self.assertIn("handles_bridge_or_message", result)
        self.assertIn("has_callback_surface_hint", result)
        self.assertIn("checks_authorization_binding", result)
        self.assertIn("calls_cross_contract_dependency", result)
        self.assertIn("has_economic_parameter_hint", result)
        self.assertIn("liquidationThresholdBps", result)
        self.assertIn("/workspace/campaign/protocol-graphs/pg-001.json", container.files)
        graph = container.files["/workspace/campaign/protocol-graphs/pg-001.json"]
        self.assertIn("Heuristic source graph", graph)
        self.assertIn('"kind": "entrypoint"', graph)
        self.assertIn('"kind": "trust_boundary"', graph)
        self.assertIn('"kind": "event_hint"', graph)
        self.assertIn('"kind": "state_mutation"', graph)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"protocol_graph": 1', state)
        self.assertIn("Protocol graph", state)

        plan = await _plan_attack_campaign(container, {
            "title": "Graph-guided plan",
            "focus": "withdraw",
            "record_result": False,
        })
        self.assertIn('"source": "protocol_graph_hotspot"', plan)
        self.assertIn('"key": "Vault::withdraw"', plan)
        self.assertIn(
            '"recommended_next_tool": "update_campaign then compose_sequence_experiment with explicit actions or compose_invariant_harness with handler actions"',
            plan,
        )
        self.assertIn("missing invariant artifact", plan)
        plan_artifact = container.files["/workspace/campaign/plans/plan-001.json"]
        self.assertIn('"protocol_graphs"', plan_artifact)
        self.assertIn('"has_protocol_graph": true', plan_artifact)

    async def test_map_protocol_graph_rejects_unapproved_path(self):
        container = FakeContainer()

        result = await _map_protocol_graph(container, {
            "files": ["/tmp/Vault.sol"],
        })

        self.assertIn("action source paths must be under", result)

    async def test_plan_attack_campaign_reviews_explicit_uncovered_action_space(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "summary": {"actions": 1, "observations": 0, "contracts": 1},
  "actions": [
    {
      "contract": "Vault",
      "function": "redeem",
      "file": "/audit/src/Vault.sol",
      "line": 31,
      "mutability": "nonpayable",
      "affordances": ["value_out_or_burn"],
      "modifiers": []
    }
  ],
  "observations": []
}
"""

        result = await _plan_attack_campaign(container, {
            "title": "Explicit action-space planning",
            "action_space": "as-001",
            "record_result": False,
        })

        self.assertIn('"plan_id": "plan-001"', result)
        self.assertIn('"recommended_next_tool": "review_attack_surface_coverage"', result)
        self.assertIn('"/workspace/campaign/action-spaces/as-001.json"', result)
        self.assertIn("/workspace/campaign/plans/plan-001.json", container.files)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"campaign_plan": 1', state)

    async def test_compose_sequence_experiment_uses_action_space_matches(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "affordances": ["value_in_or_mint"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "affordances": ["value_out_or_burn"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": [
    {
      "contract": "Vault",
      "function": "totalAssets",
      "file": "/audit/src/Vault.sol",
      "line": 30,
      "affordances": ["observation"],
      "mutability": "view",
      "parameters": [],
      "returns": "uint256"
    }
  ]
}
"""
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = """
{
  "id": "pg-001",
  "summary": {"hotspots": 2},
  "nodes": [
    {
      "id": "action:Vault.deposit",
      "kind": "entrypoint",
      "label": "Vault.deposit",
      "tags": ["value_in_or_mint"],
      "contract": "Vault",
      "function": "deposit"
    },
    {
      "id": "action:Vault.withdraw",
      "kind": "entrypoint",
      "label": "Vault.withdraw",
      "tags": ["value_out_or_burn"],
      "contract": "Vault",
      "function": "withdraw"
    },
    {
      "id": "accounting:Vault.totalAssets",
      "kind": "accounting_state",
      "label": "Vault.totalAssets"
    },
    {
      "id": "boundary:oracle_input",
      "kind": "trust_boundary",
      "label": "oracle input read"
    },
    {
      "id": "boundary:signed_authorization",
      "kind": "trust_boundary",
      "label": "authorization or signature check"
    }
  ],
  "edges": [
    {
      "source": "action:Vault.withdraw",
      "target": "accounting:Vault.totalAssets",
      "kind": "references_accounting_state",
      "label": "references accounting state"
    },
    {
      "source": "action:Vault.withdraw",
      "target": "boundary:oracle_input",
      "kind": "reads_oracle_input",
      "label": "oracle input read"
    },
    {
      "source": "action:Vault.withdraw",
      "target": "boundary:signed_authorization",
      "kind": "checks_authorization_binding",
      "label": "authorization or signature check"
    }
  ],
  "hotspots": [
    {
      "key": "Vault::withdraw",
      "contract": "Vault",
      "function": "withdraw",
      "score": 8,
      "affordances": ["value_out_or_burn"],
      "connected": [
        {
          "edge": "references_accounting_state",
          "target": "accounting:Vault.totalAssets",
          "kind": "accounting_state",
          "label": "Vault.totalAssets"
        },
        {
          "edge": "reads_oracle_input",
          "target": "boundary:oracle_input",
          "kind": "trust_boundary",
          "label": "oracle input read"
        },
        {
          "edge": "checks_authorization_binding",
          "target": "boundary:signed_authorization",
          "kind": "trust_boundary",
          "label": "authorization or signature check"
        }
      ]
    }
  ]
}
"""

        result = await _compose_sequence_experiment(container, {
            "title": "Deposit then withdraw accounting check",
            "objective": "Check whether shares can redeem for more assets than deposited.",
            "action_space": "as-001",
            "protocol_graph": "pg-001",
            "hypothesis_id": "hyp-001",
            "invariant_id": "inv-001",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "deposit",
                    "args": ["amount"],
                    "expected_effect": "mint shares",
                },
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "args": ["amount"],
                    "expected_effect": "return assets",
                },
            ],
            "observations": [{
                "label": "total assets",
                "target": "Vault",
                "call": "totalAssets()(uint256)",
                "timing": "before and after",
            }],
            "success_condition": "Attacker ends with more assets than initial balance.",
            "target_addresses": {
                "Vault": "0x0000000000000000000000000000000000001234",
            },
        })

        self.assertIn('"experiment_id": "exp-001"', result)
        self.assertIn('"contract": "Vault"', result)
        self.assertIn('"function": "deposit"', result)
        self.assertIn('"function": "withdraw"', result)
        workspace = (
            "/workspace/experiments/"
            "exp-001-deposit-then-withdraw-accounting-check"
        )
        self.assertIn(f"{workspace}/README.md", container.files)
        self.assertIn(f"{workspace}/ReentbotProSequence.t.sol", container.files)
        self.assertIn(f"{workspace}/sequence.json", container.files)
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Vault.deposit", readme)
        self.assertIn("Matched actions:", readme)
        self.assertIn("Protocol graph: `/workspace/campaign/protocol-graphs/pg-001.json`", readme)
        self.assertIn("Protocol Graph Context", readme)
        self.assertIn("Sequence Minimization Plan", readme)
        self.assertIn("Vault::withdraw", readme)
        self.assertIn("references_accounting_state", readme)
        test_contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("function test_sequence_experiment()", test_contract)
        self.assertIn("function _bindTargets() internal", test_contract)
        self.assertIn("function _configureScenario() internal", test_contract)
        self.assertIn("function _runSequence() internal", test_contract)
        self.assertIn("function _runStep001() internal", test_contract)
        self.assertIn("function _runStep002() internal", test_contract)
        self.assertIn("function _run_prefix_001() internal", test_contract)
        self.assertIn("function test_prefix_001() public", test_contract)
        self.assertIn("function test_drop_step_001() public", test_contract)
        self.assertIn("function test_parameter_sweep_001() public", test_contract)
        self.assertIn(
            "This variant reuses shared step helpers",
            test_contract,
        )
        self.assertIn("vm.skip(true);", test_contract)
        self.assertIn('before:prefix-001', test_contract)
        self.assertIn("function _assertCampaignInvariant() internal", test_contract)
        self.assertIn("function _snapshotNativeBalances", test_contract)
        self.assertIn("function _snapshotAccounting", test_contract)
        self.assertIn(
            'emit log_named_uint(string.concat(label, " native attacker"), attacker.balance);',
            test_contract,
        )
        self.assertIn(
            'emit log_named_uint(string.concat(label, " native Vault"), vaultAddress.balance);',
            test_contract,
        )
        self.assertIn(
            'emit log_named_uint(string.concat(label, " ", "total assets"), vault.totalAssets());',
            test_contract,
        )
        self.assertIn("uint256 internal constant DEFAULT_AMOUNT = 1e18;", test_contract)
        self.assertIn("uint256 internal amount = DEFAULT_AMOUNT;", test_contract)
        self.assertIn("interface IReentbotProVault", test_contract)
        self.assertIn("function deposit(uint256 amount) external;", test_contract)
        self.assertIn("function totalAssets() external view returns (uint256);", test_contract)
        self.assertIn(
            "address internal vaultAddress = 0x0000000000000000000000000000000000001234;",
            test_contract,
        )
        self.assertIn("IReentbotProVault internal vault", test_contract)
        self.assertIn("// vault.deposit(amount);", test_contract)
        self.assertIn("\n        vault.deposit(amount);\n", test_contract)
        self.assertIn("\n        vault.withdraw(amount);\n", test_contract)
        self.assertIn("Step 1: actor=attacker", test_contract)
        self.assertNotIn("function _selectFork() internal", test_contract)
        sequence_plan = container.files[f"{workspace}/sequence.json"]
        self.assertIn('"scaffold"', sequence_plan)
        self.assertIn('"protocol_graph_path"', sequence_plan)
        self.assertIn('"graph_context"', sequence_plan)
        self.assertIn('"protocol_graph_matches": 2', sequence_plan)
        self.assertIn('"snapshot_helpers"', sequence_plan)
        self.assertIn('"accounting_observations": 1', sequence_plan)
        self.assertIn('"executable_sequence_calls": 2', sequence_plan)
        self.assertIn('"sequence_minimization_plan"', sequence_plan)
        self.assertIn('"sequence_minimization_run_template"', sequence_plan)
        self.assertIn('"sequence_minimization_variants": 4', sequence_plan)
        self.assertIn('"setup_reduction"', sequence_plan)
        self.assertIn('"setup_reduction_checks": 2', sequence_plan)
        self.assertIn('"graph_edge_kinds"', sequence_plan)
        self.assertIn('"reads_oracle_input"', sequence_plan)
        self.assertIn('"checks_authorization_binding"', sequence_plan)
        self.assertIn(
            '"command": "forge test --match-test test_prefix_001 -vvv"',
            sequence_plan,
        )
        self.assertIn('"setup_checks"', sequence_plan)
        self.assertIn('"REPLACE_WITH_SETUP_CHECK_COMMAND"', sequence_plan)
        self.assertIn('"REPLACE_WITH_OBJECTIVE_MARKER"', sequence_plan)
        self.assertIn('"_runStep001"', sequence_plan)
        self.assertIn('"sequence_step_runners": 2', sequence_plan)
        parsed_sequence_plan = json.loads(sequence_plan)
        self.assertEqual(
            parsed_sequence_plan["sequence_minimization_plan"]["source"],
            "manual_sequence",
        )
        self.assertIn(
            "parameter_sweep",
            {
                variant["kind"]
                for variant in parsed_sequence_plan["sequence_minimization_plan"]["variants"]
            },
        )
        self.assertEqual(
            parsed_sequence_plan["sequence_minimization_plan"]["setup_reduction"]["summary"],
            {
                "approvals": 0,
                "balances": 0,
                "challenge_items": 2,
                "fork_assumptions": 0,
                "pranks": 1,
            },
        )
        self.assertIn(
            "For oracle-read graph edges",
            "\n".join(parsed_sequence_plan["replay_validation"]["snapshot_prompts"]),
        )
        self.assertIn(
            "For authorization graph edges",
            "\n".join(parsed_sequence_plan["replay_validation"]["snapshot_prompts"]),
        )
        setup_check_template = parsed_sequence_plan["sequence_minimization_run_template"][
            "setup_checks"
        ]
        self.assertEqual(setup_check_template[0]["kind"], "target_binding")
        self.assertEqual(setup_check_template[1]["kind"], "prank_scope")
        self.assertEqual(
            setup_check_template[0]["command"],
            "REPLACE_WITH_SETUP_CHECK_COMMAND",
        )
        self.assertIn('"_runSequence"', sequence_plan)
        self.assertIn('"test_prefix_001"', sequence_plan)
        self.assertIn('"parameter_placeholders"', sequence_plan)
        self.assertIn('"target_addresses"', sequence_plan)
        self.assertIn("0x0000000000000000000000000000000000001234", sequence_plan)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "exp-001"', state)
        self.assertIn('"hyp-001"', state)
        self.assertIn('"inv-001"', state)
        self.assertIn('"as-001"', state)
        self.assertIn('"pg-001"', state)

    async def test_compose_sequence_experiment_canonicalizes_namespaced_enum_params(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "L2MigrationFacet",
      "function": "migrateL2Beans",
      "file": "/audit/src/L2MigrationFacet.sol",
      "line": 58,
      "mutability": "payable",
      "affordances": ["cross_domain_or_message", "token_or_native_transfer"],
      "parameters": [
        {"raw": "address receiver", "name": "receiver"},
        {"raw": "address L2Beanstalk", "name": "L2Beanstalk"},
        {"raw": "uint256 amount", "name": "amount"},
        {"raw": "LibTransfer.To toMode", "name": "toMode"},
        {"raw": "uint256 maxSubmissionCost", "name": "maxSubmissionCost"},
        {"raw": "uint256 maxGas", "name": "maxGas"},
        {"raw": "uint256 gasPriceBid", "name": "gasPriceBid"}
      ]
    }
  ],
  "observations": []
}
"""

        await _compose_sequence_experiment(container, {
            "title": "Migrate L2 beans",
            "objective": "Check whether migration can credit without burn.",
            "action_space": "as-001",
            "actions": [{
                "actor": "attacker",
                "contract": "L2MigrationFacet",
                "function": "migrateL2Beans",
                "args": [
                    "receiver",
                    "L2Beanstalk",
                    "amount",
                    "toMode",
                    "maxSubmissionCost",
                    "maxGas",
                    "gasPriceBid",
                ],
                "expected_effect": "burn caller funds before migration credit",
            }],
            "observations": [],
            "target_addresses": {
                "L2MigrationFacet": "0xb7ea01231e518cd22e118165b290f5cc3263f5bb",
            },
        })

        workspace = "/workspace/experiments/exp-001-migrate-l2-beans"
        test_contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("uint8 toMode", test_contract)
        self.assertNotIn("LibTransfer.To toMode", test_contract)
        self.assertIn("uint8 internal toMode = 1;", test_contract)
        self.assertIn(
            'address internal L2Beanstalk = makeAddr("L2Beanstalk");',
            test_contract,
        )
        self.assertIn(
            "l2MigrationFacet.migrateL2Beans(receiver, L2Beanstalk, amount, toMode, maxSubmissionCost, maxGas, gasPriceBid);",
            test_contract,
        )

    async def test_compose_sequence_experiment_adds_fork_hook_when_context_present(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "affordances": ["value_out_or_burn"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": []
}
"""
        await _record_fork_context(container, {
            "title": "Mainnet vault context",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19000000,
            "contracts": [{
                "label": "Vault",
                "address": "0x0000000000000000000000000000000000001234",
                "kind": "vault",
            }],
            "tokens": [{
                "symbol": "USDC",
                "address": "0x0000000000000000000000000000000000000001",
                "decimals": 6,
            }],
            "pools": [{
                "label": "USDC/WETH pool",
                "address": "0x0000000000000000000000000000000000000020",
                "kind": "uniswap_v2",
            }],
            "oracles": [{
                "label": "ETH/USD oracle",
                "address": "0x0000000000000000000000000000000000000030",
                "kind": "chainlink",
            }],
            "flash_loan_providers": [{
                "label": "Aave v3 pool",
                "address": "0x0000000000000000000000000000000000000040",
                "kind": "aave_v3",
            }],
            "actors": [{
                "label": "attacker",
                "address": "0x0000000000000000000000000000000000000a11",
            }],
            "assumptions": ["USDC balance must be seeded before the sequence."],
            "record_result": False,
        })

        result = await _compose_sequence_experiment(container, {
            "title": "Fork withdraw sequence",
            "objective": "Run withdraw against fork state.",
            "action_space": "as-001",
            "fork_context": "fc-001",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
            }],
            "success_condition": "Vault accounting remains solvent.",
        })

        self.assertIn('"fork_context": "/workspace/campaign/fork-contexts/fc-001.json"', result)
        workspace = "/workspace/experiments/exp-001-fork-withdraw-sequence"
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("function _selectFork() internal", contract)
        self.assertIn('vm.envString("ETH_RPC_URL")', contract)
        self.assertIn("vm.createSelectFork(rpcUrl, 19000000);", contract)
        self.assertIn("_selectFork();\n        _bindTargets();", contract)
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Fork Setup Prompts", readme)
        self.assertIn("Network: `mainnet`", readme)
        self.assertIn("Explicit setup guide", readme)
        self.assertIn("Seed USDC balances", readme)
        self.assertIn("Approve only the contracts", readme)
        self.assertIn("Fork Probe Templates", readme)
        self.assertIn("USDC/WETH pool", readme)
        self.assertIn("getReserves()(uint112,uint112,uint32)", readme)
        self.assertIn("ETH/USD oracle", readme)
        self.assertIn("latestRoundData()(uint80,int256,uint256,uint256,uint80)", readme)
        self.assertIn("Aave v3 pool", readme)
        self.assertIn("Verify liquidity, fee, callback shape, and repayment", readme)
        self.assertIn("USDC", readme)
        self.assertIn("USDC balance must be seeded", readme)
        self.assertIn("Fork scenario setup guide", contract)
        self.assertIn("deal(0x0000000000000000000000000000000000000001", contract)
        self.assertIn("IERC20(0x0000000000000000000000000000000000000001).approve", contract)
        self.assertIn("interface IReentbotProSnapshotERC20", contract)
        self.assertIn("function allowance(address owner, address spender) external view returns (uint256);", contract)
        self.assertIn("function approve(address spender, uint256 amount) external returns (bool);", contract)
        self.assertIn("function _seedAndApproveForkTokens() internal", contract)
        self.assertIn("_seedAndApproveForkTokens();", contract)
        self.assertIn(
            "address forkToken1 = address(0x0000000000000000000000000000000000000001);",
            contract,
        )
        self.assertIn("if (forkToken1.code.length == 0)", contract)
        self.assertIn("Skipping USDC fork token setup; no code at token address.", contract)
        self.assertIn(
            "deal(forkToken1, attacker, DEFAULT_AMOUNT);",
            contract,
        )
        self.assertIn(
            'assertGe(IReentbotProSnapshotERC20(forkToken1).balanceOf(attacker), DEFAULT_AMOUNT, "fork token seed below DEFAULT_AMOUNT");',
            contract,
        )
        self.assertIn("vm.prank(attacker);", contract)
        self.assertIn(
            "IReentbotProSnapshotERC20(forkToken1).approve(address(0x0000000000000000000000000000000000001234), DEFAULT_AMOUNT);",
            contract,
        )
        self.assertIn(
            'assertGe(IReentbotProSnapshotERC20(forkToken1).allowance(attacker, address(0x0000000000000000000000000000000000001234)), DEFAULT_AMOUNT, "fork token allowance below DEFAULT_AMOUNT");',
            contract,
        )
        self.assertNotIn("type(uint256).max", contract)
        self.assertIn("function _snapshotTokenBalances", contract)
        self.assertIn("function _snapshotForkContext(string memory label) internal", contract)
        self.assertIn("_snapshotForkContext(label);", contract)
        self.assertIn("Pool USDC/WETH pool at 0x0000000000000000000000000000000000000020", contract)
        self.assertIn("getReserves()(uint112,uint112,uint32)", contract)
        self.assertIn("Oracle ETH/USD oracle at 0x0000000000000000000000000000000000000030", contract)
        self.assertIn("latestRoundData()(uint80,int256,uint256,uint256,uint80)", contract)
        self.assertIn("Flash provider Aave v3 pool at 0x0000000000000000000000000000000000000040", contract)
        self.assertIn("Verify liquidity, fee, callback shape, and repayment path", contract)
        self.assertIn(
            "IReentbotProSnapshotERC20(address(0x0000000000000000000000000000000000000001)).balanceOf(attacker)",
            contract,
        )
        self.assertIn('" USDC attacker"', contract)
        plan = container.files[f"{workspace}/sequence.json"]
        plan_json = json.loads(plan)
        self.assertIn('"fork": {', plan)
        self.assertIn('"fork_setup_guide"', plan)
        self.assertIn('"fork_probe_templates"', plan)
        self.assertIn('"fork_setup_tasks"', plan)
        self.assertIn('"balance_seed"', plan)
        self.assertIn('"approval"', plan)
        self.assertIn('"token_balance_assets": 1', plan)
        self.assertIn('"token_setup_helpers"', plan)
        self.assertIn('"approval_spenders": 1', plan)
        self.assertIn('"seeded_actor_balances": 3', plan)
        self.assertIn('"approval_calls": 3', plan)
        self.assertIn('"balance_assertions": 3', plan)
        self.assertIn('"allowance_assertions": 3', plan)
        self.assertIn('"uses_unlimited_approvals": false', plan)
        self.assertIn('"verifies_seeded_balances": true', plan)
        self.assertIn('"verifies_allowances": true', plan)
        self.assertIn('"skips_missing_token_code": true', plan)
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["token_setup_helpers"]["approval_policy"],
            "bounded_default_amount_per_actor_spender",
        )
        self.assertIn('"executable_sequence_calls": 1', plan)
        self.assertIn('"setup_reduction"', plan)
        self.assertIn('"setup_reduction_checks"', plan)
        setup_reduction = plan_json["sequence_minimization_plan"]["setup_reduction"]
        self.assertGreaterEqual(setup_reduction["summary"]["challenge_items"], 8)
        self.assertGreaterEqual(setup_reduction["summary"]["balances"], 1)
        self.assertGreaterEqual(setup_reduction["summary"]["approvals"], 1)
        self.assertEqual(setup_reduction["summary"]["pranks"], 1)
        self.assertGreaterEqual(setup_reduction["summary"]["fork_assumptions"], 4)
        setup_kinds = {item["kind"] for item in setup_reduction["challenge_items"]}
        self.assertIn("balance_seed", setup_kinds)
        self.assertIn("approval", setup_kinds)
        self.assertIn("fork_selection", setup_kinds)
        self.assertIn("oracle_state", setup_kinds)
        self.assertIn('"fork_context": true', plan)
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["fork_probe_helpers"],
            {
                "flash_loan_providers": 1,
                "oracles": 1,
                "pools": 1,
                "probe_templates": 3,
                "routers": 0,
            },
        )
        self.assertIn("_snapshotForkContext", plan_json["scaffold"]["entrypoints"])
        self.assertEqual(
            plan_json["fork_probe_templates"]["pools"][0]["snapshot_state_inputs"][0]["call"],
            "getReserves()(uint112,uint112,uint32)",
        )
        self.assertEqual(
            plan_json["fork_probe_templates"]["oracles"][0]["snapshot_state_inputs"][0]["call"],
            "latestRoundData()(uint80,int256,uint256,uint256,uint80)",
        )
        self.assertIn(
            "callback shape",
            plan_json["fork_probe_templates"]["flash_loan_providers"][0]["probe_prompts"][0]["prompt"],
        )
        self.assertIn('"fork_block": 19000000', plan)

    async def test_compose_sequence_experiment_adds_route_composition_plan(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "OracleAdapter",
      "function": "updatePrice",
      "file": "/audit/src/OracleAdapter.sol",
      "line": 57,
      "affordances": ["valuation_dependency", "market_or_router"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}],
      "hints": {
        "economic_parameters": [
          {
            "line": 58,
            "parameter": "twapWindow",
            "value_hint": "1800",
            "text": "uint256 twapWindow = 1800;"
          }
	        ],
	        "router_calls": [
          {
            "line": 59,
            "target": "router",
            "selector_hint": "swapExactTokensForTokens",
            "matched_term": "swapExact",
            "approval_spender": "router",
            "calldata_roles": {
              "amount_in": "amount",
              "min_output": "minOut",
              "path": "path",
              "recipient": "address(this)",
              "deadline": "deadline"
            },
            "path_terms": ["amountIn", "amountOutMinimum", "path", "deadline"],
            "validation_prompts": [
              "confirm `router` is the approval spender for the input token",
              "assert slippage bounds and quoted output before executing the route",
              "snapshot route recipient `address(this)` before and after"
            ],
            "text": "router.swapExactTokensForTokens(amount, minOut, path, address(this), deadline);"
          }
        ]
      }
    },
    {
      "contract": "LendingPool",
      "function": "liquidate",
      "file": "/audit/src/LendingPool.sol",
      "line": 88,
      "affordances": ["credit_or_liquidation", "callback_or_flashloan_surface"],
      "mutability": "nonpayable",
      "parameters": [
        {"raw": "address borrower", "name": "borrower"},
        {"raw": "uint256 amount", "name": "amount"}
      ],
      "hints": {
        "callback_surfaces": [
          {
            "line": 91,
            "surface": "executeOperation",
            "selector_hint": "executeOperation(address,uint256,uint256,address,bytes)",
            "text": "return callback selector;"
          }
        ],
        "economic_parameters": [
          {
            "line": 89,
            "parameter": "closeFactorBps",
            "value_hint": "5000",
            "text": "uint256 closeFactorBps = 5000;"
          },
          {
            "line": 90,
            "parameter": "liquidationBonusBps",
            "value_hint": "500",
            "text": "uint256 liquidationBonusBps = 500;"
          }
        ]
      }
    }
  ],
  "observations": []
}
"""
        await _record_fork_context(container, {
            "title": "Mainnet liquidation context",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19000000,
            "contracts": [
                {
                    "label": "OracleAdapter",
                    "address": "0x0000000000000000000000000000000000000100",
                },
                {
                    "label": "LendingPool",
                    "address": "0x0000000000000000000000000000000000000200",
                },
            ],
            "tokens": [
                {
                    "symbol": "USDC",
                    "address": "0x0000000000000000000000000000000000000001",
                    "decimals": 6,
                    "role": "debt repay asset",
                },
                {
                    "symbol": "WETH",
                    "address": "0x0000000000000000000000000000000000000002",
                    "decimals": 18,
                    "role": "collateral seized asset",
                },
            ],
            "pools": [{
                "label": "WETH/USDC pool",
                "address": "0x0000000000000000000000000000000000000020",
                "kind": "uniswap_v2",
                "token0": "WETH",
                "token1": "USDC",
                "fee_bps": 30,
            }],
            "routers": [{
                "label": "1inch router",
                "address": "0x0000000000000000000000000000000000000025",
                "kind": "aggregator",
            }],
            "oracles": [{
                "label": "ETH/USD oracle",
                "address": "0x0000000000000000000000000000000000000030",
                "kind": "chainlink",
            }],
            "flash_loan_providers": [{
                "label": "Aave v3 pool",
                "address": "0x0000000000000000000000000000000000000040",
                "kind": "aave_v3",
                "asset": "USDC",
            }],
            "record_result": False,
        })
        await _estimate_amm_economics(container, {
            "title": "WETH/USDC route",
            "pools": [{
                "label": "WETH/USDC",
                "reserve_in": "10000",
                "reserve_out": "20000",
                "amount_in": "1000",
                "fee_bps": 30,
                "token_in_decimals": 0,
                "token_out_decimals": 0,
                "token_in_symbol": "WETH",
                "token_out_symbol": "USDC",
                "token_in_price_usd": "2000",
                "token_out_price_usd": "1",
            }],
            "related_ids": ["as-001"],
        })
        await _estimate_flash_loan(container, {
            "title": "USDC liquidation capital",
            "assets": [{
                "symbol": "USDC",
                "asset": "0x0000000000000000000000000000000000000001",
                "provider": "0x0000000000000000000000000000000000000040",
                "amount_decimal": "100",
                "available_liquidity_decimal": "1000",
                "decimals": 6,
                "fee_bps": 9,
                "price_usd": "1",
            }],
            "related_ids": ["as-001"],
        })
        await _estimate_lending_health(container, {
            "title": "Liquidation threshold route",
            "positions": [{
                "label": "after price move",
                "collateral_amount_decimal": "2",
                "collateral_decimals": 18,
                "collateral_price_usd": "2000",
                "collateral_price_shift_bps": -3000,
                "liquidation_threshold_bps": 8000,
                "debt_amount_decimal": "2500",
                "debt_decimals": 6,
                "debt_price_usd": "1",
                "liquidation_bonus_bps": 500,
            }],
            "related_ids": ["as-001"],
        })

        result = await _compose_sequence_experiment(container, {
            "title": "Compose liquidation route replay",
            "objective": (
                "Use a flash-loan-funded swap to move oracle price and liquidate "
                "a borrower for profit."
            ),
            "action_space": "as-001",
            "fork_context": "fc-001",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "OracleAdapter",
                    "function": "updatePrice",
                    "args": ["amount"],
                },
                {
                    "actor": "attacker",
                    "contract": "LendingPool",
                    "function": "liquidate",
                    "args": ["borrower", "amount"],
                },
            ],
            "success_condition": "Liquidator keeps net profit after repayment and unwind.",
        })

        self.assertIn('"route_composition"', result)
        workspace = "/workspace/experiments/exp-001-compose-liquidation-route-replay"
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Route Composition Plan", readme)
        self.assertIn("AMM/valuation route composition", readme)
        self.assertIn("Oracle freshness/window route", readme)
        self.assertIn("Flash-loan/callback route composition", readme)
        self.assertIn("Liquidation/credit route composition", readme)
        self.assertIn("closeFactorBps", readme)
        self.assertIn("executeOperation(address,uint256,uint256,address,bytes)", readme)
        self.assertIn("/workspace/campaign/economics/econ-001.json", readme)
        self.assertIn("/workspace/campaign/economics/flash-001.json", readme)
        self.assertIn("/workspace/campaign/economics/econ-002.json", readme)
        self.assertIn("Unwind candidates", readme)
        self.assertIn("pool unwind via WETH/USDC pool", readme)
        self.assertIn("router unwind via 1inch router", readme)
        self.assertIn("Verify router code, selector", readme)
        self.assertIn("Source router hints", readme)
        self.assertIn("router.swapExactTokensForTokens", readme)
        self.assertIn("amount_in=amount", readme)
        self.assertIn("approval spender `router`", readme)
        self.assertIn("snapshot route recipient `address(this)`", readme)
        self.assertIn("Repay asset candidates", readme)
        self.assertIn("Seized asset candidates", readme)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("Route composition prompts", contract)
        self.assertIn("[amm_or_valuation_route]", contract)
        self.assertIn("[flash_loan_route]", contract)
        self.assertIn("[liquidation_credit_route]", contract)
        self.assertIn("Unwind: pool unwind via WETH/USDC pool", contract)
        self.assertIn("Unwind: router unwind via 1inch router", contract)
        self.assertIn("Router 1inch router at 0x0000000000000000000000000000000000000025", contract)
        self.assertIn("Router hint: router.swapExactTokensForTokens", contract)
        self.assertIn("spender router roles amount_in=amount", contract)
        self.assertIn("Router validation: snapshot route recipient", contract)
        self.assertIn("Source hint: closeFactorBps = 5000", contract)
        self.assertIn(
            "Callback hint: executeOperation selector executeOperation(address,uint256,uint256,address,bytes)",
            contract,
        )
        plan_json = json.loads(container.files[f"{workspace}/sequence.json"])
        route_plan = plan_json["route_composition_plan"]
        self.assertEqual(route_plan["summary"]["routes"], 4)
        self.assertEqual(route_plan["summary"]["with_economics_context"], 3)
        self.assertGreaterEqual(route_plan["summary"]["unwind_candidates"], 3)
        route_kinds = {route["kind"] for route in route_plan["routes"]}
        self.assertEqual(
            route_kinds,
            {
                "amm_or_valuation_route",
                "oracle_window_route",
                "flash_loan_route",
                "liquidation_credit_route",
            },
        )
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["route_composition_routes"],
            4,
        )
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["route_composition_with_economics"],
            3,
        )
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["fork_probe_helpers"]["routers"],
            1,
        )
        self.assertEqual(
            plan_json["fork_probe_templates"]["routers"][0]["probe_prompts"][0]["target"],
            "0x0000000000000000000000000000000000000025",
        )
        self.assertIn(
            "approval spender",
            plan_json["fork_probe_templates"]["routers"][0]["probe_prompts"][0]["prompt"],
        )
        self.assertEqual(
            plan_json["target_addresses"]["1inch router"],
            "0x0000000000000000000000000000000000000025",
        )
        self.assertGreaterEqual(
            plan_json["scaffold"]["planning_context"]["route_composition_unwind_candidates"],
            3,
        )
        amm_route = next(
            route
            for route in route_plan["routes"]
            if route["kind"] == "amm_or_valuation_route"
        )
        self.assertEqual(
            amm_route["unwind_candidates"][0]["pool"]["token0"],
            "WETH",
        )
        self.assertEqual(
            {
                asset["symbol"]
                for asset in amm_route["unwind_candidates"][0]["assets"]
            },
            {"USDC", "WETH"},
        )
        self.assertTrue(
            any(
                candidate["label"] == "router unwind via 1inch router"
                for candidate in amm_route["unwind_candidates"]
            )
        )
        self.assertEqual(
            amm_route["source_router_hints"][0]["selector_hint"],
            "swapExactTokensForTokens",
        )
        self.assertEqual(
            amm_route["source_router_hints"][0]["approval_spender"],
            "router",
        )
        self.assertEqual(
            amm_route["source_router_hints"][0]["calldata_roles"]["recipient"],
            "address(this)",
        )
        self.assertIn(
            "path",
            amm_route["source_router_hints"][0]["path_terms"],
        )
        liquidation_route = next(
            route
            for route in route_plan["routes"]
            if route["kind"] == "liquidation_credit_route"
        )
        self.assertIn(
            "closeFactorBps",
            {
                hint["parameter"]
                for hint in liquidation_route["source_parameter_hints"]
            },
        )
        flash_route = next(
            route
            for route in route_plan["routes"]
            if route["kind"] == "flash_loan_route"
        )
        self.assertEqual(
            {
                asset["symbol"]
                for asset in flash_route["unwind_candidates"][0]["repay_asset_candidates"]
            },
            {"USDC"},
        )
        self.assertIn(
            "executeOperation(address,uint256,uint256,address,bytes)",
            {
                hint["selector_hint"]
                for hint in flash_route["source_callback_hints"]
            },
        )
        self.assertEqual(
            {
                asset["symbol"]
                for asset in liquidation_route["unwind_candidates"][0]["repay_asset_candidates"]
            },
            {"USDC"},
        )
        self.assertEqual(
            {
                asset["symbol"]
                for asset in liquidation_route["unwind_candidates"][0]["seized_asset_candidates"]
            },
            {"WETH"},
        )

    async def test_compose_sequence_experiment_rejects_empty_actions(self):
        container = FakeContainer()

        result = await _compose_sequence_experiment(container, {
            "title": "No steps",
            "objective": "Should reject empty sequence.",
            "actions": [],
        })

        self.assertIn("requires actions or call_sequence", result)
        self.assertIn('"actor":"attacker"', result)
        self.assertIn("compose_invariant_harness", result)

    async def test_non_runnable_sequence_requires_concretization_before_run(self):
        container = FakeContainer()

        await _compose_sequence_experiment(container, {
            "title": "Unbound withdraw",
            "objective": "Withdraw should be concretized before running.",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "expected_effect": "value leaves",
            }],
            "observations": [],
        })

        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        entry = progress["experiments_without_results"][0]
        self.assertEqual(entry["status"], "needs_concretization")
        self.assertEqual(entry["sequence_quality"]["executable_sequence_calls"], 0)

    async def test_partial_proof_with_executable_subset_yields_needs_partial_probe(self):
        # A scaffold with an executable subset but a withheld objective assertion
        # (proof_readiness=partial, executable_sequence_calls>0) should route to a
        # partial probe, not generic concretization.
        container = FakeContainer()
        for section, title in (
            ("protocol_model", "Protocol model"),
            ("value_flow", "Value flow"),
            ("invariant", "Invariant"),
            ("hypothesis", "Hypothesis"),
        ):
            await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": f"{title} with concrete source references.",
            })
        await _compose_sequence_experiment(container, {
            "title": "Drain vault",
            "objective": "attacker drains vault",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "expected_effect": "unauthorized value leaves the vault",
            }],
            "observations": [{
                "label": "vault assets",
                "contract": "Vault",
                "call": "totalAssets()(uint256)",
            }],
            "success_condition": "attacker balance increases",
        })
        # Bind the target (step becomes executable) but keep log_only so no
        # objective assertion is emitted -- the executable subset stays partial.
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": "0x1111111111111111111111111111111111111111"},
            "objective_probe_strategy": "log_only",
            "record_result": False,
        })

        progress = json.loads(await _review_campaign_progress(container, {
            "record_result": False,
        }))
        entry = progress["experiments_without_results"][0]
        self.assertEqual(entry["status"], "needs_partial_probe")
        self.assertGreater(
            entry["sequence_quality"]["executable_sequence_calls"], 0
        )
        self.assertIn("partial probe", entry["suggested_action"])

        result = json.loads(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        branch = next(
            item for item in result["active_branches"]
            if item["status"] == "needs_partial_probe"
        )
        self.assertEqual(branch["next_tool"], "complete_sequence_experiment")
        self.assertEqual(
            branch["required_args"]["complete_sequence_experiment"]["mode"],
            "partial_probe",
        )

    async def test_compose_sequence_experiment_can_use_extracted_call_sequence(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "mutability": "nonpayable",
      "affordances": ["value_in_or_mint"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "mutability": "nonpayable",
      "affordances": ["value_out_or_burn"],
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": []
}
"""
        container.files["/workspace/campaign/fuzz-runs/fuzz-001.json"] = """
{
  "id": "fuzz-001",
  "title": "Reduced invariant failure",
  "outcome": "candidate_failure",
  "log_path": "/workspace/campaign/fuzz-runs/fuzz-001.log",
  "summary": {"candidate_failure": true},
  "failure_snippets": [
    {
      "line": 9,
      "marker": "Call sequence:",
      "context": "Call sequence:\\n  Handler.deposit(100)\\n  Handler.withdraw(150)"
    }
  ],
  "next_actions": ["Replay the reduced sequence with concrete assertions."]
}
"""
        container.files["/workspace/campaign/sequences/seq-001.json"] = """
{
  "id": "seq-001",
  "title": "Extracted failure sequence",
  "action_space_path": "/workspace/campaign/action-spaces/as-001.json",
  "fuzz_run_path": "/workspace/campaign/fuzz-runs/fuzz-001.json",
  "steps": [
    {"contract": "Vault", "function": "deposit", "args_text": "100)", "line": 3},
    {"contract": "Vault", "function": "withdraw", "args_text": "150)", "line": 4}
  ]
}
"""

        result = await _compose_sequence_experiment(container, {
            "title": "Replay extracted invariant failure",
            "objective": "Replay the reduced failing call path as a sequence PoC.",
            "call_sequence": "seq-001",
            "observations": [{
                "label": "attacker balance",
                "call": "balanceOf(address)(uint256)",
            }],
            "success_condition": "Replay reproduces the invariant failure.",
        })

        self.assertIn('"experiment_id": "exp-001"', result)
        self.assertIn('"call_sequence": "/workspace/campaign/sequences/seq-001.json"', result)
        self.assertIn('"fuzz_run": "/workspace/campaign/fuzz-runs/fuzz-001.json"', result)
        self.assertIn('"seq-001"', result)
        self.assertIn('"fuzz-001"', result)
        workspace = "/workspace/experiments/exp-001-replay-extracted-invariant-failure"
        self.assertIn(f"{workspace}/README.md", container.files)
        self.assertIn(f"{workspace}/ReentbotProSequence.t.sol", container.files)
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Candidate Fuzz Failure Context", readme)
        self.assertIn("Replay Validation Plan", readme)
        self.assertIn("Sequence Minimization Plan", readme)
        self.assertIn("Call sequence:", readme)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("interface IReentbotProVault", contract)
        self.assertIn("function _runStep001() internal", contract)
        self.assertIn("function test_drop_step_001() public", contract)
        self.assertIn("// vault.deposit(100);", contract)
        self.assertIn("// vault.withdraw(150);", contract)
        self.assertNotIn("\n        vault.deposit(100);\n", contract)
        self.assertNotIn("\n        vault.withdraw(150);\n", contract)
        plan = container.files[f"{workspace}/sequence.json"]
        self.assertIn('"call_sequence_path"', plan)
        self.assertIn('"args": [', plan)
        self.assertIn('"100"', plan)
        sequence_plan = json.loads(plan)
        self.assertEqual(sequence_plan["fuzz_context"]["id"], "fuzz-001")
        self.assertEqual(
            sequence_plan["replay_validation"]["source"],
            "fuzz_failure_replay",
        )
        self.assertIn(
            "snapshot_state",
            sequence_plan["replay_validation"]["recommended_tool_order"],
        )
        self.assertTrue(sequence_plan["replay_validation"]["snapshot_prompts"])
        minimization = sequence_plan["sequence_minimization_plan"]
        self.assertEqual(minimization["source"], "fuzz_failure_replay")
        self.assertEqual(minimization["baseline"]["steps"], 2)
        self.assertIn(
            "drop_step",
            {variant["kind"] for variant in minimization["variants"]},
        )
        self.assertEqual(
            sequence_plan["scaffold"]["planning_context"]["sequence_minimization_variants"],
            len(minimization["variants"]),
        )

    async def test_compose_sequence_experiment_carries_fuzz_failure_context(self):
        container = FakeContainer()
        container.files["/workspace/campaign/fuzz-runs/fuzz-001.json"] = """
{
  "id": "fuzz-001",
  "title": "Invariant handler campaign",
  "outcome": "candidate_failure",
  "log_path": "/workspace/campaign/fuzz-runs/fuzz-001.log",
  "summary": {"candidate_failure": true, "snippets": 1},
  "failure_snippets": [
    {
      "line": 12,
      "marker": "Call sequence:",
      "context": "Call sequence:\\n  Handler.deposit(1)\\n  Handler.withdraw(2)"
    }
  ],
  "next_actions": ["Extract the sequence and replay it as a PoC."]
}
"""

        result = await _compose_sequence_experiment(container, {
            "title": "Replay fuzz failure",
            "objective": "Reduce the candidate fuzz failure into a sequence PoC.",
            "fuzz_run": "fuzz-001",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "Handler",
                    "function": "deposit",
                    "args": ["amount"],
                },
                {
                    "actor": "attacker",
                    "contract": "Handler",
                    "function": "withdraw",
                    "args": ["amount"],
                },
            ],
            "success_condition": "The reduced sequence reproduces the invariant failure.",
        })

        self.assertIn('"experiment_id": "exp-001"', result)
        self.assertIn('"fuzz-001"', result)
        workspace = "/workspace/experiments/exp-001-replay-fuzz-failure"
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Candidate Fuzz Failure Context", readme)
        self.assertIn("Sequence Minimization Plan", readme)
        self.assertIn("Fuzz run: `/workspace/campaign/fuzz-runs/fuzz-001.json`", readme)
        self.assertIn("Call sequence:", readme)
        plan = container.files[f"{workspace}/sequence.json"]
        self.assertIn('"fuzz_context"', plan)
        self.assertIn('"candidate_fuzz_failure": true', plan)
        self.assertIn('"log_path": "/workspace/campaign/fuzz-runs/fuzz-001.log"', plan)
        sequence_plan = json.loads(plan)
        self.assertEqual(
            sequence_plan["replay_validation"]["source"],
            "fuzz_failure_replay",
        )
        self.assertEqual(
            sequence_plan["sequence_minimization_plan"]["source"],
            "fuzz_failure_replay",
        )
        self.assertIn(
            "review_finding_evidence",
            sequence_plan["replay_validation"]["recommended_tool_order"],
        )
        self.assertIn("Replay Validation Plan", readme)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"fuzz-001"', state)
        self.assertIn("Fuzz run: /workspace/campaign/fuzz-runs/fuzz-001.json", state)

    async def test_compose_invariant_harness_writes_handler_scaffold(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = """
{
  "id": "as-001",
  "actions": [
    {
      "contract": "Vault",
      "function": "deposit",
      "file": "/audit/src/Vault.sol",
      "line": 21,
      "affordances": ["value_in_or_mint"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    },
    {
      "contract": "Vault",
      "function": "withdraw",
      "file": "/audit/src/Vault.sol",
      "line": 26,
      "affordances": ["value_out_or_burn"],
      "mutability": "nonpayable",
      "parameters": [{"raw": "uint256 amount", "name": "amount"}]
    }
  ],
  "observations": []
}
"""
        container.files["/workspace/campaign/protocol-graphs/pg-001.json"] = """
{
  "id": "pg-001",
  "nodes": [
    {
      "id": "action:Vault.deposit",
      "kind": "entrypoint",
      "label": "Vault.deposit",
      "tags": ["value_in_or_mint"],
      "contract": "Vault",
      "function": "deposit"
    },
    {
      "id": "action:Vault.withdraw",
      "kind": "entrypoint",
      "label": "Vault.withdraw",
      "tags": ["value_out_or_burn"],
      "contract": "Vault",
      "function": "withdraw"
    },
    {
      "id": "asset:Vault.asset",
      "kind": "asset_hint",
      "label": "Vault.asset"
    }
  ],
  "edges": [
    {
      "source": "action:Vault.withdraw",
      "target": "asset:Vault.asset",
      "kind": "references_asset_hint",
      "label": "references asset hint"
    }
  ],
  "hotspots": [
    {
      "key": "Vault::withdraw",
      "contract": "Vault",
      "function": "withdraw",
      "score": 8,
      "affordances": ["value_out_or_burn"],
      "connected": [
        {
          "edge": "references_asset_hint",
          "target": "asset:Vault.asset",
          "kind": "asset_hint",
          "label": "Vault.asset"
        }
      ]
    }
  ]
}
"""
        await _record_fork_context(container, {
            "title": "Vault invariant fork context",
            "network": "mainnet",
            "chain_id": 1,
            "fork_block": 19000000,
            "contracts": [{
                "label": "Vault",
                "address": "0x0000000000000000000000000000000000001234",
            }],
            "tokens": [{
                "symbol": "USDC",
                "address": "0x0000000000000000000000000000000000000001",
                "decimals": 6,
            }],
            "actors": [{
                "label": "attacker",
                "address": "0x0000000000000000000000000000000000000a11",
            }],
            "assumptions": ["Vault token balances are mainnet fork state."],
            "record_result": False,
        })

        result = await _compose_invariant_harness(container, {
            "title": "Vault share solvency invariant",
            "invariant": "Total redeemable shares must not exceed vault assets.",
            "action_space": "as-001",
            "protocol_graph": "pg-001",
            "fork_context": "fc-001",
            "hypothesis_id": "hyp-002",
            "invariant_id": "inv-002",
            "actors": ["attacker", "honestUser"],
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "deposit",
                    "args": ["amount"],
                    "bounds": "amount between 1 and available balance",
                },
                {
                    "actor": "attacker",
                    "contract": "Vault",
                    "function": "withdraw",
                    "args": ["amount"],
                },
            ],
            "observations": [{
                "label": "vault assets",
                "call": "totalAssets()(uint256)",
            }],
        })

        self.assertIn('"experiment_id": "exp-001"', result)
        self.assertIn('"actors": [', result)
        workspace = "/workspace/experiments/exp-001-vault-share-solvency-invariant"
        self.assertIn(f"{workspace}/README.md", container.files)
        self.assertIn(f"{workspace}/ReentbotProInvariant.t.sol", container.files)
        self.assertIn(f"{workspace}/invariant.json", container.files)
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Protocol graph: `/workspace/campaign/protocol-graphs/pg-001.json`", readme)
        self.assertIn("Protocol Graph Context", readme)
        self.assertIn("Vault::withdraw", readme)
        self.assertIn("references_asset_hint", readme)
        self.assertIn("Fork Setup Prompts", readme)
        self.assertIn("Network: `mainnet`", readme)
        self.assertIn("Explicit setup guide", readme)
        self.assertIn("Use attacker", readme)
        harness = container.files[f"{workspace}/ReentbotProInvariant.t.sol"]
        self.assertIn("contract ReentbotProInvariant is Test", harness)
        self.assertIn("function _selectFork() internal", harness)
        self.assertIn("vm.createSelectFork(rpcUrl, 19000000);", harness)
        self.assertIn("_selectFork();\n        handler = new Handler();", harness)
        self.assertIn("targetContract(address(handler))", harness)
        self.assertIn("function _bindTargets() internal", harness)
        self.assertIn("amount = bound(amount, 1, type(uint128).max);", harness)
        self.assertIn("uint256 internal constant DEFAULT_AMOUNT = 1e18;", harness)
        self.assertIn("interface IReentbotProVault", harness)
        self.assertIn("function deposit(uint256 amount) external;", harness)
        self.assertIn("interface IReentbotProSnapshotERC20", harness)
        self.assertIn("function allowance(address owner, address spender) external view returns (uint256);", harness)
        self.assertIn("function _seedAndApproveForkTokens() internal", harness)
        self.assertIn("_seedAndApproveForkTokens();", harness)
        self.assertIn("if (forkToken1.code.length == 0)", harness)
        self.assertIn("deal(forkToken1, actors[i], DEFAULT_AMOUNT);", harness)
        self.assertIn(
            'assertGe(IReentbotProSnapshotERC20(forkToken1).balanceOf(actors[i]), DEFAULT_AMOUNT, "fork token seed below DEFAULT_AMOUNT");',
            harness,
        )
        self.assertIn(
            "IReentbotProSnapshotERC20(forkToken1).approve(address(0x0000000000000000000000000000000000001234), DEFAULT_AMOUNT);",
            harness,
        )
        self.assertIn(
            'assertGe(IReentbotProSnapshotERC20(forkToken1).allowance(actors[i], address(0x0000000000000000000000000000000000001234)), DEFAULT_AMOUNT, "fork token allowance below DEFAULT_AMOUNT");',
            harness,
        )
        self.assertNotIn("type(uint256).max", harness)
        self.assertIn(
            "address internal vaultAddress = 0x0000000000000000000000000000000000001234;",
            harness,
        )
        self.assertIn("// vault.deposit(amount);", harness)
        self.assertIn("Fork scenario setup guide", harness)
        self.assertIn(
            "vm.startPrank(0x0000000000000000000000000000000000000a11)",
            harness,
        )
        self.assertIn("function action_deposit", harness)
        self.assertIn("function action_withdraw", harness)
        self.assertIn("invariant_campaignInvariant", harness)
        plan = container.files[f"{workspace}/invariant.json"]
        self.assertIn('"scaffold"', plan)
        self.assertIn('"protocol_graph_path"', plan)
        self.assertIn('"graph_context"', plan)
        self.assertIn('"protocol_graph_matches": 2', plan)
        self.assertIn('"fork": {', plan)
        self.assertIn('"fork_setup_guide"', plan)
        self.assertIn('"impersonation"', plan)
        self.assertIn('"fork_setup_tasks"', plan)
        self.assertIn('"token_setup_helpers"', plan)
        self.assertIn('"uses_unlimited_approvals": false', plan)
        self.assertIn('"balance_assertions": 3', plan)
        self.assertIn('"allowance_assertions": 3', plan)
        self.assertIn('"verifies_seeded_balances": true', plan)
        self.assertIn('"verifies_allowances": true', plan)
        self.assertIn('"fork_context": true', plan)
        plan_json = json.loads(plan)
        self.assertNotIn("runnable", plan_json["scaffold_quality"])
        self.assertEqual(plan_json["scaffold_quality"]["handler_actions"], 2)
        self.assertIn(
            "Handler._seedAndApproveForkTokens",
            plan_json["scaffold"]["entrypoints"],
        )
        self.assertEqual(
            plan_json["scaffold"]["planning_context"]["token_setup_helpers"]["approval_policy"],
            "bounded_default_amount_per_actor_spender",
        )
        self.assertIn('"Handler._bindTargets"', plan)
        self.assertIn('"handler_actions"', plan)
        self.assertIn('"fork_context_path"', plan)
        self.assertIn("0x0000000000000000000000000000000000001234", plan)
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"id": "exp-001"', state)
        self.assertIn('"hyp-002"', state)
        self.assertIn('"inv-002"', state)
        self.assertIn('"as-001"', state)
        self.assertIn('"pg-001"', state)
        self.assertIn('"fc-001"', state)

    async def test_compose_invariant_harness_rejects_empty_actions(self):
        container = FakeContainer()

        result = await _compose_invariant_harness(container, {
            "title": "No actions",
            "invariant": "Something should hold.",
            "actions": [],
        })

        self.assertIn("requires at least one concrete handler action", result)
        self.assertIn("expected_effect", result)

    async def test_run_experiment_mirrors_target_local_poc_evidence(self):
        container = FakeContainer()
        container.exec_result = (0, "Suite result: ok. 1 passed; 0 failed")
        container.files["/audit/test/DSRForwarderBalanceDrain.t.sol"] = (
            "contract DSRForwarderBalanceDrainTest {}"
        )

        result = await _run_experiment(container, {
            "command": (
                "forge test --match-path "
                "test/DSRForwarderBalanceDrain.t.sol -vvv"
            ),
            "working_dir": "/audit",
            "run_kind": "poc_run",
            "record_result": True,
        })

        mirror = (
            "/workspace/experiments/generated-pocs/res-001/"
            "DSRForwarderBalanceDrain.t.sol"
        )
        self.assertIn(mirror, container.files)
        self.assertIn("Mirrored generated PoC", result)
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertIn(mirror, state["sections"]["result"][0]["evidence"])


class CompleteSequenceExperimentTests(unittest.IsolatedAsyncioTestCase):
    TARGET = "0x1111111111111111111111111111111111111111"

    async def _compose_base(self, container, **overrides):
        """Compose a single-step Vault::withdraw sequence (partial by default)."""
        args = {
            "title": "Drain vault",
            "objective": "attacker drains vault",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "expected_effect": "unauthorized value leaves the vault",
            }],
            "observations": [{
                "label": "vault assets",
                "contract": "Vault",
                "call": "totalAssets()(uint256)",
            }],
            "success_condition": "attacker balance increases",
        }
        args.update(overrides)
        await _compose_sequence_experiment(container, args)
        return "/workspace/experiments/exp-001-drain-vault"

    async def test_resolves_experiment_and_rewrites_artifacts(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        before_contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]

        result = await execute_tool("complete_sequence_experiment", {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }, container, [])
        parsed = json.loads(result)

        self.assertEqual(parsed["experiment_id"], "exp-001")
        self.assertEqual(parsed["workspace"], workspace)
        self.assertEqual(parsed["validated"], False)
        # Both artifacts rewritten in place.
        self.assertEqual(parsed["sequence_path"], f"{workspace}/sequence.json")
        self.assertEqual(parsed["contract_path"], f"{workspace}/ReentbotProSequence.t.sol")
        after_contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertNotEqual(before_contract, after_contract)
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        self.assertEqual(len(sequence["completion_history"]), 1)
        self.assertEqual(sequence["completion_history"][0]["mode"], "full")
        self.assertEqual(sequence["objective_probe"]["strategy"], "accounting_delta")
        self.assertEqual(sequence["target_addresses"]["Vault"], self.TARGET)

    async def test_target_binding_makes_partial_step_executable(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        before = json.loads(container.files[f"{workspace}/sequence.json"])
        self.assertEqual(before["steps"][0]["readiness"], "partial")
        self.assertIn(
            "missing_target_address",
            before["steps"][0]["blocker_classes"],
        )

        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "log_only",
        }))
        self.assertTrue(result["steps"][0]["executable"])
        self.assertEqual(result["steps"][0]["readiness"], "executable")
        self.assertEqual(result["scaffold_quality"]["executable_sequence_calls"], 1)
        self.assertIn("bound 1 target address(es)", result["applied_changes"])

    async def test_call_context_plan_records_and_recomputes_execution_identity(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Allowance pull context",
            "objective": "attacker cannot pull third-party funds with wrong spender",
            "actions": [{
                "actor": "attacker",
                "contract": "Token",
                "function": "transferFrom",
                "args": ["victim", "attacker", "amount"],
                "from": "victim",
                "beneficiary": "attacker",
                "expected_effect": "attacker pulls funds from a victim allowance",
            }],
            "observations": [{
                "label": "attacker token balance",
                "contract": "Token",
                "call": "balanceOf(attacker)(uint256)",
            }],
            "success_condition": "attacker balance increases",
        })
        workspace = "/workspace/experiments/exp-001-allowance-pull-context"
        before = json.loads(container.files[f"{workspace}/sequence.json"])
        before_plan = before["call_context_plan"]
        self.assertIn("allowance_or_approval", before_plan["categories"])
        self.assertIn("third_party_state", before_plan["categories"])
        self.assertIn("target_binding", before_plan["categories"])
        self.assertEqual(before_plan["steps"][0]["target_binding"], "unbound")
        self.assertTrue(before_plan["steps"][0]["third_party_state_sensitive"])
        self.assertIn(
            "exact token spender",
            " ".join(before_plan["validation_prompts"]),
        )

        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Token": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "record_result": False,
        }))

        after = json.loads(container.files[f"{workspace}/sequence.json"])
        after_plan = after["call_context_plan"]
        self.assertEqual(after_plan["steps"][0]["target_binding"], "bound")
        self.assertEqual(after_plan["steps"][0]["external_call_target"], self.TARGET)
        self.assertEqual(result["call_context_plan"], after_plan)
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Call Context Plan", readme)
        self.assertIn("holder=victim", readme)

    async def test_observations_and_success_condition_enable_runnable(self):
        container = FakeContainer()
        await self._compose_base(container)
        composed = json.loads(
            container.files[
                "/workspace/experiments/exp-001-drain-vault/sequence.json"
            ]
        )
        # A freshly composed scaffold is never runnable: the objective hook is a
        # placeholder even when the step is concrete.
        self.assertFalse(composed["scaffold_quality"]["runnable"])

        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        self.assertTrue(result["scaffold_quality"]["runnable"])
        self.assertFalse(result["scaffold_quality"]["requires_manual_assertions"])
        self.assertEqual(result["scaffold_quality"]["proof_readiness"], "ready")
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn("function _assertCampaignInvariant() internal", contract)
        self.assertRegex(contract, r"require\(_probeAfter_\w+ != _probeBefore_\w+,")

    async def test_never_generates_assert_true_placeholder(self):
        container = FakeContainer()
        await self._compose_base(container)
        for strategy in (
            "auto",
            "log_only",
            "balance_delta",
            "accounting_delta",
            "custom_placeholders",
        ):
            await _complete_sequence_experiment(container, {
                "sequence": "exp-001",
                "target_addresses": {"Vault": self.TARGET},
                "objective_probe_strategy": strategy,
                "record_result": False,
            })
            contract = container.files[
                "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
            ]
            self.assertNotIn("assertTrue(true)", contract)

    async def test_partial_probe_mode_withholds_assertion(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "mode": "partial_probe",
        }))
        # Snapshots captured, but no objective assertion ⇒ not runnable yet.
        self.assertFalse(result["scaffold_quality"]["runnable"])
        self.assertTrue(result["scaffold_quality"]["requires_manual_assertions"])
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        self.assertTrue(sequence["partial_probe"]["assertion_withheld"])
        self.assertGreater(sequence["partial_probe"]["snapshots"], 0)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        # Probe snapshot variables are present...
        self.assertIn("_probeBefore_Vault_totalAssets", contract)
        # ...but no require() guard was emitted for them.
        self.assertNotIn("Objective probe (", contract)
        # The rendered test is clearly labeled a partial probe, not the objective
        # test, and the scaffold entrypoint metadata stays faithful to it.
        self.assertIn("function test_partial_probe_sequence() public", contract)
        self.assertNotIn("function test_sequence_experiment() public", contract)
        self.assertIn("precondition/setup evidence only", contract)
        self.assertIn(
            "test_partial_probe_sequence", sequence["scaffold"]["entrypoints"]
        )
        self.assertNotIn(
            "test_sequence_experiment", sequence["scaffold"]["entrypoints"]
        )

    async def test_full_mode_keeps_objective_test_name(self):
        # The objective (mode=full) completion keeps the standard test name so
        # the partial-probe rename is scoped to partial_probe mode only.
        container = FakeContainer()
        workspace = await self._compose_base(container)
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "record_result": False,
        })
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("function test_sequence_experiment() public", contract)
        self.assertNotIn("function test_partial_probe_sequence", contract)

    async def test_arg_synthesis_reduces_complex_args_blocker(self):
        container = FakeContainer()
        # A complex argument expression keeps the bound step non-executable.
        await self._compose_base(container, actions=[{
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["computeRatio()"],
            "parameters": [{"name": "amount", "raw": "uint256 amount"}],
            "expected_effect": "value leaves the vault",
        }])
        composed = json.loads(
            container.files[
                "/workspace/experiments/exp-001-drain-vault/sequence.json"
            ]
        )
        self.assertIn(
            "complex_args",
            composed["scaffold_quality"]["non_executable_steps"][0]["blocker_classes"],
        )

        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [{"name": "amount", "type": "uint256", "blockers": []}],
                "candidate_calls": [{"args": ["amount"], "confidence": 0.8}],
            },
            "objective_probe_strategy": "accounting_delta",
        }))
        sequence = json.loads(
            container.files[
                "/workspace/experiments/exp-001-drain-vault/sequence.json"
            ]
        )
        self.assertEqual(sequence["actions"][0]["args"], ["amount"])
        self.assertTrue(result["steps"][0]["executable"])
        self.assertEqual(result["scaffold_quality"]["blocked_sequence_calls"], 0)
        self.assertTrue(
            any("arg synthesis" in change for change in result["applied_changes"])
        )

    async def test_arg_synthesis_holds_signature_blocker(self):
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "attacker",
            "contract": "Vault",
            "function": "claim",
            "args": ["sig"],
            "parameters": [{"name": "sig", "raw": "bytes sig"}],
            "expected_effect": "claim with forged signature",
        }])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "arg_synthesis": {
                "id": "arg-002",
                "source": {"step_index": 1},
                "parameter_plan": [{
                    "name": "sig",
                    "type": "bytes",
                    "blockers": [{"class": "signature", "parameter": "sig"}],
                }],
                "candidate_calls": [{"args": ["sig"], "confidence": 0.2}],
            },
            "record_result": False,
        }))
        # The held signature parameter is surfaced, never silently fabricated.
        self.assertTrue(
            any("signature" in blocker for blocker in result["remaining_blockers"])
        )

    async def test_callback_without_config_is_not_runnable(self):
        # A callback branch whose reentry config was not actually emitted must
        # not report runnable=true: the receive step stays partial and no
        # concrete configureReentry is written.
        container = FakeContainer()
        await self._compose_base(container, actions=[
            {"actor": "callbackAttacker", "contract": "Vault", "function": "withdraw",
             "args": ["amount"], "parameters": [{"name": "amount", "raw": "uint256 amount"}],
             "expected_effect": "value leaves the vault"},
            {"actor": "callbackAttacker", "contract": "Vault", "function": "receive"},
        ])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        self.assertFalse(result["scaffold_quality"]["runnable"])
        receive_step = next(s for s in result["steps"] if s["function"] == "receive")
        self.assertEqual(receive_step["readiness"], "partial")
        self.assertIn("callback_payload_required", receive_step["blocker_classes"])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        # No concrete reentry config was emitted (only the TODO guidance).
        self.assertNotIn("configureReentry(address(0x", contract)

    async def test_callback_with_config_becomes_runnable(self):
        # Supplying a safe payload + resolvable target at completion both makes
        # the receive step executable AND emits the concrete configureReentry.
        container = FakeContainer()
        await self._compose_base(container, actions=[
            {"actor": "callbackAttacker", "contract": "Vault", "function": "withdraw",
             "args": ["amount"], "parameters": [{"name": "amount", "raw": "uint256 amount"}],
             "expected_effect": "value leaves the vault"},
            {"actor": "callbackAttacker", "contract": "Vault", "function": "receive",
             "callback_payload": 'hex"12345678"', "reentry_target": "Vault"},
        ])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        receive_step = next(s for s in result["steps"] if s["function"] == "receive")
        self.assertEqual(receive_step["readiness"], "executable")
        self.assertTrue(result["scaffold_quality"]["runnable"])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 1)',
            contract,
        )

    # ── Normal-entrypoint reentry branch (callbackAttacker calls target.f, the
    #    target calls back, attacker re-enters): the common shape that the older
    #    callback-entry-only logic missed. configureReentry must be emitted when
    #    (and only when) the reentry config is renderable. ──────────────────────

    @staticmethod
    def _reentry_action(**overrides):
        action = {
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
            "parameters": [{"name": "amount", "raw": "uint256 amount"}],
            "expected_effect": "value leaves the vault",
            "callback_kind": "generic_receive_fallback",
            "callback_payload": 'hex"12345678"',
            "reentry_target": "Vault",
        }
        action.update(overrides)
        return action

    async def test_normal_entrypoint_reentry_emits_configure_reentry(self):
        # Requirement 1: a normal entrypoint declaring callback/reentry intent,
        # routed through the attacker contract, with a safe payload + resolvable
        # target, both becomes runnable AND emits a concrete configureReentry.
        container = FakeContainer()
        await self._compose_base(container, actions=[self._reentry_action()])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 1)',
            contract,
        )
        # runnable can be true here only because configureReentry was emitted.
        self.assertTrue(result["scaffold_quality"]["runnable"])
        self.assertTrue(result["steps"][0]["executable"])

    async def test_normal_entrypoint_reentry_without_payload_is_partial(self):
        # Requirement 2: same shape but with NO callback_payload -> partial /
        # harness_limited, blocker includes callback_payload_required, not
        # runnable, and no configureReentry is written.
        container = FakeContainer()
        action = self._reentry_action()
        action.pop("callback_payload")
        await self._compose_base(container, actions=[action])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        step = result["steps"][0]
        self.assertEqual(step["readiness"], "partial")
        self.assertTrue(step["harness_limited"])
        self.assertIn("callback_payload_required", step["blocker_classes"])
        self.assertFalse(result["scaffold_quality"]["runnable"])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertNotIn("configureReentry(address(0x", contract)
        self.assertNotIn(f"configureReentry(address({self.TARGET})", contract)

    async def test_normal_entrypoint_reentry_unsupported_payload_is_partial(self):
        # Requirement 3: a dynamic payload the generator cannot safely emit keeps
        # the step partial and emits no configureReentry; the recomputed plan
        # surfaces the unsupported_calldata blocker.
        container = FakeContainer()
        action = self._reentry_action(
            callback_payload='abi.encodeWithSignature("steal()")',
        )
        await self._compose_base(container, actions=[action])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        step = result["steps"][0]
        self.assertEqual(step["readiness"], "partial")
        self.assertTrue(step["harness_limited"])
        self.assertFalse(result["scaffold_quality"]["runnable"])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        # Only the TODO guidance (configureReentry(address(target), ...)) remains;
        # no concrete configureReentry with the resolved target is emitted.
        self.assertNotIn("configureReentry(address(0x", contract)
        self.assertNotIn(f"configureReentry(address({self.TARGET})", contract)
        sequence = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        self.assertIn(
            "unsupported_calldata",
            sequence["callback_attacker_plan"]["blockers"],
        )

    async def test_plain_attacker_contract_call_stays_executable(self):
        # Requirement 4: a plain actor=callbackAttacker call with NO callback /
        # reentry metadata is fully executable and never demands a reentry
        # payload.
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
            "parameters": [{"name": "amount", "raw": "uint256 amount"}],
            "expected_effect": "value leaves the vault",
        }])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        step = result["steps"][0]
        self.assertTrue(step["executable"])
        self.assertNotIn("callback_payload_required", step["blocker_classes"])
        self.assertTrue(result["scaffold_quality"]["runnable"])

    async def test_action_patch_introducing_callback_recomputes_plan(self):
        # Requirement 5: completing with an action patch that introduces
        # callback_kind/payload recomputes the callback plan (the composed plan
        # was disabled) and emits configureReentry.
        container = FakeContainer()
        await self._compose_base(container)  # plain EOA withdraw, no callback
        composed = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        self.assertFalse(composed["callback_attacker_plan"]["enabled"])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "actions": [self._reentry_action()],
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        }))
        sequence = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        # Plan recomputed from the patched actions: now enabled + routed.
        self.assertTrue(sequence["callback_attacker_plan"]["enabled"])
        self.assertEqual(sequence["callback_attacker_plan"]["routed_steps"], [1])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 1)',
            contract,
        )
        self.assertTrue(result["scaffold_quality"]["runnable"])

    async def test_target_patch_resolves_callback_target_required(self):
        # Requirement 6: a callback target that does not resolve at compose time
        # carries callback_target_required; binding it at completion recomputes
        # the plan and clears that blocker (and emits configureReentry).
        container = FakeContainer()
        await self._compose_base(container, actions=[self._reentry_action()])
        composed = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        self.assertIn(
            "callback_target_required",
            composed["callback_attacker_plan"]["blockers"],
        )
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        })
        sequence = json.loads(
            container.files["/workspace/experiments/exp-001-drain-vault/sequence.json"]
        )
        self.assertNotIn(
            "callback_target_required",
            sequence["callback_attacker_plan"]["blockers"],
        )
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 1)',
            contract,
        )

    async def test_arg_synthesis_materializes_expression_in_scenario(self):
        # A non-inline synthesized expression is materialized through the
        # parameter's scenario variable (not silently defaulted to DEFAULT_AMOUNT),
        # and its setup requirement is preserved.
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["shares", "receiver", "owner"],
            "parameters": [
                {"name": "shares", "raw": "uint256 shares"},
                {"name": "receiver", "raw": "address receiver"},
                {"name": "owner", "raw": "address owner"},
            ],
            "expected_effect": "value leaves the vault",
        }])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [
                    {"name": "shares", "type": "uint256", "blockers": [],
                     "setup_requirements": [
                         "Attacker must hold shares before redeeming/withdrawing; "
                         "seed or mint shares in setup."]},
                    {"name": "receiver", "type": "address", "blockers": []},
                    {"name": "owner", "type": "address", "blockers": []},
                ],
                "candidate_calls": [{
                    "args": ["shares", "attacker", "attacker"],
                    "assignments": [
                        {"name": "shares",
                         "expression": "vault.balanceOf(attacker)", "inline": False,
                         "setup_requirements": [
                             "Attacker must hold shares before redeeming/withdrawing; "
                             "seed or mint shares in setup."]},
                        {"name": "receiver", "expression": "attacker",
                         "inline": True, "setup_requirements": []},
                        {"name": "owner", "expression": "attacker",
                         "inline": True, "setup_requirements": []},
                    ],
                    "confidence": 0.8,
                }],
            },
        }))
        workspace = "/workspace/experiments/exp-001-drain-vault"
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        # The shares expression is materialized; receiver/owner inline directly.
        self.assertIn("shares = vault.balanceOf(attacker);", contract)
        self.assertIn("vault.withdraw(shares, attacker, attacker);", contract)
        # Setup requirement preserved in sequence.json AND surfaced as a blocker.
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        shares_assignment = next(
            a for a in sequence["scenario_assignments"] if a["name"] == "shares"
        )
        self.assertIn(
            "hold shares",
            " ".join(shares_assignment["setup_requirements"]).lower(),
        )
        self.assertTrue(
            any("hold shares" in b.lower() for b in result["remaining_blockers"])
        )

    async def test_arg_synthesis_materializes_address_target_not_makeaddr(self):
        # approve(spender, amount) with a bound Vault emits spender = address(vault)
        # in _configureScenario instead of leaving the makeAddr placeholder.
        container = FakeContainer()
        await self._compose_base(container, actions=[
            {"actor": "attacker", "contract": "Token", "function": "approve",
             "args": ["spender", "amount"],
             "parameters": [{"name": "spender", "raw": "address spender"},
                            {"name": "amount", "raw": "uint256 amount"}],
             "expected_effect": "approve the vault to pull"},
            {"actor": "attacker", "contract": "Vault", "function": "deposit",
             "args": ["amount"],
             "parameters": [{"name": "amount", "raw": "uint256 amount"}],
             "expected_effect": "value enters the vault"},
        ])
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Token": "0x" + "22" * 20, "Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [
                    {"name": "spender", "type": "address", "blockers": []},
                    {"name": "amount", "type": "uint256", "blockers": []},
                ],
                "candidate_calls": [{
                    "args": ["spender", "amount"],
                    "assignments": [
                        {"name": "spender", "expression": "address(vault)",
                         "inline": False, "setup_requirements": []},
                        {"name": "amount", "expression": "DEFAULT_AMOUNT",
                         "inline": True, "setup_requirements": []},
                    ],
                }],
            },
        })
        workspace = "/workspace/experiments/exp-001-drain-vault"
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("spender = address(vault);", contract)
        # The generic address placeholder default was overridden.
        self.assertNotIn("spender; // address placeholder", contract)

    async def test_arg_synthesis_with_assignments_holds_payload_param(self):
        # A held proof parameter is never assigned: no scenario assignment, no
        # fabricated value, and the blocker is surfaced.
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "attacker", "contract": "Vault", "function": "claim",
            "args": ["proof", "amount"],
            "parameters": [{"name": "proof", "raw": "bytes32[] proof"},
                           {"name": "amount", "raw": "uint256 amount"}],
            "expected_effect": "claim",
        }])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "record_result": False,
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [
                    {"name": "proof", "type": "bytes32[]",
                     "blockers": [{"class": "proof_required", "parameter": "proof"}]},
                    {"name": "amount", "type": "uint256", "blockers": []},
                ],
                "candidate_calls": [{
                    "args": ["proof", "amount"],
                    "assignments": [
                        {"name": "proof", "expression": "", "inline": False,
                         "blockers": [{"class": "proof_required"}]},
                        {"name": "amount", "expression": "DEFAULT_AMOUNT",
                         "inline": True},
                    ],
                }],
            },
        }))
        self.assertTrue(
            any("proof_required" in b for b in result["remaining_blockers"])
        )
        sequence = json.loads(container.files[
            "/workspace/experiments/exp-001-drain-vault/sequence.json"
        ])
        self.assertFalse(
            any(a["name"] == "proof" for a in sequence.get("scenario_assignments", []))
        )

    async def test_complex_arg_reduced_when_materialization_compiles(self):
        # A complex original arg is reduced to executable only because the
        # synthesized expression materializes into a compiling scenario variable.
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "attacker", "contract": "Vault", "function": "withdraw",
            "args": ["computeShares()"],
            "parameters": [{"name": "shares", "raw": "uint256 shares"}],
            "expected_effect": "value leaves the vault",
        }])
        composed = json.loads(container.files[
            "/workspace/experiments/exp-001-drain-vault/sequence.json"
        ])
        self.assertIn(
            "complex_args",
            composed["scaffold_quality"]["non_executable_steps"][0]["blocker_classes"],
        )
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [{"name": "shares", "type": "uint256", "blockers": []}],
                "candidate_calls": [{
                    "args": ["shares"],
                    "assignments": [{
                        "name": "shares", "expression": "vault.balanceOf(attacker)",
                        "inline": False, "setup_requirements": [],
                    }],
                }],
            },
        }))
        self.assertTrue(result["steps"][0]["executable"])
        self.assertNotIn("complex_args", result["steps"][0]["blocker_classes"])
        contract = container.files[
            "/workspace/experiments/exp-001-drain-vault/ReentbotProSequence.t.sol"
        ]
        self.assertIn("shares = vault.balanceOf(attacker);", contract)

    async def test_unmaterializable_expression_holds_blocker_no_silent_default(self):
        # When the referenced target is not bound, the expression cannot compile:
        # it is NOT materialized and NOT silently downgraded -- a blocker is kept.
        container = FakeContainer()
        await self._compose_base(container, actions=[{
            "actor": "attacker", "contract": "Vault", "function": "withdraw",
            "args": ["shares"],
            "parameters": [{"name": "shares", "raw": "uint256 shares"}],
            "expected_effect": "value leaves the vault",
        }])
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {},
            "record_result": False,
            "arg_synthesis": {
                "id": "arg-001",
                "source": {"step_index": 1},
                "parameter_plan": [{"name": "shares", "type": "uint256", "blockers": []}],
                "candidate_calls": [{
                    "args": ["shares"],
                    "assignments": [{
                        "name": "shares", "expression": "vault.balanceOf(attacker)",
                        "inline": False, "setup_requirements": [],
                    }],
                }],
            },
        }))
        self.assertTrue(
            any("cannot materialize" in b for b in result["remaining_blockers"])
        )
        workspace = "/workspace/experiments/exp-001-drain-vault"
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        self.assertEqual(sequence.get("scenario_assignments"), [])
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertNotIn("shares = vault.balanceOf(attacker);", contract)
        # No fabricated value: the scenario var keeps its declared default.
        self.assertIn("shares = DEFAULT_AMOUNT;", contract)

    async def test_completion_updates_state_without_validating(self):
        container = FakeContainer()
        await self._compose_base(container)
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        })
        state = await _load_campaign_state(container)
        experiment = state["sections"]["experiment"][0]
        self.assertEqual(experiment["status"], "open")
        self.assertIn("Completion:", experiment["content"])
        self.assertTrue(experiment["sequence_quality"]["runnable"])
        self.assertTrue(
            any(
                path.endswith("/ReentbotProSequence.t.sol")
                for path in experiment["evidence"]
            )
        )
        # A completion result was recorded (observed, not validated).
        completion_results = [
            entry for entry in state["sections"]["result"]
            if entry["title"].startswith("Sequence completion:")
        ]
        self.assertEqual(len(completion_results), 1)
        self.assertEqual(completion_results[0]["status"], "observed")

    async def test_run_build_failure_returns_structured_blocker(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        container.exec_result = (1, "Error: Vault not found\nCompiler run failed")
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "run_build": True,
        }))
        self.assertEqual(result["build"]["exit_code"], 1)
        self.assertFalse(result["build"]["ok"])
        self.assertTrue(result["build"]["blockers"])
        self.assertIn(f"{workspace}/build.log", container.files)
        self.assertTrue(
            any("forge build exited 1" in blocker for blocker in result["remaining_blockers"])
        )

    async def test_run_build_success(self):
        container = FakeContainer()
        await self._compose_base(container)
        container.exec_result = (0, "Compiling 1 files with 0.8.20\nCompiler run successful")
        result = json.loads(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
            "run_build": True,
        }))
        self.assertTrue(result["build"]["ok"])
        self.assertEqual(result["build"]["blockers"], [])
        self.assertTrue(
            any("forge build" in call[0] for call in container.exec_calls)
        )

    async def test_action_replacement_preserves_history(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "redeem",
                "args": ["shares"],
                "parameters": [{"name": "shares", "raw": "uint256 shares"}],
                "expected_effect": "value leaves the vault",
            }],
            "objective_probe_strategy": "log_only",
        })
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        # New action list is in force...
        self.assertEqual(sequence["actions"][0]["function"], "redeem")
        # ...and the replaced action references are kept in history.
        history = sequence["completion_history"][0]
        self.assertEqual(history["previous_actions"][0]["function"], "withdraw")
        self.assertTrue(
            any("replaced action list" in change for change in history["applied_changes"])
        )

    async def test_unknown_sequence_returns_error(self):
        container = FakeContainer()
        result = await _complete_sequence_experiment(container, {"sequence": "exp-999"})
        self.assertIn("Error", result)
        self.assertIn("exp-999", result)

    async def test_missing_sequence_arg_returns_error(self):
        container = FakeContainer()
        result = await _complete_sequence_experiment(container, {})
        self.assertIn("'sequence' is required", result)

    def test_in_experiment_toolset_and_routed(self):
        self.assertIn(
            "complete_sequence_experiment",
            tool_names_for_toolsets({"experiment"}),
        )
        self.assertNotIn(
            "complete_sequence_experiment",
            tool_names_for_toolsets({"core"}),
        )

    def test_objective_probe_auto_prefers_bound_accounting(self):
        plan = _sequence_objective_probe_plan(
            strategy="auto",
            mode="full",
            observations=[{"contract": "Vault", "call": "totalAssets()(uint256)"}],
            target_addresses={"Vault": self.TARGET},
            fork_context={"tokens": [{"label": "WETH", "address": self.TARGET}]},
            success_condition="attacker profits",
        )
        self.assertEqual(plan["strategy"], "accounting_delta")
        self.assertTrue(plan["assertion"])
        self.assertFalse(plan["requires_manual_assertions"])
        # An auto-generated delta guard is a generic probe, not a final assertion.
        self.assertEqual(plan["strength"], "generic_probe")

    def test_objective_probe_no_assertion_has_no_strength(self):
        plan = _sequence_objective_probe_plan(
            strategy="auto",
            mode="full",
            observations=[],
            target_addresses={},
            fork_context=None,
            success_condition="",
        )
        self.assertEqual(plan["assertion"], "")
        self.assertEqual(plan["strength"], "none")

    async def test_objective_probe_object_records_generic_probe_strength(self):
        container = FakeContainer()
        workspace = await self._compose_base(container)
        await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"Vault": self.TARGET},
            "objective_probe_strategy": "accounting_delta",
        })
        sequence = json.loads(container.files[f"{workspace}/sequence.json"])
        # The stored probe object carries strength so the evidence/review gates
        # can refuse to treat a generic delta guard as final proof.
        self.assertEqual(sequence["objective_probe"]["strength"], "generic_probe")

    def test_objective_probe_balance_delta_uses_fork_token(self):
        token = "0x2222222222222222222222222222222222222222"
        plan = _sequence_objective_probe_plan(
            strategy="balance_delta",
            mode="full",
            observations=[],
            target_addresses={"Vault": self.TARGET},
            fork_context={"tokens": [{"label": "WETH", "address": token}]},
            success_condition="attacker token balance increases",
        )
        primary = plan["snapshots"][0]
        self.assertEqual(primary["kind"], "token")
        self.assertIn(
            f"IReentbotProSnapshotERC20(address({token})).balanceOf(attacker)",
            primary["expr"],
        )
        # Profit framing: the attacker's primary asset must strictly increase.
        self.assertIn(">", plan["assertion"])
        variable_block, before, after, assertion_block = (
            _sequence_objective_probe_fragments(plan)
        )
        self.assertIn(primary["var_before"], variable_block)
        self.assertIn(primary["var_before"], before)
        self.assertIn(primary["var_after"], after)
        self.assertIn("require(", assertion_block)

    def test_objective_probe_auto_without_signal_blocks(self):
        plan = _sequence_objective_probe_plan(
            strategy="auto",
            mode="full",
            observations=[],
            target_addresses={},
            fork_context=None,
            success_condition="",
        )
        self.assertEqual(plan["strategy"], "log_only")
        self.assertEqual(plan["assertion"], "")
        self.assertTrue(plan["requires_manual_assertions"])
        self.assertTrue(plan["blockers"])
        # No fragments without snapshots/assertion ⇒ scaffold stays unchanged.
        self.assertEqual(
            _sequence_objective_probe_fragments(plan),
            ("", "", "", ""),
        )


class FindingToolTests(unittest.TestCase):
    def test_submit_finding_preserves_campaign_evidence(self):
        findings = []

        result = _submit_finding({
            "title": "Vault accounting drift",
            "severity": "high",
            "description": "A selected sequence causes accounting drift.",
            "impact": "Attacker profit of 1.5 USDC after costs.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "10-20"}],
            "proof_of_concept": "contract PoC {}",
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "campaign_ids": ["hyp-001", "exp-001", "res-001", "eval-001"],
            "evidence": ["/workspace/campaign/evaluations/eval-001.json"],
            "reproduction_steps": ["deposit", "withdraw"],
            "objective_evaluation": "eval-001",
            "evidence_review": "fr-001",
            "report_review": "rr-001",
        }, findings)

        self.assertIn("validated", result)
        self.assertEqual(findings[0]["campaign_ids"], [
            "hyp-001",
            "exp-001",
            "res-001",
            "eval-001",
        ])
        self.assertEqual(
            findings[0]["evidence"],
            ["/workspace/campaign/evaluations/eval-001.json"],
        )
        self.assertEqual(findings[0]["objective_evaluation"], "eval-001")
        self.assertEqual(findings[0]["evidence_review"], "fr-001")
        self.assertEqual(findings[0]["report_review"], "rr-001")

    def test_submit_finding_downgrades_validated_without_test_output(self):
        findings = []

        result = _submit_finding({
            "title": "Missing output",
            "severity": "high",
            "description": "Claimed validated with no output.",
            "impact": "Unknown.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "10"}],
            "validated": True,
        }, findings)

        self.assertIn("marked unvalidated", result)
        self.assertFalse(findings[0]["validated"])

    def test_submit_finding_downgrades_failing_forge_output(self):
        findings = []

        result = _submit_finding({
            "title": "Failing output",
            "severity": "high",
            "description": "Claimed validated with failing output.",
            "impact": "Unknown.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "10"}],
            "validated": True,
            "test_output": "Suite result: FAILED. 0 passed; 1 failed; 0 skipped",
        }, findings)

        self.assertIn("reports failing tests", result)
        self.assertFalse(findings[0]["validated"])

    def test_submit_finding_downgrades_target_artifact_evidence(self):
        findings = []

        result = _submit_finding({
            "title": "Stale target PoC",
            "severity": "high",
            "description": "Claim depends on an old target-tree PoC.",
            "impact": "Attacker profit of 1 ETH after costs.",
            "affected_code": [{"file": "src/Vault.sol", "lines": "10"}],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "evidence": [
                "/audit/test/OldPoc.t.sol",
                "/audit/findings/2026-04-28/report.md",
            ],
        }, findings)

        self.assertIn("pruned target-tree artifacts", result)
        self.assertFalse(findings[0]["validated"])
        self.assertEqual(findings[0]["contaminated_evidence"], [
            "/audit/findings/2026-04-28/report.md",
            "/audit/test/OldPoc.t.sol",
        ])

    def test_submit_finding_keeps_validated_with_clean_generated_poc_mirror(self):
        findings = []

        result = _submit_finding({
            "title": "Target-local generated PoC with clean mirror",
            "severity": "low",
            "description": "Claim cites a repo-local test plus clean mirror.",
            "impact": "Small prefunded ETH drain.",
            "affected_code": [{"file": "src/Forwarder.sol", "lines": "10"}],
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed",
            "proof_of_concept": (
                "/workspace/experiments/generated-pocs/res-001/"
                "OldPoc.t.sol"
            ),
            "evidence": [
                "/audit/test/OldPoc.t.sol",
                (
                    "/workspace/experiments/generated-pocs/res-001/"
                    "OldPoc.t.sol"
                ),
            ],
        }, findings)

        self.assertIn("supplemental traceability", result)
        self.assertTrue(findings[0]["validated"])
        self.assertEqual(findings[0]["contaminated_evidence"], [
            "/audit/test/OldPoc.t.sol",
        ])


class FindingSubmissionGateTests(unittest.IsolatedAsyncioTestCase):
    def _ready_reviews(self, container: FakeContainer, *, severity: str = "medium"):
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "title": "Ready evidence",
            "severity": severity,
            "ready": True,
            "blocking_gaps": [],
            "candidate": _exploitability_fields(),
        })
        container.files["/workspace/campaign/report-reviews/rr-001.json"] = json.dumps({
            "id": "rr-001",
            "title": "Ready report",
            "severity": severity,
            "ready": True,
            "blocking_gaps": [],
            "candidate": {
                "evidence_review": "fr-001",
                **_exploitability_fields(),
            },
        })

    def _submission_args(self, *, severity: str = "medium") -> dict:
        return {
            "title": "Bridge ingress credits more than received",
            "severity": severity,
            "description": "A validated replay proves over-crediting.",
            "impact": "Unprivileged attacker profit after replayed bridge release.",
            "affected_code": [{"file": "src/Bridge.sol", "lines": "10-30"}],
            "proof_of_concept": "/workspace/experiments/exp-001/ReentbotProSequence.t.sol",
            "validated": True,
            "test_output": "Suite result: ok. 1 passed; 0 failed; 0 skipped",
            "campaign_ids": ["exp-001", "res-001", "fr-001", "rr-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "reproduction_steps": ["run the fork replay", "inspect the objective"],
            "evidence_review": "fr-001",
            "report_review": "rr-001",
            **_exploitability_fields(),
        }

    async def test_submit_finding_checked_blocks_medium_without_ready_reviews(self):
        container = FakeContainer()
        findings: list[dict] = []

        result = await _submit_finding_checked(
            container,
            {
                **self._submission_args(),
                "evidence_review": "",
                "report_review": "",
            },
            findings,
        )

        self.assertIn("submit_finding blocked", result)
        self.assertIn("ready evidence_review", result)
        self.assertEqual(findings, [])

    async def test_submit_finding_checked_blocks_non_ready_review(self):
        container = FakeContainer()
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "title": "Blocked evidence",
            "severity": "medium",
            "ready": False,
            "blocking_gaps": ["missing live target binding"],
        })
        container.files["/workspace/campaign/report-reviews/rr-001.json"] = json.dumps({
            "id": "rr-001",
            "title": "Blocked report",
            "severity": "medium",
            "ready": False,
            "blocking_gaps": ["linked evidence review is not ready"],
            "candidate": {"evidence_review": "fr-001"},
        })
        findings: list[dict] = []

        result = await _submit_finding_checked(
            container,
            self._submission_args(),
            findings,
        )

        self.assertIn("evidence review fr-001 is not ready", result)
        self.assertIn("report review rr-001 is not ready", result)
        self.assertEqual(findings, [])

    async def test_submit_finding_checked_accepts_ready_reviews(self):
        container = FakeContainer()
        self._ready_reviews(container)
        findings: list[dict] = []

        result = await _submit_finding_checked(
            container,
            self._submission_args(),
            findings,
        )

        self.assertIn("Finding #1 submitted", result)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["validated"])

    async def test_submit_finding_checked_preserves_review_caveats(self):
        container = FakeContainer()
        container.files["/workspace/campaign/finding-reviews/fr-001.json"] = json.dumps({
            "id": "fr-001",
            "title": "Ready evidence with caveats",
            "severity": "medium",
            "ready": True,
            "blocking_gaps": [],
            "warnings": [
                "exploitability caveat: production_reachability still describes unresolved deployed context",
                "candidate's only execution evidence is a generic_probe — generic_probe is setup/context evidence",
            ],
            "candidate": _exploitability_fields(),
        })
        container.files["/workspace/campaign/report-reviews/rr-001.json"] = json.dumps({
            "id": "rr-001",
            "title": "Ready report with caveats",
            "severity": "medium",
            "ready": True,
            "blocking_gaps": [],
            "warnings": [
                "report summary is too short or generic",
            ],
            "candidate": {
                "evidence_review": "fr-001",
                **_exploitability_fields(),
            },
        })
        findings: list[dict] = []

        result = await _submit_finding_checked(
            container,
            self._submission_args(),
            findings,
        )

        self.assertIn("Finding #1 submitted", result)
        self.assertIn("Review caveats preserved", result)
        finding = findings[0]
        self.assertTrue(finding["validated"])
        self.assertEqual(len(finding["review_caveats"]), 3)
        self.assertIn("exploitability", finding["review_warning_categories"])
        self.assertIn("proof_strength", finding["review_warning_categories"])
        self.assertIn("report_quality", finding["review_warning_categories"])
        self.assertIn(
            "production_reachability",
            " ".join(finding["review_warnings"]),
        )

    async def test_submit_finding_checked_allows_high_zero_exposure_with_caveat(self):
        container = FakeContainer()
        self._ready_reviews(
            container,
            severity="high",
        )
        findings: list[dict] = []

        result = await _submit_finding_checked(
            container,
            {
                **self._submission_args(severity="high"),
                "funds_at_risk": "Measured funds at risk: $0.",
            },
            findings,
        )

        self.assertIn("Finding #1 submitted", result)
        self.assertIn("zero measured funds at risk", result)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["validated"])
        self.assertEqual(
            findings[0]["exploitability_review"]["exposure_status"],
            "measured_zero",
        )


def _vault_source_and_ast():
    """A small Solidity source plus a hand-built solc compact-AST SourceUnit
    whose `src` byte offsets index into that source."""
    source = (
        "pragma solidity ^0.8.20;\n"
        "\n"
        "contract Vault is Ownable {\n"
        "    address public owner;\n"
        "    uint256 internal _secret;\n"
        "\n"
        "    event Swept(address to);\n"
        "\n"
        "    modifier onlyOwner() {\n"
        '        require(msg.sender == owner, "no");\n'
        "        _;\n"
        "    }\n"
        "\n"
        "    constructor(address o) {\n"
        "        owner = o;\n"
        "    }\n"
        "\n"
        "    function deposit(uint256 amount) external payable {\n"
        "        _secret += amount;\n"
        "    }\n"
        "\n"
        "    function withdraw(uint256 amount) external onlyOwner {\n"
        "        token.transfer(msg.sender, amount);\n"
        "    }\n"
        "\n"
        "    function totalAssets() external view returns (uint256) {\n"
        "        return _secret;\n"
        "    }\n"
        "\n"
        "    receive() external payable {}\n"
        "}\n"
    )

    def src(snippet):
        start = source.index(snippet)
        return f"{start}:{len(snippet)}:0"

    ast = {
        "nodeType": "SourceUnit",
        "src": f"0:{len(source)}:0",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "name": "Vault",
                "contractKind": "contract",
                "abstract": False,
                "src": src("contract Vault"),
                "baseContracts": [{"baseName": {"name": "Ownable"}}],
                "nodes": [
                    {
                        "nodeType": "VariableDeclaration",
                        "name": "owner",
                        "stateVariable": True,
                        "visibility": "public",
                        "src": src("address public owner"),
                        "typeDescriptions": {"typeString": "address"},
                    },
                    {
                        "nodeType": "VariableDeclaration",
                        "name": "_secret",
                        "stateVariable": True,
                        "visibility": "internal",
                        "src": src("uint256 internal _secret"),
                        "typeDescriptions": {"typeString": "uint256"},
                    },
                    {
                        "nodeType": "EventDefinition",
                        "name": "Swept",
                        "src": src("event Swept"),
                    },
                    {
                        "nodeType": "ModifierDefinition",
                        "name": "onlyOwner",
                        "src": src("modifier onlyOwner"),
                        "body": {
                            "src": src(
                                "{\n"
                                '        require(msg.sender == owner, "no");\n'
                                "        _;\n"
                                "    }"
                            )
                        },
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "kind": "constructor",
                        "name": "",
                        "visibility": "public",
                        "stateMutability": "nonpayable",
                        "src": src("constructor(address o)"),
                        "parameters": {"parameters": [
                            {"name": "o", "typeDescriptions": {"typeString": "address"}},
                        ]},
                        "returnParameters": {"parameters": []},
                        "modifiers": [],
                        "body": {"src": src("{\n        owner = o;\n    }")},
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "kind": "function",
                        "name": "deposit",
                        "visibility": "external",
                        "stateMutability": "payable",
                        "src": src("function deposit"),
                        "parameters": {"parameters": [
                            {"name": "amount", "typeDescriptions": {"typeString": "uint256"}},
                        ]},
                        "returnParameters": {"parameters": []},
                        "modifiers": [],
                        "body": {"src": src("{\n        _secret += amount;\n    }")},
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "kind": "function",
                        "name": "withdraw",
                        "visibility": "external",
                        "stateMutability": "nonpayable",
                        "src": src("function withdraw"),
                        "parameters": {"parameters": [
                            {"name": "amount", "typeDescriptions": {"typeString": "uint256"}},
                        ]},
                        "returnParameters": {"parameters": []},
                        # The base-constructor specifier must NOT become a modifier.
                        "modifiers": [
                            {"modifierName": {"name": "onlyOwner"}},
                            {
                                "kind": "baseConstructorSpecifier",
                                "modifierName": {"name": "ERC20"},
                            },
                        ],
                        "body": {
                            "src": src(
                                "{\n        token.transfer(msg.sender, amount);\n    }"
                            )
                        },
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "kind": "function",
                        "name": "totalAssets",
                        "visibility": "external",
                        "stateMutability": "view",
                        "src": src("function totalAssets"),
                        "parameters": {"parameters": []},
                        "returnParameters": {"parameters": [
                            {"name": "", "typeDescriptions": {"typeString": "uint256"}},
                        ]},
                        "modifiers": [],
                        "body": {"src": src("{\n        return _secret;\n    }")},
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "kind": "receive",
                        "name": "",
                        "visibility": "external",
                        "stateMutability": "payable",
                        "src": src("receive()"),
                        "parameters": {"parameters": []},
                        "returnParameters": {"parameters": []},
                        "modifiers": [],
                        "body": {"src": src("{}")},
                    },
                ],
            },
        ],
    }
    return source, ast


class ExtractStateTransitionModelTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, source: str, **kwargs):
        container = FakeContainer()
        container.files["/audit/src/Target.sol"] = source
        args = {"files": ["/audit/src/Target.sol"]}
        args.update(kwargs)
        result = await _extract_state_transition_model(container, args)
        self.assertFalse(
            result.startswith("Error"), f"unexpected error result: {result}"
        )
        data = json.loads(result)
        return container, data, result

    def _artifact(self, container, data):
        path = data["path"]
        self.assertIn(path, container.files)
        return json.loads(container.files[path])

    async def test_mapping_and_aggregate_writes_produce_conservation(self):
        container, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Ledger {
                mapping(address => uint256) public userBalance;
                uint256 public total;
                function f1(uint256 amount) external {
                    userBalance[msg.sender] += amount;
                    total += amount;
                }
                function f2(uint256 amount) external {
                    userBalance[msg.sender] -= amount;
                    total -= amount;
                }
            }
            """
        )
        self.assertEqual(data["state_transition_model_id"], "stm-001")
        self.assertEqual(data["status"], "observed")
        self.assertIn("conservation", data["summary"]["invariant_kinds"])
        # The model artifact is persisted and the counter advanced in state.
        artifact = self._artifact(container, data)
        kinds_by_name = {s["name"]: s["kind"] for s in artifact["tracked_state"]}
        self.assertEqual(kinds_by_name.get("userBalance"), "mapping")
        self.assertEqual(kinds_by_name.get("total"), "aggregate")
        self.assertIn(
            "/workspace/campaign/state-transition-models/stm-001.json",
            container.files,
        )
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"state_transition_model": 1', state)
        # Records a campaign result with the planning-context framing.
        self.assertIn("State-transition model", state)
        self.assertIn("not vulnerability evidence", state)

    async def test_dynamic_call_produces_external_call_safety(self):
        _, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Forwarder {
                mapping(address => uint256) public pending;
                function execute(address target, bytes calldata data) external {
                    pending[msg.sender] += 1;
                    (bool ok, ) = target.call(data);
                    require(ok, "call failed");
                }
            }
            """
        )
        self.assertIn("external_call_safety", data["summary"]["invariant_kinds"])

    async def test_subject_mismatch_produces_authorization_binding(self):
        _, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Bank {
                mapping(address => uint256) public balance;
                address public operator;
                function withdrawFor(address account, uint256 amount) external {
                    require(msg.sender == operator, "auth");
                    balance[account] -= amount;
                    payable(account).transfer(amount);
                }
            }
            """
        )
        self.assertIn(
            "authorization_binding", data["summary"]["invariant_kinds"]
        )

    async def test_enum_status_update_produces_state_machine(self):
        _, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Sale {
                enum Status { Pending, Active, Closed }
                Status public status;
                function activate() external { status = Status.Active; }
                function close() external { status = Status.Closed; }
            }
            """
        )
        self.assertIn("state_machine", data["summary"]["invariant_kinds"])

    async def test_division_in_state_changing_path_produces_rounding(self):
        _, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Pool {
                mapping(address => uint256) public shares;
                uint256 public totalShares;
                uint256 public totalAssets;
                function convert(uint256 amount) external {
                    uint256 minted = amount * totalShares / totalAssets;
                    shares[msg.sender] += minted;
                }
            }
            """
        )
        self.assertIn("rounding", data["summary"]["invariant_kinds"])

    async def test_erc4626_like_gets_generic_invariants_plus_vault_lens(self):
        container, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Vault4626 {
                mapping(address => uint256) public balanceOf;
                uint256 public totalSupply;
                address public asset;
                function deposit(uint256 assets, address receiver)
                    external returns (uint256 shares)
                {
                    shares = assets;
                    balanceOf[receiver] += shares;
                    totalSupply += shares;
                }
                function withdraw(uint256 assets, address receiver, address owner)
                    external returns (uint256 shares)
                {
                    shares = assets;
                    balanceOf[owner] -= shares;
                    totalSupply -= shares;
                }
                function totalAssets() external view returns (uint256) { return 0; }
                function convertToShares(uint256 a) external view returns (uint256) {
                    return a;
                }
            }
            """
        )
        # Generic invariants still come first and are not crowded out by the lens.
        self.assertIn("conservation", data["summary"]["invariant_kinds"])
        # The vault lens is attached because source evidence supports it.
        self.assertIn("vault_like", data["summary"]["lenses"])
        self.assertTrue(data["lenses"].get("vault_like"))
        artifact = self._artifact(container, data)
        self.assertIn("vault_like", artifact["lenses"])
        self.assertTrue(artifact["lenses"]["vault_like"]["evidence"])

    async def test_bland_non_vault_contract_gets_no_vault_lens(self):
        _, data, result = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Ledger {
                mapping(address => uint256) public userBalance;
                uint256 public total;
                function f1(uint256 amount) external {
                    userBalance[msg.sender] += amount;
                    total += amount;
                }
                function f2(uint256 amount) external {
                    userBalance[msg.sender] -= amount;
                    total -= amount;
                }
            }
            """
        )
        # Unknown / non-vault code must NOT default to a vault lens, but generic
        # invariants are still produced.
        self.assertNotIn("vault_like", data["summary"]["lenses"])
        self.assertNotIn("vault_like", data["lenses"])
        self.assertNotIn("vault_like", result)
        self.assertIn("conservation", data["summary"]["invariant_kinds"])

    async def test_not_found_when_no_source(self):
        # Broad scan of an empty workspace (find returns nothing) yields a clean
        # not_found rather than a crash.
        container = FakeContainer()
        result = await _extract_state_transition_model(container, {})
        data = json.loads(result)
        self.assertEqual(data["status"], "not_found")
        self.assertTrue(data["blockers"])
        # The planning-context note is always present, even with no source.
        self.assertIn("This is planning context, not evidence.", data["notes"])

    async def test_unreadable_requested_file_is_partial_with_read_error(self):
        container = FakeContainer()
        result = await _extract_state_transition_model(
            container, {"files": ["/audit/src/Missing.sol"]}
        )
        data = json.loads(result)
        self.assertEqual(data["status"], "partial")
        self.assertTrue(any("could not be read" in b for b in data["blockers"]))

    async def test_contract_filter_scopes_the_model(self):
        container = FakeContainer()
        container.files["/audit/src/Two.sol"] = """
            pragma solidity ^0.8.20;
            contract Alpha {
                uint256 public total;
                function bump() external { total += 1; }
            }
            contract Beta {
                mapping(address => uint256) public bal;
                function set(uint256 x) external { bal[msg.sender] = x; }
            }
        """
        result = await _extract_state_transition_model(container, {
            "files": ["/audit/src/Two.sol"],
            "contract": "Beta",
        })
        data = json.loads(result)
        self.assertEqual(data["scope"].get("contracts"), ["Beta"])
        for entry in data["entrypoints"]:
            self.assertEqual(entry["contract"], "Beta")

    async def test_comparison_not_tracked_as_state(self):
        # A require(a == b) guard must not surface as tracked state; only the
        # real write does. Pins that the root state_mutations hint fix flows
        # through the model (the tool's local == workaround was removed).
        container, data, _ = await self._run(
            """
            pragma solidity ^0.8.20;
            contract Guarded {
                uint256 public count;
                address public owner;
                function bump() external {
                    require(msg.sender == owner, "auth");
                    count += 1;
                }
            }
            """
        )
        artifact = self._artifact(container, data)
        names = {s["name"] for s in artifact["tracked_state"]}
        self.assertIn("count", names)
        self.assertNotIn("sender", names)
        self.assertNotIn("owner", names)


class AstTransformTests(unittest.TestCase):
    def test_transform_extracts_exact_structure(self):
        source, ast = _vault_source_and_ast()
        parsed = _ast_source_unit_to_parsed_file(
            ast, "/audit/src/Vault.sol", source, max_items=100
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["parse_source"], "ast")

        self.assertEqual(len(parsed["contracts"]), 1)
        contract = parsed["contracts"][0]
        self.assertEqual(contract["name"], "Vault")
        self.assertEqual(contract["kind"], "contract")
        self.assertEqual(contract["bases"], ["Ownable"])
        self.assertEqual(contract["modifiers"], ["onlyOwner"])
        self.assertEqual(contract["events"], ["Swept"])

        actions = {a["function"]: a for a in parsed["actions"]}
        # deposit, withdraw, receive are state-changing entrypoints; the
        # constructor is excluded.
        self.assertEqual(set(actions), {"deposit", "withdraw", "receive"})
        observations = {o["function"]: o for o in parsed["observations"]}
        # totalAssets (view) and the public `owner` getter; internal _secret excluded.
        self.assertEqual(set(observations), {"totalAssets", "owner"})

        withdraw = actions["withdraw"]
        self.assertEqual(withdraw["parse_source"], "ast")
        self.assertEqual(withdraw["visibility"], "external")
        self.assertEqual(withdraw["mutability"], "nonpayable")
        # The base-constructor specifier is not captured as a modifier.
        self.assertEqual(withdraw["modifiers"], ["onlyOwner"])
        self.assertEqual(
            withdraw["parameters"],
            [{"raw": "uint256 amount", "name": "amount", "type": "uint256"}],
        )
        self.assertLessEqual(
            {"value_out_or_burn", "token_or_native_transfer", "modifier_gated"},
            set(withdraw["affordances"]),
        )

        deposit = actions["deposit"]
        self.assertEqual(deposit["mutability"], "payable")
        self.assertIn("accepts_native_value", deposit["affordances"])

        self.assertEqual(observations["totalAssets"]["returns"], "uint256")
        self.assertEqual(
            observations["owner"]["affordances"],
            ["observation", "public_variable_getter"],
        )

    def test_transform_returns_none_for_non_source_unit(self):
        self.assertIsNone(
            _ast_source_unit_to_parsed_file({"nodeType": "Block"}, "/a.sol", "", max_items=10)
        )
        self.assertIsNone(
            _ast_source_unit_to_parsed_file(
                {"nodeType": "SourceUnit", "nodes": []}, "/a.sol", "", max_items=10
            )
        )


class ReachabilityTrustCalibrationTests(unittest.TestCase):
    def _strong_gate_action(self, **extra):
        return {
            "visibility": "external",
            "modifiers": ["onlyOwner"],
            "affordances": ["state_changing_entrypoint", "modifier_gated"],
            "hints": {},
            **extra,
        }

    def test_regex_strong_gate_capped_at_medium(self):
        reach = _classify_action_reachability(
            self._strong_gate_action(parse_source="regex")
        )
        self.assertEqual(reach["kind"], "role_gated")
        self.assertFalse(reach["attacker_reachable"])
        self.assertEqual(reach["confidence"], "medium")

    def test_ast_strong_gate_stays_high(self):
        reach = _classify_action_reachability(
            self._strong_gate_action(parse_source="ast")
        )
        self.assertEqual(reach["kind"], "role_gated")
        self.assertEqual(reach["confidence"], "high")

    def test_missing_parse_source_defaults_to_medium(self):
        reach = _classify_action_reachability(self._strong_gate_action())
        self.assertEqual(reach["confidence"], "medium")

    def test_reachability_high_trust_predicate(self):
        self.assertTrue(_reachability_high_trust({"confidence": "high"}))
        self.assertTrue(_reachability_high_trust({"confidence": "live_authority_probe"}))
        self.assertFalse(_reachability_high_trust({"confidence": "medium"}))
        self.assertFalse(_reachability_high_trust({"confidence": "source"}))
        self.assertFalse(_reachability_high_trust({}))
        self.assertFalse(_reachability_high_trust(None))

    def test_low_trust_gated_scores_higher_than_high_trust(self):
        base = {
            "action_key": "Vault::withdraw",
            "contract": "Vault",
            "function": "withdraw",
            "exposure": "gated",
            "live_status": "deployed",
            "affordances": ["value_out_or_burn", "credit_or_liquidation"],
            "target_binding": {"kind": "deployed_economic_contract"},
        }
        low_trust = _attack_graph_candidate_score(
            {**base, "reachability": {
                "kind": "role_gated", "attacker_reachable": False,
                "confidence": "medium",
            }}, "",
        )
        high_trust = _attack_graph_candidate_score(
            {**base, "reachability": {
                "kind": "role_gated", "attacker_reachable": False,
                "confidence": "high",
            }}, "",
        )
        self.assertGreater(low_trust, high_trust)
        # gated -10->-4 (+6) and role_gated -4->-2 (+2) == +8.
        self.assertEqual(low_trust - high_trust, 8)

    def test_live_authority_probe_keeps_full_gated_penalty(self):
        base = {
            "action_key": "Vault::withdraw",
            "exposure": "gated",
            "live_status": "deployed",
            "affordances": ["value_out_or_burn"],
            "target_binding": {"kind": "deployed_economic_contract"},
        }
        live = _attack_graph_candidate_score(
            {**base, "reachability": {
                "kind": "role_gated", "attacker_reachable": False,
                "confidence": "live_authority_probe",
            }}, "",
        )
        regex = _attack_graph_candidate_score(
            {**base, "reachability": {
                "kind": "role_gated", "attacker_reachable": False,
                "confidence": "medium",
            }}, "",
        )
        # Live-confirmed gate is high trust, so it stays fully buried.
        self.assertEqual(regex - live, 8)


class AstActionSpaceWiringTests(unittest.IsolatedAsyncioTestCase):
    def _instascope_container(self, source):
        container = FakeContainer()
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [
                {"contract": "Vault", "src": "/audit/src/Top_1111"},
            ],
        })
        container.files["/audit/src/Top_1111/Top.sol"] = source
        container.exec_result = (0, "/audit/src/Top_1111/Top.sol\n")
        return container

    async def test_map_action_space_reports_regex_parse_mode_without_ast(self):
        source, _ast = _vault_source_and_ast()
        container = self._instascope_container(source)
        with mock.patch.dict(os.environ, {"REENTBOTPRO_DISABLE_AST_MAP": "1"}):
            result = await _map_action_space(container, {
                "path": "/audit/src",
                "record_result": False,
            })
        self.assertIn('"parse_mode": "regex"', result)
        action_space = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        self.assertEqual(action_space["source"]["parse_mode"], "regex")
        self.assertTrue(action_space["actions"])
        self.assertTrue(
            all(a.get("parse_source") == "regex" for a in action_space["actions"])
        )

    async def test_map_action_space_uses_ast_when_available(self):
        source, ast = _vault_source_and_ast()
        container = self._instascope_container(source)
        with mock.patch(
            "reentbotpro.tools._load_ast_sources",
            new=mock.AsyncMock(
                return_value={"/audit/src/Top_1111/Top.sol": ast}
            ),
        ):
            result = await _map_action_space(container, {
                "path": "/audit/src",
                "record_result": False,
            })
        self.assertIn('"parse_mode": "ast"', result)
        action_space = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        self.assertEqual(action_space["source"]["parse_mode"], "ast")
        actions = {a["function"]: a for a in action_space["actions"]}
        self.assertIn("withdraw", actions)
        self.assertEqual(actions["withdraw"]["parse_source"], "ast")
        self.assertEqual(actions["withdraw"]["modifiers"], ["onlyOwner"])


def _struct_labels_for(
    body,
    *,
    params=None,
    visibility="external",
    mutability="nonpayable",
    returns="",
):
    """Run the same hint collection the parsers do, then return only the
    delexicalized structural affordances for a function body."""
    starts = _line_starts(body)
    hints = _collect_line_hints(body, body_offset=0, line_starts=starts, max_items=12)
    return _structural_action_affordances(
        visibility=visibility,
        mutability=mutability,
        modifiers=[],
        body=body,
        hints=hints,
        parameters=params or [],
        returns=returns,
    )


class CollectLineHintsTests(unittest.TestCase):
    """The shared `state_mutations` line hint must read real writes only — an
    equality comparison is not a write to its left operand (this is the root
    that map_action_space / map_protocol_graph / source_slice / the
    state-transition model all consume)."""

    def _state_targets(self, body: str) -> list:
        hints = _collect_line_hints(
            body, body_offset=0, line_starts=_line_starts(body), max_items=12
        )
        return [entry.get("target") for entry in hints["state_mutations"]]

    def test_equality_comparison_is_not_a_write(self):
        self.assertEqual(
            self._state_targets("{ require(msg.sender == owner); }"), []
        )
        # The other relational operators were already safe (the char before `=`
        # breaks the match), but pin them so a future regex edit cannot regress.
        self.assertEqual(self._state_targets("{ if (a >= b) revert(); }"), [])
        self.assertEqual(self._state_targets("{ if (a <= b) revert(); }"), [])
        self.assertEqual(self._state_targets("{ if (a != b) revert(); }"), [])

    def test_real_assignments_still_captured(self):
        self.assertIn("total", self._state_targets("{ total += amt; }"))
        self.assertIn("x", self._state_targets("{ x = y; }"))
        self.assertIn("n", self._state_targets("{ n++; }"))
        self.assertIn(
            "bal[msg.sender]", self._state_targets("{ bal[msg.sender] -= amt; }")
        )
        # An assignment whose RHS *contains* `==` is still a write to the LHS,
        # and the `==` operand itself is not captured.
        targets = self._state_targets("{ flag = (a == b); }")
        self.assertIn("flag", targets)
        self.assertNotIn("a", targets)


class StructuralActionAffordanceTests(unittest.TestCase):
    """Delexicalized structural affordances: risky source *shape* must surface
    even when names/variables carry no known vulnerability vocabulary."""

    def test_renamed_accounting_path_labels_writes_without_vocabulary(self):
        # f1 updates m[msg.sender] and x; bland names, no deposit/total/vault.
        f1 = _struct_labels_for(
            "{ m[msg.sender] += amt; x += amt; }",
            params=[{"name": "amt", "type": "uint256"}],
        )
        self.assertIn("mapping_state_write", f1)
        self.assertIn("aggregate_state_update", f1)
        self.assertIn("user_claim_or_obligation_update", f1)
        self.assertIn("state_mutating_entrypoint", f1)
        # A plain per-user mapping key must not be mistaken for an auth check.
        self.assertNotIn("authorization_condition", f1)

        # f2 reduces m[msg.sender] and sends native value.
        f2 = _struct_labels_for(
            "{ m[msg.sender] -= amt; payable(msg.sender).transfer(amt); }",
            params=[{"name": "amt", "type": "uint256"}],
        )
        self.assertIn("mapping_state_write", f2)
        self.assertIn("external_call_with_value", f2)
        self.assertIn("external_boundary_crossing", f2)

    def test_dynamic_call_target_path_labels_without_vocabulary(self):
        # z(address t, bytes d) { (bool ok,) = t.call(d); require(ok); }
        labels = _struct_labels_for(
            "{ (bool ok,) = t.call(d); require(ok); }",
            params=[
                {"name": "t", "type": "address"},
                {"name": "d", "type": "bytes calldata"},
            ],
        )
        self.assertIn("dynamic_call_target", labels)
        self.assertIn("external_boundary_crossing", labels)
        # A guarded call is not flagged unchecked.
        self.assertNotIn("unchecked_external_boundary", labels)

        unguarded = _struct_labels_for(
            "{ (bool ok,) = t.call(d); }",
            params=[
                {"name": "t", "type": "address"},
                {"name": "d", "type": "bytes calldata"},
            ],
        )
        self.assertIn("unchecked_external_boundary", unguarded)

    def test_authorization_condition_with_renamed_roles(self):
        # q(address a) { require(a == msg.sender || ok[msg.sender]); ... }
        labels = _struct_labels_for(
            "{ require(a == msg.sender || ok[msg.sender]); s += 1; }",
            params=[{"name": "a", "type": "address"}],
        )
        self.assertIn("authorization_condition", labels)

    def test_batch_loop_surface_with_bland_names(self):
        labels = _struct_labels_for(
            "{ for (uint256 i; i < xs.length; i++) { m[xs[i]] += ys[i]; } }",
            params=[
                {"name": "xs", "type": "address[] calldata"},
                {"name": "ys", "type": "uint256[] calldata"},
            ],
        )
        self.assertIn("batch_or_loop_surface", labels)
        self.assertIn("mapping_state_write", labels)

    def test_native_send_discriminated_from_erc20_transfer(self):
        # Two-arg token transfer crosses a boundary but does not carry native
        # value; a one-arg native send does.
        erc20 = _struct_labels_for(
            "{ token.transfer(to, amt); }",
            params=[
                {"name": "to", "type": "address"},
                {"name": "amt", "type": "uint256"},
            ],
        )
        self.assertIn("external_boundary_crossing", erc20)
        self.assertNotIn("external_call_with_value", erc20)

        native = _struct_labels_for(
            "{ payable(to).transfer(amt); }",
            params=[
                {"name": "to", "type": "address"},
                {"name": "amt", "type": "uint256"},
            ],
        )
        self.assertIn("external_call_with_value", native)

    def test_division_and_loop_labels_arithmetic_and_batch(self):
        labels = _struct_labels_for(
            "{ uint256 fee = amount * rate / 10000; payouts += fee; }",
            params=[{"name": "amount", "type": "uint256"}],
        )
        self.assertIn("arithmetic_rounding_or_division", labels)
        self.assertIn("aggregate_state_update", labels)

    def test_conservative_on_benign_view_function(self):
        # A pure struct/field read must not be mislabeled as a state write or a
        # mutating entrypoint — structural labels must not overclaim.
        labels = _struct_labels_for(
            "{ uint256 v = cfg.field; return v; }",
            visibility="external",
            mutability="view",
        )
        for label in (
            "mapping_state_write",
            "aggregate_state_update",
            "state_mutating_entrypoint",
            "user_claim_or_obligation_update",
        ):
            self.assertNotIn(label, labels)

    def test_coverage_attention_weights_structural_labels(self):
        def score(label):
            return _coverage_attention({
                "mutability": "nonpayable",
                "affordances": [label],
            })[0]

        self.assertEqual(score("dynamic_call_target"), 4)
        self.assertEqual(score("external_call_with_value"), 4)
        self.assertEqual(score("mapping_state_write"), 3)
        self.assertEqual(score("aggregate_state_update"), 3)
        self.assertEqual(score("external_boundary_crossing"), 3)
        self.assertEqual(score("arithmetic_rounding_or_division"), 3)
        self.assertEqual(score("authorization_condition"), 3)
        self.assertEqual(score("user_claim_or_obligation_update"), 3)
        self.assertEqual(score("state_mutating_entrypoint"), 2)
        self.assertEqual(score("batch_or_loop_surface"), 2)
        self.assertEqual(score("lifecycle_state_change"), 2)
        # Context-only structural labels carry no attention weight.
        self.assertEqual(score("unchecked_external_boundary"), 0)
        self.assertEqual(score("emits_state_transition_event"), 0)
        # Structural labels must not swamp the strongest lexical signals.
        structural_max = max(score(label) for label in (
            "dynamic_call_target",
            "external_call_with_value",
            "mapping_state_write",
            "state_mutating_entrypoint",
        ))
        lexical_max = max(score(label) for label in (
            "value_out_or_burn",
            "credit_or_liquidation",
            "generic_execution",
            "signed_authorization",
            "cross_domain_or_message",
        ))
        self.assertLessEqual(structural_max, lexical_max)


class DelexicalizedActionSpaceCoverageTests(unittest.IsolatedAsyncioTestCase):
    """map_action_space + review_attack_surface_coverage must surface
    structurally risky functions even with adversarially bland identifiers."""

    async def _map_and_review(self, source, filename="/audit/src/X.sol"):
        container = FakeContainer()
        container.files[filename] = source
        await _map_action_space(container, {
            "files": [filename],
            "record_result": False,
        })
        artifact = json.loads(
            container.files["/workspace/campaign/action-spaces/as-001.json"]
        )
        actions = {a["function"]: a for a in artifact["actions"]}
        review = json.loads(await _review_attack_surface_coverage(container, {
            "action_space": "as-001",
        }))
        return artifact, actions, review

    async def test_map_action_space_records_structural_labels_for_bland_names(self):
        source = """pragma solidity ^0.8.20;
contract Ledger {
    mapping(address => uint256) m;
    uint256 x;
    uint256 y;

    function f1(uint256 amt) external {
        m[msg.sender] += amt;
        x += amt;
    }

    function f2(uint256 amt) external {
        m[msg.sender] -= amt;
        y -= amt;
        payable(msg.sender).transfer(amt);
    }
}
"""
        _artifact, actions, review = await self._map_and_review(source)

        self.assertIn("f1", actions)
        self.assertIn("f2", actions)
        self.assertIn("mapping_state_write", actions["f1"]["affordances"])
        self.assertIn("aggregate_state_update", actions["f1"]["affordances"])
        self.assertIn("external_call_with_value", actions["f2"]["affordances"])
        self.assertIn("external_boundary_crossing", actions["f2"]["affordances"])
        # No deposit/withdraw/vault/share vocabulary was present, so the lexical
        # value labels must be absent — attention is carried by structure alone.
        all_labels = {
            label for action in actions.values() for label in action["affordances"]
        }
        self.assertNotIn("value_in_or_mint", all_labels)
        self.assertNotIn("value_out_or_burn", all_labels)
        self.assertGreaterEqual(review["summary"]["high_attention_gaps"], 1)
        gap_keys = {gap["key"] for gap in review["high_attention_gaps"]}
        self.assertTrue({"Ledger::f1", "Ledger::f2"} & gap_keys)

    async def test_dynamic_call_path_is_high_attention_with_bland_names(self):
        source = """pragma solidity ^0.8.20;
contract Forwarder {
    function z(address t, bytes calldata d) external {
        (bool ok, ) = t.call(d);
        require(ok);
    }
}
"""
        _artifact, actions, review = await self._map_and_review(source)

        self.assertIn("z", actions)
        labels = actions["z"]["affordances"]
        self.assertIn("dynamic_call_target", labels)
        self.assertIn("external_boundary_crossing", labels)
        gap_keys = {gap["key"] for gap in review["high_attention_gaps"]}
        self.assertIn("Forwarder::z", gap_keys)

    async def test_lexical_and_delexicalized_variants_both_surface_gaps(self):
        lexical = """pragma solidity ^0.8.20;
contract A {
    mapping(address => uint256) balances;
    uint256 totalAssets;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalAssets -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""
        delexical = """pragma solidity ^0.8.20;
contract B {
    mapping(address => uint256) m;
    uint256 x;

    function f1(uint256 a) external {
        m[msg.sender] += a;
        x += a;
    }

    function f2(uint256 a) external {
        m[msg.sender] -= a;
        x -= a;
        payable(msg.sender).transfer(a);
    }
}
"""
        _a_art, lex_actions, lex_review = await self._map_and_review(
            lexical, filename="/audit/src/A.sol"
        )
        _b_art, delex_actions, delex_review = await self._map_and_review(
            delexical, filename="/audit/src/B.sol"
        )

        # Both variants surface at least one high-attention open gap.
        self.assertGreaterEqual(lex_review["summary"]["high_attention_gaps"], 1)
        self.assertGreaterEqual(delex_review["summary"]["high_attention_gaps"], 1)

        # The lexical variant still works through the name-based heuristics.
        lex_labels = {
            label for action in lex_actions.values() for label in action["affordances"]
        }
        self.assertTrue({"value_in_or_mint", "value_out_or_burn"} & lex_labels)

        # The delexicalized variant earns its attention purely structurally.
        delex_labels = {
            label for action in delex_actions.values()
            for label in action["affordances"]
        }
        self.assertFalse({"value_in_or_mint", "value_out_or_burn"} & delex_labels)
        self.assertIn("mapping_state_write", delex_labels)
        self.assertIn("external_call_with_value", delex_labels)


_SOURCE_SLICE_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Vault {
    IERC20 public asset;
    address public owner;

    event Deposited(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external onlyOwner {
        asset.transfer(msg.sender, amount);
    }

    function totalAssets() external view returns (uint256) {
        return 1;
    }
}
"""


_SOURCE_SLICE_SHARES_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function withdraw(uint256 shares, address receiver, address owner)
        external
        returns (uint256 assets)
    {
        balanceOf[owner] -= shares;
        return shares;
    }
}
"""


class ParameterParsingTypeTests(unittest.TestCase):
    """Parameter records expose an explicit ``type`` alongside ``raw``/``name``
    (Requirement 8), preserving the legacy raw/name shape."""

    def test_parse_parameters_includes_type(self):
        params = _parse_parameters("uint256 shares, address receiver")
        self.assertEqual(params, [
            {"raw": "uint256 shares", "name": "shares", "type": "uint256"},
            {"raw": "address receiver", "name": "receiver", "type": "address"},
        ])

    def test_parse_parameters_storage_location_stays_in_type(self):
        # The storage location is part of the declared type; only the trailing
        # name is dropped. A type-only declaration (no name) keeps the whole text.
        params = _parse_parameters("bytes32[] calldata proof, address")
        self.assertEqual(params[0]["type"], "bytes32[] calldata")
        self.assertEqual(params[0]["name"], "proof")
        self.assertEqual(params[1], {
            "raw": "address", "name": "", "type": "address",
        })

    def test_ast_parameters_includes_type(self):
        param_list = {"parameters": [
            {"name": "shares", "typeDescriptions": {"typeString": "uint256"}},
            {"name": "", "typeDescriptions": {"typeString": "address"}},
        ]}
        self.assertEqual(_ast_parameters(param_list), [
            {"raw": "uint256 shares", "name": "shares", "type": "uint256"},
            {"raw": "address", "name": "", "type": "address"},
        ])


class SourceSliceTests(unittest.IsolatedAsyncioTestCase):
    def _vault_container(self) -> FakeContainer:
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = _SOURCE_SLICE_VAULT
        return container

    def _shares_container(self) -> FakeContainer:
        container = FakeContainer()
        container.files["/audit/src/Vault.sol"] = _SOURCE_SLICE_SHARES_VAULT
        return container

    async def test_source_slice_by_contract_function_returns_body_and_hints(self):
        container = self._vault_container()

        result = await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "withdraw",
        })

        payload = json.loads(result)
        self.assertEqual(payload["status"], "observed")
        self.assertEqual(payload["path"], "/audit/src/Vault.sol")
        self.assertEqual(payload["contract"], "Vault")
        self.assertEqual(payload["function"], "withdraw")
        self.assertEqual(payload["signature"], "withdraw(uint256)")
        self.assertEqual(payload["modifiers"], ["onlyOwner"])
        # The slice body carries the real source of the target function.
        self.assertIn("function withdraw(uint256 amount) external onlyOwner", payload["body"])
        self.assertIn("asset.transfer(msg.sender, amount);", payload["body"])
        # Reused _collect_line_hints output: a transfer is a value flow; the
        # onlyOwner modifier surfaces an authorization check.
        self.assertIn("value_flows", payload["hints"])
        self.assertIn("authorization_checks", payload["hints"])
        # related_ranges points at the modifier definition the function applies.
        modifier_ranges = [
            item for item in payload["related_ranges"]
            if item.get("name") == "onlyOwner"
        ]
        self.assertEqual(len(modifier_ranges), 1)
        # Cognitive tool: nothing is persisted unless record_result is set.
        self.assertEqual(container.writes, [])

    async def test_source_slice_by_line_finds_containing_function(self):
        container = self._vault_container()

        located = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "deposit",
        }))
        midpoint = (located["line_range"]["start"] + located["line_range"]["end"]) // 2

        by_line = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "line": midpoint,
        }))

        self.assertEqual(by_line["status"], "observed")
        self.assertEqual(by_line["function"], "deposit")
        self.assertEqual(by_line["line_range"], located["line_range"])

    async def test_source_slice_unique_function_name_resolves_without_contract(self):
        container = self._vault_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "function": "deposit",
        }))

        self.assertEqual(payload["status"], "observed")
        self.assertEqual(payload["function"], "deposit")

    async def test_source_slice_ambiguous_function_returns_candidates(self):
        container = FakeContainer()
        container.files["/audit/src/Two.sol"] = """
pragma solidity ^0.8.20;
contract Alpha {
    function harvest() external {}
}
contract Beta {
    function harvest() external {}
}
"""

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Two.sol",
            "function": "harvest",
        }))

        self.assertEqual(payload["status"], "ambiguous")
        self.assertEqual(payload["candidate_count"], 2)
        contracts = sorted(item["contract"] for item in payload["candidates"])
        self.assertEqual(contracts, ["Alpha", "Beta"])

    async def test_source_slice_not_found_returns_status_not_an_exception(self):
        container = self._vault_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "function": "doesNotExist",
        }))

        self.assertEqual(payload["status"], "not_found")
        self.assertEqual(payload["files_scanned"], 1)

    async def test_source_slice_requires_a_locator(self):
        container = self._vault_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
        }))

        self.assertEqual(payload["status"], "error")
        self.assertIn("contract, function, or line", payload["error"])

    async def test_source_slice_include_filter_scopes_hints_and_body(self):
        container = self._vault_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "function": "deposit",
            "include": ["value_flows"],
        }))

        self.assertEqual(payload["status"], "observed")
        # Only the requested hint group is returned; body is withheld.
        self.assertEqual(list(payload["hints"]), ["value_flows"])
        self.assertNotIn("body", payload)
        self.assertIn("body", payload["omitted"])
        self.assertIn("events", payload["omitted"]["excluded_hint_groups"])

    async def test_source_slice_records_artifact_when_requested(self):
        container = self._vault_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "withdraw",
            "record_result": True,
        }))

        self.assertEqual(payload["slice_id"], "ss-001")
        self.assertEqual(payload["artifact_path"], "/workspace/campaign/source-slices/ss-001.json")
        self.assertIn(payload["artifact_path"], container.files)
        self.assertTrue(payload["result_id"].startswith("res-"))
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"source_slice": 1', state)

    async def test_source_slice_missing_file_reports_not_found(self):
        container = FakeContainer()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Missing.sol",
            "function": "withdraw",
        }))

        self.assertEqual(payload["status"], "not_found")

    async def test_source_slice_exposes_parameter_names_and_returns(self):
        container = self._shares_container()

        payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "withdraw",
        }))

        self.assertEqual(payload["status"], "observed")
        self.assertEqual(payload["signature"], "withdraw(uint256,address,address)")
        # Parameter metadata carries both the declared names and their raw types.
        self.assertEqual(
            [param["name"] for param in payload["parameters"]],
            ["shares", "receiver", "owner"],
        )
        self.assertEqual(payload["parameters"][0]["raw"], "uint256 shares")
        # Explicit type field alongside raw/name (Requirement 8/9).
        self.assertEqual(
            [param["type"] for param in payload["parameters"]],
            ["uint256", "address", "address"],
        )
        self.assertIn("assets", payload["returns"])

    async def test_source_slice_object_feeds_synthesize_args_parameter_names(self):
        container = self._shares_container()
        slice_payload = json.loads(await _source_slice(container, {
            "path": "/audit/src/Vault.sol",
            "contract": "Vault",
            "function": "withdraw",
        }))

        # The recorded slice object is a first-class typed input for synthesis:
        # its parameters drive the parameter plan and signature.
        result = json.loads(await _synthesize_args(container, {
            "action": {"contract": "Vault", "function": "withdraw"},
            "source_slice": slice_payload,
            "record_result": False,
        }))

        self.assertEqual(
            [param["name"] for param in result["parameter_plan"]],
            ["shares", "receiver", "owner"],
        )
        self.assertEqual(result["signature"], "withdraw(uint256,address,address)")
        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertIn("vault.balanceOf(attacker)", plan["shares"]["candidates"])

    def test_source_slice_is_in_core_toolset(self):
        self.assertIn("source_slice", tool_names_for_toolsets({"core"}))

    async def test_execute_tool_dispatches_source_slice(self):
        container = self._vault_container()

        result = await execute_tool(
            "source_slice",
            {"path": "/audit/src/Vault.sol", "function": "withdraw"},
            container,
            [],
        )

        payload = json.loads(result)
        self.assertEqual(payload["status"], "observed")
        self.assertEqual(payload["function"], "withdraw")


class PlannerDecidedKeyFilterTests(unittest.IsolatedAsyncioTestCase):
    def _gap_item(self, key):
        contract, _, function = key.partition("::")
        return {
            "key": key,
            "contract": contract,
            "function": function,
            "file": "/audit/src/Vault.sol",
            "line": 20,
            "attention_score": 6,
            "affordances": ["value_out_or_burn"],
            "parameters": [{"name": "amount", "raw": "uint256 amount"}],
        }

    def _action_gap_branch(self, key, decided):
        return _plan_branch_from_action_gap(
            self._gap_item(key),
            source="coverage_high_attention_gap",
            source_path="/workspace/campaign/coverage-reviews/cov-001.json",
            focus="",
            state={"sections": {}, "counters": {}},
            has_fork_context=False,
            has_economics=False,
            economics_context={},
            base_score=6,
            decided_action_keys=decided,
        )

    def test_action_gap_builder_skips_decided_key(self):
        self.assertIsNone(self._action_gap_branch("Vault::withdraw", {"Vault::withdraw"}))

    def test_action_gap_builder_keeps_undecided_key(self):
        branch = self._action_gap_branch("Vault::withdraw", {"Other::thing"})
        self.assertIsNotNone(branch)
        self.assertEqual(branch["target_actions"][0]["key"], "Vault::withdraw")

    def test_action_gap_builder_without_decided_set_keeps_branch(self):
        branch = self._action_gap_branch("Vault::withdraw", None)
        self.assertIsNotNone(branch)

    def test_protocol_hotspot_builder_skips_decided_key(self):
        item = {
            "key": "Vault::withdraw",
            "contract": "Vault",
            "function": "withdraw",
            "affordances": ["value_out_or_burn"],
            "connected": [],
        }
        branch = _plan_branch_from_protocol_hotspot(
            item,
            source_path="/workspace/campaign/protocol-graphs/pg-001.json",
            graph_id="pg-001",
            focus="",
            state={},
            has_fork_context=False,
            has_economics=False,
            economics_context={},
            decided_action_keys={"Vault::withdraw"},
        )
        self.assertIsNone(branch)

    def test_plan_add_branch_skips_none(self):
        branches: dict = {}
        _plan_add_branch(branches, None)
        self.assertEqual(branches, {})

    async def test_plan_attack_campaign_skips_decided_action_gaps(self):
        container = FakeContainer()
        container.files[_CAMPAIGN_STATE_PATH] = json.dumps({
            "attack_search": {"decided_action_keys": ["Vault::withdraw"]},
        })
        container.files["/workspace/campaign/coverage-reviews/cov-001.json"] = json.dumps({
            "id": "cov-001",
            "title": "Coverage review",
            "created_at": "2026-01-01T00:00:00+00:00",
            "action_space_path": "/workspace/campaign/action-spaces/as-001.json",
            "summary": {"high_attention_gaps": 2, "hypothesized_not_experimented": 0},
            "high_attention_gaps": [
                {
                    "key": "Vault::withdraw",
                    "contract": "Vault",
                    "function": "withdraw",
                    "file": "/audit/src/Vault.sol",
                    "line": 20,
                    "attention_score": 6,
                    "affordances": ["value_out_or_burn"],
                    "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                },
                {
                    "key": "Oracle::updatePrice",
                    "contract": "Oracle",
                    "function": "updatePrice",
                    "file": "/audit/src/Oracle.sol",
                    "line": 55,
                    "attention_score": 5,
                    "affordances": ["valuation_dependency"],
                    "parameters": [{"name": "price", "raw": "uint256 price"}],
                },
            ],
        })

        plan = json.loads(await _plan_attack_campaign(container, {
            "coverage_review": "cov-001",
            "record_result": False,
        }))

        gap_keys = {
            action.get("key")
            for branch in plan.get("branches", [])
            if branch.get("source") == "coverage_high_attention_gap"
            for action in branch.get("target_actions") or []
        }
        self.assertIn("Oracle::updatePrice", gap_keys)
        self.assertNotIn("Vault::withdraw", gap_keys)


class ObjectiveClearlyNonEconomicTests(unittest.TestCase):
    """Binary check that decides whether the scaffold should drop route prompts."""

    def test_empty_inputs_are_not_non_economic(self):
        self.assertFalse(_objective_clearly_non_economic(
            objective="",
            success_condition="",
            actions=[],
        ))

    def test_access_control_callback_objective_is_non_economic(self):
        # Verbatim style from the Gamma Hypervisor failure case: a callback
        # function name (uniswapV3MintCallback) must NOT be allowed to drag
        # the haystack into the economic bucket via substring matching.
        self.assertTrue(_objective_clearly_non_economic(
            objective=(
                "Hypervisor::uniswapV3MintCallback must not release more value "
                "than the actor is entitled to receive. Direct attacker call "
                "must REVERT. Mock pool callback must not credit unearned tokens."
            ),
            success_condition="vm.expectRevert on direct attacker invocation",
            actions=[{"actor": "attacker", "contract": "Hypervisor",
                      "function": "uniswapV3MintCallback"}],
        ))

    def test_reentrancy_objective_is_non_economic(self):
        self.assertTrue(_objective_clearly_non_economic(
            objective="Confirm nonReentrant guard prevents re-entry on withdraw",
            success_condition="",
            actions=[],
        ))

    def test_flash_loan_objective_is_economic(self):
        # The existing flash-loan integration test relies on routes being kept.
        self.assertFalse(_objective_clearly_non_economic(
            objective=(
                "Use a flash-loan-funded swap to move oracle price and "
                "liquidate a borrower for profit."
            ),
            success_condition="Liquidator keeps net profit after repayment.",
            actions=[],
        ))

    def test_generic_value_moving_objective_is_not_non_economic(self):
        # No non-economic signal -> classifier abstains, behaviour matches legacy.
        self.assertFalse(_objective_clearly_non_economic(
            objective="Replay a value-moving vault sequence.",
            success_condition="",
            actions=[],
        ))

    def test_mixed_signal_is_treated_as_economic_to_preserve_routes(self):
        # "must revert" plus "flash loan" -> we keep all routes because the
        # cost of dropping a route the agent needs is higher than an extra TODO.
        self.assertFalse(_objective_clearly_non_economic(
            objective=(
                "Direct call must revert; only the flash-loan callback path "
                "should reach storage"
            ),
            success_condition="",
            actions=[],
        ))

    def test_camelcase_function_name_does_not_trigger_economic_signal(self):
        # 'uniswapV3MintCallback' must not be parsed as containing the word
        # 'swap' or 'callback' via substring.
        self.assertTrue(_objective_clearly_non_economic(
            objective="Test that uniswapV3MintCallback reverts on unauthorized sender",
            success_condition="",
            actions=[],
        ))

    def test_action_notes_contribute_to_haystack(self):
        self.assertTrue(_objective_clearly_non_economic(
            objective="Run vault sequence",
            success_condition="",
            actions=[{
                "actor": "attacker",
                "expected_effect": "must revert when sender is unauthorized",
                "notes": "asserts onlyOwner",
            }],
        ))


class NormalizeForceRouteKindsTests(unittest.TestCase):
    def test_none_returns_empty_set(self):
        self.assertEqual(_normalize_force_route_kinds(None), set())

    def test_empty_list_returns_empty_set(self):
        self.assertEqual(_normalize_force_route_kinds([]), set())

    def test_string_input_is_wrapped_into_singleton(self):
        self.assertEqual(
            _normalize_force_route_kinds("flash_loan_route"),
            {"flash_loan_route"},
        )

    def test_invalid_kinds_are_dropped(self):
        result = _normalize_force_route_kinds([
            "flash_loan_route",
            "not_a_real_route",
            "amm_or_valuation_route",
        ])
        self.assertEqual(result, {"flash_loan_route", "amm_or_valuation_route"})

    def test_whitespace_is_stripped(self):
        result = _normalize_force_route_kinds(["  flash_loan_route  "])
        self.assertEqual(result, {"flash_loan_route"})


class SequenceRouteCompositionPlanFilteringTests(unittest.TestCase):
    """Plan-level invariants for the omit_in_scaffold / force_route_kinds path."""

    def _make_oracle_action(self) -> dict:
        # An action_space match whose AST/affordance metadata says all four
        # economic routes apply, so every route fires regardless of the
        # objective text.
        return {
            "step": 1,
            "contract": "Oracle",
            "function": "updatePrice",
            "file": "/audit/src/Oracle.sol",
            "line": 1,
            "affordances": [
                "valuation_dependency",
                "market_or_router",
                "callback_or_flashloan_surface",
                "credit_or_liquidation",
            ],
            "hints": {},
        }

    def _build_plan(
        self,
        *,
        objective: str,
        success_condition: str = "",
        force_route_kinds: set[str] | None = None,
    ) -> dict:
        return _sequence_route_composition_plan(
            objective=objective,
            setup="",
            actions=[{
                "actor": "attacker",
                "contract": "Oracle",
                "function": "updatePrice",
            }],
            matched_actions=[self._make_oracle_action()],
            graph_context=[],
            fork_context=None,
            economics_context=None,
            success_condition=success_condition,
            force_route_kinds=force_route_kinds,
        )

    def test_non_economic_objective_omits_every_route_from_scaffold(self):
        plan = self._build_plan(
            objective="Direct attacker call must revert; unauthorized sender",
        )
        self.assertTrue(plan["objective_classified_non_economic"])
        self.assertEqual(len(plan["routes"]), 4)
        for route in plan["routes"]:
            self.assertTrue(
                route.get("omit_in_scaffold"),
                f"{route['kind']} should be omitted for a non-economic objective",
            )
        self.assertEqual(plan["summary"]["routes_in_scaffold"], 0)
        self.assertEqual(plan["summary"]["routes_omitted_in_scaffold"], 4)

    def test_economic_objective_keeps_every_route_in_scaffold(self):
        plan = self._build_plan(
            objective="Use a flash-loan-funded swap to liquidate",
        )
        self.assertFalse(plan["objective_classified_non_economic"])
        for route in plan["routes"]:
            self.assertFalse(
                route.get("omit_in_scaffold"),
                f"{route['kind']} should be kept for an economic objective",
            )
        self.assertEqual(plan["summary"]["routes_in_scaffold"], 4)
        self.assertEqual(plan["summary"]["routes_omitted_in_scaffold"], 0)

    def test_force_route_kinds_reincludes_otherwise_dropped_route(self):
        plan = self._build_plan(
            objective="Direct attacker call must revert",
            force_route_kinds={"flash_loan_route"},
        )
        self.assertTrue(plan["objective_classified_non_economic"])
        by_kind = {route["kind"]: route for route in plan["routes"]}
        self.assertFalse(by_kind["flash_loan_route"]["omit_in_scaffold"])
        # The non-forced routes remain suppressed.
        self.assertTrue(by_kind["amm_or_valuation_route"]["omit_in_scaffold"])
        self.assertEqual(plan["summary"]["routes_in_scaffold"], 1)
        self.assertEqual(
            plan["summary"]["omitted_route_kinds"],
            sorted({"amm_or_valuation_route", "oracle_window_route",
                    "liquidation_credit_route"}),
        )

    def test_force_route_kinds_with_economic_objective_is_no_op(self):
        # When the classifier says "economic" we keep all routes; an explicit
        # force list shouldn't accidentally drop the others.
        plan = self._build_plan(
            objective="Use a flash-loan-funded swap to liquidate",
            force_route_kinds={"flash_loan_route"},
        )
        for route in plan["routes"]:
            self.assertFalse(route.get("omit_in_scaffold"))

    def test_notes_mention_suppressed_routes_for_audit_trail(self):
        plan = self._build_plan(
            objective="Direct attacker call must revert; only the deposit path is in scope",
        )
        joined = " ".join(plan["notes"])
        self.assertIn("Scaffold suppressed", joined)
        self.assertIn("non-economic", joined)


class SequenceStepReadinessTests(unittest.TestCase):
    """Tri-state readiness so the harness stops treating 'not scaffoldable by
    current helpers' as equivalent to 'not worth pursuing'."""

    TARGET = "0x1111111111111111111111111111111111111111"

    @staticmethod
    def _matched(contract="Vault", function="withdraw"):
        return {"step": 1, "contract": contract, "function": function, "parameters": []}

    def test_simple_known_target_and_action_is_executable(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
        }
        target = {"Vault": self.TARGET}
        readiness = _sequence_step_readiness(step, self._matched(), target)
        self.assertEqual(readiness["status"], "executable")
        self.assertTrue(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertFalse(readiness["harness_limited"])
        self.assertEqual(readiness["blockers"], [])
        self.assertEqual(readiness["blocker_classes"], [])
        # The boolean shim stays in lockstep with readiness["executable"].
        self.assertTrue(_sequence_call_is_executable(step, self._matched(), target))

    def test_missing_target_but_known_action_is_partial(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
        }
        readiness = _sequence_step_readiness(step, self._matched(), {})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("missing_target_address", readiness["blocker_classes"])
        self.assertNotIn("missing_contract", readiness["blocker_classes"])
        self.assertFalse(_sequence_call_is_executable(step, self._matched(), {}))

    def test_supported_payable_value_is_executable(self):
        # First-class payable support: a known target + supported value literal
        # ("1 ether") is now executable, not a harness-limited partial.
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "deposit",
            "args": ["amount"],
            "value": "1 ether",
        }
        readiness = _sequence_step_readiness(
            step,
            self._matched(function="deposit"),
            {"Vault": self.TARGET},
        )
        self.assertEqual(readiness["status"], "executable")
        self.assertTrue(readiness["executable"])
        self.assertFalse(readiness["harness_limited"])
        self.assertNotIn("unsupported_msg_value", readiness["blocker_classes"])

    def test_unsupported_value_expression_is_partial(self):
        # A value expression the generator cannot safely emit stays partial and
        # harness-limited (the branch is plausible; only the harness is short).
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "deposit",
            "args": ["amount"],
            "value": "type(uint256).max",
        }
        readiness = _sequence_step_readiness(
            step,
            self._matched(function="deposit"),
            {"Vault": self.TARGET},
        )
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("unsupported_msg_value", readiness["blocker_classes"])

    def test_receive_with_known_target_is_executable(self):
        # receive() executes through a low-level call: no typed interface needed,
        # just a bound target plus a supported value.
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "receive",
            "value": "1 ether",
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "executable")
        self.assertTrue(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertEqual(readiness["blocker_classes"], [])
        self.assertTrue(_sequence_call_is_executable(step, None, {"Vault": self.TARGET}))

    def test_receive_without_target_is_partial(self):
        step = {"actor": "attacker", "contract": "Vault", "function": "receive"}
        readiness = _sequence_step_readiness(step, None, {})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertIn("missing_target_address", readiness["blocker_classes"])

    def test_fallback_with_hex_calldata_is_executable(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "fallback",
            "value": "1 wei",
            "calldata": 'hex"deadbeef"',
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "executable")
        self.assertTrue(readiness["executable"])
        self.assertEqual(readiness["blocker_classes"], [])

    def test_fallback_with_unsupported_calldata_is_partial(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "fallback",
            "calldata": 'abi.encodeWithSignature("steal()")',
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("unsupported_calldata", readiness["blocker_classes"])

    def test_complex_args_are_partial(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["abi.encode(a, b)"],
        }
        readiness = _sequence_step_readiness(
            step,
            self._matched(),
            {"Vault": self.TARGET},
        )
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("complex_args", readiness["blocker_classes"])

    def test_missing_contract_is_blocked(self):
        step = {"actor": "attacker", "function": "withdraw", "args": ["amount"]}
        readiness = _sequence_step_readiness(step, None, {})
        self.assertEqual(readiness["status"], "blocked")
        self.assertFalse(readiness["executable"])
        self.assertFalse(readiness["core_call_known"])
        self.assertFalse(readiness["harness_limited"])
        self.assertIn("missing_contract", readiness["blocker_classes"])

    def test_missing_function_is_blocked(self):
        step = {"actor": "attacker", "contract": "Vault", "args": ["amount"]}
        readiness = _sequence_step_readiness(step, None, {})
        self.assertEqual(readiness["status"], "blocked")
        self.assertFalse(readiness["core_call_known"])
        self.assertIn("missing_function", readiness["blocker_classes"])

    def test_live_blocker_forces_blocked_even_when_core_call_known(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
            "live_blockers": ["live exposure is gated"],
        }
        readiness = _sequence_step_readiness(
            step,
            self._matched(),
            {"Vault": self.TARGET},
        )
        self.assertEqual(readiness["status"], "blocked")
        self.assertTrue(readiness["core_call_known"])
        self.assertFalse(readiness["harness_limited"])
        self.assertIn("live_blocker", readiness["blocker_classes"])

    def test_materialized_steps_expose_readiness_and_legacy_fields(self):
        actions = [{
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
        }]
        steps = _sequence_materialized_steps(actions, [self._matched()], {})
        step = steps[0]
        self.assertEqual(step["readiness"], "partial")
        self.assertTrue(step["core_call_known"])
        self.assertTrue(step["harness_limited"])
        self.assertIn("missing_target_address", step["blocker_classes"])
        # Backwards-compatible fields stay intact.
        self.assertFalse(step["executable"])
        self.assertIn("missing target address for Vault", step["blockers"])


class SequencePayableCallSupportTests(unittest.TestCase):
    """First-class payable / native-ETH and receive/fallback codegen so the
    harness can represent native-ETH and accounting exploit paths."""

    TARGET = "0x1111111111111111111111111111111111111111"

    @staticmethod
    def _matched(contract="Vault", function="deposit"):
        return {"step": 1, "contract": contract, "function": function, "parameters": []}

    def test_value_expression_support_classification(self):
        for supported in ("", "0", "0 wei", "100", "1e18", "1 wei", "10 gwei",
                          "0.5 ether", "1ether", "DEFAULT_AMOUNT"):
            self.assertTrue(
                _sequence_value_expression_is_supported(supported),
                supported,
            )
        for unsupported in ("type(uint256).max", "msg.value", "amount * 2",
                            "a + b", "address(this).balance"):
            self.assertFalse(
                _sequence_value_expression_is_supported(unsupported),
                unsupported,
            )

    def test_call_value_expression_normalizes_units(self):
        self.assertEqual(_sequence_call_value_expression({"value": "1ether"}), "1 ether")
        self.assertEqual(_sequence_call_value_expression({"value": "1 ETHER"}), "1 ether")
        self.assertEqual(_sequence_call_value_expression({"value": "0"}), "")
        self.assertEqual(_sequence_call_value_expression({}), "")
        # Unsupported expressions never leak into generated code.
        self.assertEqual(
            _sequence_call_value_expression({"value": "type(uint256).max"}),
            "",
        )

    def test_calldata_support_classification(self):
        self.assertTrue(_sequence_calldata_is_supported(""))
        self.assertTrue(_sequence_calldata_is_supported('hex"deadbeef"'))
        self.assertTrue(_sequence_calldata_is_supported('bytes("payload")'))
        self.assertFalse(
            _sequence_calldata_is_supported('abi.encodeWithSignature("steal()")')
        )

    def test_payable_typed_call_emits_value_modifier(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "deposit",
            "args": ["amount"],
            "value": "1 ether",
        }
        block = _sequence_executable_step_block(
            step,
            self._matched(),
            {"Vault": self.TARGET},
        )
        self.assertIn("vm.prank(attacker);", block)
        self.assertIn("vault.deposit{value: 1 ether}(amount);", block)

    def test_receive_step_emits_low_level_call_with_empty_calldata(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "receive",
            "value": "1 ether",
        }
        block = _sequence_executable_step_block(step, None, {"Vault": self.TARGET})
        self.assertIn("vm.prank(attacker);", block)
        self.assertIn(
            f'(bool ok, ) = address({self.TARGET}).call{{value: 1 ether}}("");',
            block,
        )
        self.assertIn('require(ok, "receive call failed");', block)

    def test_fallback_step_emits_low_level_call_with_calldata(self):
        step = {
            "actor": "user",
            "contract": "Vault",
            "function": "fallback",
            "value": "1 wei",
            "calldata": 'hex"deadbeef"',
        }
        block = _sequence_executable_step_block(step, None, {"Vault": self.TARGET})
        self.assertIn("vm.prank(user);", block)
        self.assertIn(
            f'(bool ok, ) = address({self.TARGET}).call{{value: 1 wei}}(hex"deadbeef");',
            block,
        )
        self.assertIn('require(ok, "fallback call failed");', block)

    def test_unsupported_value_emits_no_executable_block(self):
        step = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "deposit",
            "args": ["amount"],
            "value": "type(uint256).max",
        }
        block = _sequence_executable_step_block(
            step,
            self._matched(),
            {"Vault": self.TARGET},
        )
        self.assertEqual(block, "")

    def test_generated_scaffold_contains_payable_call_syntax(self):
        contract = _sequence_experiment_contract(
            title="Native ETH deposit accounting",
            actions=[{
                "actor": "attacker",
                "contract": "Vault",
                "function": "deposit",
                "args": ["amount"],
                "value": "1 ether",
            }],
            observations=[],
            matched_actions=[self._matched()],
            target_addresses={"Vault": self.TARGET},
            fork_context=None,
            attack_graph_candidate=None,
            success_condition="vault native balance accounting diverges",
            route_composition={},
            sequence_minimization={},
        )
        self.assertIn("vault.deposit{value: 1 ether}(amount);", contract)
        # The interface function must be payable, otherwise the {value: ...}
        # call the generator emits does not compile. (_matched() carries empty
        # parameters, so the rendered signature has no args.)
        self.assertIn("function deposit() external payable;", contract)

    def test_value_bearing_manual_interface_is_marked_payable(self):
        # No action_space: the interface is synthesized manually and defaults to
        # nonpayable. A step that sends value must still upgrade it to payable so
        # the emitted typed call compiles.
        contract = _sequence_experiment_contract(
            title="Forced ETH deposit, manual interface",
            actions=[{
                "actor": "attacker",
                "contract": "Vault",
                "function": "deposit",
                "args": ["amount"],
                "value": "1 ether",
            }],
            observations=[],
            matched_actions=[],
            target_addresses={"Vault": self.TARGET},
            fork_context=None,
            attack_graph_candidate=None,
            success_condition="vault credits more than sent",
            route_composition={},
            sequence_minimization={},
        )
        self.assertIn("function deposit(uint256 amount) external payable;", contract)
        self.assertIn("vault.deposit{value: 1 ether}(amount);", contract)

    def test_zero_value_call_keeps_interface_nonpayable(self):
        # A no-value step must NOT spuriously mark the interface payable.
        contract = _sequence_experiment_contract(
            title="Plain deposit, no value",
            actions=[{
                "actor": "attacker",
                "contract": "Vault",
                "function": "deposit",
                "args": ["amount"],
            }],
            observations=[],
            matched_actions=[self._matched()],
            target_addresses={"Vault": self.TARGET},
            fork_context=None,
            attack_graph_candidate=None,
            success_condition="accounting check",
            route_composition={},
            sequence_minimization={},
        )
        self.assertIn("function deposit() external;", contract)
        self.assertNotIn("external payable;", contract)

    def test_generated_scaffold_contains_receive_low_level_call(self):
        contract = _sequence_experiment_contract(
            title="Forced ETH via receive",
            actions=[{
                "actor": "attacker",
                "contract": "Vault",
                "function": "receive",
                "value": "1 ether",
            }],
            observations=[],
            matched_actions=[],
            target_addresses={"Vault": self.TARGET},
            fork_context=None,
            attack_graph_candidate=None,
            success_condition="vault credits ETH it should reject",
            route_composition={},
            sequence_minimization={},
        )
        self.assertIn("Low-level call for receive/fallback entrypoint", contract)
        self.assertIn(
            f'(bool ok, ) = address({self.TARGET}).call{{value: 1 ether}}("");',
            contract,
        )


class CallbackAttackerPlanTests(unittest.TestCase):
    """Deterministic attacker-as-contract harness: kind detection, the recorded
    plan, generated contract, prank routing, and the never-fabricated reentry
    payload blocker."""

    TARGET = "0x1111111111111111111111111111111111111111"

    @staticmethod
    def _callback_hint_action(step=2, contract="LendingPool", function="liquidate",
                              surface="executeOperation"):
        return {
            "step": step,
            "contract": contract,
            "function": function,
            "hints": {
                "callback_surfaces": [{
                    "line": 91,
                    "surface": surface,
                    "selector_hint": f"{surface}(address,uint256,uint256,address,bytes)",
                }],
            },
        }

    def test_callback_kind_for_token_classifies_known_surfaces(self):
        cases = {
            "onERC721Received": "erc721_receiver",
            "onERC1155Received": "erc1155_receiver",
            "onERC1155BatchReceived": "erc1155_receiver",
            "tokensReceived": "erc777_recipient",
            "uniswapV2Call": "uniswap_v2_callback",
            "pancakeCall": "uniswap_v2_callback",
            "uniswapV3SwapCallback": "uniswap_v3_callback",
            "uniswapV3MintCallback": "uniswap_v3_callback",
            "executeOperation": "flash_loan_callback",
            "receiveFlashLoan": "flash_loan_callback",
            "onFlashLoan": "flash_loan_callback",
            "receive": "generic_receive_fallback",
            "fallback": "generic_receive_fallback",
        }
        for token, expected in cases.items():
            self.assertEqual(_callback_kind_for_token(token), expected, token)
        # Plain entrypoints must NOT be mistaken for callbacks.
        for token in ("withdraw", "deposit", "setCallback", "receiveTokens", ""):
            self.assertIsNone(_callback_kind_for_token(token), token)

    def test_normalize_force_callback_kinds_accepts_aliases_and_dedupes(self):
        self.assertEqual(_normalize_force_callback_kinds(None), [])
        self.assertEqual(
            _normalize_force_callback_kinds("erc777"),
            ["erc777_recipient"],
        )
        self.assertEqual(
            _normalize_force_callback_kinds([
                "uniswap_v3_callback",
                "uniswapV3SwapCallback",  # alias for the same kind
                "flash_loan_callback",
                "not-a-kind",
            ]),
            ["uniswap_v3_callback", "flash_loan_callback"],
        )

    def test_action_uses_attacker_contract_triggers(self):
        self.assertTrue(_action_uses_attacker_contract({"actor": "callbackAttacker"}))
        self.assertTrue(_action_uses_attacker_contract({"actor": "attackerContract"}))
        self.assertTrue(_action_uses_attacker_contract({"use_attacker_contract": True}))
        self.assertTrue(_action_uses_attacker_contract({"attacker_contract": "erc777"}))
        self.assertFalse(_action_uses_attacker_contract({"actor": "attacker"}))
        self.assertFalse(_action_uses_attacker_contract({"actor": "user"}))

    def test_declares_callback_or_reentry_intent(self):
        # Explicit callback/reentry metadata on a NORMAL entrypoint counts as
        # intent (Requirement 1)...
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"contract": "Vault", "function": "withdraw",
             "callback_kind": "generic_receive_fallback"}))
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"function": "withdraw", "callback_payload": 'hex"1234"'}))
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"function": "withdraw", "reentry_calldata": 'hex"1234"'}))
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"function": "withdraw", "reentry_target": "Vault"}))
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"function": "transfer", "attacker_contract": "erc777"}))
        self.assertTrue(_step_declares_callback_or_reentry_intent(
            {"use_attacker_contract": True, "callback_surface": "uniswapV2Call"}))
        # ...but a bare attacker-contract route with NO callback metadata does
        # not (Requirement 4: a plain routed call stays executable).
        self.assertFalse(_step_declares_callback_or_reentry_intent(
            {"actor": "callbackAttacker", "contract": "Vault", "function": "withdraw"}))
        self.assertFalse(_step_declares_callback_or_reentry_intent(
            {"use_attacker_contract": True, "function": "withdraw"}))
        self.assertFalse(_step_declares_callback_or_reentry_intent(
            {"actor": "attacker", "function": "withdraw", "target": "Vault"}))

    def test_plain_eoa_sequence_disables_plan(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "Vault", "function": "withdraw"}],
            [], [], None, {},
        )
        self.assertFalse(plan["enabled"])
        self.assertEqual(plan["kinds"], [])
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(_sequence_callback_attacker_contract(plan), "")

    def test_explicit_callback_kind_enables_plan(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "Token", "function": "transfer",
              "callback_kind": "erc777_recipient"}],
            [], [], None, {},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["kinds"], ["erc777_recipient"])
        # The payload blocker is conditional: an explicit kind with NO routed
        # callback step has nothing to configure, so it does not block. The
        # guidance note still tells the agent how to route a step through it.
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(plan["routed_steps"], [])
        self.assertTrue(any("No step routes" in note for note in plan["notes"]))

    def test_routed_callback_step_without_payload_blocks_plan(self):
        # A routed callback step (receive) with no reentry config is exactly the
        # case that still carries callback_payload_required.
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive"}],
            [], [], None, {}, {"Vault": self.TARGET},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["routed_steps"], [1])
        self.assertIn("callback_payload_required", plan["blockers"])

    def test_routed_callback_step_with_config_does_not_block_plan(self):
        # When the routed callback step supplies a safe payload and a resolvable
        # target, configureReentry can be rendered, so the plan no longer blocks.
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive",
              "callback_payload": 'hex"12345678"'}],
            [], [], None, {}, {"Vault": self.TARGET},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["routed_steps"], [1])
        self.assertEqual(plan["blockers"], [])

    def test_attacker_contract_receive_step_enables_generic_hooks(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive"}],
            [], [], None, {},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["kinds"], ["generic_receive_fallback"])
        self.assertEqual(plan["routed_steps"], [1])
        self.assertIn("receive()", plan["entrypoints"])

    def test_action_space_callback_surface_hint_enables_plan(self):
        # Trigger 2: the matched target exposes a callback surface, so the
        # attacker contract implements the corresponding hook.
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "LendingPool", "function": "liquidate"}],
            [self._callback_hint_action()],
            [], None, {},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["kinds"], ["flash_loan_callback"])
        # No step routes through the attacker contract yet -> guidance note.
        self.assertEqual(plan["routed_steps"], [])
        self.assertTrue(any("No step routes" in note for note in plan["notes"]))

    def test_graph_callback_edge_falls_back_to_generic(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "Vault", "function": "deposit"}],
            [],
            [{"connections": [{"edge": "has_callback_surface_hint"}]}],
            None, {},
        )
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["kinds"], ["generic_receive_fallback"])

    def test_force_callback_kinds_arg_enables_plan(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "Vault", "function": "withdraw"}],
            [], [], None,
            {"force_callback_kinds": ["erc721_receiver", "uniswapV3SwapCallback"]},
        )
        self.assertTrue(plan["enabled"])
        # Canonical, ordered by the kind order (erc721 before uniswap_v3).
        self.assertEqual(
            plan["kinds"],
            ["erc721_receiver", "uniswap_v3_callback"],
        )

    def test_generated_contract_erc721_returns_selector(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "attacker", "contract": "NFT", "function": "safeMint",
              "callback_kind": "erc721_receiver"}],
            [], [], None, {},
        )
        contract = _sequence_callback_attacker_contract(plan)
        self.assertIn("contract CallbackAttacker", contract)
        self.assertIn("function onERC721Received(", contract)
        self.assertIn("return this.onERC721Received.selector;", contract)
        # Brace-balanced (cheap structural guard against a broken f-string).
        self.assertEqual(contract.count("{"), contract.count("}"))

    def test_generated_contract_uniswap_v3_has_swap_callback(self):
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Pool",
              "function": "uniswapV3SwapCallback"}],
            [], [], None, {},
        )
        contract = _sequence_callback_attacker_contract(plan)
        self.assertIn(
            "function uniswapV3SwapCallback(int256, int256, bytes calldata)",
            contract,
        )

    def test_routed_receive_step_is_partial_without_payload(self):
        # Requirement 5: a callback step routed through the attacker contract is
        # partial/harness_limited (not rejected) until a reentry payload exists.
        step = {"actor": "callbackAttacker", "contract": "Vault", "function": "receive"}
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["core_call_known"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("callback_payload_required", readiness["blocker_classes"])

    def test_routed_callback_step_with_payload_clears_blocker(self):
        step = {
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "receive",
            "callback_payload": 'hex"deadbeef"',
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertNotIn("callback_payload_required", readiness["blocker_classes"])
        self.assertEqual(readiness["status"], "executable")

    def test_callback_payload_with_unresolvable_target_stays_partial(self):
        # An explicit reentry target that does not resolve is NOT silently
        # replaced by the step's own contract: configureReentry cannot be
        # rendered, so the step stays partial/harness_limited even though the
        # step's own call target (Vault) is bound.
        step = {
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "receive",
            "callback_payload": 'hex"deadbeef"',
            "reentry_target": "UnboundContract",
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("callback_payload_required", readiness["blocker_classes"])

    def test_callback_unsupported_payload_expression_stays_partial(self):
        # A dynamic payload the generator cannot safely emit keeps the step
        # partial -- the harness never emits abi.encode... verbatim into a config.
        step = {
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "receive",
            "callback_payload": 'abi.encodeWithSignature("steal()")',
        }
        readiness = _sequence_step_readiness(step, None, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "partial")
        self.assertFalse(readiness["executable"])
        self.assertTrue(readiness["harness_limited"])
        self.assertIn("callback_payload_required", readiness["blocker_classes"])

    def test_callback_configure_emits_concrete_reentry_when_renderable(self):
        # Codegen agreement: a renderable routed callback step gets a concrete
        # configureReentry line (resolved target, safe payload, max calls).
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive",
              "callback_payload": 'hex"12345678"', "reentry_target": "Vault",
              "reentry_max_calls": 3}],
            [], [], None, {}, {"Vault": self.TARGET},
        )
        configure = _sequence_callback_attacker_configure(
            plan,
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive",
              "callback_payload": 'hex"12345678"', "reentry_target": "Vault",
              "reentry_max_calls": 3}],
            {"Vault": self.TARGET},
        )
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 3)',
            configure,
        )

    def test_callback_configure_keeps_todo_when_unconfigured(self):
        # An unconfigured routed callback step keeps the TODO guidance and emits
        # no concrete (address(0x...)) configureReentry.
        plan = _sequence_callback_attacker_plan(
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive"}],
            [], [], None, {}, {"Vault": self.TARGET},
        )
        configure = _sequence_callback_attacker_configure(
            plan,
            [{"actor": "callbackAttacker", "contract": "Vault", "function": "receive"}],
            {"Vault": self.TARGET},
        )
        self.assertIn("TODO: to make a hook re-enter", configure)
        self.assertNotIn("configureReentry(address(0x", configure)

    def test_plain_entry_routed_through_attacker_contract_stays_executable(self):
        # Routing a NON-callback entry through the attacker contract does not
        # demand a reentry payload; only callback entries do.
        step = {
            "actor": "callbackAttacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
        }
        matched = {"step": 1, "contract": "Vault", "function": "withdraw", "parameters": []}
        readiness = _sequence_step_readiness(step, matched, {"Vault": self.TARGET})
        self.assertEqual(readiness["status"], "executable")
        self.assertNotIn("callback_payload_required", readiness["blocker_classes"])
        # And the emitted prank routes through the attacker contract.
        block = _sequence_executable_step_block(step, matched, {"Vault": self.TARGET})
        self.assertIn("vm.prank(address(callbackAttacker));", block)
        self.assertIn("vault.withdraw(amount);", block)


class ActionGrammarQualityTriStateTests(unittest.TestCase):
    """scaffold_quality exposes tri-state proof readiness and stops using a
    blanket TODO scan as a source blocker."""

    TARGET = "0x1111111111111111111111111111111111111111"

    @staticmethod
    def _action(**overrides):
        action = {
            "actor": "attacker",
            "contract": "Vault",
            "function": "withdraw",
            "args": ["amount"],
            "expected_effect": "value leaves",
        }
        action.update(overrides)
        return action

    @staticmethod
    def _matched():
        return {"step": 1, "contract": "Vault", "function": "withdraw", "parameters": []}

    def test_unbound_target_is_partial_not_blocked(self):
        quality = _action_grammar_quality(
            [self._action()],
            [{"label": "balance"}],
            matched_actions=[],
            target_addresses={},
        )
        self.assertFalse(quality["runnable"])
        self.assertEqual(quality["proof_readiness"], "partial")
        self.assertEqual(quality["executable_sequence_calls"], 0)
        self.assertEqual(quality["partial_sequence_calls"], 1)
        self.assertEqual(quality["blocked_sequence_calls"], 0)
        self.assertIn("missing_target_address", quality["harness_limit_blockers"])
        self.assertEqual(
            quality["non_executable_steps"][0]["blocker_classes"],
            ["missing_target_address"],
        )

    def test_live_blocker_is_blocked(self):
        quality = _action_grammar_quality(
            [self._action(live_blockers=["live exposure is gated"])],
            [{"label": "balance"}],
            matched_actions=[],
            target_addresses={"Vault": self.TARGET},
        )
        self.assertEqual(quality["proof_readiness"], "blocked")
        self.assertEqual(quality["blocked_sequence_calls"], 1)
        self.assertEqual(quality["harness_limit_blockers"], [])

    def test_todo_alone_does_not_block_runnable(self):
        scaffold = (
            "// SPDX-License-Identifier: MIT\n"
            "contract C {\n"
            "    // TODO: add scenario-specific probes\n"
            "    function _assertCampaignInvariant() internal {\n"
            '        require(vault.totalAssets() < 1, "objective broken");\n'
            "    }\n"
            "}\n"
        )
        quality = _action_grammar_quality(
            [self._action()],
            [{"label": "balance"}],
            matched_actions=[self._matched()],
            target_addresses={"Vault": self.TARGET},
            scaffold_source=scaffold,
        )
        self.assertTrue(quality["runnable"])
        self.assertEqual(quality["proof_readiness"], "ready")
        self.assertEqual(quality["source_blockers"], [])
        self.assertTrue(any("TODO" in note for note in quality["source_notes"]))

    def test_precondition_assert_does_not_satisfy_objective_assertion(self):
        # A precondition assertGt(...code.length...) must NOT be mistaken for the
        # objective assertion, which lives in _assertCampaignInvariant.
        scaffold = (
            "contract C {\n"
            "    function _assertPreconditions() internal {\n"
            '        assertGt(vaultAddress.code.length, 0, "no code");\n'
            "    }\n"
            "    function _assertCampaignInvariant() internal {\n"
            "        // TODO: assert the exact invariant violation\n"
            "    }\n"
            "}\n"
        )
        quality = _action_grammar_quality(
            [self._action()],
            [{"label": "balance"}],
            matched_actions=[self._matched()],
            target_addresses={"Vault": self.TARGET},
            scaffold_source=scaffold,
        )
        self.assertFalse(quality["runnable"])
        self.assertEqual(quality["proof_readiness"], "partial")
        self.assertIn(
            "generated scaffold has no executable objective assertion",
            quality["source_blockers"],
        )


class ComposeSequenceExperimentBranchAwareScaffoldTests(unittest.IsolatedAsyncioTestCase):
    """Integration tests proving the scaffold .t.sol no longer dumps irrelevant
    route prompts when the objective is clearly non-economic."""

    async def test_non_economic_objective_strips_route_prompts_from_scaffold(self):
        container = FakeContainer()
        result = await _compose_sequence_experiment(container, {
            "title": "Hypervisor callback access control",
            "objective": (
                "Hypervisor uniswapV3MintCallback must revert when called by an "
                "unauthorized sender (access-control test). Confirm vm.expectRevert."
            ),
            "actions": [{
                "actor": "attacker",
                "contract": "Hypervisor",
                "function": "uniswapV3MintCallback",
                "args": ["amount0", "amount1", "data"],
            }],
            "observations": [{
                "label": "attacker token0 unchanged",
                "call": "token0.balanceOf(attacker)",
            }],
            "success_condition": "Direct attacker call reverts and attacker balance unchanged",
        })

        self.assertIn('"route_composition"', result)
        # Workspace path: pulled from the result body to avoid brittle slug coupling.
        workspace = next(
            path.rsplit("/", 1)[0]
            for path in container.files
            if path.endswith("/sequence.json")
        )
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]

        # No route prompts are emitted at all for a non-economic branch.
        self.assertNotIn("[amm_or_valuation_route]", contract)
        self.assertNotIn("[oracle_window_route]", contract)
        self.assertNotIn("[flash_loan_route]", contract)
        self.assertNotIn("[liquidation_credit_route]", contract)
        # But the agent is told WHY and HOW to override.
        self.assertIn("Route composition prompts suppressed", contract)
        self.assertIn("non-economic", contract)
        self.assertIn("force_route_kinds", contract)

        plan_json = json.loads(container.files[f"{workspace}/sequence.json"])
        route_plan = plan_json["route_composition_plan"]
        # All matched routes are still in sequence.json (audit trail).
        self.assertTrue(route_plan["objective_classified_non_economic"])
        self.assertGreater(len(route_plan["routes"]), 0)
        for route in route_plan["routes"]:
            self.assertTrue(route.get("omit_in_scaffold"))

        # README still includes the full route plan so the agent can review it.
        readme = container.files[f"{workspace}/README.md"]
        self.assertIn("Route Composition Plan", readme)

    async def test_force_route_kinds_re_includes_suppressed_route(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Hypervisor callback access control with flash override",
            "objective": (
                "Hypervisor uniswapV3MintCallback must revert when called by an "
                "unauthorized sender."
            ),
            "actions": [{
                "actor": "attacker",
                "contract": "Hypervisor",
                "function": "uniswapV3MintCallback",
            }],
            "force_route_kinds": ["flash_loan_route"],
        })

        workspace = next(
            path.rsplit("/", 1)[0]
            for path in container.files
            if path.endswith("/sequence.json")
        )
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]

        # The forced route IS re-included in the scaffold even though the
        # classifier said this objective is non-economic.
        self.assertIn("[flash_loan_route]", contract)
        # Other routes remain suppressed.
        self.assertNotIn("[amm_or_valuation_route]", contract)
        self.assertNotIn("[oracle_window_route]", contract)
        self.assertNotIn("[liquidation_credit_route]", contract)

    async def test_full_suppression_note_names_the_dropped_route_kinds(self):
        """Case A (every matched route suppressed): the .t.sol note must name
        the dropped kinds and populate the force_route_kinds example so the
        agent does not have to leave the working surface to discover what was
        filtered. This addresses the narrowing risk: an agent who classified
        as access-control but actually needs an economic route can see exactly
        what is available and re-include it in one tool call."""
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Hypervisor callback access control",
            "objective": (
                "Hypervisor uniswapV3MintCallback must revert when called by an "
                "unauthorized sender."
            ),
            "actions": [{
                "actor": "attacker",
                "contract": "Hypervisor",
                "function": "uniswapV3MintCallback",
            }],
        })

        workspace = next(
            path.rsplit("/", 1)[0]
            for path in container.files
            if path.endswith("/sequence.json")
        )
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        plan_json = json.loads(container.files[f"{workspace}/sequence.json"])
        omitted_kinds = sorted({
            route["kind"] for route in
            plan_json["route_composition_plan"]["routes"]
            if route.get("omit_in_scaffold")
        })

        # Every omitted kind must be named verbatim in the scaffold note.
        self.assertGreater(
            len(omitted_kinds), 0,
            "this test requires the classifier to have suppressed at least one route",
        )
        for kind in omitted_kinds:
            self.assertIn(
                kind, contract,
                f"suppressed kind {kind!r} should be named inline in the scaffold",
            )

        # The override example must be a fully-populated JSON array (not just
        # an empty `[...]` placeholder) so a weak model can copy it verbatim
        # without inventing the right strings.
        expected_force = (
            'force_route_kinds=['
            + ", ".join(f'"{k}"' for k in omitted_kinds)
            + ']'
        )
        self.assertIn(expected_force, contract)

    async def test_partial_suppression_appends_trailing_dropped_kinds_note(self):
        """Case B (some routes kept via force_route_kinds, others suppressed):
        the scaffold must NOT silently hide the remaining suppressed kinds.
        Without this trailing note, an agent who used force_route_kinds=['x']
        would see x's prompts and have no signal that y/z/... were also
        matched but dropped."""
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Hypervisor callback access control with flash override",
            "objective": (
                "Hypervisor uniswapV3MintCallback must revert when called by an "
                "unauthorized sender."
            ),
            "actions": [{
                "actor": "attacker",
                "contract": "Hypervisor",
                "function": "uniswapV3MintCallback",
            }],
            "force_route_kinds": ["flash_loan_route"],
        })

        workspace = next(
            path.rsplit("/", 1)[0]
            for path in container.files
            if path.endswith("/sequence.json")
        )
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        plan_json = json.loads(container.files[f"{workspace}/sequence.json"])
        omitted_kinds = sorted({
            route["kind"] for route in
            plan_json["route_composition_plan"]["routes"]
            if route.get("omit_in_scaffold")
        })

        # The forced route's prompts must still appear.
        self.assertIn("[flash_loan_route]", contract)

        # The trailing note must appear and must name each still-suppressed
        # kind. We tolerate kind names appearing in the note even though the
        # earlier test asserts `[amm_or_valuation_route]` etc are NOT in the
        # contract — note: the suppression note uses NO brackets around the
        # kind names, so the bracketed-form assertion in the other test
        # remains correct.
        self.assertIn("also suppressed for non-economic objective", contract)
        for kind in omitted_kinds:
            self.assertIn(
                kind, contract,
                f"still-suppressed kind {kind!r} should be named in the trailing note",
            )

        # Trailing note must include a copy-pasteable force_route_kinds example
        # for the still-suppressed kinds.
        expected_force = (
            'force_route_kinds=['
            + ", ".join(f'"{k}"' for k in omitted_kinds)
            + ']'
        )
        self.assertIn(expected_force, contract)


class ComposeSequenceCallbackAttackerTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end: compose_sequence_experiment wires a CallbackAttacker contract
    into the scaffold and records the plan, without disturbing EOA sequences."""

    TARGET = "0x1111111111111111111111111111111111111111"

    @staticmethod
    def _workspace(container):
        return next(
            path.rsplit("/", 1)[0]
            for path in container.files
            if path.endswith("/sequence.json")
        )

    async def test_generic_callback_action_emits_attacker_contract(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Reentrancy via receiver hook",
            "objective": "Attacker contract re-enters withdraw from its receive hook.",
            "actions": [{
                "actor": "callbackAttacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
            }],
            "observations": [{"label": "vault balance", "call": "vault.totalAssets()"}],
            "success_condition": "attacker withdraws more than deposited",
            "target_addresses": {"Vault": self.TARGET},
        })
        workspace = self._workspace(container)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("contract CallbackAttacker", contract)
        self.assertIn("CallbackAttacker internal callbackAttacker;", contract)
        self.assertIn("callbackAttacker = new CallbackAttacker();", contract)
        self.assertIn("vm.deal(address(callbackAttacker), 100 ether);", contract)
        # The routed step pranks as the attacker contract, not the EOA.
        self.assertIn("vm.prank(address(callbackAttacker));", contract)
        self.assertIn("receive() external payable", contract)

    async def test_erc721_receiver_kind_includes_selector(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "NFT receiver hook",
            "objective": "Attacker contract must accept ERC721 safeTransferFrom.",
            "actions": [{
                "actor": "callbackAttacker",
                "contract": "NFT",
                "function": "safeMint",
                "args": ["tokenId"],
                "callback_kind": "erc721_receiver",
            }],
            "target_addresses": {"NFT": self.TARGET},
        })
        workspace = self._workspace(container)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn("function onERC721Received(", contract)
        self.assertIn("return this.onERC721Received.selector;", contract)

    async def test_uniswap_v3_callback_kind_emits_swap_callback(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Uniswap V3 swap callback attacker",
            "objective": "Attacker implements uniswapV3SwapCallback to fund the swap.",
            "actions": [{
                "actor": "callbackAttacker",
                "contract": "Pool",
                "function": "swap",
                "args": ["zeroForOne", "amount"],
                "callback_kind": "uniswap_v3_callback",
            }],
            "target_addresses": {"Pool": self.TARGET},
        })
        workspace = self._workspace(container)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        self.assertIn(
            "function uniswapV3SwapCallback(int256, int256, bytes calldata)",
            contract,
        )

    async def test_sequence_json_records_callback_attacker_plan(self):
        container = FakeContainer()
        result = await _compose_sequence_experiment(container, {
            "title": "Flash loan callback attacker",
            "objective": "Attacker contract receives a flash loan and re-enters.",
            "actions": [{
                "actor": "callbackAttacker",
                "contract": "Pool",
                "function": "flashLoan",
                "args": ["amount"],
                "callback_kind": "flash_loan_callback",
            }],
            "target_addresses": {"Pool": self.TARGET},
        })
        workspace = self._workspace(container)
        plan_json = json.loads(container.files[f"{workspace}/sequence.json"])
        plan = plan_json["callback_attacker_plan"]
        self.assertTrue(plan["enabled"])
        self.assertEqual(plan["kinds"], ["flash_loan_callback"])
        self.assertEqual(plan["attacker_contract"], "CallbackAttacker")
        self.assertIn(
            "executeOperation(address,uint256,uint256,address,bytes)",
            plan["entrypoints"],
        )
        self.assertIn("callback_payload_required", plan["blockers"])
        # Surfaced in the response and the README too.
        self.assertTrue(json.loads(result)["callback_attacker_plan"]["enabled"])
        self.assertIn(
            "Callback Attacker Plan",
            container.files[f"{workspace}/README.md"],
        )

    async def test_missing_callback_payload_is_partial_not_rejected(self):
        container = FakeContainer()
        result = await _compose_sequence_experiment(container, {
            "title": "Receiver reentry without payload",
            "objective": "Attacker re-enters from receive but payload is unspecified.",
            "actions": [
                # A concrete state-changing entry keeps the base grammar valid so
                # the receive step's classification (not the absence of a
                # state-changing action or objective hook) is what this test
                # exercises.
                {"actor": "callbackAttacker", "contract": "Vault",
                 "function": "withdraw", "args": ["amount"],
                 "expected_effect": "value leaves the vault"},
                {"actor": "callbackAttacker", "contract": "Vault",
                 "function": "receive"},
            ],
            "observations": [{"label": "vault balance", "call": "vault.totalAssets()"}],
            "success_condition": "balance accounting diverges",
            "target_addresses": {"Vault": self.TARGET},
        })
        parsed = json.loads(result)
        receive_step = next(s for s in parsed["steps"] if s["function"] == "receive")
        self.assertEqual(receive_step["readiness"], "partial")
        self.assertFalse(receive_step["executable"])
        self.assertTrue(receive_step["harness_limited"])
        self.assertIn("callback_payload_required", receive_step["blocker_classes"])
        # Partial readiness, not a hard rejection / blocked verdict.
        self.assertEqual(
            parsed["scaffold_quality"]["proof_readiness"], "partial",
        )
        self.assertEqual(parsed["scaffold_quality"]["blocked_sequence_calls"], 0)

    async def test_callback_payload_with_target_emits_configure_reentry(self):
        container = FakeContainer()
        result = await _compose_sequence_experiment(container, {
            "title": "Receiver reentry with payload",
            "objective": "Attacker re-enters withdraw from its receive hook.",
            "actions": [
                {"actor": "callbackAttacker", "contract": "Vault",
                 "function": "withdraw", "args": ["amount"],
                 "expected_effect": "value leaves the vault"},
                {"actor": "callbackAttacker", "contract": "Vault",
                 "function": "receive", "callback_payload": 'hex"12345678"',
                 "reentry_target": "Vault", "reentry_max_calls": 2},
            ],
            "observations": [{"label": "vault balance", "call": "vault.totalAssets()"}],
            "success_condition": "balance accounting diverges",
            "target_addresses": {"Vault": self.TARGET},
        })
        workspace = self._workspace(container)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        # The reentry config is materialized in _configureScenario.
        self.assertIn(
            f'callbackAttacker.configureReentry(address({self.TARGET}), '
            'hex"12345678", 2)',
            contract,
        )
        # And the routed receive step is now executable (config renderable), so
        # readiness and the generated code agree.
        parsed = json.loads(result)
        receive_step = next(s for s in parsed["steps"] if s["function"] == "receive")
        self.assertEqual(receive_step["readiness"], "executable")
        self.assertNotIn(
            "callback_payload_required", receive_step["blocker_classes"]
        )

    async def test_eoa_sequence_unchanged_except_new_metadata(self):
        container = FakeContainer()
        result = await _compose_sequence_experiment(container, {
            "title": "Plain EOA deposit withdraw",
            "objective": "Check share accounting on deposit then withdraw.",
            "actions": [
                {"actor": "attacker", "contract": "Vault", "function": "deposit",
                 "args": ["amount"]},
                {"actor": "attacker", "contract": "Vault", "function": "withdraw",
                 "args": ["amount"]},
            ],
            "target_addresses": {"Vault": self.TARGET},
        })
        workspace = self._workspace(container)
        contract = container.files[f"{workspace}/ReentbotProSequence.t.sol"]
        # No attacker-contract surface leaks into a pure EOA scaffold.
        self.assertNotIn("CallbackAttacker", contract)
        self.assertNotIn("callbackAttacker", contract)
        # The new metadata is present but the plan is disabled.
        plan = json.loads(container.files[f"{workspace}/sequence.json"])[
            "callback_attacker_plan"
        ]
        self.assertFalse(plan["enabled"])
        self.assertEqual(plan["kinds"], [])
        self.assertFalse(json.loads(result)["callback_attacker_plan"]["enabled"])
        # The contract the generator emits with an auto-derived (disabled) plan
        # is byte-identical to one built with no plan supplied at all: the
        # feature is purely additive for EOA sequences.
        baseline = _sequence_experiment_contract(
            title="Plain EOA deposit withdraw",
            actions=[
                {"actor": "attacker", "contract": "Vault", "function": "deposit",
                 "args": ["amount"]},
                {"actor": "attacker", "contract": "Vault", "function": "withdraw",
                 "args": ["amount"]},
            ],
            observations=[],
            matched_actions=[],
            target_addresses={"Vault": self.TARGET},
            fork_context=None,
            attack_graph_candidate=None,
            success_condition="",
            route_composition={},
            sequence_minimization={},
        )
        self.assertNotIn("CallbackAttacker", baseline)


class ParseForgeTestSummaryTests(unittest.TestCase):
    """§4.11 — structured Foundry output parser."""

    def test_empty_input_returns_none(self):
        self.assertIsNone(_parse_forge_test_summary(""))

    def test_non_foundry_text_returns_none(self):
        self.assertIsNone(_parse_forge_test_summary(
            "some random hardhat-style output without forge markers"
        ))

    def test_ok_suite_returns_counts(self):
        result = _parse_forge_test_summary(
            "Test result: ok. 3 passed; 0 failed; 0 skipped; finished in 1.23ms"
        )
        self.assertEqual(result["passed"], 3)
        self.assertEqual(result["failed"], 0)
        self.assertFalse(result["suite_failed"])
        self.assertEqual(result["source"], "suite_result")

    def test_failed_suite_returns_failure(self):
        result = _parse_forge_test_summary(
            "Test result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 1.23ms"
        )
        self.assertEqual(result["failed"], 1)
        self.assertTrue(result["suite_failed"])

    def test_multi_suite_sums_counts_and_propagates_any_failure(self):
        # Concatenated output from two suites: one ok, one failed. The legacy
        # heuristic would see both "ok" and "fail" tokens and (depending on
        # ordering) misclassify; the structured parser must report the failure.
        result = _parse_forge_test_summary(
            "Test result: ok. 2 passed; 0 failed; 0 skipped\n"
            "Test result: FAILED. 1 passed; 2 failed; 0 skipped\n"
        )
        self.assertEqual(result["passed"], 3)
        self.assertEqual(result["failed"], 2)
        self.assertTrue(result["suite_failed"])

    def test_per_test_markers_count_when_no_summary_line(self):
        # Agent pasted only the per-test pass/fail markers (truncated output).
        result = _parse_forge_test_summary(
            "Running 2 tests for test/Foo.t.sol:Foo\n"
            "[PASS] testStep1() (gas: 12345)\n"
            "[PASS] testStep2() (gas: 23456)\n"
        )
        self.assertEqual(result["source"], "per_test_markers")
        self.assertEqual(result["passed"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertFalse(result["suite_failed"])

    def test_per_test_failure_marker_signals_failure(self):
        result = _parse_forge_test_summary(
            "[FAIL: assertion failed] testBroken() (gas: 1234)\n"
        )
        self.assertEqual(result["failed"], 1)
        self.assertTrue(result["suite_failed"])


class CheckTestOutputTests(unittest.TestCase):
    """§4.11 + §4.12 — gate-side semantics of _check_test_output."""

    def test_empty_output_returns_none(self):
        self.assertIsNone(_check_test_output(""))

    def test_passing_foundry_output_returns_none(self):
        self.assertIsNone(_check_test_output(
            "Test result: ok. 1 passed; 0 failed; 0 skipped"
        ))

    def test_failing_foundry_output_returns_warning_with_counts(self):
        warning = _check_test_output(
            "Test result: FAILED. 0 passed; 1 failed; 0 skipped"
        )
        self.assertIsNotNone(warning)
        self.assertIn("0 passed", warning)
        self.assertIn("1 failed", warning)

    def test_passing_vm_expect_revert_is_not_flagged_as_failure(self):
        # The pattern the agent wrote during the Gamma run: a test that uses
        # vm.expectRevert to confirm a sender check. The trace mentions
        # "revert" many times in PASS lines, but the suite passes.
        output = (
            "Running 3 tests for src/Exp001Test.t.sol:Exp001Test\n"
            "[PASS] testInvariant_noUnearnedTokens() (gas: 12345)\n"
            "[PASS] testStep1_directCall_reverts() (gas: 23456)\n"
            "[PASS] testStep2_mockPoolInflated_noFreeTokens() (gas: 34567)\n"
            "Test result: ok. 3 passed; 0 failed; 0 skipped; finished in 1.23ms\n"
        )
        self.assertIsNone(_check_test_output(output))

    def test_foundry_ok_with_zero_executed_tests_is_flagged_as_setup_only(self):
        # forge build / compile-only runs report ok but ran no tests;
        # treat as setup evidence, not validation.
        warning = _check_test_output(
            "Test result: ok. 0 passed; 0 failed; 0 skipped"
        )
        self.assertIsNotNone(warning)
        self.assertIn("zero executed tests", warning)

    def test_non_foundry_failure_falls_back_to_legacy_heuristic(self):
        # No Foundry markers at all — legacy keyword heuristic still catches
        # an obvious failure-only output.
        warning = _check_test_output("compile error: ParserError at line 5")
        self.assertIsNotNone(warning)

    def test_non_foundry_mixed_output_still_uses_heuristic(self):
        # No Foundry markers, but has both pass and fail indicators -> the
        # legacy heuristic gates on has_fail AND not has_pass, so this passes.
        self.assertIsNone(_check_test_output(
            "hardhat: 1 passing\nWarning: assertion error caught"
        ))


class ObjectiveEvaluationAltPathTests(unittest.TestCase):
    """§4.12 — non-empty objective_evaluation downgrades test_output warnings."""

    def test_alt_path_active_when_objective_evaluation_is_supplied(self):
        self.assertTrue(_objective_evaluation_alt_path_active(
            {"objective_evaluation": "eval-001"}
        ))

    def test_alt_path_inactive_when_objective_evaluation_is_missing(self):
        self.assertFalse(_objective_evaluation_alt_path_active({}))

    def test_alt_path_inactive_for_whitespace_only_value(self):
        self.assertFalse(_objective_evaluation_alt_path_active(
            {"objective_evaluation": "   "}
        ))


class SubmitFindingObjectiveEvaluationAltPathTests(unittest.TestCase):
    """§4.12 integration — _submit_finding keeps validated=true when test_output
    looks suspicious but the agent provided an objective_evaluation reference."""

    def test_alt_path_keeps_validated_when_objective_evaluation_linked(self):
        findings: list[dict] = []
        result = _submit_finding({
            "title": "Multi-suite fuzz with intentional revert traces",
            "severity": "high",
            "description": "The exploit path completes; setup harness intentionally reverts in another suite.",
            "impact": "Unprivileged attacker drains vault.",
            "affected_code": [{"file": "/audit/src/Vault.sol", "lines": "10-30"}],
            "validated": True,
            # This output would normally be blocked because of "1 failed" in a
            # separate harness suite; objective_evaluation justifies acceptance.
            "test_output": (
                "Test result: ok. 1 passed; 0 failed; 0 skipped\n"
                "Test result: FAILED. 0 passed; 1 failed; 0 skipped\n"
            ),
            "objective_evaluation": "eval-001",
        }, findings)

        # validated is preserved even though _check_test_output produced a warning.
        self.assertTrue(findings[0]["validated"])
        # The warning is surfaced via system_note so reviewers see it.
        self.assertIn("system_note", findings[0])
        self.assertIn("failing tests", findings[0]["system_note"])
        # The summary message still includes the warning text.
        self.assertIn("failing tests", result)

    def test_alt_path_inactive_without_objective_evaluation_downgrades(self):
        findings: list[dict] = []
        _submit_finding({
            "title": "Same suspicious output without objective_evaluation",
            "severity": "high",
            "description": "Same as above, but no objective_evaluation linked.",
            "impact": "Unprivileged attacker drains vault.",
            "affected_code": [{"file": "/audit/src/Vault.sol", "lines": "10-30"}],
            "validated": True,
            "test_output": (
                "Test result: ok. 1 passed; 0 failed; 0 skipped\n"
                "Test result: FAILED. 0 passed; 1 failed; 0 skipped\n"
            ),
            # No objective_evaluation -> alt-path doesn't activate.
        }, findings)

        self.assertFalse(findings[0]["validated"])

    def test_alt_path_does_not_save_findings_without_test_output(self):
        # validated=true but no test_output -> still downgraded; alt-path
        # only applies to the test_output-suspicious case, not the empty case.
        findings: list[dict] = []
        _submit_finding({
            "title": "No test_output supplied",
            "severity": "high",
            "description": "Agent claimed validated with no test output.",
            "impact": "Unprivileged attacker drains vault.",
            "affected_code": [{"file": "/audit/src/Vault.sol", "lines": "10-30"}],
            "validated": True,
            "objective_evaluation": "eval-001",
        }, findings)

        self.assertFalse(findings[0]["validated"])


class FindingReviewGapHintTests(unittest.IsolatedAsyncioTestCase):
    """§4.7 — gap strings carry concrete recovery hints."""

    async def test_root_cause_gap_includes_concrete_recovery_hint(self):
        from reentbotpro.tools import _review_finding_evidence

        container = FakeContainer()
        result = await _review_finding_evidence(container, {
            "title": "Missing fields review",
            "severity": "medium",
            "campaign_ids": ["hyp-001"],
            "evidence": [],
            "affected_code": [],
            "reproduction_steps": [],
            "known_limitations": [],
            "record_result": False,
        })
        joined = " ".join(json.loads(result)["blocking_gaps"])
        # Each augmented gap retains its original key phrase ...
        self.assertIn("missing root cause", joined)
        self.assertIn("missing economic impact", joined)
        self.assertIn("missing affected code references", joined)
        self.assertIn("missing concrete reproduction steps", joined)
        self.assertIn("missing evidence links", joined)
        # ... and carries an inline recovery hint that names the actual field
        # and shows the expected shape.
        self.assertIn("root_cause=", joined)
        self.assertIn("impact=", joined)
        self.assertIn("affected_code=[", joined)
        self.assertIn("reproduction_steps=[", joined)
        self.assertIn("evidence=[", joined)

    async def test_high_impact_objective_warning_explains_recovery(self):
        from reentbotpro.tools import _review_finding_evidence

        container = FakeContainer()
        container.files["/workspace/campaign/results/res-001.log"] = (
            "Test result: ok. 1 passed; 0 failed\n"
        )
        result = await _review_finding_evidence(container, {
            "title": "High candidate without objective evaluation",
            "severity": "high",
            "root_cause": "Detailed root-cause description of the bug pathway.",
            "impact": "Attacker drains full vault USDC balance.",
            "affected_code": [{"file": "/audit/src/Vault.sol", "lines": "42-80"}],
            "reproduction_steps": ["set up", "exploit", "observe"],
            "campaign_ids": ["hyp-001", "exp-001", "res-001"],
            "evidence": ["/workspace/campaign/results/res-001.log"],
            "test_output": "Test result: ok. 1 passed; 0 failed",
            "proof_of_concept": "test/Replay.t.sol",
            "validated": True,
            "capital_required": "$0 attacker capital",
            "trusted_role_required": False,
            "known_limitations": [],
            "record_result": False,
        })
        parsed = json.loads(result)
        joined = " ".join(parsed["warnings"])
        self.assertTrue(parsed["ready"])
        self.assertEqual(parsed["blocking_gaps"], [])
        # The high/critical objective gap names BOTH alternative paths and
        # the exact tools to call.
        self.assertIn("snapshot_state", joined)
        self.assertIn("compare_snapshots", joined)
        self.assertIn("evaluate_objective", joined)
        self.assertIn("run_sequence_minimization", joined)


_ADDR_A = "0x" + "a1" * 20
_ADDR_B = "0x" + "b2" * 20
_TX_HASH = "0x" + "cd" * 32
_KEY = "SECRET-ALCHEMY-KEY"


class AlchemyRedactionTests(unittest.TestCase):
    def test_redact_scrubs_key_everywhere(self):
        payload = {
            "url": f"https://eth-mainnet.g.alchemy.com/v2/{_KEY}",
            "nested": [_KEY, {"k": f"x-{_KEY}-y"}],
            "n": 1,
        }
        redacted = _redact_alchemy(payload, _KEY)
        self.assertNotIn(_KEY, json.dumps(redacted))
        self.assertEqual(redacted["n"], 1)
        self.assertIn("<alchemy-key>", redacted["url"])

    def test_redact_noop_without_key(self):
        self.assertEqual(_redact_alchemy({"a": 1}, None), {"a": 1})


class AlchemyToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_alchemy_runtime()
        set_alchemy_runtime(_KEY, "eth-mainnet")

    def tearDown(self):
        reset_alchemy_runtime()

    @staticmethod
    def _http(*responses):
        """An AsyncMock for _alchemy_http_post yielding (status, body) tuples."""
        if len(responses) == 1:
            return mock.AsyncMock(return_value=responses[0])
        return mock.AsyncMock(side_effect=list(responses))

    async def test_trace_onchain_tx_success_writes_redacted_artifact(self):
        container = FakeContainer()
        frame = {
            "type": "CALL", "from": _ADDR_A, "to": _ADDR_B,
            "value": "0x0", "gasUsed": "0x5208",
            # Deliberately embed the key in the result to prove redaction.
            "leak": f"https://eth-mainnet.g.alchemy.com/v2/{_KEY}",
            "calls": [{"type": "CALL", "to": _ADDR_A, "input": "0xa9059cbb" + "0" * 8}],
        }
        http = self._http((200, {"jsonrpc": "2.0", "id": 1, "result": frame}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["method"], "debug_traceTransaction")
        self.assertEqual(digest["subcall_count"], 1)
        self.assertTrue(digest["artifact"].startswith("/workspace/campaign/probes/"))
        # The request URL carries the real key; nothing returned or persisted does.
        self.assertIn(_KEY, http.call_args.args[0])
        self.assertNotIn(_KEY, out)
        self.assertIn(digest["artifact"], container.files)
        self.assertNotIn(_KEY, container.files[digest["artifact"]])

    async def test_simulate_call_builds_debug_tracecall_params(self):
        container = FakeContainer()
        http = self._http((200, {"result": {"type": "CALL", "to": _ADDR_B, "gasUsed": "0x1", "calls": []}}))
        overrides = {_ADDR_B: {"balance": "0x1"}}
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "simulate_call",
                {"to": _ADDR_B, "data": "0xabcd", "block": "0x10", "state_overrides": overrides},
                container, [],
            )
        self.assertTrue(json.loads(out)["ok"])
        payload = http.call_args.args[1]
        self.assertEqual(payload["method"], "debug_traceCall")
        self.assertEqual(payload["params"][0]["to"], _ADDR_B)
        self.assertEqual(payload["params"][0]["data"], "0xabcd")
        self.assertEqual(payload["params"][1], "0x10")
        self.assertEqual(payload["params"][2]["tracer"], "callTracer")
        self.assertEqual(payload["params"][2]["stateOverrides"], overrides)

    async def test_not_configured_returns_clean_digest_without_calling_http(self):
        reset_alchemy_runtime()  # no key
        container = FakeContainer()
        http = self._http((200, {"result": {}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("get_token_info", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "alchemy_not_configured")
        self.assertIn("fallback", digest)
        http.assert_not_called()

    async def test_403_degrades_and_caches_per_family(self):
        container = FakeContainer()
        http = self._http((403, {"error": {"message": "forbidden"}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out1 = await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
            # Same family (trace_debug) + network: must short-circuit, no 2nd call.
            out2 = await execute_tool("simulate_call", {"to": _ADDR_B}, container, [])
        d1, d2 = json.loads(out1), json.loads(out2)
        self.assertTrue(d1.get("degraded"))
        self.assertEqual(d1["error"], "unavailable")
        self.assertTrue(d2.get("degraded"))
        self.assertEqual(http.call_count, 1)

    async def test_rpc_error_marker_degrades(self):
        container = FakeContainer()
        body = {"error": {"code": -32601, "message": "trace_filter is not available on your tier"}}
        http = self._http((200, body))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "enumerate_callers",
                {"address": _ADDR_A, "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        digest = json.loads(out)
        self.assertTrue(digest.get("degraded"))
        self.assertEqual(digest["error"], "unavailable")

    async def test_plain_rpc_error_is_not_degraded(self):
        container = FakeContainer()
        body = {"error": {"code": -32602, "message": "invalid argument: bad block"}}
        http = self._http((200, body))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("state_diff", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "rpc_error")
        self.assertNotIn("degraded", digest)

    async def test_network_alias_resolves_to_subdomain(self):
        container = FakeContainer()
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "network": "base"}, container, []
            )
        digest = json.loads(out)
        self.assertEqual(digest["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", http.call_args.args[0])

    async def test_default_network_follows_record_fork_context(self):
        container = FakeContainer()
        prefix = _CAMPAIGN_ID_PREFIXES["fork_context"]
        container.files["/workspace/campaign/state.json"] = json.dumps(
            {"counters": {"fork_context": 1}, "sections": {}}
        )
        container.files[f"/workspace/campaign/fork-contexts/{prefix}-001.json"] = json.dumps(
            {"network": "arbitrum", "chain_id": 42161}
        )
        http = self._http((200, {"result": {"type": "CALL", "to": _ADDR_B, "calls": []}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            # No network arg -> inherit the chain recorded in record_fork_context.
            out = await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["network"], "arb-mainnet")
        self.assertIn("arb-mainnet.g.alchemy.com", http.call_args.args[0])

    async def test_run_level_default_chain_is_overridden_per_call(self):
        # A configured run-level default chain (from --chain / default_chain) is
        # only a fallback, never a lock: an explicit per-call network for a
        # DIFFERENT chain still wins, so a multi-chain scope is not pinned.
        reset_alchemy_runtime()
        set_alchemy_runtime(_KEY, "base-mainnet")  # run-level default = Base
        container = FakeContainer()
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "network": "arbitrum"}, container, []
            )
        digest = json.loads(out)
        self.assertEqual(digest["network"], "arb-mainnet")
        self.assertIn("arb-mainnet.g.alchemy.com", http.call_args.args[0])

    async def test_cu_usage_accounted_on_success(self):
        container = FakeContainer()
        http = self._http((200, {"result": {"type": "CALL", "to": _ADDR_B, "calls": []}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
        self.assertEqual(host_tools_mod._ALCHEMY_USAGE["cu"], 40)
        self.assertEqual(host_tools_mod._ALCHEMY_USAGE["calls"], 1)

    async def test_bad_arguments_rejected_before_http(self):
        container = FakeContainer()
        http = self._http((200, {"result": {}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            bad_hash = await execute_tool("trace_onchain_tx", {"tx_hash": "0x123"}, container, [])
            missing_to = await execute_tool("simulate_call", {}, container, [])
            missing_block = await execute_tool(
                "enumerate_callers", {"address": _ADDR_A}, container, []
            )
        self.assertEqual(json.loads(bad_hash)["error"], "bad_arguments")
        self.assertEqual(json.loads(missing_to)["error"], "bad_arguments")
        self.assertEqual(json.loads(missing_block)["error"], "bad_arguments")
        http.assert_not_called()

    async def test_get_asset_transfers_both_directions_merges_two_calls(self):
        container = FakeContainer()
        t_out = {"from": _ADDR_A, "to": _ADDR_B, "asset": "WETH", "hash": "0x" + "11" * 32,
                 "value": 1.5, "category": "erc20", "blockNum": "0x1"}
        t_in = {"from": _ADDR_B, "to": _ADDR_A, "asset": "ETH", "hash": "0x" + "22" * 32,
                "value": 2.0, "category": "external", "blockNum": "0x2"}
        http = self._http(
            (200, {"result": {"transfers": [t_out], "pageKey": ""}}),
            (200, {"result": {"transfers": [t_in], "pageKey": ""}}),
        )
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_asset_transfers", {"address": _ADDR_A, "direction": "both"}, container, []
            )
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["transfer_count"], 2)
        self.assertEqual(http.call_count, 2)
        self.assertEqual(http.call_args_list[0].args[1]["params"][0]["fromAddress"], _ADDR_A)
        self.assertEqual(http.call_args_list[1].args[1]["params"][0]["toAddress"], _ADDR_A)

    async def test_get_token_prices_uses_prices_host_and_parses_usd(self):
        container = FakeContainer()
        body = {"data": [{"network": "eth-mainnet", "address": _ADDR_A,
                          "prices": [{"currency": "USD", "value": "1.00"}]}]}
        http = self._http((200, body))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("get_token_prices", {"addresses": [_ADDR_A]}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["prices_usd"][_ADDR_A], "1.00")
        url = http.call_args.args[0]
        self.assertTrue(url.startswith("https://api.g.alchemy.com/prices/v1/"))
        self.assertNotIn(_KEY, out)

    async def test_simulate_sequence_bundle_params_and_summary(self):
        container = FakeContainer()
        body = {"result": [
            {"changes": [{"assetType": "NATIVE", "changeType": "TRANSFER",
                          "from": _ADDR_A, "to": _ADDR_B, "amount": "1", "symbol": "ETH"}]},
            {"changes": []},
        ]}
        http = self._http((200, body))
        txs = [{"from": _ADDR_A, "to": _ADDR_B, "value": "0x1"}, {"from": _ADDR_B, "to": _ADDR_A}]
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("simulate_sequence", {"transactions": txs}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["tx_count"], 2)
        self.assertEqual(digest["result_count"], 2)
        payload = http.call_args.args[1]
        self.assertEqual(payload["method"], "alchemy_simulateAssetChangesBundle")
        self.assertEqual(len(payload["params"]), 2)
        self.assertEqual(payload["params"][0]["to"], _ADDR_B)

    async def test_state_diff_summarizes_changed_addresses(self):
        container = FakeContainer()
        result = {"trace": [], "stateDiff": {
            _ADDR_A: {"storage": {"0x0": {}, "0x1": {}}, "balance": {"*": {}}, "nonce": "=", "code": "="},
            _ADDR_B: {"storage": {}, "balance": "=", "nonce": "=", "code": "="},
        }}
        http = self._http((200, {"result": result}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("state_diff", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["changed_addresses"], 2)
        top = digest["top_changes"][0]
        self.assertEqual(top["address"], _ADDR_A)
        self.assertEqual(top["storage_slots_changed"], 2)
        self.assertTrue(top["balance_changed"])

    async def test_request_failure_is_caught_and_redacted(self):
        container = FakeContainer()
        boom = mock.AsyncMock(side_effect=RuntimeError(f"connect to .../v2/{_KEY} failed"))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=boom):
            out = await execute_tool("get_token_info", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "request_failed")
        self.assertNotIn(_KEY, out)

    async def test_invalid_network_reported_cleanly(self):
        container = FakeContainer()
        http = self._http((200, {"result": {}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "network": "bad.host"}, container, []
            )
        self.assertEqual(json.loads(out)["error"], "invalid_network")
        http.assert_not_called()


_ETHERSCAN_KEY = "SECRET-ETHERSCAN-KEY"


class EtherscanToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_etherscan_runtime()
        set_etherscan_runtime(_ETHERSCAN_KEY)
        # The Etherscan chain id is now resolved, not defaulted to 1. These tests
        # model a run whose default chain is Ethereum mainnet (set via the shared
        # Alchemy runtime, where the CLI records the run default), so a
        # no-network get_contract_source resolves to mainnet intentionally.
        reset_alchemy_runtime()
        set_alchemy_runtime(_KEY, "eth-mainnet")

    def tearDown(self):
        reset_etherscan_runtime()
        reset_alchemy_runtime()

    @staticmethod
    def _http(*responses):
        if len(responses) == 1:
            return mock.AsyncMock(return_value=responses[0])
        return mock.AsyncMock(side_effect=list(responses))

    @staticmethod
    def _ok(result):
        return (200, {"status": "1", "message": "OK", "result": result})

    async def test_verified_source_writes_redacted_artifact_on_mainnet(self):
        container = FakeContainer()
        result = [{
            # Embed the key in the source to prove redaction reaches the artifact.
            "SourceCode": f"// {_ETHERSCAN_KEY}\ncontract Vault {{}}",
            "ABI": "[{\"type\":\"function\"}]",
            "ContractName": "Vault",
            "CompilerVersion": "v0.8.20+commit",
            "Proxy": "0", "Implementation": "", "LicenseType": "MIT",
        }]
        http = self._http(self._ok(result))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertTrue(digest["is_verified"])
        self.assertEqual(digest["contract_name"], "Vault")
        self.assertEqual(digest["chain_id"], 1)  # default mainnet
        self.assertFalse(digest["is_proxy"])
        # Request shape
        params = http.call_args.args[1]
        self.assertEqual(params["chainid"], 1)
        self.assertEqual(params["action"], "getsourcecode")
        self.assertEqual(params["apikey"], _ETHERSCAN_KEY)
        # Artifact written + key redacted everywhere visible.
        self.assertTrue(digest["artifact"].startswith("/workspace/campaign/probes/"))
        self.assertIn(digest["artifact"], container.files)
        self.assertNotIn(_ETHERSCAN_KEY, out)
        self.assertNotIn(_ETHERSCAN_KEY, container.files[digest["artifact"]])

    async def test_unverified_contract_reports_cleanly(self):
        container = FakeContainer()
        result = [{"SourceCode": "", "ABI": "Contract source code not verified"}]
        http = self._http(self._ok(result))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertFalse(digest["is_verified"])
        self.assertNotIn("artifact", digest)

    async def test_proxy_follows_implementation(self):
        container = FakeContainer()
        proxy = [{"SourceCode": "contract Proxy {}", "ABI": "[]", "ContractName": "Proxy",
                  "CompilerVersion": "v0.8.20", "Proxy": "1", "Implementation": _ADDR_B}]
        impl = [{"SourceCode": "contract Logic {}", "ABI": "[]", "ContractName": "Logic",
                 "CompilerVersion": "v0.8.20", "Proxy": "0", "Implementation": ""}]
        http = self._http(self._ok(proxy), self._ok(impl))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertTrue(digest["is_proxy"])
        self.assertEqual(digest["implementation"], _ADDR_B)
        self.assertEqual(digest["implementation_source"]["contract_name"], "Logic")
        self.assertEqual(http.call_count, 2)
        self.assertEqual(http.call_args_list[1].args[1]["address"], _ADDR_B)

    async def test_not_configured_returns_clean_digest(self):
        reset_etherscan_runtime()  # no key
        container = FakeContainer()
        http = self._http(self._ok([{}]))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        self.assertEqual(json.loads(out)["error"], "etherscan_not_configured")
        http.assert_not_called()

    async def test_network_maps_to_chainid(self):
        container = FakeContainer()
        http = self._http(self._ok([{"SourceCode": "contract X {}", "ABI": "[]",
                                     "ContractName": "X", "CompilerVersion": "v0.8.20", "Proxy": "0"}]))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool(
                "get_contract_source", {"address": _ADDR_A, "network": "arbitrum"}, container, []
            )
        self.assertEqual(json.loads(out)["chain_id"], 42161)
        self.assertEqual(http.call_args.args[1]["chainid"], 42161)

    async def test_paywall_degrades_and_caches(self):
        container = FakeContainer()
        http = self._http(
            (200, {"status": "0", "message": "NOTOK",
                   "result": "Upgrade to a paid plan to use this endpoint"})
        )
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out1 = await execute_tool(
                "get_contract_source", {"address": _ADDR_A, "network": "base"}, container, []
            )
            out2 = await execute_tool(
                "get_contract_source", {"address": _ADDR_B, "network": "base"}, container, []
            )
        d1, d2 = json.loads(out1), json.loads(out2)
        self.assertTrue(d1.get("degraded"))
        self.assertTrue(d2.get("degraded"))
        self.assertEqual(http.call_count, 1)  # second call short-circuits on cached chain

    async def test_invalid_network_rejected(self):
        container = FakeContainer()
        http = self._http(self._ok([{}]))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool(
                "get_contract_source", {"address": _ADDR_A, "network": "nope.bad"}, container, []
            )
        self.assertEqual(json.loads(out)["error"], "invalid_network")
        http.assert_not_called()

    async def test_default_chain_follows_fork_context(self):
        container = FakeContainer()
        prefix = _CAMPAIGN_ID_PREFIXES["fork_context"]
        container.files["/workspace/campaign/state.json"] = json.dumps(
            {"counters": {"fork_context": 1}, "sections": {}}
        )
        container.files[f"/workspace/campaign/fork-contexts/{prefix}-001.json"] = json.dumps(
            {"network": "base", "chain_id": 8453}
        )
        http = self._http(self._ok([{"SourceCode": "contract X {}", "ABI": "[]",
                                     "ContractName": "X", "CompilerVersion": "v0.8.20", "Proxy": "0"}]))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        self.assertEqual(json.loads(out)["chain_id"], 8453)


class HostToolChainResolutionTests(unittest.IsolatedAsyncioTestCase):
    """Host-side Alchemy/Etherscan tools resolve the target chain from campaign
    signals — explicit args, fork context, chain-registry binding, run default —
    and never silently fall back to Ethereum mainnet when no chain is inferred."""

    def setUp(self):
        reset_alchemy_runtime()
        reset_etherscan_runtime()

    def tearDown(self):
        reset_alchemy_runtime()
        reset_etherscan_runtime()

    @staticmethod
    def _http(*responses):
        if len(responses) == 1:
            return mock.AsyncMock(return_value=responses[0])
        return mock.AsyncMock(side_effect=list(responses))

    @staticmethod
    async def _write_registry(container, chains):
        await _write_chain_registry(container, {
            "chain_registry_id": "chainreg-001",
            "chains": chains, "ambiguous": [], "notes": [],
        })

    @staticmethod
    def _record_fork(container, *, network, chain_id):
        prefix = _CAMPAIGN_ID_PREFIXES["fork_context"]
        container.files["/workspace/campaign/state.json"] = json.dumps(
            {"counters": {"fork_context": 1}, "sections": {}}
        )
        container.files[f"/workspace/campaign/fork-contexts/{prefix}-001.json"] = json.dumps(
            {"network": network, "chain_id": chain_id}
        )

    # ── A. No chain inferred -> chain_not_inferred, no request made ──────────

    async def test_trace_onchain_tx_no_chain_returns_chain_not_inferred(self):
        set_alchemy_runtime(_KEY, None)  # key configured, but no run-default chain
        container = FakeContainer()
        http = self._http((200, {"result": {}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "chain_not_inferred")
        self.assertEqual(digest["tool"], "trace_onchain_tx")
        http.assert_not_called()

    async def test_get_contract_source_no_chain_returns_chain_not_inferred(self):
        set_etherscan_runtime(_ETHERSCAN_KEY)  # etherscan key, but no run-default chain
        container = FakeContainer()
        http = self._http((200, {"status": "1", "message": "OK", "result": [{}]}))
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "chain_not_inferred")
        http.assert_not_called()

    async def test_observed_tx_miner_no_chain_returns_chain_not_inferred(self):
        set_alchemy_runtime(_KEY, None)
        container = FakeContainer()
        http = self._http((200, {"result": []}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        digest = json.loads(out)
        self.assertEqual(digest["error"], "chain_not_inferred")
        http.assert_not_called()

    # ── B. Explicit chain selection always wins ─────────────────────────────

    async def test_explicit_chain_id_selects_base(self):
        set_alchemy_runtime(_KEY, "eth-mainnet")  # run default mainnet; explicit id wins
        container = FakeContainer()
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "chain_id": 8453}, container, []
            )
        digest = json.loads(out)
        self.assertEqual(digest["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", http.call_args.args[0])

    async def test_explicit_eth_mainnet_is_intentional(self):
        set_alchemy_runtime(_KEY, "base-mainnet")  # run default base; explicit mainnet wins
        container = FakeContainer()
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "network": "eth-mainnet"}, container, []
            )
        digest = json.loads(out)
        self.assertEqual(digest["network"], "eth-mainnet")
        self.assertIn("eth-mainnet.g.alchemy.com", http.call_args.args[0])

    # ── C. Run-level default chain ──────────────────────────────────────────

    async def test_run_default_chain_drives_host_tool(self):
        set_alchemy_runtime(_KEY, "base-mainnet")
        container = FakeContainer()
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("get_token_info", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", http.call_args.args[0])

    # ── D. Latest recorded fork context (beats run default) ─────────────────

    async def test_latest_fork_context_drives_host_tool(self):
        set_alchemy_runtime(_KEY, "eth-mainnet")  # run default mainnet; fork context wins
        container = FakeContainer()
        self._record_fork(container, network="base", chain_id=8453)
        http = self._http((200, {"result": {"type": "CALL", "to": _ADDR_B, "calls": []}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("trace_onchain_tx", {"tx_hash": _TX_HASH}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", http.call_args.args[0])

    # ── E. Chain-registry target binding (beats run default) ────────────────

    async def test_registry_single_chain_binds_target(self):
        set_alchemy_runtime(_KEY, "eth-mainnet")  # run default mainnet; registry binding wins
        container = FakeContainer()
        await self._write_registry(container, [
            {"network": "base-mainnet", "chain_id": 8453,
             "deployments": [{"address": _ADDR_A, "name": "Vault"}]},
        ])
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("get_token_info", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", http.call_args.args[0])

    async def test_registry_multi_chain_target_is_ambiguous(self):
        set_alchemy_runtime(_KEY, "eth-mainnet")
        container = FakeContainer()
        await self._write_registry(container, [
            {"network": "base-mainnet", "chain_id": 8453,
             "deployments": [{"address": _ADDR_A, "name": "Vault"}]},
            {"network": "arb-mainnet", "chain_id": 42161,
             "deployments": [{"address": _ADDR_A, "name": "Vault"}]},
        ])
        http = self._http((200, {"result": {}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool("get_token_info", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["error"], "chain_ambiguous")
        chains = {(c["network"], c["chain_id"]) for c in digest["candidates"]}
        self.assertEqual(chains, {("base-mainnet", 8453), ("arb-mainnet", 42161)})
        http.assert_not_called()

    async def test_explicit_chain_resolves_registry_ambiguity(self):
        set_alchemy_runtime(_KEY, "eth-mainnet")
        container = FakeContainer()
        await self._write_registry(container, [
            {"network": "base-mainnet", "chain_id": 8453, "deployments": [{"address": _ADDR_A}]},
            {"network": "arb-mainnet", "chain_id": 42161, "deployments": [{"address": _ADDR_A}]},
        ])
        http = self._http((200, {"result": {"name": "X", "symbol": "X", "decimals": 18}}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_info", {"address": _ADDR_A, "network": "arbitrum"}, container, []
            )
        digest = json.loads(out)
        self.assertEqual(digest["network"], "arb-mainnet")
        self.assertIn("arb-mainnet.g.alchemy.com", http.call_args.args[0])

    # ── F. Etherscan chain id is inferred, not defaulted to 1 ───────────────

    async def test_etherscan_uses_inferred_base_chainid(self):
        set_etherscan_runtime(_ETHERSCAN_KEY)
        set_alchemy_runtime(_KEY, "base-mainnet")  # run default base
        container = FakeContainer()
        body = (200, {"status": "1", "message": "OK", "result": [
            {"SourceCode": "contract X {}", "ABI": "[]", "ContractName": "X",
             "CompilerVersion": "v0.8.20", "Proxy": "0"}]})
        http = self._http(body)
        with mock.patch.object(host_tools_mod, "_etherscan_http_get", new=http):
            out = await execute_tool("get_contract_source", {"address": _ADDR_A}, container, [])
        digest = json.loads(out)
        self.assertEqual(digest["chain_id"], 8453)
        self.assertEqual(http.call_args.args[1]["chainid"], 8453)

    # ── Per-token-network price calls need no single default chain ──────────

    async def test_get_token_prices_per_token_networks_need_no_default(self):
        set_alchemy_runtime(_KEY, None)  # no run default; per-token networks suffice
        container = FakeContainer()
        body = {"data": [{"network": "base-mainnet", "address": _ADDR_A,
                          "prices": [{"currency": "USD", "value": "2.50"}]}]}
        http = self._http((200, body))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "get_token_prices",
                {"tokens": [{"network": "base", "address": _ADDR_A}]},
                container, [],
            )
        digest = json.loads(out)
        self.assertEqual(digest["prices_usd"][_ADDR_A], "2.50")
        http.assert_called_once()


def _transfer_calldata(recipient_hex_body: str, amount: int) -> str:
    """ABI-encoded transfer(address,uint256) calldata for tests."""
    return (
        "0xa9059cbb"
        + "0" * 24 + recipient_hex_body  # address left-padded to 32 bytes
        + format(amount, "064x")          # uint256
    )


class ObservedTxKeccakTests(unittest.TestCase):
    """Pin the pure-Python keccak-256 + selector derivation (no eth dep in venv)."""

    def test_keccak256_known_vectors(self):
        self.assertEqual(
            host_tools_mod._keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            host_tools_mod._keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_function_selectors_match_canonical_signatures(self):
        cases = {
            "transfer(address,uint256)": "0xa9059cbb",
            "approve(address,uint256)": "0x095ea7b3",
            "balanceOf(address)": "0x70a08231",
            "swap(uint256,uint256,address,bytes)": "0x022c0d9f",
        }
        for signature, expected in cases.items():
            self.assertEqual(host_tools_mod._function_selector(signature), expected)

    def test_abi_index_accepts_entry_dicts_and_signature_strings(self):
        idx = host_tools_mod._abi_selector_index([
            {"type": "function", "name": "transfer",
             "inputs": [{"type": "address"}, {"type": "uint256"}]},
            "approve(address,uint256)",
            {"type": "event", "name": "Transfer"},  # ignored (not a function)
            "garbage-not-a-signature",               # ignored
        ])
        self.assertEqual(idx["0xa9059cbb"]["signature"], "transfer(address,uint256)")
        self.assertEqual(idx["0xa9059cbb"]["input_types"], ["address", "uint256"])
        self.assertIn("0x095ea7b3", idx)

    def test_abi_index_expands_tuple_components(self):
        idx = host_tools_mod._abi_selector_index([{
            "type": "function", "name": "exactInput",
            "inputs": [{"type": "tuple", "components": [
                {"type": "bytes"}, {"type": "address"}, {"type": "uint256"}]}],
        }])
        (meta,) = idx.values()
        self.assertEqual(meta["signature"], "exactInput((bytes,address,uint256))")

    def test_resolve_target_selector_paths(self):
        idx = host_tools_mod._abi_selector_index(["transfer(address,uint256)"])
        self.assertEqual(
            host_tools_mod._resolve_target_selector(None, "0xA9059CBB", idx),
            ("0xa9059cbb", None),
        )
        self.assertEqual(
            host_tools_mod._resolve_target_selector("transfer(address,uint256)", None, {}),
            ("0xa9059cbb", None),
        )
        self.assertEqual(
            host_tools_mod._resolve_target_selector("transfer", None, idx),
            ("0xa9059cbb", None),
        )
        sel, err = host_tools_mod._resolve_target_selector("unknownFn", None, idx)
        self.assertIsNone(sel)
        self.assertIn("could not resolve", err)
        sel, err = host_tools_mod._resolve_target_selector(None, "0x12", idx)
        self.assertIsNone(sel)
        self.assertIn("4-byte", err)
        # ABI-only (observe-everything) is not an error.
        self.assertEqual(host_tools_mod._resolve_target_selector(None, None, idx), (None, None))

    def test_decode_calldata_static_head_types(self):
        calldata = _transfer_calldata("b2" * 20, 1234)
        decoded = host_tools_mod._decode_calldata(calldata, ["address", "uint256"])
        self.assertEqual(decoded[0], {"type": "address", "value": "0x" + "b2" * 20})
        self.assertEqual(decoded[1], {"type": "uint256", "value": "1234"})

    def test_decode_calldata_dynamic_type_surfaces_offset_word(self):
        decoded = host_tools_mod._decode_calldata("0xabcd1234" + "00" * 32, ["bytes"])
        self.assertEqual(decoded[0]["type"], "bytes")
        self.assertIn("head", decoded[0])
        self.assertNotIn("value", decoded[0])


class ObservedTxMinerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_alchemy_runtime()
        set_alchemy_runtime(_KEY, "eth-mainnet")

    def tearDown(self):
        reset_alchemy_runtime()

    @staticmethod
    def _http(*responses):
        return mock.AsyncMock(side_effect=list(responses))

    @staticmethod
    def _trace_filter_body(traces):
        return (200, {"jsonrpc": "2.0", "id": 1, "result": traces})

    @staticmethod
    def _transfers_body(transfers):
        return (200, {"result": {"transfers": transfers, "pageKey": ""}})

    @staticmethod
    def _call_trace_body(frame):
        return (200, {"result": frame})

    def _matching_trace(self, *, selector_calldata, tx_hash=_TX_HASH, frm=_ADDR_A,
                        to=_ADDR_B, block=200, error=None, trace_address=None):
        action = {"from": frm, "to": to, "input": selector_calldata,
                  "value": "0x0", "callType": "call"}
        trace = {"action": action, "blockNumber": block, "transactionHash": tx_hash,
                 "traceAddress": [] if trace_address is None else trace_address, "type": "call"}
        if error:
            trace["error"] = error
        return trace

    async def test_not_configured_returns_unavailable_without_http(self):
        reset_alchemy_runtime()  # no key
        container = FakeContainer()
        http = self._http((200, {"result": []}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        digest = json.loads(out)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], "unavailable")
        self.assertTrue(digest["blockers"])
        self.assertIn("fallback", digest)
        self.assertEqual(digest["samples"], [])
        http.assert_not_called()

    async def test_requires_target_identifier(self):
        container = FakeContainer()
        http = self._http((200, {"result": []}))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        self.assertEqual(json.loads(out)["error"], "bad_arguments")
        http.assert_not_called()

    async def test_mines_samples_decodes_args_and_writes_redacted_artifact(self):
        container = FakeContainer()
        calldata = _transfer_calldata("b2" * 20, 5_000_000)
        traces = [
            self._matching_trace(selector_calldata=calldata),
            # Different selector to the same address must be filtered out.
            self._matching_trace(selector_calldata="0xdeadbeef" + "00" * 32,
                                  tx_hash="0x" + "ee" * 32, block=150),
        ]
        transfer_row = {"from": _ADDR_A, "to": _ADDR_B, "asset": "USDC",
                        "value": 5.0, "category": "erc20", "hash": _TX_HASH,
                        # Embed the key to prove redaction reaches transfers too.
                        "rawContract": {"address": f"https://eth-mainnet.g.alchemy.com/v2/{_KEY}"}}
        sub_frame = {"type": "CALL", "to": _ADDR_B, "calls": [
            {"type": "CALL", "to": _ADDR_A, "input": "0x23b872dd" + "00" * 32},  # transferFrom
        ]}
        http = self._http(
            self._trace_filter_body(traces),
            self._transfers_body([transfer_row]),   # fromAddress sweep
            self._transfers_body([]),                # toAddress sweep
            self._call_trace_body(sub_frame),        # debug_traceTransaction for the sample
        )
        abi = [{"type": "function", "name": "transfer",
                "inputs": [{"type": "address"}, {"type": "uint256"}]}]
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "function": "transfer", "abi": abi,
                 "from_block": "0x10", "to_block": "0x3000",
                 "action_space": "as-001"},
                container, [],
            )
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], "observed")
        self.assertEqual(digest["selector"], "0xa9059cbb")
        self.assertEqual(digest["observed_tx_miner_id"], "otx-001")
        self.assertEqual(digest["action_space"], "as-001")

        # Exactly one sample: the matching-selector tx (the other was filtered).
        self.assertEqual(len(digest["samples"]), 1)
        sample = digest["samples"][0]
        self.assertEqual(sample["tx_hash"], _TX_HASH)
        self.assertEqual(sample["function"], "transfer(address,uint256)")
        self.assertEqual(sample["arg_shape"], ["address", "uint256"])
        self.assertEqual(sample["args"][0]["value"], "0x" + "b2" * 20)
        self.assertEqual(sample["args"][1]["value"], "5000000")
        # Subcall trace surfaced the transferFrom precondition hint.
        self.assertTrue(any("transferFrom" in h for h in sample["precondition_hints"]))
        # Replay hints carry the fork-replay primitives.
        self.assertEqual(sample["replay_hints"]["impersonate"], _ADDR_A)
        self.assertEqual(sample["replay_hints"]["fork_block"], 200)

        # synthesize/compose hints reference the selector + actor.
        self.assertEqual(digest["synthesize_args_hints"]["primary_selector"], "0xa9059cbb")
        self.assertIn(_ADDR_A, digest["compose_sequence_hints"]["actors"])

        # Artifact written under the campaign observed-txs dir, fully redacted.
        path = digest["path"]
        self.assertTrue(path.startswith("/workspace/campaign/observed-txs/"))
        self.assertIn(path, container.files)
        self.assertNotIn(_KEY, container.files[path])
        self.assertNotIn(_KEY, out)
        # State counter advanced so a second run is otx-002.
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["counters"]["observed_tx"], 1)

    async def test_selector_only_without_abi_reports_raw_arg_shape(self):
        container = FakeContainer()
        calldata = _transfer_calldata("b2" * 20, 7)
        traces = [self._matching_trace(selector_calldata=calldata)]
        http = self._http(
            self._trace_filter_body(traces),
            self._call_trace_body({"type": "CALL", "to": _ADDR_B, "calls": []}),
        )
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20",
                 "include_transfers": False},
                container, [],
            )
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        sample = digest["samples"][0]
        self.assertIsNone(sample["function"])
        self.assertIsNone(sample["arg_shape"])
        # 2 ABI words (address + uint256) inferred from raw calldata length.
        self.assertEqual(sample["raw_arg_word_count"], 2)

    async def test_full_signature_decodes_without_separate_abi(self):
        container = FakeContainer()
        calldata = _transfer_calldata("b2" * 20, 42)
        traces = [self._matching_trace(selector_calldata=calldata)]
        http = self._http(
            self._trace_filter_body(traces),
            self._call_trace_body({"type": "CALL", "to": _ADDR_B, "calls": []}),
        )
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "function": "transfer(address,uint256)",
                 "from_block": "0x10", "to_block": "0x20", "include_transfers": False},
                container, [],
            )
        sample = json.loads(out)["samples"][0]
        self.assertEqual(sample["function"], "transfer(address,uint256)")
        self.assertEqual(sample["args"][1]["value"], "42")

    async def test_trace_filter_unavailable_degrades_cleanly(self):
        container = FakeContainer()
        body = {"error": {"code": -32601, "message": "trace_filter is not available on your tier"}}
        http = self._http((200, body))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        digest = json.loads(out)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], "unavailable")
        self.assertIn("fallback", digest)
        self.assertEqual(http.call_count, 1)  # no enrichment after the gate fails

    async def test_no_matching_transactions_is_partial_with_blocker(self):
        container = FakeContainer()
        traces = [self._matching_trace(selector_calldata="0xdeadbeef" + "00" * 32)]
        http = self._http(self._trace_filter_body(traces))
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20"},
                container, [],
            )
        digest = json.loads(out)
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["status"], "partial")
        self.assertEqual(digest["samples"], [])
        self.assertTrue(any("no transactions matched" in b for b in digest["blockers"]))

    async def test_default_block_window_resolves_via_blocknumber(self):
        container = FakeContainer()
        calldata = _transfer_calldata("b2" * 20, 1)
        traces = [self._matching_trace(selector_calldata=calldata)]
        http = self._http(
            (200, {"result": hex(1_000_000)}),     # eth_blockNumber
            self._trace_filter_body(traces),
            self._call_trace_body({"type": "CALL", "to": _ADDR_B, "calls": []}),
        )
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb", "include_transfers": False},
                container, [],
            )
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        # Window is [head - 50000, head]; first call is eth_blockNumber.
        self.assertEqual(http.call_args_list[0].args[1]["method"], "eth_blockNumber")
        self.assertEqual(digest["to_block"], hex(1_000_000))
        self.assertEqual(digest["from_block"], hex(1_000_000 - 50_000))

    async def test_partial_when_traces_unavailable_but_filter_succeeds(self):
        container = FakeContainer()
        calldata = _transfer_calldata("b2" * 20, 9)
        traces = [self._matching_trace(selector_calldata=calldata)]
        http = self._http(
            self._trace_filter_body(traces),
            # debug_traceTransaction degrades (callTracer not on this tier).
            (200, {"error": {"code": -32601, "message": "debug_traceTransaction is not supported"}}),
        )
        with mock.patch.object(host_tools_mod, "_alchemy_http_post", new=http):
            out = await execute_tool(
                "observed_tx_miner",
                {"address": _ADDR_B, "selector": "0xa9059cbb",
                 "from_block": "0x10", "to_block": "0x20", "include_transfers": False},
                container, [],
            )
        digest = json.loads(out)
        self.assertTrue(digest["ok"])
        self.assertEqual(digest["status"], "partial")
        self.assertEqual(len(digest["samples"]), 1)  # sample still produced
        self.assertTrue(any("traces unavailable" in b for b in digest["blockers"]))


class SynthesizeArgsTests(unittest.IsolatedAsyncioTestCase):
    def _param(self, name: str, type_str: str) -> dict:
        return {"raw": f"{type_str} {name}", "name": name}

    async def test_withdraw_shares_receiver_owner_plan(self):
        # Heuristic 1+2: ERC4626-style withdraw -> shares uses vault balance,
        # receiver/owner default to attacker, and the shares-holding setup
        # requirement is surfaced.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {
                "contract": "Vault",
                "function": "withdraw",
                "parameters": [
                    self._param("shares", "uint256"),
                    self._param("receiver", "address"),
                    self._param("owner", "address"),
                ],
            },
        })
        result = json.loads(out)

        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["signature"], "withdraw(uint256,address,address)")
        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertEqual(plan["receiver"]["candidates"], ["attacker"])
        self.assertEqual(plan["owner"]["candidates"], ["attacker"])
        self.assertIn("vault.balanceOf(attacker)", plan["shares"]["candidates"])
        self.assertTrue(
            any("shares" in req.lower() for req in plan["shares"]["setup_requirements"]),
            plan["shares"]["setup_requirements"],
        )
        # The primary candidate call reads like withdraw(shares, attacker, attacker).
        self.assertEqual(
            result["candidate_calls"][0]["args"],
            ["shares", "attacker", "attacker"],
        )
        self.assertEqual(result["blockers"], [])
        # Per-parameter assignment intent is preserved so the non-inline shares
        # expression can be materialized through a scenario variable downstream.
        assignments = {
            item["name"]: item
            for item in result["candidate_calls"][0]["assignments"]
        }
        self.assertEqual(
            assignments["shares"]["expression"], "vault.balanceOf(attacker)"
        )
        self.assertFalse(assignments["shares"]["inline"])
        self.assertTrue(
            any("shares" in r.lower() for r in assignments["shares"]["setup_requirements"])
        )
        # An actor address inlines directly (no scenario variable needed).
        self.assertEqual(assignments["receiver"]["expression"], "attacker")
        self.assertTrue(assignments["receiver"]["inline"])

    async def test_writes_artifact_and_records_result(self):
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "title": "Vault withdraw args",
            "action": {
                "contract": "Vault",
                "function": "withdraw",
                "parameters": [self._param("amount", "uint256")],
            },
        })
        result = json.loads(out)

        self.assertEqual(result["arg_synthesis_id"], "arg-001")
        self.assertEqual(result["path"], "/workspace/campaign/arg-synthesis/arg-001.json")
        self.assertIn(result["path"], container.files)
        artifact = json.loads(container.files[result["path"]])
        self.assertEqual(artifact["id"], "arg-001")
        self.assertEqual(artifact["contract"], "Vault")
        # A campaign result artifact links the synthesis as evidence.
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["counters"]["arg_synthesis"], 1)
        latest_result = state["sections"]["result"][-1]
        self.assertEqual(latest_result["id"], result["result_id"])
        self.assertIn(result["path"], latest_result["evidence"])

    async def test_record_result_false_returns_null_ids_and_writes_nothing(self):
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {
                "contract": "Vault",
                "function": "withdraw",
                "parameters": [self._param("amount", "uint256")],
            },
            "record_result": False,
        })
        result = json.loads(out)

        self.assertIsNone(result["arg_synthesis_id"])
        self.assertIsNone(result["path"])
        self.assertIsNone(result["result_id"])
        self.assertEqual(container.files, {})
        self.assertEqual(result["parameter_plan"][0]["candidates"], ["DEFAULT_AMOUNT"])

    async def test_approve_picks_spender_from_target_and_amount_cap(self):
        # Heuristic 1 (spender) + 2 (approve amount): spender binds to a known
        # target contract, amount offers a max-allowance cap.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {
                "contract": "Token",
                "function": "approve",
                "parameters": [
                    self._param("spender", "address"),
                    self._param("amount", "uint256"),
                ],
            },
            "target_addresses": {"Vault": "0x" + "11" * 20},
        })
        result = json.loads(out)

        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertIn("address(vault)", plan["spender"]["candidates"])
        self.assertTrue(
            {"type(uint256).max", "DEFAULT_AMOUNT"} & set(plan["amount"]["candidates"]),
            plan["amount"]["candidates"],
        )
        self.assertEqual(result["status"], "observed")

    async def test_swap_path_without_fork_tokens_is_partial_route_required(self):
        # Heuristic 6: an address[] path with no known route tokens cannot be
        # synthesized and returns an explicit route_required blocker.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Router", "function": "swapExactTokensForTokens"},
            "source_slice": (
                "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, "
                "address[] path, address to)"
            ),
        })
        result = json.loads(out)

        self.assertEqual(result["status"], "partial")
        blocker_classes = {blocker["class"] for blocker in result["blockers"]}
        self.assertIn("route_required", blocker_classes)
        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertEqual(plan["path"]["candidates"], [])
        # minAmountOut defaults to 0 (slippage disabled, exploratory).
        self.assertEqual(plan["amountOutMin"]["candidates"], ["0"])

    async def test_signature_payload_is_blocked_not_fabricated(self):
        # Heuristic 7: a signature/bytes payload is never faked; it returns a
        # signature_required blocker with no candidate value.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Vault", "function": "withdrawWithSig"},
            "source_slice": {"signature": "withdrawWithSig(uint256 amount, bytes signature)"},
        })
        result = json.loads(out)

        self.assertIn(result["status"], ("partial", "blocked"))
        blocker_classes = {blocker["class"] for blocker in result["blockers"]}
        self.assertIn("signature_required", blocker_classes)
        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertEqual(plan["signature"]["candidates"], [])
        # No fabricated bytes literal anywhere in the output.
        self.assertNotRegex(out, r"0x[0-9a-fA-F]{16,}")
        self.assertNotIn('hex"0x', out)

    async def test_permit_and_proof_payloads_block_with_distinct_classes(self):
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Distributor", "function": "claim"},
            "source_slice": (
                "claim(bytes32[] proof, uint256 amount, bytes permitData)"
            ),
            "record_result": False,
        })
        result = json.loads(out)

        blocker_classes = {blocker["class"] for blocker in result["blockers"]}
        self.assertIn("proof_required", blocker_classes)
        self.assertIn("permit_required", blocker_classes)
        # amount is still synthesizable, so the call is partial, not blocked.
        self.assertEqual(result["status"], "partial")

    async def test_bool_deadline_and_struct_conventions(self):
        # Heuristics 3 (bool), 4 (deadline), 8 (struct): booleans get both
        # values, deadlines get a timestamp offset, a named struct blocks for its
        # shape, and an order-flavoured struct blocks as an order payload.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Exchange", "function": "execute"},
            "source_slice": (
                "execute(bool approved, uint256 deadline, Config config, Order order)"
            ),
            "record_result": False,
        })
        result = json.loads(out)

        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertEqual(plan["approved"]["candidates"], ["true", "false"])
        self.assertEqual(plan["deadline"]["candidates"], ["block.timestamp + 1 hours"])
        self.assertEqual(
            [b["class"] for b in plan["config"]["blockers"]], ["struct_shape_required"]
        )
        self.assertEqual(
            [b["class"] for b in plan["order"]["blockers"]], ["order_struct_required"]
        )
        self.assertEqual(result["status"], "partial")

    async def test_identifier_names_are_distinguished_from_amounts(self):
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Market", "function": "act"},
            "source_slice": "act(uint256 tokenId, uint256 amountPaid)",
            "record_result": False,
        })
        result = json.loads(out)

        plan = {param["name"]: param for param in result["parameter_plan"]}
        self.assertEqual(plan["tokenId"]["candidates"], ["0"])
        # amountPaid must not be mistaken for an identifier just because it ends
        # in a lowercase "id".
        self.assertEqual(plan["amountPaid"]["candidates"], ["DEFAULT_AMOUNT"])

    async def test_no_argument_function_is_observed_with_empty_call(self):
        # A genuine no-arg function (explicit empty args) is fully observed and
        # gets an empty call -- not a partial "provide typed metadata" verdict.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Vault", "function": "pause", "args": []},
            "record_result": False,
        })
        result = json.loads(out)

        self.assertEqual(result["status"], "observed")
        self.assertEqual(len(result["candidate_calls"]), 1)
        self.assertEqual(result["candidate_calls"][0]["args"], [])
        self.assertEqual(result["blockers"], [])
        self.assertFalse(
            any("No parameters detected" in note for note in result["notes"]),
            result["notes"],
        )

    async def test_no_argument_function_via_empty_parameters_is_observed(self):
        # An explicitly-empty parameters list is equally authoritative.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Vault", "function": "pause", "parameters": []},
            "record_result": False,
        })
        result = json.loads(out)

        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["candidate_calls"][0]["args"], [])

    async def test_unknown_metadata_function_stays_partial(self):
        # No args/parameters and no typed source: the tool cannot tell a no-arg
        # function from absent metadata, so it stays partial and asks for types.
        container = FakeContainer()
        out = await _synthesize_args(container, {
            "action": {"contract": "Vault", "function": "pause"},
            "record_result": False,
        })
        result = json.loads(out)

        self.assertEqual(result["status"], "partial")
        self.assertTrue(
            any("No parameters detected" in note for note in result["notes"]),
            result["notes"],
        )

    async def test_missing_action_and_step_index_errors(self):
        container = FakeContainer()
        self.assertIn(
            "Error",
            await _synthesize_args(container, {}),
        )
        self.assertIn(
            "step_index is required",
            await _synthesize_args(container, {"sequence": "exp-001"}),
        )

    async def test_sequence_step_index_enriches_from_action_space(self):
        # Heuristic 5: synthesize_args loads sequence.json for the chosen step and
        # reuses the action-space parameter metadata embedded at compose time.
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{
                "contract": "Vault",
                "function": "withdraw",
                "file": "/audit/src/Vault.sol",
                "line": 20,
                "visibility": "external",
                "mutability": "nonpayable",
                "affordances": ["value_out_or_burn"],
                "parameters": [
                    {"raw": "uint256 shares", "name": "shares"},
                    {"raw": "address receiver", "name": "receiver"},
                    {"raw": "address owner", "name": "owner"},
                ],
            }],
            "observations": [],
        })
        await _compose_sequence_experiment(container, {
            "title": "Vault withdraw replay",
            "objective": "Replay a value-moving vault withdraw.",
            "action_space": "as-001",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["shares", "receiver", "owner"],
                "expected_effect": "value leaves the vault",
            }],
        })

        out = await _synthesize_args(container, {"sequence": "exp-001", "step_index": 1})
        result = json.loads(out)

        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["signature"], "withdraw(uint256,address,address)")
        artifact = json.loads(container.files[result["path"]])
        self.assertEqual(artifact["source"]["parameter_source"], "sequence")
        self.assertEqual(artifact["source"]["step_index"], 1)
        self.assertEqual(
            result["candidate_calls"][0]["args"],
            ["shares", "attacker", "attacker"],
        )

    async def test_sequence_step_index_out_of_range_errors(self):
        container = FakeContainer()
        container.files["/workspace/campaign/action-spaces/as-001.json"] = json.dumps({
            "id": "as-001",
            "summary": {"actions": 1, "observations": 0, "contracts": 1},
            "actions": [{"contract": "Vault", "function": "withdraw", "parameters": []}],
            "observations": [],
        })
        await _compose_sequence_experiment(container, {
            "title": "Vault withdraw replay",
            "objective": "Replay a value-moving vault withdraw.",
            "action_space": "as-001",
            "actions": [{"actor": "attacker", "contract": "Vault", "function": "withdraw"}],
        })

        out = await _synthesize_args(container, {"sequence": "exp-001", "step_index": 9})
        self.assertIn("out of range", out)

    async def test_routed_through_execute_tool_and_in_experiment_toolset(self):
        container = FakeContainer()
        out = await execute_tool(
            "synthesize_args",
            {
                "action": {
                    "contract": "Vault",
                    "function": "withdraw",
                    "parameters": [self._param("amount", "uint256")],
                },
                "record_result": False,
            },
            container,
            [],
        )
        self.assertEqual(json.loads(out)["status"], "observed")
        self.assertIn("synthesize_args", tool_names_for_toolsets({"experiment"}))


class DiagnoseBuildTests(unittest.IsolatedAsyncioTestCase):
    MISSING_IMPORT = "\n".join([
        "Error: Compiler run failed:",
        'Error (6275): ParserError: Source "./interfaces/IVault.sol" not found:'
        " File not found.",
        " --> src/Vault.sol:5:1:",
        "  |",
        '5 | import "./interfaces/IVault.sol";',
        "  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
    ])
    UNDECLARED = "\n".join([
        "Error: Compiler run failed:",
        'Error (7576): DeclarationError: Undeclared identifier. Did you mean'
        ' "totalSupply"?',
        " --> src/Token.sol:42:16:",
    ])
    TYPE_ERROR = "\n".join([
        "Error: Compiler run failed:",
        "Error (9574): TypeError: Type uint256 is not implicitly convertible to"
        " expected type address.",
        " --> test/Exploit.t.sol:18:9:",
    ])
    MISSING_DEP = "\n".join([
        "Error: Compiler run failed:",
        'Error (6275): ParserError: Source "@openzeppelin/contracts/token/ERC20/'
        'IERC20.sol" not found: File import callback not supported.',
        " --> src/Pool.sol:4:1:",
    ])

    def test_classify_build_output_handles_multiple_errors(self):
        diagnostics = _classify_build_output(
            self.MISSING_IMPORT + "\n" + self.UNDECLARED
        )
        kinds = [d["kind"] for d in diagnostics]
        self.assertEqual(kinds, ["missing_import", "undeclared_identifier"])
        # Echoed source lines (the `5 | import ...` line) must not be classified.
        self.assertEqual(len(diagnostics), 2)

    def test_classify_build_output_ignores_clean_log(self):
        self.assertEqual(_classify_build_output("Compiler run successful!"), [])

    def test_infer_build_system_marks_profile_as_foundry(self):
        self.assertEqual(_infer_build_system("", "", source="profile"), "foundry")
        self.assertEqual(
            _infer_build_system("npx hardhat compile", ""), "hardhat"
        )

    async def test_diagnose_build_classifies_missing_import(self):
        container = FakeContainer()
        container.exec_result = (1, self.MISSING_IMPORT)

        out = await _diagnose_build(container, {"command": "forge build"})
        data = json.loads(out)

        self.assertEqual(data["build_diagnostic_id"], "bdiag-001")
        self.assertEqual(data["status"], "observed")
        self.assertEqual(data["build_system"], "foundry")
        self.assertEqual(data["exit_code"], 1)
        first = data["first_error"]
        self.assertEqual(first["kind"], "missing_import")
        self.assertEqual(first["file"], "src/Vault.sol")
        self.assertEqual(first["line"], 5)
        self.assertTrue(first["repair_hint"])
        self.assertEqual(data["suggested_next"], "repair_experiment")
        # Artifact + bounded log are written; result is recorded by default.
        artifact = json.loads(
            container.files["/workspace/campaign/build-diagnostics/bdiag-001.json"]
        )
        self.assertEqual(artifact["log_path"], data["log_path"])
        self.assertEqual(artifact["log_line_count"], data["log_line_count"])
        self.assertTrue(artifact["log_sha256"])
        self.assertIn(
            "/workspace/campaign/build-diagnostics/bdiag-001.log", container.files
        )
        self.assertEqual(data["result_id"], "res-001")
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"build_diagnostic": 1', state)
        self.assertIn('"id": "res-001"', state)
        self.assertIn('"bdiag-001"', state)

    async def test_diagnose_build_classifies_undeclared_identifier(self):
        container = FakeContainer()
        container.exec_result = (1, self.UNDECLARED)

        out = await _diagnose_build(
            container, {"command": "forge build", "record_result": False}
        )
        data = json.loads(out)

        self.assertEqual(data["first_error"]["kind"], "undeclared_identifier")
        self.assertEqual(data["first_error"]["file"], "src/Token.sol")
        self.assertEqual(data["first_error"]["line"], 42)
        self.assertIsNone(data["result_id"])
        # record_result=false still writes the diagnostic artifact, no result.
        self.assertIn(
            "/workspace/campaign/build-diagnostics/bdiag-001.json", container.files
        )
        self.assertNotIn('"id": "res-001"', container.files[_CAMPAIGN_STATE_PATH])

    async def test_diagnose_build_classifies_type_error(self):
        container = FakeContainer()
        container.exec_result = (1, self.TYPE_ERROR)

        out = await _diagnose_build(container, {"command": "forge build"})
        data = json.loads(out)

        self.assertEqual(data["first_error"]["kind"], "type_error")
        self.assertEqual(data["first_error"]["file"], "test/Exploit.t.sol")
        self.assertEqual(data["first_error"]["line"], 18)

    async def test_diagnose_build_routes_external_dependency_to_install(self):
        container = FakeContainer()
        container.exec_result = (1, self.MISSING_DEP)

        out = await _diagnose_build(container, {"command": "forge build"})
        data = json.loads(out)

        self.assertEqual(data["first_error"]["kind"], "missing_dependency")
        self.assertEqual(data["suggested_next"], "install_dependency")

    async def test_diagnose_build_parses_log_path_without_running(self):
        container = FakeContainer()
        container.files["/workspace/campaign/results/res-009.log"] = self.MISSING_IMPORT

        out = await _diagnose_build(
            container, {"log_path": "/workspace/campaign/results/res-009.log"}
        )
        data = json.loads(out)

        self.assertEqual(data["status"], "observed")
        self.assertIsNone(data["exit_code"])
        self.assertEqual(data["command"], None)
        self.assertEqual(data["first_error"]["kind"], "missing_import")
        # Parsing must not run any command.
        self.assertEqual(container.exec_calls, [])

    async def test_diagnose_build_unclassifiable_log_is_unknown(self):
        container = FakeContainer()

        out = await _diagnose_build(
            container, {"log": "just some unrelated build chatter, nothing useful"}
        )
        data = json.loads(out)

        self.assertEqual(data["status"], "unknown")
        self.assertEqual(data["diagnostics"], [])
        self.assertIsNone(data["first_error"])
        # An unclassifiable parsed log must not suggest running the harness.
        self.assertEqual(data["suggested_next"], "repair_experiment")

    async def test_diagnose_build_rejects_log_path_outside_sandbox(self):
        container = FakeContainer()

        out = await _diagnose_build(container, {"log_path": "/etc/passwd"})
        data = json.loads(out)

        self.assertEqual(data["error"], "log_path_not_allowed")
        self.assertEqual(container.exec_calls, [])

    async def test_diagnose_build_classifies_test_discovery(self):
        container = FakeContainer()
        container.exec_result = (0, "No tests to run")

        out = await _diagnose_build(container, {"command": "forge test --list"})
        data = json.loads(out)

        self.assertEqual(data["first_error"]["kind"], "test_discovery")
        self.assertEqual(data["status"], "observed")

    async def test_diagnose_build_marks_unclassified_failure_blocked(self):
        container = FakeContainer()
        container.exec_result = (1, "make: *** [build] segmentation fault")

        out = await _diagnose_build(container, {"command": "make build"})
        data = json.loads(out)

        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["first_error"]["kind"], "unknown")

    async def test_diagnose_build_clean_build_suggests_run(self):
        container = FakeContainer()
        container.exec_result = (0, "Compiler run successful!")

        out = await _diagnose_build(container, {"command": "forge build"})
        data = json.loads(out)

        self.assertEqual(data["status"], "observed")
        self.assertEqual(data["diagnostics"], [])
        self.assertIsNone(data["first_error"])
        self.assertEqual(data["suggested_next"], "run_experiment")

    async def test_diagnose_build_unknown_build_system_when_no_inputs(self):
        container = FakeContainer()
        # foundry-root probe fails -> no command can be chosen.
        container.exec_result = (1, "")

        out = await _diagnose_build(container, {})
        data = json.loads(out)

        self.assertEqual(data["status"], "unknown")
        self.assertEqual(data["build_system"], "unknown")
        self.assertIn("no foundry.toml", data["message"])
        # The "useful error" path writes no diagnostic artifact.
        self.assertNotIn(
            "/workspace/campaign/build-diagnostics/bdiag-001.json", container.files
        )

    async def test_diagnose_build_experiment_targets_workspace_and_completion(self):
        container = FakeContainer()
        await _create_experiment(container, {
            "title": "Vault replay",
            "template": "foundry_test",
        })
        workspace = _experiment_workspace_line(container)
        wrong_iface = "\n".join([
            "Error: Compiler run failed:",
            'Error (9582): TypeError: Member "deposit" not found or not visible'
            " after argument-dependent lookup in contract IVault.",
            " --> test/ReentbotProSequence.t.sol:20:9:",
        ])
        container.exec_result = (1, wrong_iface)

        out = await _diagnose_build(
            container, {"experiment": "exp-001", "record_result": False}
        )
        data = json.loads(out)

        self.assertEqual(data["first_error"]["kind"], "wrong_interface")
        # Interface mismatch in a generated sequence experiment routes to the
        # completion regenerator, not a raw manual repair.
        self.assertEqual(data["suggested_next"], "complete_sequence_experiment")
        # The build ran inside the experiment workspace, mutating nothing there.
        ran_command, ran_dir, _timeout = container.exec_calls[-1]
        self.assertIn("forge build", ran_command)
        self.assertEqual(ran_dir, workspace)


def _experiment_workspace_line(container) -> str:
    state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
    for experiment in state["sections"]["experiment"]:
        for line in str(experiment.get("content") or "").splitlines():
            if line.startswith("Workspace: "):
                return line.split("Workspace: ", 1)[1].strip()
    raise AssertionError("no experiment workspace recorded")


class RepairExperimentTests(unittest.IsolatedAsyncioTestCase):
    TARGET = "0x1111111111111111111111111111111111111111"

    async def _compose(self, container, **overrides):
        """Compose a single-step Vault::withdraw sequence experiment."""
        args = {
            "title": "Drain vault",
            "objective": "attacker drains vault",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
                "parameters": [{"name": "amount", "raw": "uint256 amount"}],
                "expected_effect": "unauthorized value leaves the vault",
            }],
            "observations": [{
                "label": "vault assets",
                "contract": "Vault",
                "call": "totalAssets()(uint256)",
            }],
            "success_condition": "attacker balance increases",
        }
        args.update(overrides)
        await _compose_sequence_experiment(container, args)
        return "/workspace/experiments/exp-001-drain-vault"

    async def test_writes_forge_std_shim_and_remapping_when_absent(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        # Simulate a workspace that lost its forge-std shim and remapping.
        del container.files[f"{workspace}/lib/forge-std/src/Test.sol"]
        del container.files[f"{workspace}/foundry.toml"]

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "log": (
                'Error (6275): ParserError: Source "forge-std/Test.sol" not '
                "found: File not found."
            ),
            "record_result": False,
        }))

        kinds = {item["kind"] for item in result["applied_repairs"]}
        self.assertIn("missing_forge_std_import", kinds)
        self.assertIn(
            "contract Test",
            container.files[f"{workspace}/lib/forge-std/src/Test.sol"],
        )
        self.assertIn(
            "forge-std/=lib/forge-std/src/",
            container.files[f"{workspace}/foundry.toml"],
        )
        # forge-std is repaired, not surfaced as an install suggestion.
        self.assertEqual(result["repair_suggestions"], [])

    async def test_repairs_checksum_address_literal(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[contract_path] = f"contract T {{ address a = {bad}; }}\n"
        log = "\n".join([
            "Compiler run failed:",
            "Error (9429): This looks like an address but has an invalid checksum.",
            f'Correct checksummed address: "{good}"',
            "  --> ReentbotProSequence.t.sol:1:26",
        ])

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "log": log,
            "record_result": False,
        }))

        kinds = {item["kind"] for item in result["applied_repairs"]}
        self.assertIn("checksum_address_literal", kinds)
        self.assertIn(good, container.files[contract_path])
        self.assertNotIn(bad, container.files[contract_path])

    async def test_repairs_from_bdiag_artifact_reference(self):
        # End-to-end: diagnose_build writes bdiag-001(+log), repair_experiment
        # resolves the artifact, reads its log, and fixes the checksum.
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[contract_path] = f"contract T {{ address a = {bad}; }}\n"
        container.exec_result = (1, "\n".join([
            "Compiler run failed:",
            "Error (9429): This looks like an address but has an invalid checksum.",
            f'Correct checksummed address: "{good}"',
            "  --> ReentbotProSequence.t.sol:1:26",
        ]))
        diag = json.loads(await _diagnose_build(
            container, {"experiment": "exp-001", "record_result": False}
        ))
        self.assertEqual(diag["build_diagnostic_id"], "bdiag-001")

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "diagnostic": "bdiag-001",
            "record_result": False,
        }))

        self.assertEqual(result["diagnostic_source"], "bdiag-001")
        kinds = {item["kind"] for item in result["applied_repairs"]}
        self.assertIn("checksum_address_literal", kinds)
        self.assertIn(good, container.files[contract_path])

    async def test_declares_undeclared_scenario_placeholder(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        # Simulate a stale scaffold: drop the generated `amount` declaration.
        contract = container.files[contract_path]
        needle = "    uint256 internal amount = DEFAULT_AMOUNT;\n"
        self.assertIn(needle, contract)
        container.files[contract_path] = contract.replace(needle, "", 1)

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "diagnostic": {
                "kind": "undeclared_identifier",
                "file": "ReentbotProSequence.t.sol",
                "symbol": "amount",
                "message": 'Undeclared identifier "amount".',
            },
            "record_result": False,
        }))

        kinds = {item["kind"] for item in result["applied_repairs"]}
        self.assertIn("undeclared_identifier", kinds)
        self.assertIn(
            "uint256 internal amount = DEFAULT_AMOUNT;",
            container.files[contract_path],
        )

    async def test_unsafe_signature_returns_suggestion_without_patch(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        before = container.files[contract_path]

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "diagnostic": {
                "kind": "signature_required",
                "file": "ReentbotProSequence.t.sol",
                "line": 20,
                "message": "claim requires a forged signature payload",
            },
            "record_result": False,
        }))

        self.assertEqual(result["applied_repairs"], [])
        suggestion_kinds = {item["kind"] for item in result["repair_suggestions"]}
        self.assertIn("signature_required", suggestion_kinds)
        self.assertTrue(result["remaining_blockers"])
        # The harness source is never rewritten for an unsafe payload blocker.
        self.assertEqual(container.files[contract_path], before)

    async def test_repair_history_written_to_sequence_json(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        sequence_path = f"{workspace}/sequence.json"
        self.assertNotIn(
            "repair_history", json.loads(container.files[sequence_path])
        )

        await _repair_experiment(container, {
            "experiment": "exp-001",
            "diagnostic": {
                "kind": "type_error",
                "file": "ReentbotProSequence.t.sol",
                "line": 18,
                "message": "Type uint256 is not implicitly convertible",
            },
            "record_result": False,
        })

        sequence = json.loads(container.files[sequence_path])
        self.assertEqual(len(sequence["repair_history"]), 1)
        entry = sequence["repair_history"][0]
        self.assertIn("applied", entry)
        self.assertIn("suggestions", entry)
        self.assertIn("remaining_blockers", entry)

    async def test_fills_stale_target_binding_from_sequence_json(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        sequence_path = f"{workspace}/sequence.json"
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        # The composed scaffold renders address(0) for the unbound Vault.
        self.assertIn("vaultAddress = address(0)", container.files[contract_path])
        # Bind it in sequence.json without re-rendering the .t.sol (stale state).
        payload = json.loads(container.files[sequence_path])
        payload["target_addresses"] = {"Vault": self.TARGET}
        container.files[sequence_path] = json.dumps(payload)

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "record_result": False,
        }))

        kinds = {item["kind"] for item in result["applied_repairs"]}
        self.assertIn("missing_target_binding", kinds)
        self.assertIn(
            f"vaultAddress = {self.TARGET};", container.files[contract_path]
        )
        self.assertNotIn(
            "vaultAddress = address(0)", container.files[contract_path]
        )

    async def test_records_result_and_notes_experiment(self):
        container = FakeContainer()
        await self._compose(container)

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "log": 'Source "forge-std/Test.sol" not found: File not found.',
        }))

        self.assertTrue(result["result_id"])
        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertTrue(any(
            entry["id"] == result["result_id"]
            for entry in state["sections"]["result"]
        ))
        experiment = next(
            entry for entry in state["sections"]["experiment"]
            if entry["id"] == "exp-001"
        )
        self.assertIn("Repair:", experiment["content"])

    async def test_explicit_repair_applies_find_replace(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        container.files[contract_path] = "contract T { uint256 x = 1; }\n"

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "auto": False,
            "repairs": [{
                "file": "ReentbotProSequence.t.sol",
                "find": "uint256 x = 1;",
                "replace": "uint256 x = 2;",
                "reason": "fix constant",
            }],
            "record_result": False,
        }))

        self.assertEqual(len(result["applied_repairs"]), 1)
        self.assertEqual(result["applied_repairs"][0]["kind"], "explicit_repair")
        self.assertIn("uint256 x = 2;", container.files[contract_path])

    async def test_explicit_repair_outside_workspace_is_rejected(self):
        container = FakeContainer()
        await self._compose(container)

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "repairs": [{
                "file": "/audit/src/Vault.sol",
                "find": "x",
                "replace": "y",
            }],
            "record_result": False,
        }))

        self.assertEqual(result["applied_repairs"], [])
        self.assertTrue(any(
            item["kind"] == "explicit_repair"
            for item in result["repair_suggestions"]
        ))
        # The out-of-workspace target file is never created or touched.
        self.assertNotIn("/audit/src/Vault.sol", container.files)

    async def test_auto_false_suggests_without_patching(self):
        container = FakeContainer()
        workspace = await self._compose(container)
        contract_path = f"{workspace}/ReentbotProSequence.t.sol"
        bad = "0x37DE57183491Fa9745d8Fa5DCd950f0c3a4645c9"
        good = "0x37dE57183491Fa9745D8Fa5DCd950F0c3a4645C9"
        container.files[contract_path] = f"contract T {{ address a = {bad}; }}\n"
        log = "\n".join([
            "Error (9429): This looks like an address but has an invalid checksum.",
            f'Correct checksummed address: "{good}"',
            "  --> ReentbotProSequence.t.sol:1:26",
        ])

        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-001",
            "log": log,
            "auto": False,
            "record_result": False,
        }))

        # auto disabled -> no automatic checksum patch; source untouched.
        self.assertEqual(result["applied_repairs"], [])
        self.assertIn(bad, container.files[contract_path])

    async def test_unresolved_experiment_returns_error(self):
        container = FakeContainer()
        result = json.loads(await _repair_experiment(container, {
            "experiment": "exp-404",
        }))
        self.assertEqual(result["error"], "experiment_unresolved")


class AttackSearchNextActionStructuredTests(unittest.TestCase):
    def test_next_action_passes_through_branch_expected_tools_and_pipeline(self):
        from reentbotpro.tools import _attack_search_next_action

        search = {
            "selected_branch_id": "br-001",
            "branches": [{
                "id": "br-001",
                "title": "Concretize experiment",
                "status": "needs_concretization",
                "source": "experiment_without_result",
                "next_tool": "compose then complete the sequence",
                "expected_tools": ["compose_sequence_experiment"],
                "pipeline": [
                    {"tool": "synthesize_args"},
                    {"tool": "complete_sequence_experiment"},
                ],
            }],
        }

        next_action = _attack_search_next_action(search)

        self.assertEqual(next_action["expected_tools"], ["compose_sequence_experiment"])
        self.assertEqual(
            [step["tool"] for step in next_action["pipeline"]],
            ["synthesize_args", "complete_sequence_experiment"],
        )

    def test_next_action_omits_structured_fields_when_branch_lacks_them(self):
        from reentbotpro.tools import _attack_search_next_action

        search = {
            "selected_branch_id": "br-001",
            "branches": [{
                "id": "br-001",
                "status": "needs_mapping",
                "next_tool": "map_action_space",
            }],
        }

        next_action = _attack_search_next_action(search)

        self.assertNotIn("expected_tools", next_action)
        self.assertNotIn("pipeline", next_action)

    def test_next_action_includes_selection_rationale_and_top_alternatives(self):
        from reentbotpro.tools import _attack_search_next_action

        search = {
            "selected_branch_id": "",
            "branches": [
                {
                    "id": "repair",
                    "title": "Repair generated PoC",
                    "status": "needs_poc_repair",
                    "source": "blocked_result",
                    "next_tool": "repair_experiment",
                    "priority": "high",
                    "priority_score": 24,
                    "evidence": ["/workspace/campaign/results/res-001.log"],
                },
                {
                    "id": "new-harness",
                    "title": "Start a new harness",
                    "status": "needs_harness",
                    "source": "hypothesis_without_experiment",
                    "next_tool": "compose_sequence_experiment",
                    "priority": "medium",
                    "priority_score": 4,
                },
            ],
        }

        next_action = _attack_search_next_action(search)

        self.assertEqual(next_action["branch_id"], "repair")
        rationale = next_action["selection_rationale"]
        self.assertEqual(rationale["selected"]["branch_id"], "repair")
        self.assertIn("selected_reason", rationale)
        self.assertEqual(
            rationale["top_alternatives"][0]["branch_id"],
            "new-harness",
        )
        self.assertIn(
            "reason_not_selected",
            rationale["top_alternatives"][0],
        )


class AttackSearchSchedulingTests(unittest.TestCase):
    """Expected-value / proof-cost branch scheduling and parking tiers."""

    def _order(self, branches):
        from reentbotpro.tools import _attack_search_branch_sort_key

        return [
            branch["id"]
            for branch in sorted(branches, key=_attack_search_branch_sort_key)
        ]

    def test_ready_to_submit_outranks_everything(self):
        # A ready-to-submit branch wins over the most attractive exploration and
        # over a needs-evidence branch, regardless of scheduling score.
        branches = [
            {
                "id": "explore",
                "status": "needs_harness",
                "priority": "critical",
                "priority_score": 80,
                "target_binding": {"live_deployed": True},
                "target_actions": [{"affordances": ["value_out_or_burn"]}],
            },
            {
                "id": "evidence",
                "status": "needs_evidence",
                "priority": "high",
                "priority_score": 40,
            },
            {
                "id": "ready",
                "status": "ready_to_submit",
                "priority": "low",
                "priority_score": 0,
            },
        ]
        self.assertEqual(self._order(branches)[0], "ready")

    def test_needs_evidence_outranks_mapping_and_harness(self):
        # Strict (claim/evidence) precedence is never reordered by scheduling: a
        # low-value needs_evidence branch still beats a high-value harness/mapping
        # branch.
        branches = [
            {
                "id": "harness",
                "status": "needs_harness",
                "priority": "critical",
                "priority_score": 80,
                "target_binding": {"live_deployed": True},
                "target_actions": [{"affordances": ["value_out_or_burn"]}],
            },
            {
                "id": "mapping",
                "status": "needs_mapping",
                "priority": "high",
                "priority_score": 30,
            },
            {
                "id": "evidence",
                "status": "needs_evidence",
                "priority": "low",
                "priority_score": 0,
            },
        ]
        order = self._order(branches)
        self.assertEqual(order[0], "evidence")
        self.assertLess(order.index("evidence"), order.index("harness"))
        self.assertLess(order.index("evidence"), order.index("mapping"))

    def test_scheduling_score_orders_construction_branches(self):
        # Among proof-construction branches, the cheaper, higher-value, live one
        # outranks an expensive, repeatedly-stalled, hard-blocked one even though
        # the latter carries the better raw status rank (needs_concretization=15
        # would historically beat needs_harness=19).
        from reentbotpro.tools import _attack_search_scheduling

        high = {
            "id": "high",
            "status": "needs_harness",
            "priority": "high",
            "priority_score": 30,
            "target_binding": {"live_deployed": True},
            "target_actions": [{"affordances": ["value_out_or_burn"]}],
        }
        low = {
            "id": "low",
            "status": "needs_concretization",
            "priority": "high",
            "priority_score": 6,
            "inventory_context": {"hard_blockers": [{"label": "Vault"}]},
            "history": [
                {"event": "status_changed", "to": "blocked_compile"},
                {"event": "status_changed", "to": "blocked_compile"},
            ],
        }
        self.assertEqual(self._order([low, high]), ["high", "low"])
        self.assertGreater(
            _attack_search_scheduling(high)["scheduling_score"],
            _attack_search_scheduling(low)["scheduling_score"],
        )

    def test_higher_scheduling_score_wins_same_status(self):
        # Two needs_harness branches: the live, value-moving one outranks the
        # inert one purely on scheduling score.
        live = {
            "id": "live",
            "status": "needs_harness",
            "priority": "medium",
            "priority_score": 10,
            "target_binding": {"economically_significant_hint": True},
            "target_actions": [{"affordances": ["credit_or_liquidation"]}],
        }
        inert = {
            "id": "inert",
            "status": "needs_harness",
            "priority": "medium",
            "priority_score": 10,
        }
        self.assertEqual(self._order([inert, live]), ["live", "inert"])

    def test_parked_sorts_below_active_needs_harness(self):
        # Every parked_* status sorts below an active needs_harness branch, even
        # when the parked branch is the higher-value one.
        active = {
            "id": "active",
            "status": "needs_harness",
            "priority": "low",
            "priority_score": 0,
        }
        for parked_status in (
            "parked_harness_limit",
            "parked_low_roi",
            "parked_needs_dependency",
            "parked_needs_live_context",
        ):
            parked = {
                "id": "parked",
                "status": parked_status,
                "priority": "critical",
                "priority_score": 80,
                "target_binding": {"live_deployed": True},
            }
            self.assertEqual(
                self._order([parked, active]), ["active", "parked"], parked_status
            )

    def test_scheduling_score_is_components_combination(self):
        from reentbotpro.tools import _attack_search_scheduling

        scores = _attack_search_scheduling({
            "status": "needs_harness",
            "priority": "high",
            "priority_score": 20,
            "target_binding": {"live_deployed": True},
            "target_actions": [{"affordances": ["value_out_or_burn"]}],
            "evidence": ["/workspace/campaign/results/res-001.log"],
        })
        self.assertEqual(
            scores["scheduling_score"],
            scores["expected_value_score"]
            - scores["proof_cost_score"]
            - scores["blocker_penalty"]
            + scores["next_step_value"]
            + scores["diversity_bonus"],
        )
        for key in (
            "expected_value_score",
            "proof_cost_score",
            "next_step_value",
            "diversity_bonus",
        ):
            self.assertGreaterEqual(scores[key], 0)

    def test_compact_branch_surfaces_scheduling_fields(self):
        from reentbotpro.tools import (
            _attack_search_score_branch,
            _compact_attack_branch,
        )

        branch = {
            "id": "br-001",
            "status": "needs_harness",
            "priority": "high",
            "priority_score": 20,
            "target_binding": {"live_deployed": True},
        }
        _attack_search_score_branch(branch)
        compact = _compact_attack_branch(branch)
        for field in (
            "scheduling_score",
            "expected_value_score",
            "proof_cost_score",
            "blocker_penalty",
            "next_step_value",
        ):
            self.assertIn(field, compact)

    def test_non_novel_branch_omits_curiosity_fields(self):
        # A plain (non-frontier, non-novel) branch carries no curiosity noise in
        # its compact view.
        from reentbotpro.tools import (
            _attack_search_score_branch,
            _compact_attack_branch,
        )

        branch = {
            "id": "br-002",
            "status": "needs_harness",
            "priority": "high",
            "priority_score": 20,
            "target_binding": {"live_deployed": True},
        }
        _attack_search_score_branch(branch)
        compact = _compact_attack_branch(branch)
        for field in (
            "novelty_score",
            "diversity_reason",
            "frontier_source",
            "diversity_bonus",
            "curiosity_budget_eligible",
        ):
            self.assertNotIn(field, compact)


class AttackSearchCuriosityFrontierTests(unittest.TestCase):
    """Bounded curiosity/diversity budget and source-only frontier branches."""

    def _order(self, branches):
        from reentbotpro.tools import _attack_search_branch_sort_key

        return [
            branch["id"]
            for branch in sorted(branches, key=_attack_search_branch_sort_key)
        ]

    def _frontier_branch(self, **overrides):
        branch = {
            "id": "frontier",
            "status": "needs_mapping",
            "source": "attack_graph_frontier",
            "priority": "medium",
            "priority_score": 2,
            "exposure": "source_only",
            "root_mechanism": "generic_state_transition",
            "frontier_source": {"attack_graph_id": "ag-001"},
            "source_artifacts": ["/workspace/campaign/attack-graphs/ag-001.json"],
            "target_actions": [{
                "contract": "Pool",
                "function": "poke",
                "affordances": ["mapping_state_write", "external_boundary_crossing"],
            }],
        }
        branch.update(overrides)
        return branch

    def test_source_only_generic_state_transition_gets_positive_novelty(self):
        from reentbotpro.tools import _attack_search_novelty_score

        branch = {
            "id": "src",
            "status": "needs_harness",
            "source": "attack_graph_candidate",
            "root_mechanism": "generic_state_transition",
            "source_artifacts": ["/workspace/campaign/attack-graphs/ag-001.json"],
            "target_actions": [{
                "contract": "Pool",
                "function": "settle",
                "affordances": ["mapping_state_write", "external_boundary_crossing"],
                "live_exposure": "source_only",
            }],
        }
        score, reasons = _attack_search_novelty_score(branch)
        self.assertGreater(score, 0)
        self.assertTrue(any("source_only" in reason for reason in reasons))
        self.assertTrue(any("generic mechanism" in reason for reason in reasons))

    def test_ready_to_submit_outranks_frontier(self):
        # Strict claim/evidence work is never reordered by curiosity: a
        # ready-to-submit branch with zero novelty still wins.
        ready = {
            "id": "ready",
            "status": "ready_to_submit",
            "priority": "low",
            "priority_score": 0,
        }
        self.assertEqual(self._order([self._frontier_branch(), ready])[0], "ready")

    def test_needs_evidence_outranks_frontier(self):
        evidence = {
            "id": "evidence",
            "status": "needs_evidence",
            "priority": "low",
            "priority_score": 0,
        }
        self.assertEqual(
            self._order([self._frontier_branch(), evidence])[0], "evidence"
        )

    def test_frontier_novelty_outranks_familiar_with_similar_ev(self):
        # Among exploratory branches, a high-novelty frontier branch beats a
        # familiar low-novelty branch that has an *equal-or-better* raw
        # expected-value/proof-cost base. The bounded diversity bonus is the
        # decisive lift — without it the familiar branch would win.
        from reentbotpro.tools import _attack_search_scheduling

        frontier = self._frontier_branch()
        familiar = {
            "id": "familiar",
            "status": "needs_mapping",
            "source": "missing_map",
            "priority": "medium",
            # Tuned so the familiar branch's raw base score is *above* the
            # frontier's; only the curiosity bonus flips the order.
            "priority_score": 4,
            "root_mechanism": "lending",
            "source_artifacts": ["/workspace/campaign/protocol-graphs/pg-001.json"],
        }

        sched_frontier = _attack_search_scheduling(frontier)
        sched_familiar = _attack_search_scheduling(familiar)
        base_frontier = sched_frontier["scheduling_score"] - sched_frontier["diversity_bonus"]
        base_familiar = sched_familiar["scheduling_score"] - sched_familiar["diversity_bonus"]

        # Familiar has the stronger raw EV/PC base, yet loses on total.
        self.assertGreater(base_familiar, base_frontier)
        self.assertGreater(sched_frontier["diversity_bonus"], 0)
        self.assertEqual(sched_familiar["diversity_bonus"], 0)
        self.assertGreater(
            sched_frontier["scheduling_score"], sched_familiar["scheduling_score"]
        )
        self.assertEqual(self._order([familiar, frontier])[0], "frontier")

    def test_frontier_curiosity_does_not_flood_high_value_work(self):
        # A genuinely high-value exploratory branch still outranks a frontier
        # curiosity branch: the capped bonus nudges, it does not dominate.
        high_value = {
            "id": "high_value",
            "status": "needs_harness",
            "source": "hypothesis_without_experiment",
            "priority": "high",
            "priority_score": 18,
            "target_binding": {"live_deployed": True},
            "target_actions": [{"affordances": ["value_out_or_burn"]}],
            "source_artifacts": ["/workspace/campaign/action-spaces/as-001.json"],
        }
        self.assertEqual(
            self._order([self._frontier_branch(), high_value])[0], "high_value"
        )

    def test_parked_frontier_does_not_rise_above_active(self):
        from reentbotpro.tools import _attack_search_scheduling

        parked_frontier = self._frontier_branch(id="pf", status="parked_low_roi")
        active = {
            "id": "active",
            "status": "needs_harness",
            "priority": "low",
            "priority_score": 0,
        }
        self.assertEqual(self._order([parked_frontier, active]), ["active", "pf"])
        # Parked branches are never granted the curiosity bonus.
        sched = _attack_search_scheduling(parked_frontier)
        self.assertEqual(sched["diversity_bonus"], 0)
        self.assertFalse(sched["curiosity_budget_eligible"])

    def test_frontier_branch_cap_respected(self):
        from reentbotpro.tools import (
            _ATTACK_SEARCH_FRONTIER_BRANCH_CAP,
            _attack_search_frontier_candidates,
        )

        attack_graph = {
            "id": "ag-009",
            "frontier": {
                "omitted_by_score": [
                    {
                        "attack_key": f"k{index}",
                        "title": f"Low-signal action {index}",
                        "action_key": f"Mod.f{index}",
                        "contract": "Mod",
                        "function": f"f{index}",
                        "mechanism": "generic_state_transition",
                        "exposure": "source_only",
                        "affordances": ["mapping_state_write"],
                        "priority_score": index,
                        "frontier_reason": "omitted_by_score",
                    }
                    for index in range(8)
                ],
            },
        }
        candidates = _attack_search_frontier_candidates(
            attack_graph,
            "/workspace/campaign/attack-graphs/ag-009.json",
            existing_attack_keys=set(),
            decided_attack_keys=set(),
        )
        self.assertEqual(len(candidates), _ATTACK_SEARCH_FRONTIER_BRANCH_CAP)
        self.assertLessEqual(len(candidates), 3)
        for candidate in candidates:
            self.assertEqual(candidate["source"], "attack_graph_frontier")
            self.assertIn(candidate["priority"], {"medium", "low"})
            self.assertIn(candidate["status"], {
                "needs_context",
                "needs_mapping",
                "needs_harness",
            })
            self.assertTrue(candidate.get("frontier_source"))
            # Exploratory-only framing, never a finding.
            self.assertTrue(
                any("not a finding" in item for item in candidate["required_evidence"])
            )
            self.assertIn("exploratory", candidate["stop_condition"].lower())

    def test_frontier_candidates_skip_existing_and_decided_keys(self):
        from reentbotpro.tools import _attack_search_frontier_candidates

        attack_graph = {
            "id": "ag-010",
            "frontier": {
                "omitted_by_score": [
                    {
                        "attack_key": "live-key",
                        "title": "Already a live candidate",
                        "action_key": "A.live",
                        "contract": "A",
                        "function": "live",
                        "exposure": "source_only",
                        "affordances": ["mapping_state_write"],
                        "frontier_reason": "omitted_by_score",
                    },
                    {
                        "attack_key": "decided-key",
                        "title": "Already decided",
                        "action_key": "A.decided",
                        "contract": "A",
                        "function": "decided",
                        "exposure": "source_only",
                        "affordances": ["mapping_state_write"],
                        "frontier_reason": "omitted_by_score",
                    },
                    {
                        "attack_key": "fresh-key",
                        "title": "Fresh frontier lead",
                        "action_key": "A.fresh",
                        "contract": "A",
                        "function": "fresh",
                        "exposure": "source_only",
                        "affordances": ["mapping_state_write"],
                        "frontier_reason": "omitted_by_score",
                    },
                ],
            },
        }
        candidates = _attack_search_frontier_candidates(
            attack_graph,
            "/workspace/campaign/attack-graphs/ag-010.json",
            existing_attack_keys={"live-key"},
            decided_attack_keys={"decided-key"},
        )
        self.assertEqual([c["attack_keys"] for c in candidates], [["fresh-key"]])

    def test_frontier_status_tracks_blockers(self):
        from reentbotpro.tools import _attack_search_frontier_branch_from_entry

        live_blocked = _attack_search_frontier_branch_from_entry(
            {
                "attack_key": "k-live",
                "title": "needs live context",
                "action_key": "A.f",
                "contract": "A",
                "function": "f",
                "exposure": "source_only",
                "affordances": ["mapping_state_write"],
                "blockers": ["live reachability not mapped"],
            },
            attack_graph_id="ag-1",
            attack_graph_path="/p/ag-1.json",
        )
        self.assertEqual(live_blocked["status"], "needs_mapping")

        structural_ready = _attack_search_frontier_branch_from_entry(
            {
                "attack_key": "k-struct",
                "title": "structural exposed",
                "action_key": "A.g",
                "contract": "A",
                "function": "g",
                "exposure": "exposed",
                "affordances": ["external_call_with_value"],
            },
            attack_graph_id="ag-1",
            attack_graph_path="/p/ag-1.json",
        )
        self.assertEqual(structural_ready["status"], "needs_harness")

        bland = _attack_search_frontier_branch_from_entry(
            {
                "attack_key": "k-bland",
                "title": "bland",
                "action_key": "A.h",
                "contract": "A",
                "function": "h",
                "exposure": "exposed",
                "affordances": [],
            },
            attack_graph_id="ag-1",
            attack_graph_path="/p/ag-1.json",
        )
        self.assertEqual(bland["status"], "needs_context")

    def test_compact_and_dossier_include_novelty_fields(self):
        from reentbotpro.tools import (
            _attack_search_branch_dossier,
            _attack_search_score_branch,
            _compact_attack_branch,
        )

        branch = self._frontier_branch(id="br-101")
        _attack_search_score_branch(branch)

        compact = _compact_attack_branch(branch)
        for field in (
            "novelty_score",
            "diversity_reason",
            "frontier_source",
            "curiosity_budget_eligible",
        ):
            self.assertIn(field, compact)
        self.assertGreater(compact["novelty_score"], 0)

        search = {
            "id": "search-001",
            "focus": "",
            "paths": {"history": "/workspace/campaign/attack-search/search-001.json"},
        }
        dossier = _attack_search_branch_dossier(search, branch)
        for field in (
            "novelty_score",
            "diversity_reason",
            "frontier_source",
            "structural_affordances",
        ):
            self.assertIn(field, dossier)
        self.assertEqual(
            dossier["structural_affordances"],
            ["external_boundary_crossing", "mapping_state_write"],
        )


class ChainHintInferenceTests(unittest.TestCase):
    def test_foundry_broadcast_chain_id_path(self):
        hint = _chain_hint_from_path("broadcast/Deploy.s.sol/8453/run-latest.json")
        self.assertEqual(hint["network"], "base-mainnet")
        self.assertEqual(hint["chain_id"], 8453)

    def test_hardhat_deployments_network_file(self):
        self.assertEqual(
            _chain_hint_from_path("deployments/arbitrum.json")["network"],
            "arb-mainnet",
        )
        self.assertEqual(
            _chain_hint_from_path("contracts/deployments/base/Vault.json")["network"],
            "base-mainnet",
        )

    def test_non_deployment_and_unknown_paths_are_ignored(self):
        self.assertIsNone(_chain_hint_from_path("src/Vault.sol"))
        # An unrecognized network directory is never fabricated into a chain.
        self.assertIsNone(_chain_hint_from_path("deployments/localhost.json"))

    def test_explorer_links_in_text_produce_hints(self):
        hints = _chain_hints_from_text(
            "Deployed at https://basescan.org/address/0x1 and "
            "https://arbiscan.io/address/0x2",
            source="README.md",
        )
        nets = {hint["network"] for hint in hints}
        self.assertEqual(nets, {"base-mainnet", "arb-mainnet"})

    def test_json_keys_grouped_by_chain_with_addresses(self):
        obj = {"base": {"Vault": _ADDR_A}, "arbitrum": {"Vault": _ADDR_B}}
        hints = _chain_hints_from_json_obj(obj, source="deployments/all.json")
        by_net = {h["network"]: h for h in hints}
        self.assertEqual(set(by_net), {"base-mainnet", "arb-mainnet"})
        self.assertEqual(by_net["base-mainnet"]["deployments"][0]["address"], _ADDR_A)

    def test_contract_name_address_map_is_not_a_chain(self):
        # A bare contractName->address map carries no chain signal and must not
        # be misread as chains or flagged ambiguous.
        hints = _chain_hints_from_json_obj(
            {"Vault": _ADDR_A, "Token": _ADDR_B}, source="deployments/base.json"
        )
        self.assertEqual(hints, [])

    def test_unresolved_chain_group_is_marked_ambiguous(self):
        obj = {"base": {"Vault": _ADDR_A}, "myCustomL2": {"Vault": _ADDR_B}}
        hints = _chain_hints_from_json_obj(obj, source="deployments/all.json")
        resolved = [h for h in hints if h.get("network")]
        ambiguous = [h for h in hints if not h.get("network") and h.get("token")]
        self.assertEqual([h["network"] for h in resolved], ["base-mainnet"])
        self.assertEqual(ambiguous[0]["token"], "myCustomL2")


class ChainRegistryBuildTests(unittest.TestCase):
    def test_same_contract_on_multiple_chains_is_explicit(self):
        obj = {"base": {"Vault": _ADDR_A}, "arbitrum": {"Vault": _ADDR_B}}
        hints = _chain_hints_from_json_obj(obj, source="deployments/all.json")
        registry = _build_chain_registry(hints, chain_registry_id="chainreg-001")
        nets = {chain["network"] for chain in registry["chains"]}
        self.assertEqual(nets, {"base-mainnet", "arb-mainnet"})
        for chain in registry["chains"]:
            names = {dep["name"] for dep in chain["deployments"]}
            self.assertIn("Vault", names)
        self.assertEqual(registry["chain_registry_id"], "chainreg-001")

    def test_hints_for_contract_return_all_chains(self):
        obj = {"base": {"Vault": _ADDR_A}, "arbitrum": {"Vault": _ADDR_B}}
        registry = _build_chain_registry(
            _chain_hints_from_json_obj(obj, source="deployments/all.json"),
            chain_registry_id="chainreg-001",
        )
        candidates = _chain_hints_for_address_or_contract(registry, name="Vault")
        self.assertEqual(
            {c["network"] for c in candidates}, {"base-mainnet", "arb-mainnet"}
        )

    def test_hints_for_address_single_chain(self):
        obj = {"base": {"Vault": _ADDR_A}, "arbitrum": {"Pool": _ADDR_B}}
        registry = _build_chain_registry(
            _chain_hints_from_json_obj(obj, source="deployments/all.json"),
            chain_registry_id="chainreg-001",
        )
        candidates = _chain_hints_for_address_or_contract(registry, address=_ADDR_A)
        self.assertEqual([c["network"] for c in candidates], ["base-mainnet"])

    def test_next_chain_registry_id_increments(self):
        self.assertEqual(_next_chain_registry_id(None), "chainreg-001")
        self.assertEqual(
            _next_chain_registry_id({"chain_registry_id": "chainreg-004"}),
            "chainreg-005",
        )


class ChainRegistryArtifactTests(unittest.IsolatedAsyncioTestCase):
    async def test_collect_chain_hints_from_grouped_deployment_files(self):
        container = FakeContainer()
        container.exec_results = [
            (
                0,
                "/audit/deployments/base.json\n"
                "/audit/deployments/arbitrum.json\n",
            )
        ]
        container.files["/audit/deployments/base.json"] = json.dumps({"Vault": _ADDR_A})
        container.files["/audit/deployments/arbitrum.json"] = json.dumps(
            {"Vault": _ADDR_B}
        )

        hints, _notes, scanned = await _collect_chain_hints(container, "/audit")
        registry = _build_chain_registry(hints, chain_registry_id="chainreg-001")
        nets = {chain["network"] for chain in registry["chains"]}
        self.assertEqual(nets, {"base-mainnet", "arb-mainnet"})
        self.assertIn("/audit/deployments/base.json", scanned)

    async def test_latest_chain_registry_round_trips(self):
        container = FakeContainer()
        self.assertIsNone(await _latest_chain_registry(container))
        await _write_chain_registry(
            container, {"chain_registry_id": "chainreg-001", "chains": []}
        )
        self.assertEqual(container.writes[-1][0], _CHAIN_REGISTRY_PATH)
        loaded = await _latest_chain_registry(container)
        self.assertEqual(loaded["chain_registry_id"], "chainreg-001")

    async def test_inspect_scope_records_chain_registry(self):
        container = FakeContainer()
        container.exec_results = [
            (0, ""),  # _default_source_scan_roots (inside _workspace_sol_files)
            (0, ""),  # find *.sol
            (0, ""),  # _default_source_scan_roots (direct)
            (0, ""),  # _artifact_dirs
            (
                0,
                "/audit/deployments/base.json\n"
                "/audit/deployments/arbitrum.json\n",
            ),  # _find_deployment_files
        ]
        container.files["/audit/deployments/base.json"] = json.dumps({"Vault": _ADDR_A})
        container.files["/audit/deployments/arbitrum.json"] = json.dumps(
            {"Vault": _ADDR_B}
        )

        from reentbotpro.tools import _inspect_scope

        result = json.loads(await _inspect_scope(container, {}))
        self.assertIn(_CHAIN_REGISTRY_PATH, container.files)
        self.assertTrue(result["chain_registry"]["multi_chain"])
        self.assertGreaterEqual(result["chain_registry"]["chain_count"], 2)

    async def test_inspect_scope_without_chain_hints_notes_no_binding(self):
        container = FakeContainer()
        result = json.loads(await _inspect_scope(container, {}))
        self.assertNotIn(_CHAIN_REGISTRY_PATH, container.files)
        self.assertEqual(result["chain_registry"]["chain_count"], 0)
        self.assertIn("note", result["chain_registry"])


class ResolveToolRpcEndpointTests(unittest.IsolatedAsyncioTestCase):
    KEY = "alchemy-test-key"

    def _registry_files(self, container, chains):
        registry = _build_chain_registry(chains, chain_registry_id="chainreg-001")
        container.files[_CHAIN_REGISTRY_PATH] = json.dumps(registry)

    async def test_explicit_args_rpc_url_wins(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {"rpc_url": "https://custom.example", "network": "base"},
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(endpoint.url, "https://custom.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)

    async def test_explicit_network_arg_derives_chain(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {"network": "base"},
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.chain_id, 8453)
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertEqual(endpoint.source, "args")

    async def test_explicit_chain_id_arg_derives_chain(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {"chain_id": 42161},
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(endpoint.network, "arb-mainnet")
        self.assertEqual(endpoint.source, "args")

    async def test_unambiguous_registry_binding(self):
        container = FakeContainer()
        self._registry_files(
            container,
            _chain_hints_from_json_obj(
                {"base": {"Vault": _ADDR_A}}, source="deployments/base.json"
            ),
        )
        endpoint = await _resolve_tool_rpc_endpoint(
            container,
            {},
            target_name="Vault",
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertEqual(endpoint.source, "chain_registry")

    async def test_ambiguous_multi_chain_target_is_not_chosen(self):
        container = FakeContainer()
        self._registry_files(
            container,
            _chain_hints_from_json_obj(
                {"base": {"Vault": _ADDR_A}, "arbitrum": {"Vault": _ADDR_B}},
                source="deployments/all.json",
            ),
        )
        endpoint = await _resolve_tool_rpc_endpoint(
            container,
            {},
            target_name="Vault",
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(endpoint.provider, "none")
        self.assertIsNone(endpoint.url)
        self.assertEqual(endpoint.source, "ambiguous_chain_registry")

    async def test_fork_context_used_over_run_default(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {},
            fork_context={"network": "arbitrum"},
            environ={
                "ALCHEMY_API_KEY": self.KEY,
                "REENTBOT_DEFAULT_NETWORK": "base",
            },
            config={},
        )
        self.assertEqual(endpoint.network, "arb-mainnet")
        self.assertEqual(endpoint.source, "fork_context")

    async def test_run_default_used_only_without_better_context(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {},
            environ={
                "ALCHEMY_API_KEY": self.KEY,
                "REENTBOT_DEFAULT_NETWORK": "base",
            },
            config={},
        )
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.source, "env:REENTBOT_DEFAULT_NETWORK")

    async def test_no_chain_with_alchemy_key_returns_no_endpoint(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {},
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
            allow_default_mainnet=False,
        )
        self.assertEqual(endpoint.provider, "none")
        self.assertIsNone(endpoint.url)
        self.assertFalse(endpoint.assumed_default_mainnet)

    async def test_eth_rpc_url_is_fallback_when_no_chain(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {},
            environ={"ETH_RPC_URL": "https://eth.example"},
            config={},
        )
        self.assertEqual(endpoint.url, "https://eth.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertEqual(endpoint.source, "ETH_RPC_URL")

    async def test_resolved_chain_alchemy_beats_eth_rpc_url(self):
        # A correctly resolved chain must not be overridden by a chain-agnostic
        # global ETH_RPC_URL.
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {"network": "base"},
            environ={
                "ALCHEMY_API_KEY": self.KEY,
                "ETH_RPC_URL": "https://eth.example",
            },
            config={},
        )
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertIn("base-mainnet", endpoint.url)

    async def test_allow_default_mainnet_opt_in(self):
        endpoint = await _resolve_tool_rpc_endpoint(
            FakeContainer(),
            {},
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
            allow_default_mainnet=True,
        )
        self.assertEqual(endpoint.network, "eth-mainnet")
        self.assertTrue(endpoint.assumed_default_mainnet)

    async def test_endpoints_for_chains_keys_by_chain_id(self):
        result = await _resolve_tool_rpc_endpoints_for_chains(
            FakeContainer(),
            [{"network": "base"}, {"chain_id": 42161}],
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(set(result), {"8453", "42161"})
        self.assertEqual(result["8453"].network, "base-mainnet")
        self.assertEqual(result["42161"].network, "arb-mainnet")

    def test_rpc_endpoint_summary_omits_url(self):
        summary = _rpc_endpoint_summary(
            ResolvedRpcEndpoint(
                url="https://secret.example",
                provider="alchemy",
                network="base-mainnet",
                chain_id=8453,
                source="chain_registry",
            )
        )
        self.assertEqual(
            set(summary),
            {
                "provider",
                "network",
                "chain_id",
                "source",
                "override",
                "assumed_default_mainnet",
                "configured",
            },
        )
        self.assertNotIn("url", summary)
        self.assertTrue(summary["configured"])

    def test_rpc_endpoint_summary_handles_none(self):
        summary = _rpc_endpoint_summary(None)
        self.assertFalse(summary["configured"])
        self.assertEqual(summary["provider"], "none")


class ExperimentRpcEnvHelpersTests(unittest.TestCase):
    def test_command_needs_rpc_detects_markers(self):
        self.assertTrue(_command_needs_rpc("forge test --fork-url $ETH_RPC_URL"))
        self.assertTrue(_command_needs_rpc("cast call x --rpc-url $RPC_URL_8453"))
        self.assertFalse(_command_needs_rpc("forge test --match-test t -vvv"))
        self.assertFalse(_command_needs_rpc("python3 model.py"))

    def test_network_env_token_normalizes(self):
        self.assertEqual(_network_env_token("base-mainnet"), "BASE_MAINNET")
        self.assertEqual(_network_env_token("arb-mainnet"), "ARB_MAINNET")
        self.assertIsNone(_network_env_token(None))
        self.assertIsNone(_network_env_token(""))

    def test_parse_chain_ref_accepts_dict_name_and_id(self):
        self.assertEqual(
            _parse_chain_ref({"network": "base", "chain_id": 8453}),
            ("base-mainnet", 8453),
        )
        self.assertEqual(_parse_chain_ref("arbitrum"), ("arb-mainnet", 42161))
        self.assertEqual(_parse_chain_ref(8453), ("base-mainnet", 8453))
        self.assertIsNone(_parse_chain_ref(None))
        self.assertIsNone(_parse_chain_ref({}))
        self.assertIsNone(_parse_chain_ref({"network": None, "chain_id": None}))

    def test_target_chain_refs_plain_string_form_is_backward_compatible(self):
        addresses, refs = _sequence_target_chain_refs({"Vault": _ADDR_A})
        self.assertEqual(addresses, [_ADDR_A])
        self.assertEqual(refs, [])

    def test_target_chain_refs_object_form_with_chain_binding(self):
        addresses, refs = _sequence_target_chain_refs({
            "Vault": {"address": _ADDR_A, "network": "base", "chain_id": 8453},
        })
        self.assertEqual(addresses, [_ADDR_A])
        self.assertEqual(refs, [("base-mainnet", 8453)])


class ResolveExperimentRpcEndpointTests(unittest.IsolatedAsyncioTestCase):
    KEY = "alchemy-test-key"
    ENV = {"ALCHEMY_API_KEY": KEY}

    async def test_explicit_rpc_url_override(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {"rpc_url": "http://localhost:8545"},
            command="forge test -vvv",
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertEqual(plan["env"]["ETH_RPC_URL"], "http://localhost:8545")

    async def test_network_arg_injects_eth_rpc_url_and_chain_vars(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {"network": "base"},
            command="forge test --fork-url $ETH_RPC_URL",
            environ=self.ENV,
            config={},
        )
        env = plan["env"]
        self.assertIn("base-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_BASE_MAINNET"])

    async def test_sequence_primary_chain_injects_without_explicit_args(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={"primary_chain": {"network": "base", "chain_id": 8453}},
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertIn("base-mainnet.g.alchemy.com", plan["env"]["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", plan["env"]["RPC_URL_8453"])

    async def test_required_chains_inject_per_chain_endpoints(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={
                "primary_chain": {"network": "base", "chain_id": 8453},
                "required_chains": [
                    {"network": "base-mainnet", "chain_id": 8453},
                    {"network": "arb-mainnet", "chain_id": 42161},
                ],
            },
            environ=self.ENV,
            config={},
        )
        env = plan["env"]
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])
        self.assertIn("arb-mainnet.g.alchemy.com", env["RPC_URL_42161"])
        self.assertIn("RPC_URL_BASE_MAINNET", env)
        self.assertIn("RPC_URL_ARB_MAINNET", env)

    async def test_eth_rpc_url_is_primary_chain_only_when_multi_chain(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {"primary_chain": {"network": "arbitrum", "chain_id": 42161}},
            sequence_payload={
                "required_chains": [
                    {"network": "base-mainnet", "chain_id": 8453},
                    {"network": "arb-mainnet", "chain_id": 42161},
                ],
            },
            environ=self.ENV,
            config={},
        )
        env = plan["env"]
        # ETH_RPC_URL points only at the declared primary (arbitrum), not base.
        self.assertIn("arb-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertNotIn("base-mainnet", env["ETH_RPC_URL"])
        # but both chains still get their own per-chain endpoint.
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])
        self.assertIn("arb-mainnet.g.alchemy.com", env["RPC_URL_42161"])

    async def test_object_target_addresses_single_chain_resolves(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={
                "target_addresses": {
                    "Vault": {"address": _ADDR_A, "network": "base", "chain_id": 8453},
                }
            },
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertIn("base-mainnet.g.alchemy.com", plan["env"]["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", plan["env"]["RPC_URL_8453"])

    async def test_plain_string_targets_without_intent_inject_nothing(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={"target_addresses": {"Vault": _ADDR_A}},
            command="forge test -vvv",
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertEqual(plan["env"], {})

    async def test_multi_chain_targets_without_primary_are_ambiguous(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={
                "target_addresses": {
                    "Vault": {"address": _ADDR_A, "network": "base", "chain_id": 8453},
                    "Pool": {"address": _ADDR_B, "network": "arbitrum", "chain_id": 42161},
                }
            },
            environ=self.ENV,
            config={},
        )
        payload = json.loads(plan["error"])
        self.assertEqual(payload["error"], "chain_ambiguous")
        self.assertEqual(
            {c["network"] for c in payload["candidates"]},
            {"base-mainnet", "arb-mainnet"},
        )

    async def test_multi_chain_targets_with_primary_chain_resolve(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {"primary_chain": {"network": "base", "chain_id": 8453}},
            sequence_payload={
                "target_addresses": {
                    "Vault": {"address": _ADDR_A, "network": "base", "chain_id": 8453},
                    "Pool": {"address": _ADDR_B, "network": "arbitrum", "chain_id": 42161},
                }
            },
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        env = plan["env"]
        self.assertIn("base-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertIn("RPC_URL_8453", env)
        self.assertIn("RPC_URL_42161", env)

    async def test_target_address_binds_chain_via_registry(self):
        container = FakeContainer()
        registry = _build_chain_registry(
            _chain_hints_from_json_obj(
                {"base": {"Vault": _ADDR_A}}, source="deployments/base.json"
            ),
            chain_registry_id="chainreg-001",
        )
        container.files[_CHAIN_REGISTRY_PATH] = json.dumps(registry)
        plan = await _resolve_experiment_rpc_endpoints(
            container,
            {},
            sequence_payload={"target_addresses": {"Vault": _ADDR_A}},
            command="forge test --fork-url $ETH_RPC_URL",
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertIn("base-mainnet.g.alchemy.com", plan["env"]["ETH_RPC_URL"])

    async def test_no_rpc_intent_returns_empty_plan(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            command="forge build",
            environ=self.ENV,
            config={},
        )
        self.assertIsNone(plan["error"])
        self.assertEqual(plan["env"], {})
        self.assertIsNone(plan["metadata"]["primary"])

    async def test_declared_chain_without_endpoint_is_rpc_not_configured(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {},
            sequence_payload={"primary_chain": {"network": "base", "chain_id": 8453}},
            environ={},
            config={},
        )
        payload = json.loads(plan["error"])
        self.assertEqual(payload["error"], "rpc_not_configured")

    async def test_metadata_never_exposes_raw_url(self):
        plan = await _resolve_experiment_rpc_endpoints(
            FakeContainer(),
            {"network": "base"},
            environ=self.ENV,
            config={},
        )
        self.assertNotIn(self.KEY, json.dumps(plan["metadata"]))
        self.assertNotIn("alchemy.com", json.dumps(plan["metadata"]))


class RunExperimentRpcInjectionTests(unittest.IsolatedAsyncioTestCase):
    KEY = "alchemy-test-key"
    ENV = {"ALCHEMY_API_KEY": KEY}

    async def test_run_experiment_injects_chain_env_for_network_arg(self):
        container = FakeContainer()
        result = await _run_experiment(
            container,
            {
                "command": "forge test --fork-url $ETH_RPC_URL",
                "network": "base",
                "record_result": False,
            },
            environ=self.ENV,
            config={},
        )
        env = container.exec_envs[0]
        self.assertIn("base-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])
        # compact response names the chain but leaks no key/url.
        self.assertIn("base-mainnet", result)
        self.assertNotIn(self.KEY, result)

    async def test_run_experiment_explicit_rpc_url_override(self):
        container = FakeContainer()
        await _run_experiment(
            container,
            {
                "command": "forge test -vvv",
                "rpc_url": "http://localhost:8545",
                "record_result": False,
            },
            environ=self.ENV,
            config={},
        )
        self.assertEqual(container.exec_envs[0]["ETH_RPC_URL"], "http://localhost:8545")

    async def test_run_experiment_fork_command_without_endpoint_blocks(self):
        container = FakeContainer()
        result = await _run_experiment(
            container,
            {
                "command": "forge test --fork-url $ETH_RPC_URL",
                "network": "base",
                "record_result": False,
            },
            environ={},
            config={},
        )
        payload = json.loads(result)
        self.assertEqual(payload["error"], "rpc_not_configured")
        # the command must not run against an implicit default endpoint.
        self.assertEqual(container.exec_calls, [])

    async def test_run_experiment_non_fork_command_injects_nothing(self):
        container = FakeContainer()
        await _run_experiment(
            container,
            {"command": "forge build", "record_result": False},
            environ=self.ENV,
            config={},
        )
        self.assertEqual(len(container.exec_calls), 1)
        self.assertIsNone(container.exec_envs[0])

    async def test_run_experiment_derives_chain_from_sequence_metadata(self):
        container = FakeContainer()
        await _compose_sequence_experiment(container, {
            "title": "Fork vault replay",
            "objective": "Replay a value-moving vault sequence on a fork.",
            "actions": [{
                "actor": "attacker",
                "contract": "Vault",
                "function": "withdraw",
                "args": ["amount"],
            }],
            "target_addresses": {"Vault": _ADDR_A},
            "success_condition": "Vault assets decrease unexpectedly.",
        })
        seq_key = next(
            key for key in container.files if key.endswith("/sequence.json")
        )
        payload = json.loads(container.files[seq_key])
        payload["primary_chain"] = {"network": "base", "chain_id": 8453}
        container.files[seq_key] = json.dumps(payload)

        await _run_experiment(
            container,
            {
                "command": "forge test --match-contract ReentbotProSequence -vvv",
                "experiment_id": "exp-001",
                "record_result": False,
            },
            environ=self.ENV,
            config={},
        )
        env = container.exec_envs[0]
        self.assertIsNotNone(env)
        self.assertIn("base-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])

    async def test_run_experiment_records_rpc_endpoints_metadata(self):
        container = FakeContainer()
        await _run_experiment(
            container,
            {
                "command": "forge test --fork-url $ETH_RPC_URL",
                "network": "base",
            },
            environ=self.ENV,
            config={},
        )
        state = container.files[_CAMPAIGN_STATE_PATH]
        self.assertIn('"rpc_endpoints"', state)
        # the durable artifact records provenance, never the key-bearing URL.
        self.assertNotIn(self.KEY, state)
        self.assertNotIn("alchemy.com", state)

    async def test_run_sequence_minimization_injects_chain_env(self):
        container = FakeContainer()
        seq_path = "/workspace/experiments/exp-min/sequence.json"
        container.files[seq_path] = json.dumps({
            "id": "exp-min",
            "primary_chain": {"network": "base", "chain_id": 8453},
        })
        container.exec_result = (0, "OBJECTIVE_PASS\n")
        await _run_sequence_minimization(
            container,
            {
                "sequence": seq_path,
                "baseline": {
                    "command": "forge test --fork-url $ETH_RPC_URL",
                    "expected_markers": ["OBJECTIVE_PASS"],
                },
                "variants": [],
                "setup_checks": [],
                "record_result": False,
            },
            environ=self.ENV,
            config={},
        )
        env = container.exec_envs[0]
        self.assertIn("base-mainnet.g.alchemy.com", env["ETH_RPC_URL"])
        self.assertIn("base-mainnet.g.alchemy.com", env["RPC_URL_8453"])


class GeneratedForkTemplateRpcDocsTests(unittest.TestCase):
    def test_fork_template_documents_run_experiment_injected_env(self):
        contract = _foundry_template_contract("fork_test", "Fork probe")
        self.assertIn("injected by run_experiment", contract)
        self.assertIn('vm.envString("ETH_RPC_URL")', contract)
        self.assertIn('RPC_URL_8453', contract)

    def test_experiment_readme_documents_injected_env(self):
        readme = _experiment_readme(
            artifact_id="exp-001",
            title="Fork probe",
            template="fork_test",
            notes="",
            related_ids=[],
        )
        self.assertIn("You do not export `ETH_RPC_URL` by hand", readme)
        self.assertIn("RPC_URL_<chain_id>", readme)
        self.assertIn("RPC_URL_BASE_MAINNET", readme)


class ToolRpcResolutionWiringTests(unittest.IsolatedAsyncioTestCase):
    """The state/economics tools resolve RPC via the shared chain-aware resolver
    (explicit args > fork context > registry binding > run defaults), never an
    implicit global default, and keep raw key-bearing URLs out of artifacts."""

    KEY = "alchemy-test-key"
    ALCHEMY_ENV = {"ALCHEMY_API_KEY": KEY}

    def _registry(self, container, *grouped):
        hints = []
        for index, group in enumerate(grouped):
            hints += _chain_hints_from_json_obj(group, source=f"deployments/{index}.json")
        registry = _build_chain_registry(hints, chain_registry_id="chainreg-001")
        container.files[_CHAIN_REGISTRY_PATH] = json.dumps(registry)

    # ── record_fork_context ──────────────────────────────────────────────
    async def test_record_fork_context_derives_endpoint_from_network_arg(self):
        container = FakeContainer()
        container.exec_results = [(0, "8453"), (0, "20000000"), (0, "0x6001600055")]
        result = json.loads(await _record_fork_context(
            container,
            {
                "title": "Base fork",
                "network": "base",
                "validate": True,
                "probe_token_metadata": False,
                "contracts": [{"label": "Vault", "address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["rpc_endpoint"]["network"], "base-mainnet")
        self.assertEqual(result["rpc_endpoint"]["provider"], "alchemy")
        self.assertTrue(result["validation"]["executed"])
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])
        # Artifact carries the provenance summary but not the key-bearing URL.
        context = container.files["/workspace/campaign/fork-contexts/fc-001.json"]
        self.assertNotIn(self.KEY, context)
        self.assertIn("<rpc_url>", context)
        self.assertIn('"rpc_endpoint"', context)

    async def test_record_fork_context_infers_chain_from_registry_target(self):
        container = FakeContainer()
        self._registry(container, {"base": {"Vault": _ADDR_A}})
        container.exec_results = [(0, "8453"), (0, "20000000"), (0, "0x6001600055")]
        result = json.loads(await _record_fork_context(
            container,
            {
                "title": "Inferred base fork",
                "validate": True,
                "probe_token_metadata": False,
                "contracts": [{"label": "Vault", "address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["rpc_endpoint"]["network"], "base-mainnet")
        self.assertEqual(result["rpc_endpoint"]["source"], "chain_registry")
        self.assertEqual(result["chain_evidence"]["source"], "chain_registry")
        self.assertTrue(result["validation"]["executed"])
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])

    async def test_record_fork_context_ambiguous_chain_is_not_chosen(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"Vault": _ADDR_A}}, {"arbitrum": {"Vault": _ADDR_A}}
        )
        result = json.loads(await _record_fork_context(
            container,
            {
                "title": "Ambiguous fork",
                "validate": True,
                "contracts": [{"label": "Vault", "address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertFalse(result["validation"]["executed"])
        self.assertEqual(result["validation"]["error"], "chain_ambiguous")
        self.assertTrue(result["validation"]["candidates"])
        self.assertEqual(result["rpc_endpoint"]["provider"], "none")
        # No silent fallback chain means no probes ran.
        self.assertEqual(container.exec_calls, [])

    # ── snapshot_state ───────────────────────────────────────────────────
    async def test_snapshot_state_derives_endpoint_from_network_arg(self):
        container = FakeContainer()
        container.exec_results = [(0, "100\n")]
        result = json.loads(await _snapshot_state(
            container,
            {
                "title": "Base snapshot",
                "network": "base",
                "eth_balances": [{"label": "a", "address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["snapshot_id"], "snap-001")
        self.assertEqual(result["rpc_endpoint"]["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])
        snapshot = container.files["/workspace/campaign/snapshots/snap-001.json"]
        self.assertNotIn(self.KEY, snapshot)
        self.assertIn('"rpc_endpoint"', snapshot)

    async def test_snapshot_state_infers_chain_from_registry_target(self):
        container = FakeContainer()
        self._registry(container, {"base": {"Vault": _ADDR_A}})
        container.exec_results = [(0, "0xabc\n")]
        result = json.loads(await _snapshot_state(
            container,
            {
                "title": "Registry snapshot",
                "calls": [{
                    "label": "x",
                    "target": _ADDR_A,
                    "signature": "totalAssets()(uint256)",
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["rpc_endpoint"]["source"], "chain_registry")
        self.assertEqual(result["rpc_endpoint"]["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])

    async def test_snapshot_state_multi_chain_target_requires_explicit_chain(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"Vault": _ADDR_A}}, {"arbitrum": {"Vault": _ADDR_A}}
        )
        probe = {
            "calls": [{
                "label": "x",
                "target": _ADDR_A,
                "signature": "totalAssets()(uint256)",
            }],
            "record_result": False,
        }
        ambiguous = json.loads(await _snapshot_state(
            container,
            {"title": "Ambiguous", **probe},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(ambiguous["error"], "chain_ambiguous")
        self.assertTrue(ambiguous["candidates"])
        self.assertIn("unambiguous deployment chain binding", ambiguous["message"])
        self.assertEqual(container.exec_calls, [])

        # Supplying the chain disambiguates and the snapshot runs.
        container2 = FakeContainer()
        self._registry(
            container2, {"base": {"Vault": _ADDR_A}}, {"arbitrum": {"Vault": _ADDR_A}}
        )
        container2.exec_results = [(0, "0xabc\n")]
        ok = json.loads(await _snapshot_state(
            container2,
            {"title": "Disambiguated", "chain_id": 8453, **probe},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(ok["snapshot_id"], "snap-001")
        self.assertEqual(ok["rpc_endpoint"]["chain_id"], 8453)

    async def test_snapshot_state_uses_fork_context_arg_chain(self):
        container = FakeContainer()
        container.files["/workspace/campaign/fork-contexts/fc-001.json"] = json.dumps(
            {"id": "fc-001", "network": "arbitrum", "chain_id": 42161}
        )
        container.exec_results = [(0, "100\n")]
        result = json.loads(await _snapshot_state(
            container,
            {
                "title": "Fork-context snapshot",
                "fork_context": "fc-001",
                "eth_balances": [{"address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["rpc_endpoint"]["network"], "arb-mainnet")
        self.assertEqual(result["rpc_endpoint"]["source"], "fork_context")

    # ── estimate_amm_economics ───────────────────────────────────────────
    async def test_estimate_amm_economics_manual_reserves_need_no_rpc(self):
        container = FakeContainer()
        result = json.loads(await _estimate_amm_economics(
            container,
            {
                "title": "Manual",
                "pools": [{
                    "reserve_in": "10000",
                    "reserve_out": "20000",
                    "amount_in": "1000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                }],
                "record_result": False,
            },
            environ={},
            config={},
        ))
        self.assertEqual(result["economics_id"], "econ-001")
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(result["legs"][0]["reserve_source"]["source"], "manual")

    async def test_estimate_amm_economics_onchain_reserves_derive_endpoint(self):
        # Explicit chain arg derives the endpoint.
        container = FakeContainer()
        container.exec_results = [(0, "10000\n20000\n12345\n")]
        result = json.loads(await _estimate_amm_economics(
            container,
            {
                "network": "base",
                "pools": [{
                    "pair": _ADDR_A,
                    "amount_in": "1000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        leg = result["legs"][0]
        self.assertEqual(leg["reserve_source"]["rpc_endpoint"]["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])
        self.assertNotIn(self.KEY, json.dumps(result))
        economics = container.files["/workspace/campaign/economics/econ-001.json"]
        self.assertNotIn(self.KEY, economics)

        # Registry binding derives the endpoint with no explicit chain.
        container2 = FakeContainer()
        self._registry(container2, {"base": {"Pool": _ADDR_A}})
        container2.exec_results = [(0, "10000\n20000\n12345\n")]
        result2 = json.loads(await _estimate_amm_economics(
            container2,
            {
                "pools": [{
                    "pair": _ADDR_A,
                    "amount_in": "1000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(
            result2["legs"][0]["reserve_source"]["rpc_endpoint"]["source"],
            "chain_registry",
        )

    async def test_estimate_amm_economics_ambiguous_pool_chain(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"Pool": _ADDR_A}}, {"arbitrum": {"Pool": _ADDR_A}}
        )
        result = json.loads(await _estimate_amm_economics(
            container,
            {
                "pools": [{"pair": _ADDR_A, "amount_in": "1000", "fee_bps": 30}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["error"], "chain_ambiguous")
        self.assertEqual(result["address"], _ADDR_A)
        self.assertTrue(result["candidates"])
        self.assertEqual(container.exec_calls, [])

    # ── estimate_flash_loan ──────────────────────────────────────────────
    async def test_estimate_flash_loan_manual_liquidity_needs_no_rpc(self):
        container = FakeContainer()
        result = json.loads(await _estimate_flash_loan(
            container,
            {
                "assets": [{
                    "symbol": "USDC",
                    "amount_decimal": "1000",
                    "decimals": 6,
                    "fee_bps": 9,
                    "available_liquidity_decimal": "5000",
                    "price_usd": "1",
                }],
                "record_result": False,
            },
            environ={},
            config={},
        ))
        self.assertEqual(result["flash_loan_id"], "flash-001")
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(result["assets"][0]["liquidity_source"]["source"], "manual")

    async def test_estimate_flash_loan_provider_lookup_derives_endpoint(self):
        container = FakeContainer()
        container.exec_results = [(0, "2500000000\n")]
        result = json.loads(await _estimate_flash_loan(
            container,
            {
                "network": "base",
                "assets": [{
                    "symbol": "USDC",
                    "asset": _ADDR_A,
                    "provider": _ADDR_B,
                    "amount_decimal": "1000",
                    "decimals": 6,
                    "fee_bps": 5,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        source = result["assets"][0]["liquidity_source"]
        self.assertEqual(source["rpc_endpoint"]["network"], "base-mainnet")
        self.assertIn("base-mainnet.g.alchemy.com", container.exec_calls[0][0])
        self.assertNotIn(self.KEY, json.dumps(result))
        estimate = container.files["/workspace/campaign/economics/flash-001.json"]
        self.assertNotIn(self.KEY, estimate)

    async def test_estimate_flash_loan_ambiguous_provider_chain(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"USDC": _ADDR_A}}, {"arbitrum": {"USDC": _ADDR_A}}
        )
        result = json.loads(await _estimate_flash_loan(
            container,
            {
                "assets": [{
                    "symbol": "USDC",
                    "asset": _ADDR_A,
                    "provider": _ADDR_B,
                    "amount_decimal": "1000",
                    "decimals": 6,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(result["error"], "chain_ambiguous")
        self.assertTrue(result["candidates"])
        self.assertEqual(container.exec_calls, [])

    # ── explicit override across all four tools ──────────────────────────
    async def test_explicit_rpc_url_overrides_derived_endpoint(self):
        override = "https://override.example/secret"

        fork = FakeContainer()
        fork.exec_results = [(0, "1"), (0, "100"), (0, "0x6001")]
        fork_result = json.loads(await _record_fork_context(
            fork,
            {
                "title": "Override",
                "network": "base",
                "rpc_url": override,
                "validate": True,
                "probe_token_metadata": False,
                "contracts": [{"label": "Vault", "address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertTrue(fork_result["rpc_endpoint"]["override"])
        self.assertEqual(fork_result["rpc_endpoint"]["provider"], "explicit")
        self.assertIn("override.example", fork.exec_calls[0][0])
        self.assertNotIn("g.alchemy.com", fork.exec_calls[0][0])

        snap = FakeContainer()
        snap.exec_results = [(0, "100\n")]
        snap_result = json.loads(await _snapshot_state(
            snap,
            {
                "title": "Override",
                "network": "base",
                "rpc_url": override,
                "eth_balances": [{"address": _ADDR_A}],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertTrue(snap_result["rpc_endpoint"]["override"])
        self.assertIn("override.example", snap.exec_calls[0][0])
        self.assertNotIn("g.alchemy.com", snap.exec_calls[0][0])

        amm = FakeContainer()
        amm.exec_results = [(0, "10000\n20000\n1\n")]
        amm_result = json.loads(await _estimate_amm_economics(
            amm,
            {
                "network": "base",
                "rpc_url": override,
                "pools": [{
                    "pair": _ADDR_A,
                    "amount_in": "1000",
                    "fee_bps": 30,
                    "token_in_decimals": 0,
                    "token_out_decimals": 0,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertTrue(amm_result["legs"][0]["reserve_source"]["rpc_endpoint"]["override"])
        self.assertIn("override.example", amm.exec_calls[0][0])
        self.assertNotIn("g.alchemy.com", amm.exec_calls[0][0])

        flash = FakeContainer()
        flash.exec_results = [(0, "2500000000\n")]
        flash_result = json.loads(await _estimate_flash_loan(
            flash,
            {
                "network": "base",
                "rpc_url": override,
                "assets": [{
                    "symbol": "USDC",
                    "asset": _ADDR_A,
                    "provider": _ADDR_B,
                    "amount_decimal": "1000",
                    "decimals": 6,
                }],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertTrue(
            flash_result["assets"][0]["liquidity_source"]["rpc_endpoint"]["override"]
        )
        self.assertIn("override.example", flash.exec_calls[0][0])
        self.assertNotIn("g.alchemy.com", flash.exec_calls[0][0])


class LiveProbeChainGroupingTests(unittest.IsolatedAsyncioTestCase):
    """The large live-probe tools (map_live_reachability, inventory_live_targets)
    group targets by chain, derive a per-chain endpoint, and report ambiguity /
    missing endpoints instead of probing the wrong chain or a global RPC."""

    KEY = "alchemy-test-key"
    ALCHEMY_ENV = {"ALCHEMY_API_KEY": KEY}
    PROBE_OUTPUT = (0, "code=0x60006000\nnative_balance=10\n")

    def _registry(self, container, *grouped):
        hints = []
        for index, group in enumerate(grouped):
            hints += _chain_hints_from_json_obj(group, source=f"deployments/{index}.json")
        registry = _build_chain_registry(hints, chain_registry_id="chainreg-001")
        container.files[_CHAIN_REGISTRY_PATH] = json.dumps(registry)

    def _scope_manifest(self, container, *profiles):
        container.files["/workspace/campaign/scope-manifest.json"] = json.dumps({
            "ranked_profiles": [
                {
                    "profile": f"contract_{contract}_{addr[-4:]}",
                    "contract": contract,
                    "address": addr,
                    "src": f"/audit/src/{contract}_{addr[-4:]}",
                }
                for contract, addr in profiles
            ],
        })

    @staticmethod
    def _commands(container):
        return [call[0] for call in container.exec_calls]

    # ── inventory_live_targets ───────────────────────────────────────────
    async def test_inventory_groups_targets_by_chain(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"VaultA": _ADDR_A}}, {"arbitrum": {"VaultB": _ADDR_B}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _inventory_live_targets(
            container,
            {
                "targets": [
                    {"label": "VaultA", "address": _ADDR_A},
                    {"label": "VaultB", "address": _ADDR_B},
                ],
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        # Each target is probed against its own chain's derived endpoint.
        commands = self._commands(container)
        self.assertTrue(any("base-mainnet.g.alchemy.com" in c for c in commands))
        self.assertTrue(any("arb-mainnet.g.alchemy.com" in c for c in commands))
        self.assertEqual(payload["summary"]["chains_probed"], 2)
        self.assertEqual(payload["summary"]["ambiguous_targets"], 0)
        self.assertEqual(payload["targets_by_chain"]["8453"], [_ADDR_A])
        self.assertEqual(payload["targets_by_chain"]["42161"], [_ADDR_B])
        by_chain = {block["chain_id"]: block for block in payload["chains_probed"]}
        self.assertEqual(by_chain[8453]["network"], "base-mainnet")
        self.assertEqual(by_chain[42161]["network"], "arb-mainnet")
        # The artifact preserves chain grouping with a per-chain rpc_endpoint
        # summary and never leaks the key-bearing URL.
        artifact = json.loads(
            container.files["/workspace/campaign/live-inventory/linv-001.json"]
        )
        self.assertEqual(len(artifact["chains"]), 2)
        artifact_chain = {c["chain_id"]: c for c in artifact["chains"]}
        self.assertEqual(artifact_chain[8453]["rpc_endpoint"]["network"], "base-mainnet")
        self.assertEqual(artifact_chain[8453]["targets"], [_ADDR_A])
        self.assertEqual(artifact["ambiguous_targets"], [])
        self.assertNotIn(self.KEY, json.dumps(artifact))

    async def test_inventory_multi_chain_target_is_ambiguous(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"Vault": _ADDR_A}}, {"arbitrum": {"Vault": _ADDR_A}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _inventory_live_targets(
            container,
            {"targets": [{"label": "Vault", "address": _ADDR_A}], "record_result": False},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        # A target the registry maps to two chains is never probed arbitrarily.
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(payload["summary"]["ambiguous_targets"], 1)
        self.assertEqual(payload["ambiguous_targets"][0]["address"], _ADDR_A)
        self.assertEqual(len(payload["ambiguous_targets"][0]["candidates"]), 2)
        self.assertEqual(payload["chains_probed"], [])

    async def test_inventory_explicit_network_filters_other_chain(self):
        container = FakeContainer()
        self._registry(
            container, {"base": {"VaultA": _ADDR_A}}, {"arbitrum": {"VaultB": _ADDR_B}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _inventory_live_targets(
            container,
            {
                "targets": [
                    {"label": "VaultA", "address": _ADDR_A},
                    {"label": "VaultB", "address": _ADDR_B},
                ],
                "network": "base",
                "record_result": False,
            },
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        commands = self._commands(container)
        # Only Base is probed; the Arbitrum-bound target is filtered, not probed.
        self.assertTrue(any("base-mainnet.g.alchemy.com" in c for c in commands))
        self.assertFalse(any("arb-mainnet" in c for c in commands))
        self.assertEqual(payload["summary"]["chains_probed"], 1)
        skipped = {item["address"]: item for item in payload["skipped_targets"]}
        self.assertEqual(skipped[_ADDR_B]["reason"], "chain_mismatch")
        self.assertEqual(skipped[_ADDR_B]["requested_chain"]["network"], "base-mainnet")

    async def test_inventory_execute_probes_false_needs_no_endpoint(self):
        container = FakeContainer()
        self._registry(container, {"base": {"VaultA": _ADDR_A}})
        payload = json.loads(await _inventory_live_targets(
            container,
            {
                "targets": [{"label": "VaultA", "address": _ADDR_A}],
                "execute_probes": False,
                "record_result": False,
            },
            environ={},
            config={},
        ))
        # No endpoint required: grouped by chain, nothing probed or skipped.
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(payload["targets_by_chain"]["8453"], [_ADDR_A])
        self.assertEqual(payload["summary"]["skipped_targets"], 0)
        self.assertEqual(payload["summary"]["ambiguous_targets"], 0)

    async def test_inventory_missing_endpoint_marks_rpc_not_configured(self):
        container = FakeContainer()
        self._registry(container, {"base": {"VaultA": _ADDR_A}})
        payload = json.loads(await _inventory_live_targets(
            container,
            {"targets": [{"label": "VaultA", "address": _ADDR_A}], "record_result": False},
            environ={},  # chain resolves to Base, but no Alchemy key -> no endpoint
            config={},
        ))
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(payload["summary"]["skipped_targets"], 1)
        self.assertEqual(payload["skipped_targets"][0]["reason"], "rpc_not_configured")
        self.assertEqual(payload["summary"]["rpc_missing"], 1)
        # The legacy global-RPC sentinel never appears anywhere.
        artifact = container.files["/workspace/campaign/live-inventory/linv-001.json"]
        self.assertNotIn("__NO_ETH_RPC_URL__", artifact)

    # ── map_live_reachability ────────────────────────────────────────────
    async def test_map_groups_profiles_by_chain(self):
        container = FakeContainer()
        self._scope_manifest(container, ("Market", _ADDR_A), ("Market", _ADDR_B))
        self._registry(
            container, {"base": {"Market": _ADDR_A}}, {"arbitrum": {"Market": _ADDR_B}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _map_live_reachability(
            container,
            {"record_result": False},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        commands = self._commands(container)
        self.assertTrue(any("base-mainnet.g.alchemy.com" in c for c in commands))
        self.assertTrue(any("arb-mainnet.g.alchemy.com" in c for c in commands))
        self.assertEqual(payload["summary"]["chains_probed"], 2)
        self.assertEqual(payload["targets_by_chain"]["8453"], [_ADDR_A])
        self.assertEqual(payload["targets_by_chain"]["42161"], [_ADDR_B])
        artifact = json.loads(
            container.files["/workspace/campaign/live-reachability/lr-001.json"]
        )
        artifact_chain = {c["chain_id"]: c for c in artifact["chains"]}
        self.assertEqual(artifact_chain[42161]["rpc_endpoint"]["network"], "arb-mainnet")
        self.assertNotIn(self.KEY, json.dumps(artifact))

    async def test_map_multi_chain_profile_is_ambiguous(self):
        container = FakeContainer()
        self._scope_manifest(container, ("Market", _ADDR_A))
        self._registry(
            container, {"base": {"Market": _ADDR_A}}, {"arbitrum": {"Market": _ADDR_A}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _map_live_reachability(
            container,
            {"record_result": False},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(payload["summary"]["ambiguous_targets"], 1)
        self.assertEqual(payload["ambiguous_targets"][0]["address"], _ADDR_A)
        self.assertEqual(payload["chains_probed"], [])

    async def test_map_explicit_network_filters_other_chain(self):
        container = FakeContainer()
        self._scope_manifest(container, ("Market", _ADDR_A), ("Market", _ADDR_B))
        self._registry(
            container, {"base": {"Market": _ADDR_A}}, {"arbitrum": {"Market": _ADDR_B}}
        )
        container.exec_result = self.PROBE_OUTPUT
        payload = json.loads(await _map_live_reachability(
            container,
            {"network": "base", "record_result": False},
            environ=self.ALCHEMY_ENV,
            config={},
        ))
        commands = self._commands(container)
        self.assertTrue(any("base-mainnet.g.alchemy.com" in c for c in commands))
        self.assertFalse(any("arb-mainnet" in c for c in commands))
        self.assertEqual(payload["summary"]["chains_probed"], 1)
        skipped = {item["address"]: item for item in payload["skipped_targets"]}
        self.assertEqual(skipped[_ADDR_B]["reason"], "chain_mismatch")

    async def test_map_missing_endpoint_marks_rpc_not_configured(self):
        container = FakeContainer()
        self._scope_manifest(container, ("Market", _ADDR_A))
        self._registry(container, {"base": {"Market": _ADDR_A}})
        payload = json.loads(await _map_live_reachability(
            container,
            {"record_result": False},
            environ={},  # Base resolves, but no Alchemy key -> no endpoint
            config={},
        ))
        self.assertEqual(container.exec_calls, [])
        self.assertEqual(payload["summary"]["skipped_targets"], 1)
        self.assertEqual(payload["skipped_targets"][0]["reason"], "rpc_not_configured")
        self.assertEqual(payload["summary"]["rpc_missing"], 1)
        artifact = container.files["/workspace/campaign/live-reachability/lr-001.json"]
        self.assertNotIn("__NO_ETH_RPC_URL__", artifact)


if __name__ == "__main__":
    unittest.main()
