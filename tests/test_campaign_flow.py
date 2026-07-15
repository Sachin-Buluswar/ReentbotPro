import json
import unittest

from reentbotpro.tools import (
    _CAMPAIGN_STATE_PATH,
    _attack_search,
    _compare_snapshots,
    _complete_sequence_experiment,
    _compose_sequence_experiment,
    _evaluate_objective,
    _map_action_space,
    _mutate_hypothesis,
    _record_fork_context,
    _review_finding_evidence,
    _review_report_quality,
    _run_experiment,
    _snapshot_state,
    _submit_finding,
    _summarize_trace,
    _update_campaign,
)


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


def _json_result(raw: str) -> dict:
    assert not raw.startswith("Error:"), raw
    return json.loads(raw)


def _exploitability_fields() -> dict:
    return {
        "preconditions": [
            (
                "The unprivileged attacker can donate, deposit, and redeem "
                "against the deployed vault with attacker-owned ERC20 funds."
            )
        ],
        "precondition_provenance": [{
            "precondition": "Attacker-controlled donation, deposit, and redeem calls",
            "provenance": "attacker_controlled",
            "evidence": (
                "The fork replay uses only attacker-signed public calls and "
                "eval-001 measures the resulting attacker balance delta."
            ),
        }],
        "production_reachability": (
            "The fork context binds the DonationVault target, and the PoC calls "
            "the same public donate, deposit, and redeem entrypoints exposed by "
            "the deployed contract."
        ),
        "funds_at_risk": (
            "eval-001 records nonzero attacker profit against vault assets in "
            "the fork campaign."
        ),
        "negative_controls": [
            "The before/after snapshots are compared against the stated profit objective."
        ],
    }


class AttackCampaignFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_validated_attack_campaign_flow_preserves_evidence_chain(self):
        container = FakeContainer()
        container.files["/audit/src/DonationVault.sol"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract DonationVault {
    IERC20 public asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    event Donated(address indexed from, uint256 amount);
    event Deposited(address indexed from, uint256 amount, uint256 minted);
    event Redeemed(address indexed from, uint256 sharesBurned, uint256 assetsOut);

    function donate(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        emit Donated(msg.sender, amount);
    }

    function deposit(uint256 amount) external {
        uint256 assetsBefore = asset.balanceOf(address(this));
        asset.transferFrom(msg.sender, address(this), amount);
        uint256 minted = totalShares == 0 ? amount : amount * totalShares / assetsBefore;
        shares[msg.sender] += minted;
        totalShares += minted;
        emit Deposited(msg.sender, amount, minted);
    }

    function redeem(uint256 shareAmount) external {
        uint256 assetsOut = shareAmount * asset.balanceOf(address(this)) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        asset.transfer(msg.sender, assetsOut);
        emit Redeemed(msg.sender, shareAmount, assetsOut);
    }

    function totalAssets() external view returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
"""

        for section, title, content in (
            (
                "protocol_model",
                "DonationVault accepts external asset transfers",
                "The vault prices shares from current token balance and totalShares.",
            ),
            (
                "value_flow",
                "Attacker can move asset balance before minting shares",
                "donate, deposit, and redeem all move the same underlying asset.",
            ),
            (
                "invariant",
                "Redeem cannot return more assets than attacker contributed",
                "For unprivileged actors, post-sequence asset balance should not increase.",
            ),
            (
                "hypothesis",
                "Donation sequence can inflate first depositor redemption",
                "Donate before a tiny deposit, then redeem shares against donated assets.",
            ),
        ):
            raw = await _update_campaign(container, {
                "section": section,
                "title": title,
                "content": content,
                "priority": "high" if section == "hypothesis" else "medium",
            })
            self.assertNotIn("Error:", raw)

        action_space = _json_result(await _map_action_space(container, {
            "files": ["/audit/src/DonationVault.sol"],
            "related_ids": ["pm-001", "vf-001"],
        }))
        self.assertEqual(action_space["action_space_id"], "as-001")
        self.assertGreaterEqual(action_space["summary"]["actions"], 3)
        action_names = {item["function"] for item in action_space["actions"]}
        self.assertTrue({"donate", "deposit", "redeem"}.issubset(action_names))

        usdc = "0x0000000000000000000000000000000000000001"
        attacker = "0x0000000000000000000000000000000000000a11"
        fork_context = _json_result(await _record_fork_context(container, {
            "title": "DonationVault local fork context",
            "network": "local-mainnet-fork",
            "fork_block": 19000000,
            "contracts": [{
                "label": "DonationVault",
                "address": "0x000000000000000000000000000000000000dead",
                "kind": "vault",
            }],
            "tokens": [{
                "symbol": "USDC",
                "address": usdc,
                "decimals": 6,
            }],
            "actors": [{
                "label": "attacker",
                "address": attacker,
            }],
            "assumptions": ["Addresses are fixture bindings for the simulated campaign."],
            "related_ids": ["hyp-001", "as-001"],
            "record_result": False,
        }))
        self.assertEqual(fork_context["context_id"], "fc-001")
        self.assertEqual(
            fork_context["target_addresses"]["DonationVault"],
            "0x000000000000000000000000000000000000dead",
        )

        sequence = _json_result(await _compose_sequence_experiment(container, {
            "title": "Donate deposit redeem profit sequence",
            "objective": "Show that an unprivileged attacker ends with more USDC.",
            "action_space": "as-001",
            "fork_context": "fc-001",
            "hypothesis_id": "hyp-001",
            "invariant_id": "inv-001",
            "setup": "Seed attacker and vault with a mock ERC20 on a local fork/test.",
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "donate",
                    "args": ["donationAmount"],
                    "expected_effect": "increase vault assets without minting shares",
                },
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "deposit",
                    "args": ["1"],
                    "expected_effect": "mint shares using donated balance",
                },
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "redeem",
                    "args": ["attackerShares"],
                    "expected_effect": "return more assets than the deposit amount",
                },
            ],
            "observations": [{
                "label": "attacker USDC balance",
                "target": "USDC",
                "call": "balanceOf(address)(uint256)",
                "timing": "before and after sequence",
            }],
            "success_condition": "Attacker USDC balance increases after all transfers and fees.",
            "priority": "high",
        }))
        self.assertEqual(sequence["experiment_id"], "exp-001")
        self.assertEqual(
            sequence["fork_context"],
            "/workspace/campaign/fork-contexts/fc-001.json",
        )
        self.assertEqual(
            sequence["target_addresses"]["DonationVault"],
            "0x000000000000000000000000000000000000dead",
        )
        self.assertEqual(len(sequence["matched_actions"]), 3)
        self.assertEqual(sequence["unmatched_actions"], [])
        self.assertIn(
            "/workspace/experiments/exp-001-donate-deposit-redeem-profit-sequence/sequence.json",
            container.files,
        )
        sequence_contract = container.files[
            "/workspace/experiments/"
            "exp-001-donate-deposit-redeem-profit-sequence/ReentbotProSequence.t.sol"
        ]
        self.assertIn("interface IReentbotProDonationVault", sequence_contract)
        self.assertIn("function donate(uint256 amount) external;", sequence_contract)
        self.assertIn(
            "address internal donationVaultAddress = 0x000000000000000000000000000000000000dead;",
            sequence_contract,
        )
        self.assertIn("// donationVault.donate(donationAmount);", sequence_contract)

        controller = _json_result(await _attack_search(container, {
            "action": "sync",
            "focus": "donation redeem",
            "record_result": False,
        }))
        experiment_branch = next(
            branch
            for branch in controller["active_branches"]
            if branch["source"] == "experiment_without_result"
        )
        self.assertEqual(
            experiment_branch["next_tool"],
            "complete_sequence_experiment",
        )
        selected = _json_result(await _attack_search(container, {
            "action": "select",
            "branch_id": experiment_branch["id"],
            "record_result": False,
        }))
        self.assertEqual(selected["next_action"]["branch_id"], experiment_branch["id"])
        self.assertEqual(
            selected["next_action"]["tool"],
            "complete_sequence_experiment",
        )
        controller_text = json.dumps(selected, sort_keys=True)
        for retired_tool in (
            "plan_attack_campaign",
            "prepare_fork_exploit_workbench",
            "review_attack_surface_coverage",
            "review_campaign_progress",
        ):
            self.assertNotIn(retired_tool, controller_text)

        completion = _json_result(await _complete_sequence_experiment(container, {
            "sequence": "exp-001",
            "target_addresses": {"USDC": usdc},
            "observations": [{
                "label": "vault total assets",
                "contract": "DonationVault",
                "function": "totalAssets",
                "returns": "uint256",
            }],
            "actions": [
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "donate",
                    "args": ["1000000"],
                    "expected_effect": "increase vault assets without minting shares",
                },
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "deposit",
                    "args": ["1"],
                    "expected_effect": "mint shares using donated balance",
                },
                {
                    "actor": "attacker",
                    "contract": "DonationVault",
                    "function": "redeem",
                    "args": ["1"],
                    "expected_effect": "return more assets than the deposit amount",
                },
            ],
            "objective_probe_strategy": "accounting_delta",
            "record_result": False,
        }))
        self.assertTrue(completion["scaffold_quality"]["runnable"], completion)

        forge_output = """
[PASS] test_donation_deposit_redeem_profit() (gas: 210000)
Traces:
  [210000] ReentbotProSequence::test_sequence_experiment()
    ├─ [50000] DonationVault::donate(1000000)
    │   └─ emit Donated(attacker, 1000000)
    ├─ [60000] DonationVault::deposit(1)
    │   └─ emit Deposited(attacker, 1, 1)
    ├─ [70000] DonationVault::redeem(1)
    │   └─ emit Redeemed(attacker, 1, 1500001)
    └─ [10000] MockUSDC::transfer(attacker, 1500001)
Suite result: ok. 1 passed; 0 failed; 0 skipped
"""
        container.exec_result = (0, forge_output)
        run_result = await _run_experiment(container, {
            "command": "forge test --match-test test_donation_deposit_redeem_profit -vvvv",
            "working_dir": "/workspace/experiments/exp-001-donate-deposit-redeem-profit-sequence",
            "experiment_id": "exp-001",
            "hypothesis_id": "hyp-001",
            "interpretation": "The sequence produced attacker profit in the local harness.",
        })
        self.assertIn("Recorded campaign result: res-002 (observed)", run_result)
        self.assertIn("/workspace/campaign/results/res-002.log", container.files)

        trace = _json_result(await _summarize_trace(container, {
            "path": "/workspace/campaign/results/res-002.log",
            "title": "Donation profit trace",
            "related_ids": ["hyp-001", "exp-001", "res-002"],
        }))
        self.assertEqual(trace["trace_id"], "trace-001")
        trace_calls = {item["call"] for item in trace["calls"]["top"]}
        self.assertIn("DonationVault::redeem", trace_calls)
        self.assertTrue(trace["events"])

        probe = {
            "token": usdc,
            "token_label": "USDC",
            "account": attacker,
            "account_label": "attacker",
        }
        container.exec_results = [(0, "1000000"), (0, "2500000")]
        before = _json_result(await _snapshot_state(container, {
            "title": "Before donation sequence",
            "rpc_url": "http://localhost:8545",
            "erc20_balances": [probe],
            "related_ids": ["hyp-001", "exp-001", "res-002"],
        }))
        after = _json_result(await _snapshot_state(container, {
            "title": "After donation sequence",
            "rpc_url": "http://localhost:8545",
            "erc20_balances": [probe],
            "related_ids": ["hyp-001", "exp-001", "res-002"],
        }))
        self.assertEqual(before["snapshot_id"], "snap-001")
        self.assertEqual(after["snapshot_id"], "snap-002")

        comparison = _json_result(await _compare_snapshots(container, {
            "before": "snap-001",
            "after": "snap-002",
            "title": "Donation sequence attacker PnL",
            "related_ids": ["hyp-001", "exp-001", "res-002", "trace-001"],
        }))
        self.assertEqual(comparison["comparison_id"], "cmp-001")
        self.assertEqual(comparison["changed"][0]["delta"], 1500000)

        evaluation = _json_result(await _evaluate_objective(container, {
            "comparison": "cmp-001",
            "title": "Attacker USDC profit objective",
            "objectives": [{
                "label": "attacker USDC profit",
                "match": "attacker",
                "direction": "increase",
                "decimals": 6,
                "unit": "USDC",
                "price_usd": "1",
                "role": "attacker",
            }],
            "related_ids": [
                "hyp-001",
                "exp-001",
                "res-002",
                "cmp-001",
                "trace-001",
            ],
        }))
        self.assertEqual(evaluation["evaluation_id"], "eval-001")
        self.assertEqual(evaluation["summary"]["passed"], 1)
        self.assertEqual(evaluation["objectives"][0]["matches"][0]["delta"], "1.5")

        review = _json_result(await _review_finding_evidence(container, {
            "title": "Donation accounting lets attacker redeem more assets than deposited",
            "severity": "high",
            "root_cause": "Share minting uses the post-donation asset balance as pricing input.",
            "impact": "An unprivileged attacker can convert an asset donation into net USDC profit.",
            "affected_code": [{"file": "src/DonationVault.sol", "lines": "22-36"}],
            "reproduction_steps": [
                "Donate assets to the vault without minting shares.",
                "Deposit a minimal amount to mint shares against the donated balance.",
                "Redeem those shares and compare attacker USDC before and after.",
            ],
            "campaign_ids": [
                "hyp-001",
                "fc-001",
                "exp-001",
                "res-002",
                "trace-001",
                "cmp-001",
                "eval-001",
            ],
            "evidence": [
                "/workspace/campaign/results/res-002.log",
                "/workspace/campaign/traces/trace-001.json",
                "/workspace/campaign/comparisons/cmp-001.json",
                "/workspace/campaign/evaluations/eval-001.json",
                "/workspace/experiments/exp-001-donate-deposit-redeem-profit-sequence/sequence.json",
            ],
            "test_output": forge_output,
            "proof_of_concept": (
                "/workspace/experiments/"
                "exp-001-donate-deposit-redeem-profit-sequence/ReentbotProSequence.t.sol"
            ),
            "validated": True,
            "objective_evaluation": "eval-001",
            "capital_required": "Temporary liquidity for the donation amount; no privileged role.",
            **_exploitability_fields(),
            "trusted_role_required": False,
            "known_limitations": [],
        }))
        self.assertEqual(review["review_id"], "fr-001")
        self.assertTrue(review["ready"])
        self.assertEqual(review["blocking_gaps"], [])

        finding_ready = _json_result(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertEqual(finding_ready["next_action"]["tool"], "review_report_quality")
        self.assertEqual(finding_ready["next_action"]["source"], "ready_finding_review")

        report_review = _json_result(await _review_report_quality(container, {
            "title": "Donation accounting lets attacker redeem more assets than deposited",
            "severity": "high",
            "summary": (
                "The vault prices share minting from token balance that an "
                "attacker can inflate through an unaccounted donation."
            ),
            "root_cause": (
                "The deposit path derives minted shares from current assets and "
                "total shares, so direct donations become part of the pricing "
                "input for the next depositor."
            ),
            "impact": (
                "An unprivileged attacker can chain donate, deposit, and redeem "
                "to finish with 1.5 more USDC in the simulated campaign."
            ),
            "attack_path": [
                "Attacker donates assets directly to the vault without receiving shares.",
                "Attacker deposits a minimal amount after the donation skews share pricing.",
                "Attacker redeems the resulting shares and captures more USDC than contributed.",
            ],
            "affected_code": [{"file": "src/DonationVault.sol", "lines": "22-36"}],
            "reproduction_steps": [
                "Run the generated sequence PoC with forge test.",
                "Inspect the passing Foundry output saved in res-002.log.",
                "Compare snap-001 and snap-002, then inspect eval-001 for profit.",
            ],
            "proof_of_concept": (
                "/workspace/experiments/"
                "exp-001-donate-deposit-redeem-profit-sequence/ReentbotProSequence.t.sol"
            ),
            "validation": "Foundry passes and eval-001 records 1.5 USDC attacker profit.",
            "test_output": forge_output,
            "economic_analysis": (
                "Capital required is the temporary donation amount plus gas; "
                "the recorded objective evaluation shows 1.5 USDC profit."
            ),
            "assumptions": [
                "The attacker is unprivileged.",
                "The asset follows ERC20 balance semantics.",
            ],
            "limitations": ["None identified in this minimal campaign fixture."],
            **_exploitability_fields(),
            "remediation": (
                "Price deposits from internal accounting or pre-transfer assets "
                "rather than raw token balance that includes unsolicited donations."
            ),
            "campaign_ids": [
                "hyp-001",
                "fc-001",
                "exp-001",
                "res-002",
                "trace-001",
                "cmp-001",
                "eval-001",
                "fr-001",
            ],
            "evidence": [
                "/workspace/campaign/results/res-002.log",
                "/workspace/campaign/traces/trace-001.json",
                "/workspace/campaign/comparisons/cmp-001.json",
                "/workspace/campaign/evaluations/eval-001.json",
                "/workspace/campaign/finding-reviews/fr-001.json",
                "/workspace/experiments/exp-001-donate-deposit-redeem-profit-sequence/sequence.json",
            ],
            "evidence_review": "fr-001",
            "objective_evaluation": "eval-001",
        }))
        self.assertEqual(report_review["review_id"], "rr-001")
        self.assertTrue(report_review["ready"])
        self.assertEqual(report_review["blocking_gaps"], [])

        report_ready = _json_result(await _attack_search(container, {
            "action": "sync",
            "record_result": False,
        }))
        self.assertEqual(
            report_ready["next_action"]["tool"],
            "submit_finding",
            report_ready,
        )
        self.assertEqual(report_ready["next_action"]["source"], "ready_report_review")

        findings: list[dict] = []
        submit = _submit_finding({
            "title": "Donation accounting lets attacker redeem more assets than deposited",
            "severity": "high",
            "description": "The campaign reproduced a donate/deposit/redeem sequence with profit.",
            "impact": "Unprivileged attacker profit of 1.5 USDC in the simulated campaign.",
            "affected_code": [{"file": "src/DonationVault.sol", "lines": "22-36"}],
            "proof_of_concept": (
                "/workspace/experiments/"
                "exp-001-donate-deposit-redeem-profit-sequence/ReentbotProSequence.t.sol"
            ),
            "validated": True,
            "test_output": forge_output,
            "campaign_ids": [
                "hyp-001",
                "fc-001",
                "exp-001",
                "res-002",
                "trace-001",
                "eval-001",
            ],
            "evidence": [
                "/workspace/campaign/results/res-002.log",
                "/workspace/campaign/traces/trace-001.json",
                "/workspace/campaign/evaluations/eval-001.json",
            ],
            "reproduction_steps": [
                "Run the sequence PoC.",
                "Confirm Foundry passes.",
                "Compare attacker USDC snapshots and evaluate the profit objective.",
            ],
            "objective_evaluation": "eval-001",
            "evidence_review": "fr-001",
            "report_review": "rr-001",
            **_exploitability_fields(),
        }, findings)
        self.assertIn("validated", submit)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["validated"])
        self.assertEqual(findings[0]["evidence_review"], "fr-001")
        self.assertEqual(findings[0]["report_review"], "rr-001")
        self.assertIn("eval-001", findings[0]["campaign_ids"])

        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        self.assertEqual(state["counters"]["action_space"], 1)
        self.assertEqual(state["counters"]["experiment"], 1)
        self.assertEqual(state["counters"]["snapshot"], 2)
        self.assertEqual(state["counters"]["comparison"], 1)
        self.assertEqual(state["counters"]["trace"], 1)
        self.assertEqual(state["counters"]["evaluation"], 1)
        self.assertEqual(state["counters"]["fork_context"], 1)
        self.assertEqual(state["counters"]["finding_review"], 1)
        self.assertEqual(state["counters"]["report_review"], 1)
        self.assertEqual(len(state["sections"]["hypothesis"]), 1)
        self.assertEqual(len(state["sections"]["experiment"]), 1)
        self.assertGreaterEqual(len(state["sections"]["result"]), 8)
        for legacy_directory in (
            "/workspace/campaign/coverage-reviews/",
            "/workspace/campaign/fork-workbenches/",
            "/workspace/campaign/plans/",
            "/workspace/campaign/progress-reviews/",
        ):
            self.assertFalse(any(
                path.startswith(legacy_directory) for path in container.files
            ))

    async def test_failed_objective_can_mutate_campaign_without_losing_lineage(self):
        container = FakeContainer()
        raw = await _update_campaign(container, {
            "section": "hypothesis",
            "title": "Spot price manipulation creates borrow headroom",
            "content": "Swap before borrow and expect attacker debt capacity to increase.",
            "priority": "high",
        })
        self.assertNotIn("Error:", raw)
        container.files["/workspace/campaign/comparisons/cmp-001.json"] = json.dumps({
            "id": "cmp-001",
            "title": "Borrow headroom",
            "changed": [{
                "key": "call:attackerBorrowLimit:0xlending:maxBorrow(address):(attacker)",
                "kind": "calls",
                "before": "1000000",
                "after": "1000000",
                "delta": 0,
            }],
        })

        evaluation = _json_result(await _evaluate_objective(container, {
            "comparison": "cmp-001",
            "title": "Borrow headroom increase objective",
            "objectives": [{
                "label": "attacker borrow headroom",
                "match": "attackerBorrowLimit",
                "direction": "increase",
                "decimals": 6,
                "unit": "USDC",
            }],
            "related_ids": ["hyp-001", "cmp-001"],
        }))
        self.assertEqual(evaluation["summary"]["passed"], 0)
        self.assertFalse(evaluation["objectives"][0]["passed"])

        mutation = _json_result(await _mutate_hypothesis(container, {
            "source_hypothesis_id": "hyp-001",
            "failed_assumption": "The protocol reads the manipulated spot price on borrow.",
            "interpretation": (
                "Borrow headroom did not move, so the next campaign branch should test "
                "oracle update cadence and collateral accounting side effects."
            ),
            "evidence": ["eval-001"],
            "source_status": "rejected",
            "mutations": [{
                "title": "Oracle update cadence can be controlled around borrow",
                "hypothesis": (
                    "If an attacker can force or time an oracle update after pool "
                    "manipulation, borrow headroom may change in a later block."
                ),
                "rationale": "The failed spot-read hypothesis leaves time-dependent oracle paths open.",
                "experiment": "Fork across oracle update boundaries and replay swap-update-borrow.",
                "expected_observation": "Borrow headroom changes only after an oracle update.",
                "priority": "high",
            }],
            "open_questions": [{
                "title": "Oracle update trigger",
                "question": "Which function refreshes the price used by borrow?",
                "priority": "medium",
            }],
        }))
        self.assertEqual(mutation["mutation_id"], "mut-001")
        self.assertEqual(mutation["mutations"][0]["hypothesis_id"], "hyp-002")
        self.assertNotIn("experiment_id", mutation["mutations"][0])

        state = json.loads(container.files[_CAMPAIGN_STATE_PATH])
        source = state["sections"]["hypothesis"][0]
        self.assertEqual(source["id"], "hyp-001")
        self.assertEqual(source["status"], "rejected")
        self.assertIn("mut-001", source["related_ids"])
        self.assertEqual(state["sections"]["hypothesis"][1]["id"], "hyp-002")
        self.assertEqual(state["sections"]["experiment"], [])
        self.assertEqual(state["sections"]["open_question"][0]["id"], "oq-001")
