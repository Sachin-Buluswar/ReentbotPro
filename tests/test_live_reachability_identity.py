import json
import unittest

from reentbotpro.tools import (
    _action_matches_profile,
    _action_signature_key,
    _action_source_relation,
    _action_space_contract_bases,
    _action_stable_uid,
    _contract_inherits_contract,
    _inventory_live_targets,
    _map_live_reachability,
    _merge_live_profiles,
    _reachability_attack_graph_candidates,
    _stm_coherent_live_exposures,
)


ADDRESS = "0x1111111111111111111111111111111111111111"


class FakeContainer:
    def __init__(self):
        self.files: dict[str, str] = {}
        self.writes: list[tuple[str, str]] = []
        self.exec_calls: list[tuple[str, str, int]] = []

    async def write_file(self, path: str, content: str) -> None:
        self.files[path] = content
        self.writes.append((path, content))

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
        del extra_env
        self.exec_calls.append((command, working_dir, timeout))
        return 0, ""


class LiveReachabilityIdentityTests(unittest.TestCase):
    def test_cross_file_base_resolves_inside_one_profile_root(self):
        root = "/audit/src/Child_a111"
        action_space = {
            "contracts": [
                {
                    "name": "BaseVault",
                    "file": f"{root}/BaseVault.sol",
                    "bases": [],
                },
                {
                    "name": "Child",
                    "file": f"{root}/Child.sol",
                    "bases": ["BaseVault"],
                },
            ],
            "actions": [
                {
                    "contract": "BaseVault",
                    "file": f"{root}/BaseVault.sol",
                    "function": "withdraw",
                }
            ],
        }
        action = action_space["actions"][0]
        profile = {"contract": "Child", "src": root}
        bases = _action_space_contract_bases(action_space)

        self.assertTrue(_action_matches_profile(action, profile))
        self.assertTrue(
            _contract_inherits_contract(
                file_path=action["file"],
                child_contract="Child",
                base_contract="BaseVault",
                bases_by_contract=bases,
                source_root=root,
            )
        )
        relation = _action_source_relation(
            action,
            profile,
            bases_by_contract=bases,
        )
        self.assertEqual(relation["kind"], "inherited_base")
        self.assertTrue(relation["executable_source"])

    def test_same_name_from_another_profile_root_never_cross_binds(self):
        first_root = "/audit/src/Vault_a111"
        second_root = "/audit/src/Vault_b222"
        first = {
            "contract": "Vault",
            "file": f"{first_root}/Vault.sol",
            "function": "withdraw",
        }
        second = {
            "contract": "Vault",
            "file": f"{second_root}/Vault.sol",
            "function": "withdraw",
        }
        action_space = {
            "contracts": [
                {"name": "Vault", "file": first["file"], "bases": []},
                {"name": "Vault", "file": second["file"], "bases": []},
            ],
            "actions": [first, second],
        }
        profile = {"contract": "Vault", "src": second_root}
        bases = _action_space_contract_bases(action_space)

        self.assertFalse(_action_matches_profile(first, profile))
        first_relation = _action_source_relation(
            first, profile, bases_by_contract=bases
        )
        self.assertEqual(first_relation["kind"], "external_source")
        self.assertFalse(first_relation["executable_source"])

        self.assertTrue(_action_matches_profile(second, profile))
        second_relation = _action_source_relation(
            second, profile, bases_by_contract=bases
        )
        self.assertEqual(second_relation["kind"], "profile_contract")
        self.assertTrue(second_relation["executable_source"])

    def test_same_name_inside_one_root_requires_unique_definition(self):
        root = "/audit/src/Ambiguous_a111"
        action = {
            "contract": "Child",
            "file": f"{root}/First.sol",
            "function": "withdraw",
        }
        bases = _action_space_contract_bases({
            "contracts": [
                {"name": "Child", "file": action["file"], "bases": []},
                {"name": "Child", "file": f"{root}/Second.sol", "bases": []},
            ],
            "actions": [action],
        })
        relation = _action_source_relation(
            action,
            {"contract": "Child", "src": root},
            bases_by_contract=bases,
        )
        self.assertEqual(relation["kind"], "ambiguous_profile_source")
        self.assertFalse(relation["executable_source"])

    def test_overloaded_live_actions_keep_signature_identity(self):
        common = {
            "contract": "Vault",
            "file": "/audit/src/Vault_a111/Vault.sol",
            "function": "act",
            "line": 10,
            "affordances": ["value_out_or_burn"],
            "exposure": "exposed",
            "live_status": "deployed",
            "target_address": "0x1111111111111111111111111111111111111111",
            "profile_contract": "Vault",
            "reachability": {"kind": "public", "attacker_reachable": True},
            "target_binding": {"kind": "deployed_economic_contract"},
        }
        uint_action = {
            **common,
            "parameters": [{"name": "value", "raw": "uint256 value"}],
        }
        address_action = {
            **common,
            "parameters": [{"name": "account", "raw": "address account"}],
        }
        for action in (uint_action, address_action):
            action["action_key"] = "Vault::act"
            action["action_definition_key"] = _action_signature_key(action)
            action["action_uid"] = _action_stable_uid(action)

        self.assertNotEqual(
            uint_action["action_definition_key"],
            address_action["action_definition_key"],
        )
        self.assertNotEqual(uint_action["action_uid"], address_action["action_uid"])
        candidates, *_rest = _reachability_attack_graph_candidates(
            live_reachability={
                "profiles": [{"action_exposures": [uint_action, address_action]}]
            },
            focus="",
            action_space_path="as-test",
            live_path="lr-test",
            protocol_graph_path="",
        )
        overload_candidates = [
            item for item in candidates if item.get("action_key") == "Vault::act"
        ]
        self.assertEqual(len(overload_candidates), 2)
        self.assertEqual(
            len({item["attack_key"] for item in overload_candidates}), 2
        )

    def test_live_profile_merge_keeps_same_address_on_distinct_chains(self):
        common = {
            "profile": "Vault",
            "contract": "Vault",
            "address": ADDRESS,
            "src": "/audit/src/Vault",
        }
        merged = _merge_live_profiles(
            [{**common, "chain_id": 1}],
            [{**common, "chain_id": 10}],
        )
        self.assertEqual(len(merged), 2)
        self.assertEqual({item["chain_id"] for item in merged}, {1, 10})

    def test_stm_live_groups_are_chain_coherent(self):
        actions = [
            {
                "contract": "Vault",
                "function": function,
                "signature": f"{function}()",
                "parameters": [],
                "file": "/audit/src/Vault/Vault.sol",
            }
            for function in ("seed", "withdraw")
        ]

        def exposure(action: dict, chain_id: int) -> dict:
            return {
                **action,
                "action_key": f"Vault::{action['function']}",
                "target_address": ADDRESS,
                "chain_id": chain_id,
                "exposure": "exposed",
                "live_status": "deployed",
                "reachability": {
                    "kind": "public",
                    "attacker_reachable": True,
                },
            }

        all_exposures = [
            exposure(action, chain_id)
            for chain_id in (1, 10)
            for action in actions
        ]
        groups = _stm_coherent_live_exposures(actions, all_exposures)
        self.assertEqual(len(groups), 2)
        self.assertEqual(
            {
                tuple(item["chain_id"] for item in group)
                for group in groups
            },
            {(1, 1), (10, 10)},
        )
        self.assertEqual(
            _stm_coherent_live_exposures(
                actions,
                [exposure(actions[0], 1), exposure(actions[1], 10)],
            ),
            [],
        )

        legacy = [
            {
                **exposure(action, 1),
                "chain_id": None,
            }
            for action in actions
        ]
        chain_markers = [
            {
                **exposure(actions[0], chain_id),
                "function": "unrelated",
                "action_key": "Vault::unrelated",
                "exposure": "gated",
            }
            for chain_id in (1, 10)
        ]
        self.assertEqual(
            _stm_coherent_live_exposures(actions, [*legacy, *chain_markers]),
            [],
        )
        one_chain_groups = _stm_coherent_live_exposures(
            actions, [*legacy, chain_markers[0]]
        )
        self.assertEqual(len(one_chain_groups), 1)


class LiveChainPropagationTests(unittest.IsolatedAsyncioTestCase):
    async def test_inventory_retains_same_address_on_two_explicit_chains(self):
        container = FakeContainer()
        payload = json.loads(await _inventory_live_targets(
            container,
            {
                "targets": [
                    {"label": "mainnet", "address": ADDRESS, "chain_id": 1},
                    {"label": "optimism", "address": ADDRESS, "chain_id": 10},
                ],
                "execute_probes": False,
                "record_result": False,
            },
            environ={},
            config={},
        ))
        self.assertEqual(payload["summary"]["targets"], 2)
        self.assertEqual(payload["targets_by_chain"]["1"], [ADDRESS])
        self.assertEqual(payload["targets_by_chain"]["10"], [ADDRESS])
        self.assertEqual(
            {item["target_identity"]["chain_key"] for item in payload["targets"]},
            {"1", "10"},
        )

    async def test_live_map_propagates_profile_chain_to_every_exposure(self):
        container = FakeContainer()
        manifest_path = "/workspace/campaign/scope-manifest.json"
        action_space_path = "/workspace/campaign/action-spaces/as-chain.json"
        common_profile = {
            "profile": "Vault",
            "contract": "Vault",
            "address": ADDRESS,
            "src": "/audit/src/Vault",
        }
        container.files[manifest_path] = json.dumps({
            "ranked_profiles": [
                {**common_profile, "chain_id": 1},
                {**common_profile, "chain_id": 10},
            ]
        })
        action = {
            "contract": "Vault",
            "contract_kind": "contract",
            "function": "withdraw",
            "signature": "withdraw()",
            "file": "/audit/src/Vault/Vault.sol",
            "line": 10,
            "visibility": "external",
            "mutability": "nonpayable",
            "parameters": [],
            "modifiers": [],
            "affordances": ["value_out_or_burn"],
        }
        container.files[action_space_path] = json.dumps({
            "contracts": [
                {
                    "name": "Vault",
                    "file": action["file"],
                    "bases": [],
                }
            ],
            "actions": [action],
            "observations": [],
        })
        payload = json.loads(await _map_live_reachability(
            container,
            {
                "scope_manifest": manifest_path,
                "action_space": action_space_path,
                "execute_probes": False,
                "record_result": False,
            },
            environ={},
            config={},
        ))
        self.assertEqual(len(payload["profiles"]), 2)
        self.assertEqual(
            {profile["chain_id"] for profile in payload["profiles"]},
            {1, 10},
        )
        exposures = [
            exposure
            for profile in payload["profiles"]
            for exposure in profile["action_exposures"]
        ]
        self.assertEqual({item["chain_id"] for item in exposures}, {1, 10})
        self.assertEqual(
            {item["target_identity"]["chain_key"] for item in exposures},
            {"1", "10"},
        )


if __name__ == "__main__":
    unittest.main()
