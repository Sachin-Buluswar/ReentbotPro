import unittest

from reentbotpro.tools import (
    _ast_source_unit_to_parsed_file,
    _attack_graph_candidate_hypothesis_readiness,
    _causal_attack_graph_candidates,
    _causal_source_paths,
    _parse_action_space_file,
    _parse_protocol_graph_file,
)


SOURCE = """pragma solidity ^0.8.20;
interface IERC20 { function transfer(address,uint256) external returns (bool); }
contract Base {
    uint256 internal credit;
    IERC20 internal token;
    function inheritedSeed(uint256 value) external { credit = value; }
    function _store(uint256 value) internal { credit = value; }
}
contract Child is Base {
    function seed(uint256 value) external { _store(value); }
    function release(uint256 amount) external {
        require(credit >= amount);
        token.transfer(msg.sender, amount);
    }
}
"""


def _inheritance_ast() -> dict:
    def src(snippet: str) -> str:
        start = SOURCE.index(snippet)
        return f"{start}:{len(snippet)}:0"

    def parameters(name: str = "", type_name: str = "uint256") -> dict:
        return {
            "parameters": (
                [{"name": name, "typeDescriptions": {"typeString": type_name}}]
                if name else []
            )
        }

    def function(
        name: str,
        visibility: str,
        body: str,
        parameter: str,
    ) -> dict:
        return {
            "nodeType": "FunctionDefinition",
            "kind": "function",
            "name": name,
            "visibility": visibility,
            "stateMutability": "nonpayable",
            "src": src(f"function {name}"),
            "parameters": parameters(parameter),
            "returnParameters": parameters(),
            "modifiers": [],
            "body": {"src": src(body)},
        }

    return {
        "nodeType": "SourceUnit",
        "src": f"0:{len(SOURCE)}:0",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "name": "Base",
                "contractKind": "contract",
                "src": src("contract Base"),
                "baseContracts": [],
                "nodes": [
                    {
                        "nodeType": "VariableDeclaration",
                        "name": "credit",
                        "stateVariable": True,
                        "visibility": "internal",
                        "src": src("uint256 internal credit"),
                        "typeDescriptions": {"typeString": "uint256"},
                    },
                    {
                        "nodeType": "VariableDeclaration",
                        "name": "token",
                        "stateVariable": True,
                        "visibility": "internal",
                        "src": src("IERC20 internal token"),
                        "typeDescriptions": {"typeString": "contract IERC20"},
                    },
                    function(
                        "inheritedSeed",
                        "external",
                        "{ credit = value; }",
                        "value",
                    ),
                    function(
                        "_store",
                        "internal",
                        "{ credit = value; }",
                        "value",
                    ),
                ],
            },
            {
                "nodeType": "ContractDefinition",
                "name": "Child",
                "contractKind": "contract",
                "src": src("contract Child"),
                "baseContracts": [{"baseName": {"name": "Base"}}],
                "nodes": [
                    function(
                        "seed",
                        "external",
                        "{ _store(value); }",
                        "value",
                    ),
                    function(
                        "release",
                        "external",
                        "{\n        require(credit >= amount);\n"
                        "        token.transfer(msg.sender, amount);\n    }",
                        "amount",
                    ),
                ],
            },
        ],
    }


class CausalInheritanceTests(unittest.TestCase):
    def _assert_inherited_causal_paths(self, parsed: dict) -> None:
        child = next(
            item for item in parsed["contracts"] if item["name"] == "Child"
        )
        self.assertEqual(
            {item["name"] for item in child["inherited_state_variables"]},
            {"credit", "token"},
        )
        actions = {
            (item["contract"], item["function"]): item
            for item in parsed["actions"]
        }
        seed_writes = actions[("Child", "seed")]["causal_facts"]["state_writes"]
        self.assertEqual(seed_writes[0]["declaring_contract"], "Base")
        self.assertEqual(seed_writes[0]["via_internal"], ["_store"])
        release_reads = actions[("Child", "release")]["causal_facts"]["state_reads"]
        credit_read = next(
            item for item in release_reads if item["variable"] == "credit"
        )
        self.assertEqual(credit_read["declaring_contract"], "Base")

        paths, search = _causal_source_paths(parsed)
        path_index = {
            tuple((item["contract"], item["function"]) for item in path["actions"]): path
            for path in paths
        }
        cross_contract = path_index[
            (("Base", "inheritedSeed"), ("Child", "release"))
        ]
        self.assertFalse(cross_contract["same_contract"])
        self.assertEqual(cross_contract["storage_context"], "Child")
        self.assertEqual(
            cross_contract["dependencies"][0]["accesses"][0][
                "declaring_contract"
            ],
            "Base",
        )
        self.assertIn(
            (("Child", "seed"), ("Child", "release")),
            path_index,
        )
        self.assertEqual(search["direct_inheritance_paths"], 1)
        self.assertEqual(search["inheritance_scope"], "direct_same_file_only")
        self.assertTrue(search["inheritance_limitations"])

        candidates, _candidate_search = _causal_attack_graph_candidates(
            action_space=parsed,
            exposures=[],
            mode="source_only",
            focus="auto",
            action_space_path="/workspace/campaign/action-spaces/as-test.json",
            live_path="",
            protocol_graph_path="",
        )
        inherited_candidate = next(
            item for item in candidates
            if [action["function"] for action in item["actions"]]
            == ["inheritedSeed", "release"]
        )
        self.assertFalse(inherited_candidate["causal_path"]["same_contract"])
        self.assertEqual(
            inherited_candidate["causal_path"]["storage_context"], "Child"
        )
        self.assertIn(
            "direct_inheritance_state_dependencies",
            inherited_candidate["score_reasons"][0],
        )

    def test_regex_parser_connects_direct_base_state_and_functions(self):
        parsed = _parse_action_space_file(
            "/audit/src/Inheritance.sol", SOURCE, max_items=100
        )
        self._assert_inherited_causal_paths(parsed)

    def test_ast_parser_connects_direct_base_state_and_functions(self):
        parsed = _ast_source_unit_to_parsed_file(
            _inheritance_ast(),
            "/audit/src/Inheritance.sol",
            SOURCE,
            max_items=100,
        )
        self.assertIsNotNone(parsed)
        self._assert_inherited_causal_paths(parsed)

    def test_protocol_graph_binds_child_facts_to_declaring_base_state(self):
        graph = _parse_protocol_graph_file(
            "/audit/src/Inheritance.sol", SOURCE, max_items=100
        )
        base_credit = next(
            node for node in graph["nodes"]
            if node.get("contract") == "Base"
            and node.get("variable") == "credit"
        )
        child_release = next(
            node for node in graph["nodes"]
            if node.get("contract") == "Child"
            and node.get("function") == "release"
        )
        child_seed = next(
            node for node in graph["nodes"]
            if node.get("contract") == "Child"
            and node.get("function") == "seed"
        )
        self.assertTrue(any(
            edge["source"] == child_release["id"]
            and edge["target"] == base_credit["id"]
            and edge["kind"] == "reads_state"
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["source"] == child_seed["id"]
            and edge["target"] == base_credit["id"]
            and edge["kind"] == "writes_state"
            for edge in graph["edges"]
        ))

    def test_ambiguous_direct_base_state_is_not_guessed(self):
        source = """pragma solidity ^0.8.20;
contract First { uint256 internal shared; }
contract Second { uint256 internal shared; }
contract Child is First, Second {
    function touch() external { shared = 1; }
}
"""
        parsed = _parse_action_space_file(
            "/audit/src/Ambiguous.sol", source, max_items=100
        )
        child = next(
            item for item in parsed["contracts"] if item["name"] == "Child"
        )
        self.assertEqual(child["ambiguous_inherited_state_names"], ["shared"])
        touch = next(
            item for item in parsed["actions"] if item["function"] == "touch"
        )
        self.assertFalse(touch.get("causal_facts"))

    def test_source_only_gated_start_is_preserved_with_explicit_caveat(self):
        source = """pragma solidity ^0.8.20;
interface IERC20 { function transfer(address,uint256) external returns (bool); }
contract Gated {
    uint256 credit;
    IERC20 token;
    modifier onlyOwner() { _; }
    function seed(uint256 value) external onlyOwner { credit = value; }
    function release(uint256 amount) external {
        require(credit >= amount);
        token.transfer(msg.sender, amount);
    }
}
"""
        parsed = _parse_action_space_file(
            "/audit/src/Gated.sol", source, max_items=100
        )
        candidates, _search = _causal_attack_graph_candidates(
            action_space=parsed,
            exposures=[],
            mode="source_only",
            focus="auto",
            action_space_path="as-gated",
            live_path="",
            protocol_graph_path="",
        )
        candidate = next(
            item for item in candidates
            if [action["function"] for action in item["actions"]]
            == ["seed", "release"]
        )
        self.assertTrue(candidate["caveats"])
        self.assertTrue(
            any("unproven_start_gate" in item for item in candidate["score_reasons"])
        )
        self.assertTrue(
            any("prove an unprivileged route" in item for item in candidate["blockers"])
        )
        self.assertNotIn("attacker_control", candidate["hypothesis_card"])
        self.assertNotEqual(candidate["actions"][0]["actor"], "attacker")
        readiness = _attack_graph_candidate_hypothesis_readiness(candidate)
        self.assertFalse(readiness["ready"])
        self.assertIn(
            "hypothesis_card.attacker_control", readiness["missing"]
        )

    def test_live_causal_targets_are_ranked_and_omissions_are_recorded(self):
        parsed = _parse_action_space_file(
            "/audit/src/Inheritance.sol", SOURCE, max_items=100
        )
        relevant = [
            action for action in parsed["actions"]
            if (action["contract"], action["function"]) in {
                ("Base", "inheritedSeed"),
                ("Child", "release"),
            }
        ]
        target_bindings = {
            "0x1111111111111111111111111111111111111111": {
                "kind": "deployed_contract",
            },
            "0x2222222222222222222222222222222222222222": {
                "kind": "active_proxy",
                "economically_significant_hint": True,
            },
            "0x3333333333333333333333333333333333333333": {
                "kind": "deployed_economic_contract",
                "economically_significant_hint": True,
            },
        }
        exposures = []
        for target, binding in target_bindings.items():
            for action in relevant:
                exposures.append({
                    **action,
                    "action_key": (
                        f"{action['contract']}::{action['signature']}"
                    ),
                    "target_address": target,
                    "target_binding": binding,
                    "exposure": "exposed",
                    "live_status": "deployed",
                    "reachability": {
                        "kind": "public",
                        "attacker_reachable": True,
                    },
                })
        candidates, search = _causal_attack_graph_candidates(
            action_space=parsed,
            exposures=exposures,
            mode="reachability_aware",
            focus="auto",
            action_space_path="as-live",
            live_path="lr-live",
            protocol_graph_path="",
        )
        selected = {item["target_address"] for item in candidates}
        self.assertEqual(
            selected,
            {
                "0x2222222222222222222222222222222222222222",
                "0x3333333333333333333333333333333333333333",
            },
        )
        self.assertEqual(search["live_targets_considered"], 3)
        self.assertEqual(search["live_targets_selected"], 2)
        self.assertEqual(search["live_targets_omitted"], 1)
        self.assertTrue(search["live_target_binding_truncated"])
        self.assertTrue(search["truncated"])
        self.assertEqual(
            search["live_target_omissions"][0]["omitted_targets"],
            [{"address": "0x1111111111111111111111111111111111111111"}],
        )

    def test_live_causal_join_uses_chain_and_address_identity(self):
        parsed = _parse_action_space_file(
            "/audit/src/Inheritance.sol", SOURCE, max_items=100
        )
        relevant = [
            action for action in parsed["actions"]
            if (action["contract"], action["function"]) in {
                ("Base", "inheritedSeed"),
                ("Child", "release"),
            }
        ]
        address = "0x1111111111111111111111111111111111111111"

        def exposure(action: dict, chain_id: int) -> dict:
            return {
                **action,
                "action_key": f"{action['contract']}::{action['signature']}",
                "target_address": address,
                "chain_id": chain_id,
                "target_binding": {"kind": "deployed_economic_contract"},
                "exposure": "exposed",
                "live_status": "deployed",
                "reachability": {
                    "kind": "public",
                    "attacker_reachable": True,
                },
            }

        exposures = [
            exposure(action, chain_id)
            for chain_id in (1, 10)
            for action in relevant
        ]
        candidates, _search = _causal_attack_graph_candidates(
            action_space=parsed,
            exposures=exposures,
            mode="reachability_aware",
            focus="auto",
            action_space_path="as-live",
            live_path="lr-live",
            protocol_graph_path="",
        )
        inherited = [
            item for item in candidates
            if [action["function"] for action in item["actions"]]
            == ["inheritedSeed", "release"]
        ]
        self.assertEqual({item["chain_id"] for item in inherited}, {1, 10})
        self.assertEqual(
            {item["target_identity"]["chain_key"] for item in inherited},
            {"1", "10"},
        )
        self.assertEqual(len({item["attack_key"] for item in inherited}), 2)
        for item in inherited:
            self.assertTrue(all(
                action["chain_id"] == item["chain_id"]
                for action in item["actions"]
            ))

        cross_chain_only = [
            exposure(relevant[0], 1),
            exposure(relevant[1], 10),
        ]
        mismatched, _search = _causal_attack_graph_candidates(
            action_space=parsed,
            exposures=cross_chain_only,
            mode="reachability_aware",
            focus="auto",
            action_space_path="as-live",
            live_path="lr-live",
            protocol_graph_path="",
        )
        self.assertFalse(any(
            [action["function"] for action in item["actions"]]
            == ["inheritedSeed", "release"]
            for item in mismatched
        ))


if __name__ == "__main__":
    unittest.main()
