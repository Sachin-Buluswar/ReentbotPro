"""Characterization tests that pin the tool-registry and facade contract.

These guard the ``tools.py`` module split: they fail loudly if a tool becomes
callable-but-invisible (in ``execute_tool`` but no toolset), visible-but-unrouted
(in a toolset but no dispatch arm), or if a name the rest of the codebase imports
from ``reentbotpro.tools`` stops resolving after code is moved into submodules.

They are intentionally static (AST/attribute introspection, no tool execution),
so they are fast and have no container/network dependencies.
"""

import ast
import asyncio
import glob
import inspect
import json
import os
import re
import unittest
from unittest import mock

from reentbotpro import tools as tools_mod
from reentbotpro.tools import (
    PARALLEL_SAFE,
    TOOL_BY_NAME,
    TOOLS,
    TOOLSET_DEFINITIONS,
    _NAVIGATION_TOOL_NAMES,
    _SCHEMA_DESCRIPTION_LIMIT,
    _TOOL_DESCRIPTION_LIMIT,
    execute_tool,
    tool_names_for_toolsets,
    tools_for_toolsets,
    toolsets_for_tool_names,
)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _execute_tool_case_names() -> set[str]:
    """The string literals dispatched by ``execute_tool``'s match statement."""
    source = inspect.getsource(execute_tool)
    tree = ast.parse(source.lstrip())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.match_case):
            for sub in ast.walk(node.pattern):
                if isinstance(sub, ast.MatchValue) and isinstance(sub.value, ast.Constant):
                    if isinstance(sub.value.value, str):
                        names.add(sub.value.value)
    return names


def _names_imported_from_tools() -> set[str]:
    """Every name imported via ``from reentbotpro.tools import ...`` repo-wide."""
    names: set[str] = set()
    pattern = re.compile(
        r"^[ \t]*from reentbotpro\.tools import \(([^)]*)\)|"
        r"^[ \t]*from reentbotpro\.tools import ([^\(\n]+)",
        re.S | re.M,
    )
    files = glob.glob(os.path.join(_REPO_ROOT, "tests", "*.py"))
    files += glob.glob(os.path.join(_REPO_ROOT, "src", "reentbotpro", "*.py"))
    for path in files:
        if os.path.basename(path) == "test_tool_registry.py":
            continue  # this file references the import string in prose/regex
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for grouped, inline in pattern.findall(src):
            block = grouped or inline
            for part in block.split(","):
                name = part.strip().split(" as ")[0].strip()
                if name and name != "*":
                    names.add(name)
    return names


class ToolRegistryConsistencyTests(unittest.TestCase):
    def test_tool_by_name_matches_tools(self):
        derived = {
            t["function"]["name"]
            for t in TOOLS
            if isinstance(t, dict) and isinstance(t.get("function"), dict)
        }
        self.assertEqual(set(TOOL_BY_NAME), derived)

    def test_every_tool_routed_by_dispatch(self):
        case_names = _execute_tool_case_names()
        missing = set(TOOL_BY_NAME) - case_names
        self.assertEqual(
            missing, set(),
            f"tools with no execute_tool dispatch arm: {sorted(missing)}",
        )

    def test_dispatch_arms_are_real_tools(self):
        # Every dispatched name (except the unknown-tool sentinel path) must be a
        # real tool schema, so a renamed/removed tool can't leave a dead arm.
        case_names = _execute_tool_case_names()
        unknown = case_names - set(TOOL_BY_NAME)
        self.assertEqual(
            unknown, set(),
            f"execute_tool dispatches names that are not in TOOLS: {sorted(unknown)}",
        )

    def test_every_tool_in_exactly_one_toolset(self):
        membership: dict[str, list[str]] = {}
        for toolset, names in TOOLSET_DEFINITIONS.items():
            for name in names:
                membership.setdefault(name, []).append(toolset)
        # request_toolset is the only verb allowed to live in core only; all other
        # tool names must appear in exactly one toolset.
        for name in TOOL_BY_NAME:
            self.assertIn(
                name, membership,
                f"{name} is a tool but belongs to no toolset",
            )
            self.assertEqual(
                len(membership[name]), 1,
                f"{name} appears in multiple toolsets: {membership[name]}",
            )

    def test_toolset_members_are_real_tools(self):
        for toolset, names in TOOLSET_DEFINITIONS.items():
            for name in names:
                self.assertIn(
                    name, TOOL_BY_NAME,
                    f"toolset {toolset!r} lists unknown tool {name!r}",
                )

    def test_all_toolsets_expand_to_full_tool_set(self):
        every = set(tool_names_for_toolsets({"all"}))
        self.assertEqual(every, set(TOOL_BY_NAME))

    def test_toolsets_for_tool_names_inverts_toolset_definitions(self):
        # toolsets_for_tool_names is the reverse of TOOLSET_DEFINITIONS that
        # demand-driven activation relies on: every specialized tool maps back to
        # exactly its owning toolset; core tools and unknown names map to nothing
        # (already always visible / no-op), so activation stays minimal.
        for toolset, names in TOOLSET_DEFINITIONS.items():
            for name in names:
                resolved = toolsets_for_tool_names({name})
                if toolset == "core":
                    self.assertEqual(
                        resolved, set(),
                        f"{name} is core and must need no activation",
                    )
                else:
                    self.assertEqual(
                        resolved, {toolset},
                        f"{name} should resolve to its owning toolset {toolset!r}",
                    )
        self.assertEqual(toolsets_for_tool_names({"not_a_tool", ""}), set())
        # A mixed request unions the specialized owners and drops core.
        self.assertEqual(
            toolsets_for_tool_names(
                {"read_file", "build_attack_graph", "complete_sequence_experiment"}
            ),
            {"map", "experiment"},
        )

    def test_parallel_safe_are_real_tools(self):
        unknown = set(PARALLEL_SAFE) - set(TOOL_BY_NAME)
        self.assertEqual(
            unknown, set(),
            f"PARALLEL_SAFE names that are not tools: {sorted(unknown)}",
        )

    def test_synthesize_args_routed_and_in_experiment_toolset(self):
        # Focused pin for the arg-synthesis tool: a real schema, routed by
        # execute_tool, and a member of the experiment toolset only.
        self.assertIn("synthesize_args", TOOL_BY_NAME)
        self.assertIn("synthesize_args", _execute_tool_case_names())
        self.assertIn("synthesize_args", TOOLSET_DEFINITIONS["experiment"])
        memberships = [
            toolset for toolset, names in TOOLSET_DEFINITIONS.items()
            if "synthesize_args" in names
        ]
        self.assertEqual(memberships, ["experiment"])

    def test_complete_sequence_experiment_routed_and_in_experiment_toolset(self):
        # Focused pin for the sequence-completion tool: a real schema, routed by
        # execute_tool, and a member of the experiment toolset only.
        self.assertIn("complete_sequence_experiment", TOOL_BY_NAME)
        self.assertIn("complete_sequence_experiment", _execute_tool_case_names())
        self.assertIn(
            "complete_sequence_experiment", TOOLSET_DEFINITIONS["experiment"]
        )
        memberships = [
            toolset for toolset, names in TOOLSET_DEFINITIONS.items()
            if "complete_sequence_experiment" in names
        ]
        self.assertEqual(memberships, ["experiment"])

    def test_diagnose_build_routed_and_in_experiment_toolset(self):
        # Focused pin for the build-diagnosis tool: a real schema, routed by
        # execute_tool, and a member of the experiment toolset only.
        self.assertIn("diagnose_build", TOOL_BY_NAME)
        self.assertIn("diagnose_build", _execute_tool_case_names())
        self.assertIn("diagnose_build", TOOLSET_DEFINITIONS["experiment"])
        memberships = [
            toolset for toolset, names in TOOLSET_DEFINITIONS.items()
            if "diagnose_build" in names
        ]
        self.assertEqual(memberships, ["experiment"])

    def test_repair_experiment_routed_and_in_experiment_toolset(self):
        # Focused pin for the harness-repair tool: a real schema, routed by
        # execute_tool, and a member of the experiment toolset only.
        self.assertIn("repair_experiment", TOOL_BY_NAME)
        self.assertIn("repair_experiment", _execute_tool_case_names())
        self.assertIn("repair_experiment", TOOLSET_DEFINITIONS["experiment"])
        memberships = [
            toolset for toolset, names in TOOLSET_DEFINITIONS.items()
            if "repair_experiment" in names
        ]
        self.assertEqual(memberships, ["experiment"])

    def test_extract_state_transition_model_routed_and_in_map_toolset(self):
        # Focused pin for the state-transition modeling tool: a real schema,
        # routed by execute_tool, and a member of the map toolset only.
        self.assertIn("extract_state_transition_model", TOOL_BY_NAME)
        self.assertIn("extract_state_transition_model", _execute_tool_case_names())
        self.assertIn(
            "extract_state_transition_model", TOOLSET_DEFINITIONS["map"]
        )
        memberships = [
            toolset for toolset, names in TOOLSET_DEFINITIONS.items()
            if "extract_state_transition_model" in names
        ]
        self.assertEqual(memberships, ["map"])

    def test_build_attack_graph_accepts_state_transition_model_param(self):
        # Pin the Prompt 9 integration surface: build_attack_graph exposes an
        # optional state_transition_model string arg so generic invariants can be
        # scheduled as attack-graph branches.
        params = (
            TOOL_BY_NAME["build_attack_graph"]["function"]["parameters"]["properties"]
        )
        self.assertIn("state_transition_model", params)
        self.assertEqual(params["state_transition_model"]["type"], "string")

    def test_prepare_fork_exploit_workbench_accepts_state_transition_model_param(self):
        # The fork workbench consumes the same artifact so model-derived invariants
        # can shape generic objective/observation templates.
        params = (
            TOOL_BY_NAME["prepare_fork_exploit_workbench"]["function"]["parameters"][
                "properties"
            ]
        )
        self.assertIn("state_transition_model", params)
        self.assertEqual(params["state_transition_model"]["type"], "string")

    def test_submission_review_tools_expose_exploitability_checklist(self):
        expected = {
            "preconditions",
            "precondition_provenance",
            "production_reachability",
            "funds_at_risk",
            "negative_controls",
        }
        for name in (
            "review_finding_evidence",
            "review_report_quality",
            "submit_finding",
        ):
            params = TOOL_BY_NAME[name]["function"]["parameters"]["properties"]
            self.assertTrue(expected.issubset(params), name)


class ToolDescriptionCompactionTests(unittest.TestCase):
    """TD-1: tool-level descriptions reach the model whole; params stay compact."""

    def _raw_tool_description(self, name: str) -> str:
        for tool in TOOLS:
            fn = tool.get("function", {})
            if fn.get("name") == name:
                return " ".join(str(fn.get("description", "")).split())
        raise AssertionError(f"tool {name!r} not found")

    def test_long_tool_description_survives_uncut(self):
        # review_report_quality has the longest authored description; before TD-1
        # it was clipped to 120 chars on the wire.
        wire = {
            t["function"]["name"]: t["function"].get("description", "")
            for t in tools_for_toolsets({"all"})
        }
        raw = self._raw_tool_description("review_report_quality")
        self.assertGreater(len(raw), _SCHEMA_DESCRIPTION_LIMIT)
        self.assertEqual(wire["review_report_quality"], raw)
        self.assertFalse(wire["review_report_quality"].endswith("..."))

    def test_all_tool_descriptions_within_tool_limit_and_untruncated(self):
        for tool in tools_for_toolsets({"all"}):
            name = tool["function"]["name"]
            desc = tool["function"].get("description", "")
            # Navigation tools (request_toolset) carry a bounded, derived map and
            # are intentionally exempt from the tool-level length bound.
            if name not in _NAVIGATION_TOOL_NAMES:
                self.assertLessEqual(len(desc), _TOOL_DESCRIPTION_LIMIT, name)
            # Equal to the whitespace-collapsed source ⇒ not truncated.
            self.assertEqual(desc, self._raw_tool_description(name), name)

    def test_parameter_descriptions_stay_compact(self):
        def check_params(schema):
            props = schema.get("function", {}).get("parameters", {}).get("properties", {})
            for arg, spec in props.items():
                desc = spec.get("description")
                if isinstance(desc, str):
                    self.assertLessEqual(len(desc), _SCHEMA_DESCRIPTION_LIMIT, arg)

        for tool in tools_for_toolsets({"all"}):
            check_params(tool)

    def test_attack_search_status_description_mentions_poc_repair(self):
        schema = next(
            tool for tool in tools_for_toolsets({"core"})
            if tool["function"]["name"] == "attack_search"
        )
        status_description = (
            schema["function"]["parameters"]["properties"]["status"]["description"]
        )
        self.assertIn("needs_poc_repair", status_description)
        self.assertIn("not exploit evidence", status_description)


class RequestToolsetNavigationTests(unittest.TestCase):
    """TD-2: request_toolset advertises the live toolset map + activation rules."""

    def _wire_description(self) -> str:
        for tool in tools_for_toolsets({"core"}):
            if tool["function"]["name"] == "request_toolset":
                return tool["function"]["description"]
        raise AssertionError("request_toolset not visible in core toolset")

    def test_describes_activation_and_all(self):
        desc = self._wire_description()
        # Activation is next-turn, not current-turn.
        self.assertIn("NEXT turn", desc)
        self.assertIn("visible on the NEXT turn", desc)
        # Narrow-first: prefer the toolset the controller's next_action needs.
        self.assertIn("narrowest toolset", desc)
        self.assertIn("attack_search.next_action", desc)
        # 'all' survives only as an escape hatch, not the default efficient path.
        self.assertIn("'all'", desc)
        self.assertIn("Request 'all' only for", desc)

    def test_does_not_frame_all_as_the_default_efficient_path(self):
        # Regression: the old description sold 'all' as the way to "reveal every
        # specialized tool at once and avoid repeated round-trips". With
        # demand-driven activation the visible surface should stay narrow, so
        # that round-trip-avoidance framing must be gone.
        desc = self._wire_description()
        self.assertNotIn("reveal every specialized tool", desc)
        self.assertNotIn("repeated round-trips", desc)

    def test_lists_every_toolset_member_uncut(self):
        # Drift guard: every requestable toolset and every one of its tools must
        # appear, so the advertised map cannot fall out of sync with
        # TOOLSET_DEFINITIONS, and the navigation map is never clipped.
        desc = self._wire_description()
        self.assertFalse(desc.endswith("..."))
        for toolset, members in TOOLSET_DEFINITIONS.items():
            if toolset == "core":
                continue
            self.assertIn(toolset, desc)
            for name in members:
                self.assertIn(name, desc, f"{name} ({toolset}) missing from request_toolset map")


class ExecuteToolErrorTests(unittest.TestCase):
    """TD-3: tool failures return structured, actionable errors (no leaked values)."""

    def test_tool_exception_returns_structured_error_without_values(self):
        async def boom(container, args):
            raise ValueError("kaboom mechanism detail")

        with mock.patch.object(tools_mod, "_inspect_scope", new=boom):
            out = asyncio.run(
                execute_tool("inspect_scope", {"secret_value": "TOPSECRET"}, None, [])
            )
        payload = json.loads(out)
        self.assertEqual(payload["error"], "tool_failed")
        self.assertEqual(payload["tool"], "inspect_scope")
        self.assertEqual(payload["error_type"], "ValueError")
        self.assertEqual(payload["arg_keys"], ["secret_value"])
        # Argument VALUES must never be echoed (probe/key redaction contract).
        self.assertNotIn("TOPSECRET", out)

    def test_unknown_tool_still_reported(self):
        out = asyncio.run(execute_tool("not_a_tool", {}, None, []))
        self.assertIn("Unknown tool", out)


class ToolsFacadeContractTests(unittest.TestCase):
    """Pin the public+private import surface so the split keeps the facade whole."""

    def test_all_imported_names_resolve_on_facade(self):
        wanted = _names_imported_from_tools()
        self.assertIn("execute_tool", wanted)  # sanity: the scan found imports
        missing = sorted(n for n in wanted if not hasattr(tools_mod, n))
        self.assertEqual(
            missing, [],
            f"names imported from reentbotpro.tools that no longer resolve: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
