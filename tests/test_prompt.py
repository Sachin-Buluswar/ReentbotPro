import unittest

from reentbotpro.prompt import REPORT_INSTRUCTION, build_system_prompt


class PromptCapitalGuidanceTests(unittest.TestCase):
    def test_prompt_has_no_fixed_capital_budget(self):
        prompt = build_system_prompt()
        self.assertIn(
            "should not be used as a hard scope filter",
            prompt,
        )
        self.assertIn("Prioritize exploit paths", prompt)
        self.assertIn("Highest priority: attacks with few assumptions", prompt)
        self.assertIn("Still investigate non-atomic, multi-step", prompt)
        self.assertIn("Do not discard a severe bug solely because", prompt)
        self.assertIn("attack_search action=decision", prompt)
        self.assertIn("run_kind=build", prompt)
        self.assertIn("one concrete action/call step", prompt)
        self.assertIn("inventory_live_targets", prompt)
        self.assertIn("needs_concretization", prompt)
        self.assertIn("scaffold_quality.runnable=false", prompt)
        self.assertNotIn("capital model", prompt)
        self.assertNotIn("OUT OF SCOPE unless a flash loan can provide the capital", prompt)
        self.assertNotIn("$1,000", prompt)

    def test_prompt_documents_always_allowed_cognitive_surface(self):
        # The agent must know it can freely read source, search patterns, and
        # record observations even while the controller has a must-follow
        # next action on a different branch — otherwise it wastes turns
        # trying to bypass blocks that no longer exist.
        prompt = build_system_prompt()
        self.assertIn("core tools are available", prompt)
        self.assertIn("always allowed regardless of", prompt)
        for name in (
            "read_file",
            "search_code",
            "source_slice",
            "list_files",
            "inspect_scope",
            "update_campaign",
            "build_campaign_brief",
            "fetch_url",
            "web_search",
        ):
            self.assertIn(name, prompt, f"prompt should mention {name}")
        # Visible tools are not the same as controller-always-allowed tools.
        self.assertIn("Visible tools are not the same as the", prompt)
        self.assertIn("controller-always-allowed tools", prompt)
        self.assertIn("Some branch-unblocked cognitive tools", prompt)
        self.assertIn("request_toolset", prompt)
        self.assertIn("mutate_hypothesis", prompt)
        self.assertIn("/workspace/experiments/", prompt)
        self.assertIn("run_experiment", prompt)

    def test_prompt_prefers_narrow_toolset_requests(self):
        # Demand-driven activation: request_toolset should be nudged toward the
        # narrowest toolset the controller's next_action needs, with 'all'
        # reserved as a wrap-up/debugging escape hatch — not framed as the
        # efficient default that pre-reveals everything to save round-trips.
        prompt = build_system_prompt()
        self.assertIn("narrowest toolset the current", prompt)
        self.assertIn("appear on the next turn", prompt)
        self.assertIn("Reserve `request_toolset all`", prompt)
        self.assertIn("late wrap-up, debugging tool visibility", prompt)
        self.assertNotIn("reveal every specialized tool", prompt)
        self.assertNotIn("avoid repeated round-trips", prompt)

    def test_prompt_promotes_source_slice_for_focused_context(self):
        # source_slice is the preferred focused-Solidity-context tool. The
        # prompt must say to reach for it over whole-file reads when zeroing in
        # on a function/modifier/range/hypothesis, and keep read_file for small
        # or config files and broader context.
        prompt = build_system_prompt()
        self.assertIn("Prefer `source_slice` over whole-file reads", prompt)
        self.assertIn("function, modifier, line range, or exploit hypothesis", prompt)
        self.assertIn("Use `read_file` for small", prompt)

    def test_prompt_marks_write_file_and_run_command_side_effecting(self):
        # Visible-but-side-effecting tools must be distinguished from the
        # cognitive surface: write_file and general run_command follow
        # attack_search.next_action, except for the diagnostic and
        # generated-experiment workspace exceptions the controller guard allows.
        prompt = build_system_prompt()
        self.assertIn("Some core-visible tools are side-effecting", prompt)
        self.assertIn("`write_file` and general", prompt)
        self.assertIn("should follow `attack_search.next_action`", prompt)
        self.assertIn(
            "diagnostic commands and generated-experiment workspace validation",
            prompt,
        )

    def test_prompt_reasons_from_structure_for_bland_names(self):
        # Generic state-transition/invariant reasoning is first-class: when names
        # are bland or misleading the agent reasons from structure and must not
        # deprioritize a function just because it lacks familiar names.
        prompt = build_system_prompt()
        self.assertIn(
            "Generic state-transition and invariant reasoning is a first-class",
            prompt,
        )
        self.assertIn("When names are bland or misleading, reason from structure", prompt)
        self.assertIn("rights consumed, assets or claims moved", prompt)
        self.assertIn("authorization subjects checked", prompt)
        self.assertIn(
            "Do not lower a function's priority solely because it lacks familiar",
            prompt,
        )

    def test_prompt_pairs_state_transition_and_attack_graph_as_planning_context(self):
        # The generic planning pair must be advertised together and framed as
        # planning context, not evidence, so neither a state-transition model nor
        # a graph candidate is ever treated as proof.
        prompt = build_system_prompt()
        self.assertIn("extract_state_transition_model", prompt)
        self.assertIn("build_attack_graph", prompt)
        self.assertIn("generic invariant/frontier branches", prompt)
        self.assertIn("graph candidates are planning context", prompt)

    def test_prompt_documents_state_transition_model_as_planning_context(self):
        # The generic state/invariant modeling tool must be advertised as a
        # planning aid, not evidence, so the agent never treats its output as a
        # finding or a substitute for a runnable PoC.
        prompt = build_system_prompt()
        self.assertIn("extract_state_transition_model", prompt)
        self.assertIn("planning context, not vulnerability evidence", prompt)

    def test_prompt_documents_scaffold_route_filter_and_override(self):
        # The agent must know the scaffold filter exists AND how to override
        # when the classifier suppresses a route it actually needs.
        prompt = build_system_prompt()
        self.assertIn("non-economic", prompt)
        self.assertIn("force_route_kinds", prompt)
        # We deliberately do NOT mention a closed intent enum — the contract
        # is one boolean plus one override list, not a taxonomy.
        self.assertNotIn("branch_intent", prompt)

    def test_prompt_compresses_mechanism_playbooks_into_generic_rule(self):
        # The detailed AMM/oracle/flash/lending playbooks are gone from the
        # permanent prompt and replaced with one generic rule: reach for the
        # branch/tool surfaces to get mechanism-specific checks, treat those
        # checks as questions to turn into fork setup/snapshots/objective
        # assertions, and never let them override generic reasoning or stand in
        # for a runnable PoC. The tool pointers must survive so the agent still
        # knows where the mechanism detail lives.
        prompt = build_system_prompt()
        collapsed = " ".join(prompt.split())
        self.assertIn(
            "use the relevant map, economics, workbench, and sequence tools to "
            "obtain branch-specific setup checks",
            collapsed,
        )
        self.assertIn(
            "Treat those checks as questions to turn into concrete fork setup, "
            "snapshots, and objective assertions",
            collapsed,
        )
        self.assertIn("corroboration, not proof", collapsed)
        self.assertIn(
            "must not override generic state/invariant reasoning", collapsed
        )
        self.assertIn(
            "cannot substitute for a runnable PoC with objective evidence",
            collapsed,
        )
        # A concise examples sentence is allowed (mechanisms as lenses), but no
        # long always-on procedure per mechanism.
        self.assertIn(
            "AMMs, lending and liquidation, vaults, bridges, queues, "
            "signatures, and oracles among them",
            collapsed,
        )
        # The branch/tool surfaces stay named so the agent knows where to reach.
        for name in (
            "estimate_amm_economics",
            "estimate_flash_loan",
            "estimate_lending_health",
            "prepare_fork_exploit_workbench",
            "route_composition_plan",
        ):
            self.assertIn(name, prompt, f"prompt should still point at {name}")

    def test_prompt_drops_always_on_mechanism_playbooks(self):
        # The spelled-out, always-on mechanism checklists must not be injected
        # into every audit anymore. They now live in the branch/tool outputs:
        # plan_attack_campaign's branch checks, compose_sequence_experiment's
        # route_composition_plan, and prepare_fork_exploit_workbench's mechanism
        # adapter. Pin their absence so the permanent prompt stays generic.
        prompt = build_system_prompt()
        collapsed = " ".join(prompt.split())
        for banned in (
            "Before spending time on oracle manipulation",
            "follow the `oracle_window_checks` from",
            "record answer, decimals, updatedAt/timestamp, heartbeat, "
            "deviation threshold",
            "adds `flash_loan_checks`",
            "post-unwind balance",
            "Follow its `liquidation_route_checks`",
            "identify close factor, repay asset,",
        ):
            self.assertNotIn(
                banned,
                collapsed,
                f"always-on mechanism playbook text should be gone: {banned!r}",
            )

    def test_prompt_prioritizes_generic_state_invariant_methodology(self):
        # Generic state/invariant reasoning is the prominent, first-class
        # methodology, and known bug classes stay lenses, not rails — so the
        # compressed prompt cannot drift back into a mechanism taxonomy.
        prompt = build_system_prompt()
        collapsed = " ".join(prompt.split())
        self.assertIn("Known bug classes are useful lenses, not rails", prompt)
        self.assertIn(
            "Generic state-transition and invariant reasoning is a first-class",
            prompt,
        )
        self.assertIn("rights consumed, assets or claims moved", collapsed)
        self.assertIn("invariants that should hold before and after", collapsed)
        self.assertIn(
            "preserve generic invariant/frontier branches", collapsed
        )

    def test_prompt_documents_alchemy_investigation_tools(self):
        # The agent must know the live on-chain tools exist, how to target a
        # chain, the cheap-vs-expensive cost split, and that simulation is
        # corroboration — never a substitute for a runnable PoC.
        prompt = build_system_prompt()
        for name in (
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
        ):
            self.assertIn(name, prompt, f"prompt should mention {name}")
        self.assertIn("Live On-Chain Investigation", prompt)
        self.assertIn("corroboration, not proof", prompt)
        self.assertIn("base-mainnet", prompt)
        # Etherscan verified-source tool is documented alongside the Alchemy tools.
        self.assertIn("get_contract_source", prompt)
        self.assertIn("Etherscan", prompt)
        # The live section leads with the Alchemy/Etherscan-first model, not the
        # legacy ETH_RPC_URL-first phrasing.
        self.assertNotIn(
            "When `ETH_RPC_URL`, Alchemy, or Etherscan context is configured",
            prompt,
        )

    def test_prompt_frames_chain_aware_rpc_and_multichain(self):
        # The live/fork RPC model is Alchemy/Etherscan-first and chain-aware:
        #   (a) endpoints derive per chain from the Alchemy key + recorded chain,
        #   (b) ETH_RPC_URL / --rpc-url is only an explicit override,
        #   (c) neither ETH_RPC_URL nor --chain is required for live tools,
        #   (d) chain assumptions and multi-chain bindings are recorded, and
        #   (e) a scope may span multiple chains (never collapsed to one).
        prompt = build_system_prompt()
        collapsed = " ".join(prompt.split())
        # (a) Alchemy/Etherscan context derives a chain-specific endpoint.
        self.assertIn("When Alchemy or Etherscan context is configured", prompt)
        self.assertIn("derives a chain-specific RPC endpoint", collapsed)
        # (b) ETH_RPC_URL / --rpc-url is an explicit override only.
        self.assertIn(
            "`ETH_RPC_URL` / `--rpc-url` is an explicit override only", prompt
        )
        # (c) Live tools do not require ETH_RPC_URL or --chain.
        self.assertIn("You do not need `ETH_RPC_URL` or `--chain`", prompt)
        # (d) Chain assumptions and multi-chain bindings are recorded.
        self.assertIn("Record each chain assumption and multi-chain binding", prompt)
        self.assertIn("per-target chain bindings", collapsed)
        # (e) A scope may span multiple chains, never collapsed onto one.
        self.assertIn("A scope may span multiple chains", prompt)
        self.assertIn(
            "rather than collapsing the run onto a single chain", collapsed
        )

    def test_prompt_documents_submission_gate_recovery_path(self):
        # Tier-1 surfaces: the agent must know
        #   (a) gap strings carry recovery hints after an em-dash,
        #   (b) Foundry-aware test_output parsing doesn't false-positive on
        #       vm.expectRevert,
        #   (c) linking objective_evaluation downgrades the test_output
        #       heuristic from blocker to warning.
        prompt = build_system_prompt()
        self.assertIn("recovery hint", prompt)
        self.assertIn("em-dash", prompt)
        self.assertIn("vm.expectRevert", prompt)
        self.assertIn("zero executed tests", prompt)
        self.assertIn("objective_evaluation", prompt)

    def test_prompt_matches_no_tool_stop_contract(self):
        prompt = build_system_prompt()

        self.assertIn("include at least one concrete tool call", prompt)
        self.assertIn("does no audit work and stalls campaign progress", prompt)
        self.assertNotIn("irreversibly terminates", prompt)
        self.assertNotIn('There is no "continue"', prompt)

    def test_prompt_scopes_tool_call_requirement_to_audit_phase(self):
        # The "one concrete tool call per response" rule is scoped to the
        # autonomous audit phase, so it does not read as a blanket rule that
        # forbids a no-tool-call answer once readiness gates permit stopping or
        # the system has moved into report/chat mode.
        prompt = build_system_prompt()
        self.assertIn("during the autonomous audit phase", prompt)
        self.assertIn(
            "the controller and readiness checks permit stopping or the system "
            "has moved into report/chat mode",
            prompt,
        )
        # The old unqualified phrasing is gone.
        self.assertNotIn(
            "in EVERY response until you have genuinely exhausted", prompt
        )

    def test_prompt_matches_submission_validation_gate(self):
        prompt = build_system_prompt()

        self.assertIn("Every medium/high/critical finding must be validated", prompt)
        self.assertIn("If the bug looks glaring, prove it", prompt)
        self.assertIn("A passing PoC proves the mechanics", prompt)
        self.assertIn("production reachability and precondition provenance", prompt)
        self.assertIn("synthetic victim setup", prompt)
        self.assertIn("zero measured funds at risk", prompt)
        self.assertIn("do not suppress a mechanically validated candidate", prompt)
        self.assertIn("honest severity/exploitability status", prompt)
        self.assertIn("Review warnings about absent objective evaluation", prompt)
        self.assertIn("trusted-role ambiguity", prompt)
        self.assertIn("confidence caveats", prompt)
        self.assertIn("`call_context_plan`", prompt)
        self.assertIn("caller, execution/state context", prompt)
        self.assertIn("Linked review warnings are copied", prompt)
        self.assertIn(
            "Do not use `validated: false` for medium, high, or critical",
            prompt,
        )
        self.assertIn("low/info observations", prompt)
        self.assertNotIn("trivially obvious", prompt)
        self.assertNotIn("public unguarded `withdraw`", prompt)

    def test_report_instruction_transcribes_validated_artifacts(self):
        self.assertIn("full findings JSON", REPORT_INSTRUCTION)
        self.assertIn("authoritative", REPORT_INSTRUCTION)
        self.assertIn("AUTHORITATIVE_SUBMITTED_FINDINGS_JSON", REPORT_INSTRUCTION)
        self.assertIn("source of truth for", REPORT_INSTRUCTION)
        self.assertIn("Do not reconstruct findings from truncated", REPORT_INSTRUCTION)
        self.assertIn(
            "PoC validation evidence copied from the submitted finding",
            REPORT_INSTRUCTION,
        )
        self.assertIn("Production reachability", REPORT_INSTRUCTION)
        self.assertIn("precondition provenance", REPORT_INSTRUCTION)
        self.assertIn("measured funds at risk", REPORT_INSTRUCTION)
        self.assertIn("You cannot run forge in this report phase", REPORT_INSTRUCTION)
        self.assertIn("do not invent compile or test results", REPORT_INSTRUCTION)
        self.assertNotIn("Compiles with `forge build`", REPORT_INSTRUCTION)
        self.assertNotIn("paste the forge output", REPORT_INSTRUCTION)

    def test_prompt_keeps_static_analysis_artifacts_out_of_target_tree(self):
        prompt = build_system_prompt()

        self.assertIn("run_kind=static_analysis", prompt)
        self.assertIn("/workspace/campaign/static-analysis/", prompt)
        self.assertIn("keep analyzer output out of the target tree", prompt)
        self.assertIn("Prefer `rg`", prompt)
        self.assertNotIn("slither . --json slither-results.json", prompt)

    def test_prompt_has_concrete_first_five_turn_playbook(self):
        prompt = build_system_prompt()

        self.assertIn("Your first five turns should create", prompt)
        self.assertIn("Call `inspect_scope`", prompt)
        self.assertIn("Call `attack_search action=sync`", prompt)
        self.assertIn("Read the smallest high-value source and config set", prompt)
        self.assertIn("Record evidence-backed campaign artifacts", prompt)
        self.assertIn("one invariant or open question", prompt)
        self.assertIn("Record a hypothesis only when it is concrete", prompt)
        self.assertIn(
            "Record an `experiment` artifact in the first 5 turns only if",
            prompt,
        )
        self.assertIn("actor, target, action/call step", prompt)
        self.assertNotIn("needed for the first hypothesis", prompt)
        self.assertNotIn("One `experiment` artifact for the most promising hypothesis", prompt)

    def test_prompt_infers_target_chain_before_mainnet_fallback(self):
        # No-chain startup is normal: the agent infers the chain(s) and, when
        # chain context stays unknown, continues source-only or records live
        # context as blocked instead of immediately defaulting to mainnet. An
        # Ethereum mainnet fallback is allowed only as an explicit, recorded
        # campaign assumption when no better chain evidence exists.
        prompt = build_system_prompt()

        self.assertIn("Infer the target chain or chains from scope metadata", prompt)
        # Chain inference draws on the chain/deployment registry artifact.
        self.assertIn("chain/deployment registry", prompt)
        # Unknown chain context stays source-only / blocked before any fallback.
        self.assertIn(
            "continue source-only analysis or record live context as blocked",
            prompt,
        )
        # Mainnet fallback is conditional and must be a recorded campaign
        # assumption — not the default next move.
        self.assertIn(
            "Use Ethereum mainnet fallback only after recording it as an "
            "explicit campaign assumption",
            prompt,
        )
        self.assertIn("explicit campaign assumption", prompt)
        # ETH_RPC_URL / --rpc-url is an explicit override only, never the live
        # default.
        self.assertIn(
            "`ETH_RPC_URL` / `--rpc-url` is an explicit override only", prompt
        )
        # Multi-chain bindings are recorded.
        self.assertIn("per-target chain bindings", prompt)
        self.assertIn("deployment-chain", prompt)
        self.assertIn("selected-chain fork", prompt)
        self.assertIn("fork the inferred target chain", prompt)
        # The eager, unconditional mainnet-fallback nudge is gone.
        self.assertNotIn("fall back to Ethereum mainnet", prompt)
        self.assertNotIn(
            "Assume the protocol is deployed on Ethereum mainnet unless otherwise specified",
            prompt,
        )

    def test_prompt_softens_compile_turn_budget(self):
        prompt = build_system_prompt()

        self.assertIn("spend at most a few turns", prompt)
        self.assertNotIn("spend at most 2-3 turns", prompt)

    def test_prompt_routes_build_failures_through_diagnose_build(self):
        # Build / test-discovery failures lead with diagnose_build (and
        # repair_experiment for generated workspaces) before manual run_command
        # dependency loops, and fall back to source_slice-based manual review
        # that continues through the controller — not to manual forge install /
        # git clone ahead of diagnosis.
        prompt = build_system_prompt()
        self.assertIn("call `diagnose_build` first to classify the blocker", prompt)
        self.assertIn(
            "before spending manual `run_command` turns on repair", prompt
        )
        self.assertIn("use `repair_experiment` for the narrow scaffold fixes", prompt)
        self.assertIn("switch to manual source review with `source_slice`", prompt)
        self.assertIn("continue through `attack_search`", prompt)
        # The init-report guidance also diagnoses before the manual install path.
        self.assertIn(
            "call `diagnose_build` first, then install only what the diagnosis "
            "flags as missing",
            prompt,
        )
        # The legacy lead-ins are replaced.
        self.assertNotIn("diagnose systematically", prompt)
        self.assertNotIn("switch to manual code review with `read_file`", prompt)

    def test_prompt_makes_attack_search_the_authoritative_scheduler(self):
        # One authoritative scheduler: attack_search owns branch scheduling and
        # the required next_action. Every other planning tool is advisory context
        # and must not override the controller without an explicit transition.
        prompt = build_system_prompt()

        self.assertIn("authoritative for branch scheduling", prompt)
        self.assertIn("advisory context", prompt)
        self.assertIn("must not override", prompt)
        self.assertIn("attack_search.next_action", prompt)
        # The planner is reframed as advisory, not "the main orchestration tool".
        self.assertIn("advisory planning aid", prompt)
        self.assertNotIn("main orchestration tool", prompt)
        # Known bug classes remain lenses, not rails.
        self.assertIn("lenses, not rails", prompt)

    def test_prompt_documents_partial_probe_and_harness_limit_parking(self):
        # Partial probes preserve research momentum but are setup evidence only,
        # and a plausible-but-hard branch can be parked without being rejected.
        prompt = build_system_prompt()

        self.assertIn("a partial probe instead of stalling", prompt)
        self.assertIn("run_kind=partial_probe", prompt)
        self.assertIn("test_partial_probe_*", prompt)
        self.assertIn("setup/precondition evidence only", prompt)
        self.assertIn("guide mutation but cannot validate", prompt)
        self.assertIn("needs_partial_probe", prompt)
        self.assertIn("needs_poc_repair", prompt)
        self.assertIn("is not proof", prompt)
        self.assertIn("parked_harness_limit", prompt)
        self.assertIn("unproven_due_to_harness_limit", prompt)
        self.assertIn("is not a rejection", prompt)
