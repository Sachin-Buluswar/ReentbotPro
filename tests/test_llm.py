import base64
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from reentbotpro.llm import (
    CODEX_ORIGINATOR,
    CodexAuthProfile,
    CodexCliAuthStore,
    DEFAULT_MODEL,
    OPENAI_API_PROVIDER,
    OPENAI_CODEX_PROVIDER,
    OAUTH_REDIRECT_URI,
    OAUTH_SCOPE,
    ResponsesLLMClient,
    estimate_responses_request_tokens,
    get_model_settings,
    resolve_reasoning_effort,
    _messages_to_responses_input,
    _oauth_authorize_url,
    _responses_tools,
)


def _jwt(payload: dict) -> str:
    def enc(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc(payload)}.sig"


class CodexAuthProfileTests(unittest.TestCase):
    def test_extracts_chatgpt_account_claims(self):
        profile = CodexAuthProfile.from_token_response({
            "access_token": _jwt({
                "exp": 9999999999,
                "https://api.openai.com/auth.chatgpt_account_id": "acct_123",
                "https://api.openai.com/auth.chatgpt_plan_type": "plus",
            }),
            "id_token": _jwt({"email": "user@example.com"}),
            "refresh_token": "refresh",
        })

        self.assertEqual(profile.account_id, "acct_123")
        self.assertEqual(profile.email, "user@example.com")
        self.assertEqual(profile.plan_type, "plus")
        self.assertTrue(profile.is_fresh())

    def test_extracts_nested_chatgpt_account_claims(self):
        profile = CodexAuthProfile.from_token_response({
            "access_token": _jwt({
                "exp": 9999999999,
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct_nested",
                    "chatgpt_plan_type": "pro",
                    "chatgpt_account_is_fedramp": True,
                },
                "https://api.openai.com/profile": {"email": "nested@example.com"},
            }),
            "id_token": _jwt({
                "https://api.openai.com/profile": {"email": "id@example.com"},
            }),
            "refresh_token": "refresh",
        })

        self.assertEqual(profile.account_id, "acct_nested")
        self.assertEqual(profile.email, "id@example.com")
        self.assertEqual(profile.plan_type, "pro")
        self.assertTrue(profile.is_fedramp_account)

    def test_loads_codex_cli_auth_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": _jwt({
                        "exp": 9999999999,
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "acct_cli",
                        },
                    }),
                    "id_token": _jwt({
                        "https://api.openai.com/profile": {"email": "cli@example.com"},
                    }),
                    "refresh_token": "refresh",
                },
            }))

            profile = CodexCliAuthStore(auth_path).load()

        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile.account_id, "acct_cli")
        self.assertEqual(profile.email, "cli@example.com")

    def test_authorize_url_matches_openclaw_codex_oauth_shape(self):
        url = _oauth_authorize_url("state", "challenge")

        self.assertIn(f"redirect_uri={OAUTH_REDIRECT_URI.replace(':', '%3A').replace('/', '%2F')}", url)
        self.assertIn("scope=openid+profile+email+offline_access", url)
        self.assertEqual(OAUTH_SCOPE, "openid profile email offline_access")
        self.assertIn(f"originator={CODEX_ORIGINATOR}", url)


class ResponsesAdapterTests(unittest.TestCase):
    def test_converts_chat_history_to_responses_items(self):
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "inspect"},
            {
                "role": "assistant",
                "content": "I will read a file.",
                "response_items": [{
                    "type": "reasoning",
                    "id": "rs_1",
                    "summary": [],
                    "encrypted_content": "encrypted",
                }],
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path": "A.sol"}'},
                }],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "contract A {}"},
        ]

        instructions, items = _messages_to_responses_input(messages)

        self.assertEqual(instructions, "system prompt")
        self.assertEqual(items[0], {"type": "message", "role": "user", "content": "inspect"})
        self.assertEqual(items[1], {
            "type": "message",
            "role": "assistant",
            "content": "I will read a file.",
        })
        self.assertEqual(items[2], {
            "type": "reasoning",
            "summary": [],
            "encrypted_content": "encrypted",
        })
        self.assertEqual(items[3]["type"], "function_call")
        self.assertEqual(items[3]["call_id"], "call_1")
        self.assertEqual(items[4], {
            "type": "function_call_output",
            "call_id": "call_1",
            "output": "contract A {}",
        })

    def test_omits_unpersisted_reasoning_item_references(self):
        messages = [
            {"role": "user", "content": "inspect"},
            {
                "role": "assistant",
                "response_items": [{"type": "reasoning", "id": "rs_1"}],
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path": "A.sol"}'},
                }],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "contract A {}"},
        ]

        _, items = _messages_to_responses_input(messages)

        self.assertNotIn({"type": "reasoning", "id": "rs_1"}, items)
        self.assertEqual(items[1]["type"], "function_call")
        self.assertEqual(items[2]["type"], "function_call_output")

    def test_preserves_encrypted_compaction_items(self):
        messages = [
            {"role": "user", "content": "inspect"},
            {
                "role": "assistant",
                "response_items": [{
                    "type": "compaction",
                    "id": "cmp_1",
                    "encrypted_content": "opaque",
                }],
            },
        ]

        _, items = _messages_to_responses_input(messages)

        self.assertEqual(items[1], {
            "type": "compaction",
            "encrypted_content": "opaque",
        })

    def test_converts_tool_schema_to_responses_function_tools(self):
        tools = [{
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file",
                "parameters": {"type": "object", "properties": {}},
            },
        }]

        self.assertEqual(_responses_tools(tools), [{
            "type": "function",
            "name": "read_file",
            "description": "Read a file",
            "strict": False,
            "parameters": {"type": "object", "properties": {}},
        }])

    def test_estimates_responses_payload_with_tool_schema_overhead(self):
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "inspect"},
        ]
        tools = [{
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file",
                "parameters": {"type": "object", "properties": {}},
            },
        }]

        without_tools = estimate_responses_request_tokens(messages)
        with_tools = estimate_responses_request_tokens(messages, tools)

        self.assertGreater(with_tools, without_tools)
        self.assertGreater(without_tools, 0)

    def test_stream_turn_normalizes_responses_events(self):
        class FakeDisplay:
            def stream_text(self, text):
                pass

            def stream_reasoning(self, text):
                pass

            def end_reasoning(self):
                pass

            def reasoning_summary(self, token_count):
                pass

        class FakeClient(ResponsesLLMClient):
            def __init__(self, events):
                self.events = events

            async def _stream_events(self, payload):
                self.payload = payload
                for event in self.events:
                    yield event

        client = FakeClient([
            {"type": "response.output_text.delta", "delta": "Reading."},
            {
                "type": "response.output_item.done",
                "item": {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "read_file",
                    "arguments": '{"path":"A.sol"}',
                },
            },
            {
                "type": "response.completed",
                "response": {"usage": {"total_tokens": 42}},
            },
        ])

        msg, tokens, reasoning, finish = asyncio.run(client.stream_turn(
            model="gpt-5.4",
            messages=[{"role": "system", "content": "system"}],
            tools=[],
            display=FakeDisplay(),
            max_output_tokens=100,
        ))

        self.assertEqual(client.payload["input"][0]["content"], "Begin the audit.")
        self.assertEqual(client.payload["include"], ["reasoning.encrypted_content"])
        self.assertEqual(msg["content"], "Reading.")
        self.assertEqual(msg["tool_calls"][0]["id"], "call_1")
        self.assertEqual(tokens, 42)
        self.assertEqual(reasoning, 0)
        self.assertEqual(finish, "tool_calls")

    def _run_stream_capture(self, *, session_id, provider_name):
        class FakeDisplay:
            def stream_text(self, text):
                pass

            def stream_reasoning(self, text):
                pass

            def end_reasoning(self):
                pass

            def reasoning_summary(self, token_count):
                pass

        class FakeClient(ResponsesLLMClient):
            def __init__(self):
                self.events = [{
                    "type": "response.completed",
                    "response": {"usage": {"total_tokens": 1}},
                }]
                self.session_id = session_id
                self.provider_name = provider_name

            async def _stream_events(self, payload):
                self.payload = payload
                for event in self.events:
                    yield event

        client = FakeClient()
        asyncio.run(client.stream_turn(
            model="gpt-5.4",
            messages=[{"role": "system", "content": "system"}],
            tools=[],
            display=FakeDisplay(),
            max_output_tokens=100,
        ))
        return client.payload

    def test_stream_turn_sets_prompt_cache_key_on_api_path(self):
        payload = self._run_stream_capture(
            session_id="sess-xyz", provider_name=OPENAI_API_PROVIDER,
        )
        self.assertEqual(payload["prompt_cache_key"], "sess-xyz")

    def test_stream_turn_omits_prompt_cache_key_on_codex_path(self):
        payload = self._run_stream_capture(
            session_id="sess-xyz", provider_name=OPENAI_CODEX_PROVIDER,
        )
        self.assertNotIn("prompt_cache_key", payload)


class ModelSettingsTests(unittest.TestCase):
    def test_default_model_is_gpt_55(self):
        self.assertEqual(DEFAULT_MODEL, "gpt-5.5")
        self.assertEqual(get_model_settings(None).context_window, 1_050_000)
        self.assertEqual(
            get_model_settings(None).reasoning_efforts,
            ("low", "medium", "high", "xhigh"),
        )

    def test_api_model_context_windows_are_resolved(self):
        self.assertEqual(get_model_settings("gpt-5.5").context_window, 1_050_000)
        self.assertEqual(get_model_settings("gpt-5.4").context_window, 1_050_000)
        self.assertEqual(
            get_model_settings("gpt-5.4-2026-03-05").context_window,
            1_050_000,
        )
        self.assertEqual(get_model_settings("gpt-5.4-mini").context_window, 400_000)
        self.assertEqual(get_model_settings("gpt-5.4-nano").context_window, 400_000)
        self.assertEqual(
            get_model_settings("gpt-5.3-codex-spark").context_window,
            128_000,
        )

    def test_openrouter_model_context_windows_are_resolved(self):
        self.assertEqual(
            get_model_settings("minimax/minimax-m3").context_window, 524_288
        )
        self.assertEqual(
            get_model_settings("deepseek/deepseek-v4-pro").context_window, 1_048_576
        )
        self.assertEqual(
            get_model_settings("z-ai/glm-5.2").context_window, 1_048_576
        )
        # Context windows verified live against the OpenRouter gateway
        # (over-limit prompt rejected with the enforced max).
        self.assertEqual(
            get_model_settings("google/gemini-3.5-flash").context_window, 1_048_576
        )
        self.assertEqual(
            get_model_settings("xiaomi/mimo-v2.5-pro").context_window, 1_048_576
        )
        self.assertEqual(
            get_model_settings("qwen/qwen3.7-max").context_window, 1_000_000
        )
        self.assertEqual(
            get_model_settings("tencent/hy3-preview").context_window, 262_144
        )
        self.assertEqual(
            get_model_settings("nex-agi/nex-n2-pro:free").context_window, 262_144
        )
        self.assertEqual(
            get_model_settings("moonshotai/kimi-k2.7-code").context_window, 262_144
        )

    def test_openrouter_mimo_pro_does_not_match_bare_id(self):
        # "xiaomi/mimo-v2.5-pro" resolves on its own; the bare
        # "xiaomi/mimo-v2.5" id was removed and must fall back to the
        # conservative window (the longer key must not bleed onto it).
        self.assertEqual(
            get_model_settings("xiaomi/mimo-v2.5-pro").context_window, 1_048_576
        )
        self.assertEqual(
            get_model_settings("xiaomi/mimo-v2.5").context_window, 128_000
        )

    def test_openrouter_glm_5_2_resolves_without_bleeding_onto_neighbors(self):
        # glm-5.2 must resolve to its own live-verified window and must not
        # bleed onto the neighboring glm-5.1 id (removed from the registry),
        # which now falls back to the conservative default.
        self.assertEqual(
            get_model_settings("z-ai/glm-5.2").context_window, 1_048_576
        )
        self.assertEqual(
            get_model_settings("z-ai/glm-5.1").context_window, 128_000
        )
        # OpenRouter's underlying dated id resolves to the same entry via the
        # -20 snapshot rule.
        self.assertEqual(
            get_model_settings("z-ai/glm-5.2-20260616").context_window, 1_048_576
        )

    def test_openrouter_openai_prefix_resolves_to_bare_model(self):
        self.assertEqual(
            get_model_settings("openai/gpt-5.4").context_window, 1_050_000
        )
        self.assertEqual(
            get_model_settings("openai/gpt-5.5").context_window, 1_050_000
        )
        self.assertEqual(
            get_model_settings("openai/gpt-5.4-mini").context_window, 400_000
        )

    def test_unknown_model_uses_conservative_fallback(self):
        self.assertEqual(
            get_model_settings("anthropic/claude-opus-4.7").context_window, 128_000
        )
        self.assertEqual(
            get_model_settings("totally-made-up-model").context_window, 128_000
        )

    def test_codex_model_context_windows_are_resolved(self):
        provider = OPENAI_CODEX_PROVIDER

        self.assertEqual(
            get_model_settings("gpt-5.5", provider_name=provider).context_window,
            272_000,
        )
        self.assertEqual(
            get_model_settings("gpt-5.2", provider_name=provider).context_window,
            272_000,
        )
        self.assertEqual(
            get_model_settings("gpt-5.4", provider_name=provider).context_window,
            1_000_000,
        )
        self.assertEqual(
            get_model_settings("gpt-5.4-mini", provider_name=provider).context_window,
            272_000,
        )
        self.assertEqual(
            get_model_settings("gpt-5.3-codex", provider_name=provider).context_window,
            272_000,
        )
        self.assertEqual(
            get_model_settings(
                "gpt-5.3-codex-spark",
                provider_name=provider,
            ).context_window,
            128_000,
        )

    def test_api_provider_is_default_for_backwards_compatibility(self):
        self.assertEqual(
            get_model_settings("gpt-5.5", provider_name=OPENAI_API_PROVIDER).context_window,
            get_model_settings("gpt-5.5").context_window,
        )

    def test_default_reasoning_prefers_xhigh_when_supported(self):
        self.assertEqual(get_model_settings("gpt-5.4").default_reasoning, "xhigh")
        self.assertEqual(
            get_model_settings(
                "gpt-5.4",
                provider_name=OPENAI_CODEX_PROVIDER,
            ).default_reasoning,
            "xhigh",
        )
        self.assertEqual(get_model_settings("gpt-5.1").default_reasoning, "high")

    def test_reasoning_effort_is_adjusted_for_selected_model(self):
        pro = resolve_reasoning_effort("gpt-5.4-pro", "none")
        self.assertEqual(pro.display_effort, "medium")
        self.assertEqual(pro.api_effort, "medium")
        self.assertIsNotNone(pro.note)

        legacy = resolve_reasoning_effort("gpt-5", "xhigh")
        self.assertEqual(legacy.display_effort, "high")
        self.assertEqual(legacy.api_effort, "high")


if __name__ == "__main__":
    unittest.main()
