"""OpenAI Responses client and ChatGPT/Codex OAuth authentication."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

DEFAULT_MODEL = "gpt-5.6-sol"

OPENAI_API_BASE_URL = "https://api.openai.com/v1"
CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
OPENAI_API_PROVIDER = "openai-api"
OPENAI_CODEX_PROVIDER = "openai-codex"
OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_PORT = 1455
OAUTH_REDIRECT_URI = f"http://localhost:{OAUTH_PORT}/auth/callback"
OAUTH_SCOPE = "openid profile email offline_access"
CODEX_ORIGINATOR = os.environ.get("REENTBOTPRO_CODEX_ORIGINATOR", "pi")
TOKEN_REFRESH_MARGIN_SECONDS = 120

REASONING_ORDER = ("none", "minimal", "low", "medium", "high", "xhigh", "max")


@dataclass(frozen=True)
class ModelSettings:
    """Model-specific limits needed by the agent loop."""

    context_window: int
    max_output_tokens: int = 128_000
    reasoning_efforts: tuple[str, ...] = ("none", "low", "medium", "high", "xhigh")
    default_reasoning: str = "xhigh"


@dataclass(frozen=True)
class ReasoningResolution:
    """Resolved reasoning config for the selected model."""

    requested: str
    display_effort: str
    api_effort: str | None
    note: str | None = None


_API_MODEL_SETTINGS = {
    # GPT-5.6 API models share the same published context/output limits and
    # reasoning-effort surface. ReentbotPro keeps xhigh as its quality-first
    # audit default; the API default when effort is omitted is medium.
    "gpt-5.6-sol": ModelSettings(
        context_window=1_050_000,
        reasoning_efforts=("none", "low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.6-terra": ModelSettings(
        context_window=1_050_000,
        reasoning_efforts=("none", "low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.6-luna": ModelSettings(
        context_window=1_050_000,
        reasoning_efforts=("none", "low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.3-codex-spark": ModelSettings(
        context_window=128_000,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
        default_reasoning="xhigh",
    ),
    # Non-OpenAI models served via OpenRouter (OPENAI_BASE_URL override, API-key
    # path). Listed for correct context-window budgeting; reasoning effort is
    # honored, mapped, or ignored per provider, so defaults are left inherited.
    # Nominal context is 1M, but OpenRouter's only provider for m3 caps prompts
    # at 524288 and the gateway hard-rejects anything larger. Budget for served
    # capacity, not advertised capacity.
    "minimax/minimax-m3": ModelSettings(context_window=524_288),
    "deepseek/deepseek-v4-pro": ModelSettings(context_window=1_048_576),
    # GLM 5.2 providers split (Cloudflare/Io Net 262144, AtlasCloud 202752 vs
    # five at the full 1M); default routing elevates an over-limit prompt to a
    # 1M provider, so the gateway rejects only above 1048576 (verified live).
    # Budget the bare id the agent sends to that served maximum.
    "z-ai/glm-5.2": ModelSettings(context_window=1_048_576),
    # Windows below were verified live against the OpenRouter gateway: an
    # over-limit prompt is rejected with "maximum context length is N tokens",
    # and N is recorded here (not the advertised /models value, which can be a
    # cross-provider maximum the routed provider does not actually serve).
    "google/gemini-3.5-flash": ModelSettings(context_window=1_048_576),
    "xiaomi/mimo-v2.5-pro": ModelSettings(context_window=1_048_576),
    "qwen/qwen3.7-max": ModelSettings(context_window=1_000_000),
    "moonshotai/kimi-k2.7-code": ModelSettings(context_window=262_144),
}

_CODEX_MODEL_SETTINGS = {
    # The live Codex catalog hard-caps each GPT-5.6 variant at 272k. Unlike the
    # OpenAI API's 1.05M window, the larger context is not available through
    # ChatGPT/Codex OAuth. Ultra is a separate multi-agent mode, not a raw
    # Responses API reasoning effort supported by this harness.
    "gpt-5.6-sol": ModelSettings(
        context_window=272_000,
        reasoning_efforts=("low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.6-terra": ModelSettings(
        context_window=272_000,
        reasoning_efforts=("low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.6-luna": ModelSettings(
        context_window=272_000,
        reasoning_efforts=("low", "medium", "high", "xhigh", "max"),
        default_reasoning="xhigh",
    ),
    "gpt-5.3-codex-spark": ModelSettings(
        context_window=128_000,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
        default_reasoning="xhigh",
    ),
}

_MODEL_SETTINGS_BY_PROVIDER = {
    OPENAI_API_PROVIDER: _API_MODEL_SETTINGS,
    OPENAI_CODEX_PROVIDER: _CODEX_MODEL_SETTINGS,
}

_MODEL_ALIASES = {
    # Official GPT-5.6 alias; keep aliases out of the registry so model
    # membership remains the set of concrete model ids.
    "gpt-5.6": "gpt-5.6-sol",
}

# Unknown / un-tabulated models (including non-OpenAI OpenRouter models without an
# explicit entry) fall back to a conservative window so the agent under-sizes the
# context budget rather than over-sizing a smaller real window and overflowing.
_FALLBACK_MODEL_SETTINGS = ModelSettings(context_window=128_000)


def normalize_reasoning(value: str | None) -> str:
    """Normalize reasoning effort names to OpenAI Responses values."""
    if not value:
        return "none"
    normalized = value.lower()
    return "none" if normalized == "off" else normalized


def get_model_settings(
    model: str | None,
    provider_name: str | None = OPENAI_API_PROVIDER,
) -> ModelSettings:
    """Return known limits for a model.

    Matches the full id first (so namespaced OpenRouter entries like
    ``minimax/minimax-m3`` win), then retries with the bare id after a leading
    ``vendor/`` prefix (so ``openai/gpt-5.6-sol`` resolves to
    ``gpt-5.6-sol``), matching
    dated ``-20xx`` snapshots by prefix. Unknown models fall back to a
    conservative window to avoid over-sizing a smaller real context window.
    """
    model_name = (model or DEFAULT_MODEL).lower()
    settings_by_model = _MODEL_SETTINGS_BY_PROVIDER.get(
        provider_name or OPENAI_API_PROVIDER,
        _API_MODEL_SETTINGS,
    )
    candidates = [model_name]
    if "/" in model_name:
        candidates.append(model_name.split("/", 1)[1])
    candidates = [_MODEL_ALIASES.get(candidate, candidate) for candidate in candidates]
    for candidate in candidates:
        for key in sorted(settings_by_model, key=len, reverse=True):
            if candidate == key or candidate.startswith(f"{key}-20"):
                return settings_by_model[key]
    return _FALLBACK_MODEL_SETTINGS


def resolve_reasoning_effort(
    model: str | None,
    requested: str | None,
    provider_name: str | None = OPENAI_API_PROVIDER,
) -> ReasoningResolution:
    """Resolve a requested reasoning effort to one supported by the model."""
    requested_effort = normalize_reasoning(requested)
    settings = get_model_settings(model, provider_name=provider_name)
    supported = settings.reasoning_efforts

    if requested_effort in supported:
        # `none` is an explicit supported API value. Omitting the reasoning
        # field would select the provider/model default (medium for GPT-5.6),
        # which is observably different from the user's request.
        return ReasoningResolution(
            requested_effort,
            requested_effort,
            requested_effort,
        )

    if requested_effort not in REASONING_ORDER:
        fallback = (
            settings.default_reasoning
            if settings.default_reasoning in supported
            else _nearest_reasoning_effort(settings.default_reasoning, supported)
        )
    else:
        fallback = _nearest_reasoning_effort(requested_effort, supported)
    api_effort = fallback if supported else None
    model_name = model or DEFAULT_MODEL
    note = (
        f"{model_name} does not support reasoning effort '{requested_effort}'; "
        f"using '{fallback}' instead."
    )
    return ReasoningResolution(requested_effort, fallback, api_effort, note)


def _nearest_reasoning_effort(requested: str, supported: tuple[str, ...]) -> str:
    if not supported:
        return "none"
    if requested not in REASONING_ORDER:
        return supported[0]
    requested_index = REASONING_ORDER.index(requested)
    return min(
        supported,
        key=lambda effort: (
            abs(REASONING_ORDER.index(effort) - requested_index),
            REASONING_ORDER.index(effort) > requested_index,
        ),
    )


class AuthError(RuntimeError):
    """Raised when OpenAI auth cannot be established or refreshed."""


def _auth_file() -> Path:
    home = Path(os.environ.get("REENTBOTPRO_HOME", Path.home() / ".reentbotpro"))
    return home / "auth.json"


def _base64_url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
    except IndexError:
        return {}
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return {}


def _claim(claims: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in claims:
            return claims[name]
    return None


def _chatgpt_auth_claims(claims: dict[str, Any]) -> dict[str, Any]:
    nested = claims.get("https://api.openai.com/auth")
    return nested if isinstance(nested, dict) else claims


def _profile_email(claims: dict[str, Any]) -> str | None:
    email = claims.get("email")
    if isinstance(email, str):
        return email
    profile = claims.get("https://api.openai.com/profile")
    if isinstance(profile, dict) and isinstance(profile.get("email"), str):
        return profile["email"]
    return None


@dataclass
class CodexAuthProfile:
    """Persisted ChatGPT/Codex OAuth tokens for the local user."""

    id_token: str
    access_token: str
    refresh_token: str
    account_id: str
    expires_at: int
    email: str | None = None
    plan_type: str | None = None
    is_fedramp_account: bool = False

    @classmethod
    def from_token_response(
        cls,
        data: dict[str, Any],
        previous: "CodexAuthProfile | None" = None,
    ) -> "CodexAuthProfile":
        access_token = data.get("access_token") or (previous.access_token if previous else None)
        id_token = data.get("id_token") or (previous.id_token if previous else None)
        refresh_token = data.get("refresh_token") or (previous.refresh_token if previous else None)
        if not access_token or not id_token or not refresh_token:
            raise AuthError("OAuth token response was missing required token fields")

        access_claims = _decode_jwt_payload(access_token)
        id_claims = _decode_jwt_payload(id_token)
        access_auth_claims = _chatgpt_auth_claims(access_claims)
        id_auth_claims = _chatgpt_auth_claims(id_claims)
        account_id = (
            _claim(
                access_auth_claims,
                "https://api.openai.com/auth.chatgpt_account_id",
                "chatgpt_account_id",
            )
            or _claim(id_auth_claims, "chatgpt_account_id")
            or (previous.account_id if previous else None)
        )
        if not account_id:
            raise AuthError("OAuth token response did not include a ChatGPT account ID")

        expires_at = int(
            access_claims.get("exp")
            or time.time() + int(data.get("expires_in") or 3600)
        )
        email = _profile_email(id_claims) or _profile_email(access_claims) or (
            previous.email if previous else None
        )
        plan_type = (
            _claim(
                access_auth_claims,
                "https://api.openai.com/auth.chatgpt_plan_type",
                "chatgpt_plan_type",
            )
            or _claim(id_auth_claims, "chatgpt_plan_type")
            or (previous.plan_type if previous else None)
        )
        is_fedramp = bool(
            _claim(
                access_auth_claims,
                "https://api.openai.com/auth.chatgpt_account_is_fedramp",
                "chatgpt_account_is_fedramp",
            )
            or _claim(id_auth_claims, "chatgpt_account_is_fedramp")
            or (previous.is_fedramp_account if previous else False)
        )
        return cls(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            account_id=str(account_id),
            expires_at=expires_at,
            email=email,
            plan_type=str(plan_type) if plan_type else None,
            is_fedramp_account=is_fedramp,
        )

    def is_fresh(self) -> bool:
        return self.expires_at - TOKEN_REFRESH_MARGIN_SECONDS > int(time.time())


class AuthStore:
    """Small file-backed auth store for ReentbotPro-managed OAuth tokens."""

    def __init__(self, path: Path | None = None):
        self.path = path or _auth_file()

    def load(self) -> CodexAuthProfile | None:
        try:
            raw = json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthError(f"Could not read auth profile at {self.path}: {exc}") from exc
        try:
            return CodexAuthProfile(**raw)
        except TypeError as exc:
            raise AuthError(f"Auth profile at {self.path} is not valid") from exc

    def save(self, profile: CodexAuthProfile) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(asdict(profile), indent=2)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.write("\n")
        finally:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass


def _codex_cli_auth_file() -> Path:
    home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    return home / "auth.json"


class CodexCliAuthStore:
    """Auth store adapter for the official Codex CLI's ChatGPT login."""

    def __init__(self, path: Path | None = None):
        self.path = path or _codex_cli_auth_file()

    def load(self) -> CodexAuthProfile | None:
        try:
            raw = json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthError(f"Could not read Codex CLI auth profile at {self.path}: {exc}") from exc

        if str(raw.get("auth_mode") or "").lower() not in ("chatgpt", "chatgptauthtokens"):
            return None
        tokens = raw.get("tokens")
        if not isinstance(tokens, dict):
            return None
        data = {
            "id_token": tokens.get("id_token"),
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
        }
        try:
            return CodexAuthProfile.from_token_response(data)
        except AuthError as exc:
            raise AuthError(f"Codex CLI auth profile at {self.path} is not usable: {exc}") from exc

    def save(self, profile: CodexAuthProfile) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except FileNotFoundError:
            raw = {}
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthError(f"Could not update Codex CLI auth profile at {self.path}: {exc}") from exc

        raw["auth_mode"] = "chatgpt"
        tokens = raw.get("tokens")
        if not isinstance(tokens, dict):
            tokens = {}
            raw["tokens"] = tokens
        tokens["id_token"] = profile.id_token
        tokens["access_token"] = profile.access_token
        tokens["refresh_token"] = profile.refresh_token
        tokens["account_id"] = profile.account_id
        raw["last_refresh"] = datetime.now(timezone.utc).isoformat()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(raw, indent=2)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.write("\n")
        finally:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    server: "_OAuthHTTPServer"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/auth/callback":
            self.send_response(404)
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        self.server.oauth_result = {
            "code": query.get("code", [None])[0],
            "state": query.get("state", [None])[0],
            "error": query.get("error", [None])[0],
            "error_description": query.get("error_description", [None])[0],
        }
        body = (
            "<html><body><h1>ReentbotPro login complete</h1>"
            "<p>You can close this tab and return to the terminal.</p>"
            "</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


class _OAuthHTTPServer(HTTPServer):
    oauth_result: dict[str, str | None] | None = None


def _oauth_authorize_url(state: str, code_challenge: str) -> str:
    params = {
        'response_type': 'code',
        'client_id': OAUTH_CLIENT_ID,
        'redirect_uri': OAUTH_REDIRECT_URI,
        'scope': OAUTH_SCOPE,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'id_token_add_organizations': 'true',
        'codex_cli_simplified_flow': 'true',
        'state': state,
        'originator': CODEX_ORIGINATOR,
    }
    return f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(params)}"


def login_chatgpt(console: Any | None = None) -> CodexAuthProfile:
    """Run the ChatGPT/Codex OAuth browser flow and persist the profile."""
    code_verifier = _base64_url_no_pad(secrets.token_bytes(32))
    code_challenge = _base64_url_no_pad(hashlib.sha256(code_verifier.encode("ascii")).digest())
    state = _base64_url_no_pad(secrets.token_bytes(32))
    authorize_url = _oauth_authorize_url(state, code_challenge)

    try:
        server = _OAuthHTTPServer(("127.0.0.1", OAUTH_PORT), _OAuthCallbackHandler)
    except OSError as exc:
        raise AuthError(f"Could not start OAuth callback server on {OAUTH_REDIRECT_URI}: {exc}") from exc

    if console:
        console.print("\n  [cyan]Opening ChatGPT/Codex login in your browser...[/]")
        console.print(f"  [dim]{authorize_url}[/]")
    webbrowser.open(authorize_url)

    server.timeout = 300
    deadline = time.time() + 300
    try:
        while server.oauth_result is None and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()

    result = server.oauth_result
    if result is None:
        raise AuthError("Timed out waiting for ChatGPT/Codex login callback")
    if result.get("error"):
        detail = result.get("error_description") or result["error"]
        raise AuthError(f"ChatGPT/Codex login failed: {detail}")
    if result.get("state") != state:
        raise AuthError("OAuth state mismatch; refusing to use callback")
    code = result.get("code")
    if not code:
        raise AuthError("OAuth callback did not include an authorization code")

    token_data = _exchange_authorization_code(code, code_verifier)
    profile = CodexAuthProfile.from_token_response(token_data)
    AuthStore().save(profile)
    if console:
        label = profile.email or profile.account_id
        console.print(f"  [green]Signed in to ChatGPT/Codex as {label}.[/]")
    return profile


def _exchange_authorization_code(code: str, code_verifier: str) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "client_id": OAUTH_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                f"{OAUTH_ISSUER}/oauth/token",
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as exc:
        raise AuthError(f"OAuth token exchange failed: {exc}") from exc
    if response.status_code >= 400:
        body = response.text
        raise AuthError(
            f"OAuth token exchange failed with HTTP {response.status_code}: "
            f"{_truncate_error_body(body, 1000)}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise AuthError("OAuth token exchange returned invalid JSON") from exc


class _ApiKeyAuth:
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}


class _CodexOAuthAuth:
    def __init__(self, profile: CodexAuthProfile, store: AuthStore):
        self.profile = profile
        self.store = store
        self._refresh_lock = asyncio.Lock()

    async def headers(self) -> dict[str, str]:
        if not self.profile.is_fresh():
            async with self._refresh_lock:
                if not self.profile.is_fresh():
                    await self._refresh()
        headers = {
            "Authorization": f"Bearer {self.profile.access_token}",
            "ChatGPT-Account-ID": self.profile.account_id,
        }
        if self.profile.is_fedramp_account:
            headers["X-OpenAI-Fedramp"] = "true"
        return headers

    async def _refresh(self) -> None:
        payload = {
            "client_id": OAUTH_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": self.profile.refresh_token,
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{OAUTH_ISSUER}/oauth/token",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise AuthError(f"Could not refresh ChatGPT/Codex auth: {exc}") from exc
        if response.status_code >= 400:
            raise AuthError(
                "ChatGPT/Codex session expired or was revoked. "
                "Run ReentbotPro interactively to log in again."
            )
        try:
            token_data = response.json()
        except ValueError as exc:
            raise AuthError("ChatGPT/Codex refresh returned invalid JSON") from exc
        self.profile = CodexAuthProfile.from_token_response(token_data, previous=self.profile)
        self.store.save(self.profile)


class ResponsesLLMClient:
    """Streaming Responses API client with ReentbotPro's normalized output contract."""

    def __init__(self, base_url: str, auth: _ApiKeyAuth | _CodexOAuthAuth, provider_name: str):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.provider_name = provider_name
        self.session_id = f"reentbotpro-{secrets.token_hex(16)}"

    async def stream_turn(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict],
        display: Any,
        max_output_tokens: int,
        reasoning_config: dict | None = None,
    ) -> tuple[dict, int, int, str | None]:
        instructions, input_items = _messages_to_responses_input(messages)
        payload: dict[str, Any] = {
            "model": model,
            "input": input_items,
            "tools": _responses_tools(tools),
            "stream": True,
            "store": False,
            "include": ["reasoning.encrypted_content"],
            "parallel_tool_calls": True,
        }
        if getattr(self, "provider_name", OPENAI_API_PROVIDER) != OPENAI_CODEX_PROVIDER:
            payload["max_output_tokens"] = max_output_tokens
            session_id = getattr(self, "session_id", None)
            if session_id:
                # Pin prompt-cache routing for this session so the stable prefix
                # (system prompt + early turns) keeps hitting the provider's
                # prompt cache. Scoped to the non-Codex (OpenAI-compatible API)
                # path; the Codex backend manages its own session/caching.
                payload["prompt_cache_key"] = session_id
        if instructions:
            payload["instructions"] = instructions
        if reasoning_config and reasoning_config.get("effort"):
            payload["reasoning"] = {"effort": reasoning_config["effort"]}

        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        replay_items: list[dict[str, Any]] = []
        tool_calls: list[dict[str, Any]] = []
        tool_call_ids: set[str] = set()
        usage_tokens = 0
        reasoning_tokens = 0
        finish_reason: str | None = None
        reasoning_active = False
        function_acc: dict[str, dict[str, Any]] = {}

        async for event in self._stream_events(payload):
            event_type = event.get("type")

            if event_type in ("response.output_text.delta", "response.text.delta"):
                delta = event.get("delta") or event.get("text") or ""
                if delta:
                    if reasoning_active:
                        reasoning_active = False
                        display.end_reasoning()
                    content_parts.append(delta)
                    display.stream_text(delta)
                continue

            if event_type in (
                "response.reasoning_text.delta",
                "response.reasoning_summary_text.delta",
            ):
                delta = event.get("delta") or event.get("text") or ""
                if delta:
                    reasoning_active = True
                    reasoning_parts.append(delta)
                    display.stream_reasoning(delta)
                continue

            if event_type == "response.output_item.added":
                item = event.get("item") or {}
                if item.get("type") == "function_call":
                    key = _event_item_key(event, item)
                    function_acc[key] = {
                        "id": item.get("call_id") or item.get("id") or "",
                        "type": "function",
                        "function": {
                            "name": item.get("name") or "",
                            "arguments": item.get("arguments") or "",
                        },
                    }
                continue

            if event_type == "response.function_call_arguments.delta":
                key = _event_item_key(event, {})
                acc = function_acc.setdefault(
                    key,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                acc["function"]["arguments"] += event.get("delta") or ""
                continue

            if event_type == "response.output_item.done":
                item = event.get("item") or {}
                item_type = item.get("type")
                if item_type == "function_call":
                    tc = _function_call_item_to_tool_call(item)
                    if tc and tc["id"] not in tool_call_ids:
                        tool_call_ids.add(tc["id"])
                        tool_calls.append(tc)
                elif item_type == "message" and not content_parts:
                    text = _message_item_text(item)
                    if text:
                        content_parts.append(text)
                elif item_type in ("reasoning", "compaction"):
                    replay_item = _sanitize_replay_item(item)
                    if replay_item:
                        replay_items.append(replay_item)
                continue

            if event_type == "response.completed":
                response = event.get("response") or {}
                usage_tokens, reasoning_tokens = _usage_counts(response.get("usage") or {})
                incomplete = response.get("incomplete_details") or {}
                if incomplete.get("reason") in ("max_output_tokens", "max_tokens"):
                    finish_reason = "length"
                continue

            if event_type == "response.incomplete":
                finish_reason = "length"
                continue

            if event_type in ("response.failed", "response.error", "error"):
                error = event.get("error") or event
                message = error.get("message") if isinstance(error, dict) else str(error)
                raise RuntimeError(f"Responses API error: {message}")

        if reasoning_active:
            display.end_reasoning()

        for tc in function_acc.values():
            if tc["id"] and tc["function"]["name"] and tc["id"] not in tool_call_ids:
                tool_call_ids.add(tc["id"])
                tool_calls.append(tc)

        content = "".join(content_parts)
        reasoning_text = "".join(reasoning_parts)
        if reasoning_text and reasoning_tokens == 0:
            reasoning_tokens = len(reasoning_text) // 4
        if reasoning_tokens > 0:
            display.reasoning_summary(reasoning_tokens)

        if usage_tokens == 0:
            completion_len = len(content) + len(reasoning_text)
            for tc in tool_calls:
                completion_len += len(tc["function"].get("arguments", ""))
            usage_tokens = (len(json.dumps(messages, default=str)) + completion_len) // 4

        if finish_reason is None:
            finish_reason = "tool_calls" if tool_calls else "stop"

        msg: dict[str, Any] = {"role": "assistant"}
        if content:
            msg["content"] = content
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if replay_items:
            msg["response_items"] = replay_items
        if reasoning_text:
            msg["reasoning"] = reasoning_text
        return msg, usage_tokens, reasoning_tokens, finish_reason

    async def _stream_events(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": "ReentbotPro/0.1",
        }
        if self.provider_name == OPENAI_CODEX_PROVIDER:
            headers.update({
                "OpenAI-Beta": "responses=experimental",
                "originator": CODEX_ORIGINATOR,
                "session_id": self.session_id,
                "x-client-request-id": f"reentbotpro-{secrets.token_hex(16)}",
            })
        headers.update(await self.auth.headers())
        timeout = httpx.Timeout(connect=30.0, read=None, write=60.0, pool=30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/responses",
                headers=headers,
                json=payload,
            ) as response:
                if response.status_code >= 400:
                    body = (await response.aread()).decode("utf-8", errors="replace")
                    raise RuntimeError(
                        f"Responses API HTTP {response.status_code}: {_truncate_error_body(body)}"
                    )
                async for event in _iter_sse_json(response):
                    yield event


async def _iter_sse_json(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    data_lines: list[str] = []
    async for line in response.aiter_lines():
        if line == "":
            if not data_lines:
                continue
            data = "\n".join(data_lines)
            data_lines = []
            if data.strip() == "[DONE]":
                break
            try:
                yield json.loads(data)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid SSE JSON from Responses API: {exc}") from exc
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        data = "\n".join(data_lines)
        if data.strip() != "[DONE]":
            yield json.loads(data)


def _messages_to_responses_input(messages: list[dict]) -> tuple[str | None, list[dict[str, Any]]]:
    instructions = None
    input_items: list[dict[str, Any]] = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content") or ""
        if role == "system" and instructions is None:
            instructions = content
            continue
        if role == "system":
            input_items.append({"type": "message", "role": "user", "content": content})
            continue
        if role == "user":
            input_items.append({"type": "message", "role": "user", "content": content})
            continue
        if role == "assistant":
            if content:
                input_items.append({"type": "message", "role": "assistant", "content": content})
            for item in msg.get("response_items") or []:
                replay_item = _sanitize_replay_item(item)
                if replay_item:
                    input_items.append(replay_item)
            for tc in msg.get("tool_calls") or []:
                input_items.append(_tool_call_to_response_item(tc))
            continue
        if role == "tool":
            call_id = msg.get("tool_call_id")
            if call_id:
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": content,
                })
    if not input_items:
        input_items.append({
            "type": "message",
            "role": "user",
            "content": "Begin the audit.",
        })
    return instructions, input_items


def _responses_tools(tools: list[dict]) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            continue
        fn = tool.get("function") or {}
        converted.append({
            "type": "function",
            "name": fn.get("name"),
            "description": fn.get("description", ""),
            "strict": bool(fn.get("strict", False)),
            "parameters": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return converted


def estimate_responses_request_tokens(
    messages: list[dict],
    tools: list[dict] | None = None,
    reasoning_config: dict | None = None,
    provider_name: str | None = OPENAI_API_PROVIDER,
) -> int:
    """Estimate tokens for the actual Responses request shape.

    This intentionally runs chat history through the same adapter used by
    stream_turn, so estimates include Responses input items, encrypted replay
    item filtering, tool schemas, instructions, and request-level fields instead
    of the pre-adapter chat dicts.
    """
    instructions, input_items = _messages_to_responses_input(messages)
    payload: dict[str, Any] = {
        "input": input_items,
        "stream": True,
        "store": False,
        "include": ["reasoning.encrypted_content"],
        "parallel_tool_calls": True,
    }
    if tools is not None:
        payload["tools"] = _responses_tools(tools)
    if instructions:
        payload["instructions"] = instructions
    if reasoning_config and reasoning_config.get("effort"):
        payload["reasoning"] = {"effort": reasoning_config["effort"]}
    if provider_name != OPENAI_CODEX_PROVIDER:
        payload["max_output_tokens"] = 0
    return max(1, len(json.dumps(payload, default=str, separators=(",", ":"))) // 4)


def _tool_call_to_response_item(tool_call: dict[str, Any]) -> dict[str, Any]:
    fn = tool_call.get("function") or {}
    return {
        "type": "function_call",
        "call_id": tool_call.get("id", ""),
        "name": fn.get("name", ""),
        "arguments": fn.get("arguments", "{}"),
    }


def _function_call_item_to_tool_call(item: dict[str, Any]) -> dict[str, Any] | None:
    name = item.get("name")
    call_id = item.get("call_id") or item.get("id")
    if not name or not call_id:
        return None
    arguments = item.get("arguments") or "{}"
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments)
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }


def _event_item_key(event: dict[str, Any], item: dict[str, Any]) -> str:
    value = event.get("item_id") or item.get("id") or event.get("output_index")
    return str(value if value is not None else len(item))


def _message_item_text(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for part in item.get("content") or []:
        if isinstance(part, dict) and part.get("type") in ("output_text", "text"):
            text = part.get("text")
            if text:
                parts.append(text)
    return "".join(parts)


def _sanitize_replay_item(item: dict[str, Any]) -> dict[str, Any]:
    item_type = item.get("type")
    if item_type not in ("reasoning", "compaction"):
        return {}
    # With store=false, reasoning ids (rs_*) are not durable. Replay the
    # encrypted payload instead; a bare id is an unresolved server-side reference.
    # Compaction items follow the same opaque encrypted replay pattern.
    if not item.get("encrypted_content"):
        return {}
    keep = {"type", "summary", "encrypted_content", "content"}
    return {k: v for k, v in item.items() if k in keep and v is not None}


def _usage_counts(usage: dict[str, Any]) -> tuple[int, int]:
    total = int(usage.get("total_tokens") or 0)
    output_details = usage.get("output_tokens_details") or {}
    completion_details = usage.get("completion_tokens_details") or {}
    reasoning = int(
        output_details.get("reasoning_tokens")
        or completion_details.get("reasoning_tokens")
        or 0
    )
    return total, reasoning


def _truncate_error_body(body: str, limit: int = 2000) -> str:
    if len(body) <= limit:
        return body
    return body[:limit] + "... [truncated]"


def create_client(
    api_key: str | None = None,
    *,
    console: Any | None = None,
    interactive: bool = False,
    force_login: bool = False,
) -> ResponsesLLMClient:
    """Create the OpenAI Responses client.

    OPENAI_API_KEY or --api-key uses OpenAI API billing. Without an API key,
    ReentbotPro uses ChatGPT/Codex subscription OAuth and prompts for login when
    no local profile exists.
    """
    if api_key:
        return ResponsesLLMClient(
            base_url=os.environ.get("OPENAI_BASE_URL", OPENAI_API_BASE_URL),
            auth=_ApiKeyAuth(api_key),
            provider_name=OPENAI_API_PROVIDER,
        )

    store = AuthStore()
    profile = None if force_login else store.load()
    if profile is None and not force_login:
        codex_store = CodexCliAuthStore()
        codex_profile = codex_store.load()
        if codex_profile is not None:
            store = codex_store
            profile = codex_profile
            if console:
                label = profile.email or profile.account_id
                console.print(f"  [green]Using Codex CLI ChatGPT login for {label}.[/]")
    if profile is None:
        if not interactive:
            raise AuthError(
                "No OpenAI API key or ChatGPT/Codex login found. "
                "Run ReentbotPro in an interactive terminal to sign in, or set OPENAI_API_KEY."
            )
        profile = login_chatgpt(console=console)

    return ResponsesLLMClient(
        base_url=os.environ.get("REENTBOTPRO_CODEX_BASE_URL", CODEX_BASE_URL),
        auth=_CodexOAuthAuth(profile, store),
        provider_name=OPENAI_CODEX_PROVIDER,
    )
