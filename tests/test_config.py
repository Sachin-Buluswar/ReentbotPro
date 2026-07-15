import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reentbotpro.config import (
    DEFAULT_ALCHEMY_NETWORK,
    ResolvedRpcEndpoint,
    alchemy_node_url,
    alchemy_prices_url,
    chain_from_explorer_url,
    config_path,
    load_local_config,
    merge_local_config,
    normalize_alchemy_network,
    normalize_chain_hint,
    parse_alchemy_url,
    resolve_alchemy_api_key,
    resolve_alchemy_network,
    resolve_chain_id,
    resolve_etherscan_api_key,
    resolve_rpc_endpoint,
    resolve_rpc_url,
    save_local_config,
)


class LocalConfigTests(unittest.TestCase):
    def test_config_path_uses_reentbot_home_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                self.assertEqual(config_path(), Path(tmp) / "config.json")

    def test_missing_local_config_loads_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_local_config(Path(tmp) / "config.json"), {})

    def test_invalid_local_config_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("[]")

            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_local_config(path)

    def test_save_local_config_round_trips_and_is_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Parent directory is created on demand.
            path = Path(tmp) / "app" / "config.json"
            save_local_config({"alchemy_api_key": "SECRET"}, path)

            self.assertEqual(load_local_config(path), {"alchemy_api_key": "SECRET"})
            # The file may hold API keys, so it must be owner-only (0600).
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_save_local_config_tightens_existing_permissive_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{}")
            os.chmod(path, 0o644)

            save_local_config({"etherscan_api_key": "SECRET"}, path)

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rpc_resolution_prefers_cli_then_env_then_config(self):
        config = {"rpc_urls": {"ethereum_mainnet": "https://config.example"}}

        self.assertEqual(
            resolve_rpc_url(
                "https://cli.example",
                environ={"ETH_RPC_URL": "https://env.example"},
                config=config,
            ),
            "https://cli.example",
        )
        self.assertEqual(
            resolve_rpc_url(
                None,
                environ={"ETH_RPC_URL": "https://env.example"},
                config=config,
            ),
            "https://env.example",
        )
        self.assertEqual(
            resolve_rpc_url(None, environ={}, config=config),
            "https://config.example",
        )

    def test_rpc_resolution_uses_local_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "rpc_urls": {"ethereum_mainnet": "https://config.example"},
            }))
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                self.assertEqual(
                    resolve_rpc_url(None, environ={}),
                    "https://config.example",
                )

    def test_rpc_resolution_no_longer_derives_alchemy_from_bare_key(self):
        # Demoted resolve_rpc_url is explicit-override-only: a bare Alchemy key
        # must not silently become an eth-mainnet URL. Chain-aware derivation
        # belongs to resolve_rpc_endpoint, which knows the target chain.
        self.assertIsNone(
            resolve_rpc_url(
                None,
                environ={},
                config={"api_keys": {"alchemy": "alchemy-test-key"}},
            )
        )
        self.assertIsNone(
            resolve_rpc_url(
                None,
                environ={},
                config={"alchemy_api_key": "alchemy-test-key"},
            )
        )


class AlchemyNetworkHelperTests(unittest.TestCase):
    def test_normalize_network_defaults_and_lowercases(self):
        self.assertEqual(normalize_alchemy_network(None), DEFAULT_ALCHEMY_NETWORK)
        self.assertEqual(normalize_alchemy_network("  "), DEFAULT_ALCHEMY_NETWORK)
        self.assertEqual(normalize_alchemy_network("Base-Mainnet"), "base-mainnet")

    def test_normalize_network_rejects_malformed_values(self):
        for bad in ("eth.mainnet", "eth_mainnet", "1eth", "eth mainnet", "eth/x"):
            with self.assertRaises(ValueError):
                normalize_alchemy_network(bad)

    def test_node_url_builds_per_network(self):
        self.assertEqual(
            alchemy_node_url("arb-mainnet", "KEY123"),
            "https://arb-mainnet.g.alchemy.com/v2/KEY123",
        )
        # Empty/None network falls back to the default mainnet subdomain.
        self.assertEqual(
            alchemy_node_url(None, "KEY123"),
            "https://eth-mainnet.g.alchemy.com/v2/KEY123",
        )

    def test_node_url_requires_key_and_valid_network(self):
        with self.assertRaises(ValueError):
            alchemy_node_url("eth-mainnet", "")
        with self.assertRaises(ValueError):
            alchemy_node_url("bad.host", "KEY123")

    def test_prices_url_builds_and_validates_endpoint(self):
        self.assertEqual(
            alchemy_prices_url("KEY123"),
            "https://api.g.alchemy.com/prices/v1/KEY123/tokens/by-address",
        )
        self.assertEqual(
            alchemy_prices_url("KEY123", endpoint="tokens/historical"),
            "https://api.g.alchemy.com/prices/v1/KEY123/tokens/historical",
        )
        with self.assertRaises(ValueError):
            alchemy_prices_url("KEY123", endpoint="../etc/passwd")
        with self.assertRaises(ValueError):
            alchemy_prices_url("", endpoint="tokens/by-address")

    def test_parse_alchemy_url_extracts_network_and_key(self):
        self.assertEqual(
            parse_alchemy_url("https://base-mainnet.g.alchemy.com/v2/abc123"),
            ("base-mainnet", "abc123"),
        )
        # Case-insensitive host; trailing path/query ignored for the key capture.
        self.assertEqual(
            parse_alchemy_url("https://ETH-MAINNET.G.ALCHEMY.COM/v2/Key9"),
            ("eth-mainnet", "Key9"),
        )
        self.assertIsNone(parse_alchemy_url("https://mainnet.infura.io/v3/xyz"))
        self.assertIsNone(parse_alchemy_url(None))
        # The Prices REST host has no /v2/ segment and must not parse as a node URL.
        self.assertIsNone(
            parse_alchemy_url("https://api.g.alchemy.com/prices/v1/abc/tokens/by-address")
        )


class ResolveAlchemyNetworkTests(unittest.TestCase):
    def test_friendly_names_map_to_subdomains(self):
        self.assertEqual(resolve_alchemy_network("base"), "base-mainnet")
        self.assertEqual(resolve_alchemy_network("ethereum"), "eth-mainnet")
        self.assertEqual(resolve_alchemy_network("Arbitrum"), "arb-mainnet")
        self.assertEqual(resolve_alchemy_network("op"), "opt-mainnet")
        self.assertEqual(resolve_alchemy_network("bsc"), "bnb-mainnet")

    def test_subdomain_passes_through(self):
        self.assertEqual(resolve_alchemy_network("base-mainnet"), "base-mainnet")
        # Unknown-but-shaped subdomain still passes (new chains work w/o code change).
        self.assertEqual(resolve_alchemy_network("newchain-mainnet"), "newchain-mainnet")

    def test_decimal_and_chain_id_resolve(self):
        self.assertEqual(resolve_alchemy_network("10"), "opt-mainnet")
        self.assertEqual(resolve_alchemy_network(None, 8453), "base-mainnet")
        self.assertEqual(resolve_alchemy_network(None, "0x2105"), "base-mainnet")  # 8453 hex
        self.assertEqual(resolve_alchemy_network(None, 1), "eth-mainnet")

    def test_unrecognized_returns_none(self):
        self.assertIsNone(resolve_alchemy_network("bad.host"))
        self.assertIsNone(resolve_alchemy_network("eth mainnet"))
        self.assertIsNone(resolve_alchemy_network(None, None))
        self.assertIsNone(resolve_alchemy_network(None, 999999999))


class ResolveAlchemyKeyTests(unittest.TestCase):
    def test_env_key_takes_precedence_and_network_from_url(self):
        key, network = resolve_alchemy_api_key(
            "https://base-mainnet.g.alchemy.com/v2/url-key",
            environ={"ALCHEMY_API_KEY": "env-key"},
            config={"api_keys": {"alchemy": "cfg-key"}},
        )
        self.assertEqual(key, "env-key")
        self.assertEqual(network, "base-mainnet")

    def test_config_key_used_when_no_env(self):
        key, network = resolve_alchemy_api_key(
            None,
            environ={},
            config={"alchemy_api_key": "top-key"},
        )
        self.assertEqual(key, "top-key")
        self.assertIsNone(network)

        key, network = resolve_alchemy_api_key(
            None,
            environ={},
            config={"api_keys": {"alchemy": "nested-key"}},
        )
        self.assertEqual(key, "nested-key")

    def test_key_parsed_from_resolved_rpc_url(self):
        key, network = resolve_alchemy_api_key(
            "https://opt-mainnet.g.alchemy.com/v2/derived",
            environ={},
            config={},
        )
        self.assertEqual(key, "derived")
        self.assertEqual(network, "opt-mainnet")

    def test_key_parsed_from_config_rpc_url(self):
        key, network = resolve_alchemy_api_key(
            None,
            environ={},
            config={"rpc_urls": {"ethereum_mainnet": "https://eth-mainnet.g.alchemy.com/v2/cfgurl"}},
        )
        self.assertEqual(key, "cfgurl")
        self.assertEqual(network, "eth-mainnet")

    def test_returns_none_when_no_alchemy_key_available(self):
        key, network = resolve_alchemy_api_key(
            "https://mainnet.infura.io/v3/xyz",
            environ={},
            config={"rpc_urls": {"ethereum_mainnet": "https://my.node.example"}},
        )
        self.assertIsNone(key)
        self.assertIsNone(network)


class ResolveChainIdTests(unittest.TestCase):
    def test_resolves_from_name_subdomain_and_id(self):
        self.assertEqual(resolve_chain_id("base"), 8453)
        self.assertEqual(resolve_chain_id("arb-mainnet"), 42161)
        self.assertEqual(resolve_chain_id("10"), 10)
        self.assertEqual(resolve_chain_id(None, 1), 1)
        self.assertEqual(resolve_chain_id(None, "0x2105"), 8453)

    def test_unknown_returns_none(self):
        self.assertIsNone(resolve_chain_id("nope.bad"))
        self.assertIsNone(resolve_chain_id(None, None))


class ResolveEtherscanKeyTests(unittest.TestCase):
    def test_env_takes_precedence(self):
        self.assertEqual(
            resolve_etherscan_api_key(
                environ={"ETHERSCAN_API_KEY": "env"},
                config={"api_keys": {"etherscan": "cfg"}},
            ),
            "env",
        )

    def test_config_fallbacks(self):
        self.assertEqual(
            resolve_etherscan_api_key(environ={}, config={"etherscan_api_key": "top"}),
            "top",
        )
        self.assertEqual(
            resolve_etherscan_api_key(environ={}, config={"api_keys": {"etherscan": "nested"}}),
            "nested",
        )

    def test_none_when_absent(self):
        self.assertIsNone(resolve_etherscan_api_key(environ={}, config={}))


class ResolveRpcEndpointTests(unittest.TestCase):
    KEY = "alchemy-test-key"

    def test_alchemy_key_plus_network_name_derives_chain_url(self):
        endpoint = resolve_rpc_endpoint(
            network="base",
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(
            endpoint.url, f"https://base-mainnet.g.alchemy.com/v2/{self.KEY}"
        )
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.chain_id, 8453)
        self.assertFalse(endpoint.is_override)
        self.assertFalse(endpoint.assumed_default_mainnet)

    def test_alchemy_key_plus_chain_id_derives_chain_url(self):
        endpoint = resolve_rpc_endpoint(
            chain_id=8453,
            environ={"ALCHEMY_API_KEY": self.KEY},
            config={},
        )
        self.assertEqual(
            endpoint.url, f"https://base-mainnet.g.alchemy.com/v2/{self.KEY}"
        )
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.chain_id, 8453)

    def test_config_alchemy_key_plus_chain_id_derives_arbitrum(self):
        endpoint = resolve_rpc_endpoint(
            chain_id=42161,
            environ={},
            config={"alchemy_api_key": self.KEY},
        )
        self.assertEqual(
            endpoint.url, f"https://arb-mainnet.g.alchemy.com/v2/{self.KEY}"
        )
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertEqual(endpoint.network, "arb-mainnet")
        self.assertEqual(endpoint.chain_id, 42161)

    def test_bare_key_without_chain_does_not_assume_mainnet(self):
        endpoint = resolve_rpc_endpoint(
            environ={},
            config={"alchemy_api_key": self.KEY},
            allow_default_mainnet=False,
        )
        self.assertIsNone(endpoint.url)
        self.assertEqual(endpoint.provider, "none")
        self.assertFalse(endpoint.assumed_default_mainnet)

    def test_bare_key_with_allow_default_mainnet_derives_eth_mainnet(self):
        endpoint = resolve_rpc_endpoint(
            environ={},
            config={"alchemy_api_key": self.KEY},
            allow_default_mainnet=True,
        )
        self.assertEqual(
            endpoint.url, f"https://eth-mainnet.g.alchemy.com/v2/{self.KEY}"
        )
        self.assertEqual(endpoint.provider, "alchemy")
        self.assertEqual(endpoint.network, DEFAULT_ALCHEMY_NETWORK)
        self.assertEqual(endpoint.chain_id, 1)
        self.assertTrue(endpoint.assumed_default_mainnet)

    def test_per_call_rpc_url_wins_over_everything(self):
        endpoint = resolve_rpc_endpoint(
            rpc_url="https://explicit.example",
            cli_rpc_url="https://cli.example",
            network="base",
            environ={"ETH_RPC_URL": "https://env.example", "ALCHEMY_API_KEY": self.KEY},
            config={"rpc_urls": {"base-mainnet": "https://cfg.example"}},
        )
        self.assertEqual(endpoint.url, "https://explicit.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)

    def test_cli_rpc_url_wins_over_env_config_and_alchemy(self):
        endpoint = resolve_rpc_endpoint(
            cli_rpc_url="https://cli.example",
            network="base",
            environ={"ETH_RPC_URL": "https://env.example", "ALCHEMY_API_KEY": self.KEY},
            config={"rpc_urls": {"base-mainnet": "https://cfg.example"}},
        )
        self.assertEqual(endpoint.url, "https://cli.example")
        self.assertTrue(endpoint.is_override)

    def test_eth_rpc_url_wins_over_config_and_alchemy(self):
        endpoint = resolve_rpc_endpoint(
            network="base",
            environ={"ETH_RPC_URL": "https://env.example", "ALCHEMY_API_KEY": self.KEY},
            config={"rpc_urls": {"base-mainnet": "https://cfg.example"}},
        )
        self.assertEqual(endpoint.url, "https://env.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)

    def test_chain_specific_config_entry_wins_over_derived_alchemy(self):
        endpoint = resolve_rpc_endpoint(
            network="base",
            environ={},
            config={
                "alchemy_api_key": self.KEY,
                "rpc_urls": {"base-mainnet": "https://custom-base.example"},
            },
        )
        self.assertEqual(endpoint.url, "https://custom-base.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)
        self.assertEqual(endpoint.network, "base-mainnet")
        self.assertEqual(endpoint.chain_id, 8453)

    def test_chain_specific_config_entry_by_chain_id_key(self):
        endpoint = resolve_rpc_endpoint(
            chain_id=8453,
            environ={},
            config={
                "alchemy_api_key": self.KEY,
                "rpc_urls": {"8453": "https://custom-base-id.example"},
            },
        )
        self.assertEqual(endpoint.url, "https://custom-base-id.example")
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)

    def test_top_level_config_override_still_works(self):
        for key in ("rpc_url", "eth_rpc_url"):
            with self.subTest(key=key):
                endpoint = resolve_rpc_endpoint(
                    environ={},
                    config={key: "https://top-level.example"},
                )
                self.assertEqual(endpoint.url, "https://top-level.example")
                self.assertEqual(endpoint.provider, "explicit")
                self.assertTrue(endpoint.is_override)

    def test_explicit_alchemy_url_keeps_explicit_provider_with_chain(self):
        endpoint = resolve_rpc_endpoint(
            cli_rpc_url="https://arb-mainnet.g.alchemy.com/v2/somekey",
            environ={},
            config={},
        )
        self.assertEqual(endpoint.provider, "explicit")
        self.assertTrue(endpoint.is_override)
        self.assertEqual(endpoint.network, "arb-mainnet")
        self.assertEqual(endpoint.chain_id, 42161)

    def test_legacy_default_chain_keys_do_not_seed_derivation(self):
        endpoint = resolve_rpc_endpoint(
            environ={},
            config={
                "alchemy_api_key": self.KEY,
                "default_chain": "base",
                "default_network": "arb-mainnet",
                "default_chain_id": 10,
            },
        )
        self.assertIsNone(endpoint.url)
        self.assertIsNone(endpoint.network)
        self.assertIsNone(endpoint.chain_id)
        self.assertFalse(endpoint.assumed_default_mainnet)

    def test_returns_none_endpoint_when_nothing_resolvable(self):
        endpoint = resolve_rpc_endpoint(environ={}, config={})
        self.assertIsInstance(endpoint, ResolvedRpcEndpoint)
        self.assertIsNone(endpoint.url)
        self.assertEqual(endpoint.provider, "none")
        self.assertFalse(endpoint.is_override)

    def test_explicit_url_short_circuits_before_loading_config(self):
        # A malformed local config must not break an explicit override: explicit
        # URLs resolve without ever reading the config file.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.json").write_text("{ not json")
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                endpoint = resolve_rpc_endpoint(
                    cli_rpc_url="https://cli.example", environ={}
                )
                self.assertEqual(endpoint.url, "https://cli.example")
                self.assertTrue(endpoint.is_override)
                # Without an override, the malformed config does surface.
                with self.assertRaises(ValueError):
                    resolve_rpc_endpoint(environ={})


class LocalConfigWriteTests(unittest.TestCase):
    def test_save_creates_dir_and_writes_sorted_indented_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "config.json"
            save_local_config({"b": 2, "a": 1}, path)

            self.assertTrue(path.exists())
            text = path.read_text()
            self.assertEqual(json.loads(text), {"a": 1, "b": 2})
            # Keys are sorted ("a" before "b") and pretty-printed with indent=2.
            self.assertLess(text.index('"a"'), text.index('"b"'))
            self.assertIn('\n  "a": 1', text)

    def test_save_to_default_path_uses_config_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"REENTBOTPRO_HOME": tmp}, clear=False):
                save_local_config({"alchemy_api_key": "alchemy-test-key"})
                self.assertEqual(
                    load_local_config(),
                    {"alchemy_api_key": "alchemy-test-key"},
                )

    def test_merge_preserves_existing_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            save_local_config(
                {"etherscan_api_key": "etherscan-test-key", "keep": "me"}, path
            )

            merged = merge_local_config({"alchemy_api_key": "alchemy-test-key"}, path)

            self.assertEqual(
                merged,
                {
                    "etherscan_api_key": "etherscan-test-key",
                    "keep": "me",
                    "alchemy_api_key": "alchemy-test-key",
                },
            )
            self.assertEqual(json.loads(path.read_text()), merged)

    def test_merge_into_absent_config_creates_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            merged = merge_local_config({"model": "gpt-test"}, path)
            self.assertEqual(merged, {"model": "gpt-test"})
            self.assertTrue(path.exists())

    def test_merge_overrides_existing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            save_local_config({"model": "gpt-old"}, path)
            merged = merge_local_config({"model": "gpt-new"}, path)
            self.assertEqual(merged["model"], "gpt-new")


class ChainFromExplorerUrlTests(unittest.TestCase):
    def test_known_explorers_resolve_to_network_and_chain_id(self):
        cases = {
            "https://etherscan.io/address/0xabc": ("eth-mainnet", 1),
            "https://basescan.org/address/0xabc": ("base-mainnet", 8453),
            "https://arbiscan.io/tx/0xabc": ("arb-mainnet", 42161),
            "https://optimistic.etherscan.io/address/0x": ("opt-mainnet", 10),
            "https://polygonscan.com/": ("polygon-mainnet", 137),
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(chain_from_explorer_url(url), expected)

    def test_bare_host_and_www_prefix_resolve(self):
        self.assertEqual(chain_from_explorer_url("basescan.org"), ("base-mainnet", 8453))
        self.assertEqual(
            chain_from_explorer_url("www.basescan.org"), ("base-mainnet", 8453)
        )

    def test_testnet_host_is_not_mainnet(self):
        self.assertEqual(
            chain_from_explorer_url("https://sepolia.basescan.org/"),
            ("base-sepolia", 84532),
        )

    def test_unknown_or_empty_returns_none(self):
        self.assertIsNone(chain_from_explorer_url("https://example.com/x"))
        self.assertIsNone(chain_from_explorer_url("not-an-explorer"))
        self.assertIsNone(chain_from_explorer_url(""))
        self.assertIsNone(chain_from_explorer_url(None))


class NormalizeChainHintTests(unittest.TestCase):
    def test_friendly_name_and_subdomain(self):
        self.assertEqual(normalize_chain_hint("base"), ("base-mainnet", 8453))
        self.assertEqual(normalize_chain_hint("arb-mainnet"), ("arb-mainnet", 42161))

    def test_decimal_and_explicit_chain_id(self):
        self.assertEqual(normalize_chain_hint("8453"), ("base-mainnet", 8453))
        self.assertEqual(
            normalize_chain_hint(None, chain_id=42161), ("arb-mainnet", 42161)
        )

    def test_explorer_url_is_recognized(self):
        self.assertEqual(
            normalize_chain_hint("https://arbiscan.io/address/0x"),
            ("arb-mainnet", 42161),
        )

    def test_permissive_default_passes_unknown_subdomain_through(self):
        # Matches resolve_alchemy_network: a subdomain-shaped name passes through
        # so a newly launched chain works without a code change.
        self.assertEqual(
            normalize_chain_hint("brandnew-mainnet"), ("brandnew-mainnet", None)
        )

    def test_strict_rejects_unrecognized_tokens(self):
        for token in ("localhost", "hardhat", "staging", "brandnew-mainnet"):
            with self.subTest(token=token):
                self.assertIsNone(normalize_chain_hint(token, strict=True))

    def test_strict_still_resolves_known_names_and_ids(self):
        self.assertEqual(normalize_chain_hint("base", strict=True), ("base-mainnet", 8453))
        self.assertEqual(normalize_chain_hint("8453", strict=True), ("base-mainnet", 8453))

    def test_unrecognized_returns_none(self):
        self.assertIsNone(normalize_chain_hint("not a chain"))
        self.assertIsNone(normalize_chain_hint(None))


if __name__ == "__main__":
    unittest.main()
