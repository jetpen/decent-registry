import argparse
from pathlib import Path

import pytest
import yaml

from decent_registry.config import (
    DEFAULT_CLI_CONFIG_PATH,
    DEFAULT_CLI_DATASTORE_PATH,
    DEFAULT_SERVER_DATASTORE_DIR,
    load_client_config,
    load_server_config,
    load_yaml_file,
    apply_cli_overrides_to_client,
    apply_cli_overrides_to_server,
    resolve_client_config,
    resolve_required_owner_privkey_pem_path,
    resolve_server_config,
)


def test_load_yaml_file_missing_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"
    assert load_yaml_file(missing) == {}


def test_resolve_server_config_requires_port(tmp_path: Path) -> None:
    p = tmp_path / "registry.yaml"
    p.write_text("network:\n  host: 127.0.0.1\n", encoding="utf-8")

    cfg = load_server_config(p)
    with pytest.raises(ValueError):
        resolve_server_config(cfg)


def test_apply_cli_overrides_server_replaces_bootstrap_list(tmp_path: Path) -> None:
    p = tmp_path / "registry.yaml"
    p.write_text(
        """
network:
  host: 0.0.0.0
  port: 1111
  bootstrap: ["/ip4/1.2.3.4/tcp/9999/p2p/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
datastore:
  path: ~/x
logging:
  verbosity: 1
""".strip(),
        encoding="utf-8",
    )

    cfg = load_server_config(p)
    assert cfg.network_port == 1111
    assert len(cfg.network_bootstrap) == 1

    ns = argparse.Namespace(
        host=None,
        port=2222,
        bootstrap=["/ip4/5.6.7.8/tcp/9999/p2p/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        datastore_path=None,
        mapsize=None,
        verbose=None,
    )

    cfg2 = apply_cli_overrides_to_server(cfg, ns)
    assert cfg2.network_port == 2222
    assert cfg2.network_bootstrap == ns.bootstrap

    resolved = resolve_server_config(cfg2)
    assert resolved.network_bootstrap == ns.bootstrap


def test_resolve_server_config_rejects_invalid_bootstrap_entry(tmp_path: Path) -> None:
    p = tmp_path / "registry.yaml"
    p.write_text(
        """
network:
  host: 127.0.0.1
  port: 1111
  bootstrap: ["not-a-multiaddr"]
""".strip(),
        encoding="utf-8",
    )

    cfg = load_server_config(p)
    with pytest.raises(ValueError):
        resolve_server_config(cfg)


def test_owner_privkey_resolution_uses_cli_config_path(tmp_path: Path) -> None:
    key_path = tmp_path / "owner_privkey.pem"
    key_path.write_text("dummy", encoding="utf-8")

    p = tmp_path / "registry_cli.yaml"
    data = {
        "network": {"host": "127.0.0.1", "port": 3333, "bootstrap": []},
        "datastore": {"path": "~/y"},
        "crypto": {"owner_privkey_pem_path": str(key_path)},
        "logging": {"verbosity": 0},
    }
    p.write_text(yaml.safe_dump(data), encoding="utf-8")

    cfg = load_client_config(p)
    resolved = resolve_client_config(cfg)
    assert resolved.owner_privkey_pem_path is not None
    assert resolved.owner_privkey_pem_path == str(key_path)

    owner = resolve_required_owner_privkey_pem_path(resolved)
    assert owner == str(key_path)


def test_owner_privkey_resolution_fails_if_file_missing(tmp_path: Path) -> None:
    missing_key = tmp_path / "missing.pem"
    p = tmp_path / "registry_cli.yaml"
    data = {
        "network": {"host": "127.0.0.1", "port": 3333, "bootstrap": []},
        "datastore": {"path": "~/y"},
        "crypto": {"owner_privkey_pem_path": str(missing_key)},
    }
    p.write_text(yaml.safe_dump(data), encoding="utf-8")

    cfg = load_client_config(p)
    resolved = resolve_client_config(cfg)
    with pytest.raises(ValueError):
        resolve_required_owner_privkey_pem_path(resolved)


def test_cli_config_defaults_are_non_null(tmp_path: Path) -> None:
    # Missing config file => load_* returns defaults.
    # (We don't use DEFAULT_* paths directly because that touches user home.)
    missing = tmp_path / "missing_cli.yaml"
    assert missing.exists() is False

    # Sanity: YAML missing returns empty mapping, so load_client_config produces defaults.
    cfg = load_client_config(missing)
    assert cfg.datastore_path == str(DEFAULT_CLI_DATASTORE_PATH)
    assert cfg.network_host == "127.0.0.1"


def test_server_config_default_datastore_dir(tmp_path: Path) -> None:
    missing = tmp_path / "missing_server.yaml"
    cfg = load_server_config(missing)
    assert cfg.datastore_path == str(DEFAULT_SERVER_DATASTORE_DIR.expanduser())
    assert cfg.network_host == "127.0.0.1"
    # network_port is not set until provided.
    assert cfg.network_port is None


def test_default_paths_constants_are_distinct() -> None:
    assert str(DEFAULT_SERVER_DATASTORE_DIR) != str(DEFAULT_CLI_DATASTORE_PATH)
    assert str(DEFAULT_CLI_CONFIG_PATH).endswith("registry_cli.yaml")
