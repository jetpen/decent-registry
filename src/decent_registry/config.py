from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_SERVER_CONFIG_PATH = Path("~/.decent/registry.yaml")
DEFAULT_SERVER_DATASTORE_DIR = Path("~/.decent/registry")

DEFAULT_CLI_CONFIG_PATH = Path("~/.decent/registry_cli.yaml")

# Preserve existing CLI default behaviour: LMDB file under repo-local .scratch.
DEFAULT_CLI_DATASTORE_PATH = Path(".scratch/decent-registry.lmdb")


@dataclass
class ServerConfig:
    network_host: str = "127.0.0.1"
    network_port: int | None = None
    network_bootstrap: list[str] = field(default_factory=list)

    datastore_path: str = str(DEFAULT_SERVER_DATASTORE_DIR)
    mapsize_bytes: int | None = None

    # 0=WARNING, 1=INFO, >=2=DEBUG
    verbosity: int = 0


@dataclass
class ClientConfig:
    network_host: str = "127.0.0.1"
    network_port: int | None = None
    network_bootstrap: list[str] = field(default_factory=list)

    datastore_path: str = str(DEFAULT_CLI_DATASTORE_PATH)
    mapsize_bytes: int | None = None

    verbosity: int = 0

    # Path to an Ed25519 private key PEM file. No inline key material.
    owner_privkey_pem_path: str | None = None


def _expand_path(p: str | Path) -> str:
    return str(Path(p).expanduser())


def _coerce_int(v: Any, *, name: str) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        i = int(v)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"{name} must be an integer") from e
    return i


def _coerce_list_str(v: Any, *, name: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{name} must be a list of strings")
    return list(v)


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    p = Path(path).expanduser()
    if not p.exists():
        return {}

    data: Any
    with p.open("rb") as f:
        # safe_load can return None for empty files.
        data = yaml.safe_load(f)

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {p}")
    return data


def load_server_config(config_path: str | Path) -> ServerConfig:
    raw = load_yaml_file(config_path)

    network = raw.get("network", {}) if isinstance(raw, dict) else {}
    datastore = raw.get("datastore", {}) if isinstance(raw, dict) else {}
    logging = raw.get("logging", {}) if isinstance(raw, dict) else {}

    cfg = ServerConfig(
        network_host=str(network.get("host", "127.0.0.1")) if network else "127.0.0.1",
        network_port=_coerce_int(network["port"], name="network.port")
        if isinstance(network, dict) and "port" in network and network["port"] is not None
        else None,
        network_bootstrap=_coerce_list_str(
            network.get("bootstrap", []), name="network.bootstrap"
        ),
        datastore_path=_expand_path(
            datastore.get("path", str(DEFAULT_SERVER_DATASTORE_DIR))
        ),
        mapsize_bytes=_coerce_int(datastore["mapsize_bytes"], name="datastore.mapsize_bytes")
        if isinstance(datastore, dict) and "mapsize_bytes" in datastore and datastore["mapsize_bytes"] is not None
        else None,
        verbosity=_coerce_int(logging.get("verbosity", 0), name="logging.verbosity")
        if isinstance(logging, dict)
        else 0,
    )

    return cfg


def load_client_config(config_path: str | Path) -> ClientConfig:
    raw = load_yaml_file(config_path)

    network = raw.get("network", {}) if isinstance(raw, dict) else {}
    datastore = raw.get("datastore", {}) if isinstance(raw, dict) else {}
    logging = raw.get("logging", {}) if isinstance(raw, dict) else {}
    crypto = raw.get("crypto", {}) if isinstance(raw, dict) else {}

    cfg = ClientConfig(
        network_host=str(network.get("host", "127.0.0.1")) if network else "127.0.0.1",
        network_port=_coerce_int(network["port"], name="network.port")
        if isinstance(network, dict) and "port" in network and network["port"] is not None
        else None,
        network_bootstrap=_coerce_list_str(
            network.get("bootstrap", []), name="network.bootstrap"
        ),
        datastore_path=_expand_path(
            datastore.get("path", str(DEFAULT_CLI_DATASTORE_PATH))
        ),
        mapsize_bytes=_coerce_int(datastore["mapsize_bytes"], name="datastore.mapsize_bytes")
        if isinstance(datastore, dict) and "mapsize_bytes" in datastore and datastore["mapsize_bytes"] is not None
        else None,
        verbosity=_coerce_int(logging.get("verbosity", 0), name="logging.verbosity")
        if isinstance(logging, dict)
        else 0,
        owner_privkey_pem_path=_expand_path(crypto["owner_privkey_pem_path"])
        if isinstance(crypto, dict) and crypto.get("owner_privkey_pem_path") is not None
        else None,
    )

    # Validate type only; do not read key material here.
    if cfg.owner_privkey_pem_path is not None and not isinstance(
        cfg.owner_privkey_pem_path, str
    ):
        raise ValueError("crypto.owner_privkey_pem_path must be a string")

    return cfg


def apply_cli_overrides_to_server(cfg: ServerConfig, args: Any) -> ServerConfig:
    # args fields expected:
    # - host, port, bootstrap, datastore_path, mapsize, verbose
    if getattr(args, "host", None) is not None:
        cfg.network_host = args.host
    if getattr(args, "port", None) is not None:
        cfg.network_port = int(args.port)
    if getattr(args, "bootstrap", None) is not None:
        cfg.network_bootstrap = list(args.bootstrap)
    if getattr(args, "datastore_path", None) is not None:
        cfg.datastore_path = _expand_path(args.datastore_path)
    if getattr(args, "mapsize", None) is not None:
        cfg.mapsize_bytes = int(args.mapsize)
    if getattr(args, "verbose", None) is not None:
        cfg.verbosity = int(args.verbose)
    return cfg


def resolve_server_config(cfg: ServerConfig) -> ServerConfig:
    if cfg.network_port is None:
        raise ValueError(
            "network.port is required (put it in ~/.decent/registry.yaml or pass --port)"
        )

    if not isinstance(cfg.network_host, str) or not cfg.network_host:
        raise ValueError("network.host must be a non-empty string")

    if not (1 <= int(cfg.network_port) <= 65535):
        raise ValueError("network.port must be in range 1..65535")

    if cfg.verbosity < 0:
        raise ValueError("logging.verbosity must be >= 0")

    # Basic sanity: libp2p seed multiaddrs start with '/'
    for s in cfg.network_bootstrap:
        if not isinstance(s, str) or not s.startswith("/"):
            raise ValueError("network.bootstrap entries must be multiaddr strings starting with '/'")

    # datastore_path may be a directory (server config spec) or a file.
    cfg.datastore_path = _expand_path(cfg.datastore_path)
    return cfg


def apply_cli_overrides_to_client(cfg: ClientConfig, args: Any) -> ClientConfig:
    # args fields expected:
    # - host, port, bootstrap, datastore_path, mapsize, verbose, owner_privkey
    if getattr(args, "host", None) is not None:
        cfg.network_host = args.host
    if getattr(args, "port", None) is not None:
        cfg.network_port = int(args.port)
    if getattr(args, "bootstrap", None) is not None:
        cfg.network_bootstrap = list(args.bootstrap)
    if getattr(args, "datastore_path", None) is not None:
        cfg.datastore_path = _expand_path(args.datastore_path)
    if getattr(args, "mapsize", None) is not None:
        cfg.mapsize_bytes = int(args.mapsize)
    if getattr(args, "verbose", None) is not None:
        cfg.verbosity = int(args.verbose)

    owner_privkey_flag = getattr(args, "owner_privkey", None)
    if owner_privkey_flag is not None:
        cfg.owner_privkey_pem_path = _expand_path(owner_privkey_flag)

    return cfg


def resolve_client_config(cfg: ClientConfig) -> ClientConfig:
    if cfg.network_port is None:
        raise ValueError("network.port is required (put it in the CLI config or pass --port)")

    if not isinstance(cfg.network_host, str) or not cfg.network_host:
        raise ValueError("network.host must be a non-empty string")

    if not (1 <= int(cfg.network_port) <= 65535):
        raise ValueError("network.port must be in range 1..65535")

    if cfg.verbosity < 0:
        raise ValueError("logging.verbosity must be >= 0")

    for s in cfg.network_bootstrap:
        if not isinstance(s, str) or not s.startswith("/"):
            raise ValueError(
                "network.bootstrap entries must be multiaddr strings starting with '/'"
            )

    cfg.datastore_path = _expand_path(cfg.datastore_path)

    return cfg


def resolve_required_owner_privkey_pem_path(cfg: ClientConfig) -> str:
    if cfg.owner_privkey_pem_path is None:
        raise ValueError(
            "owner private key is required (set crypto.owner_privkey_pem_path in the CLI config or pass --owner-privkey)"
        )

    # Validate file existence without reading contents (no key material into logs).
    if not Path(cfg.owner_privkey_pem_path).expanduser().exists():
        raise ValueError("owner private key file does not exist")

    return cfg.owner_privkey_pem_path
