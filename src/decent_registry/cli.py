import argparse
import json
import logging
import os
import signal
import sys
from typing import Any

import trio

from decent_registry.config import (
    DEFAULT_CLI_CONFIG_PATH,
    DEFAULT_SERVER_CONFIG_PATH,
    apply_cli_overrides_to_client,
    apply_cli_overrides_to_server,
    load_client_config,
    load_server_config,
    resolve_client_config,
    resolve_required_owner_privkey_pem_path,
    resolve_server_config,
)
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.registry_service import RegistryService
from decent_registry.durable_store import LMDBDatastore

logger = logging.getLogger("decent-registry.cli")


def _configure_logging(verbosity: int | None) -> None:
    # argparse now defaults --verbose to None; treat it as 0 (WARNING).
    if verbosity is None:
        verbosity = 0
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s", force=True)


def _parse_endpoints(values: list[str]) -> list[str]:
    eps: list[str] = []
    for v in values:
        if not v:
            continue
        parts = [p.strip() for p in v.split(",") if p.strip()]
        eps.extend(parts)
    return eps


def _add_network_args(p: argparse.ArgumentParser) -> None:
    # All network fields are optional here so a config file can supply defaults.
    # Final requiredness is enforced after config load + merge.
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument(
        "--bootstrap",
        action="append",
        default=None,
        help=(
            "libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated"
        ),
    )


def _add_datastore_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--datastore-path",
        default=None,
        help="LMDB datastore path (defaults come from YAML or built-in config defaults)",
    )
    p.add_argument(
        "--mapsize",
        type=int,
        default=None,
        help="LMDB mapsize in bytes (default: 1TB when omitted)",
    )


def _make_datastore_from_args(args: argparse.Namespace) -> LMDBDatastore:
    if args.mapsize is None:
        return LMDBDatastore(path=args.datastore_path)
    return LMDBDatastore(path=args.datastore_path, mapsize_bytes=args.mapsize)


def _keygen_command(args: argparse.Namespace) -> int:
    output_path = args.output
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    try:
        priv = Ed25519PrivateKey.generate()
        pem_bytes = priv.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        with open(output_path, "wb") as f:
            f.write(pem_bytes)
        os.chmod(output_path, 0o600)
        print(f"wrote {output_path} with mode 0o600")
        return 0
    except OSError:
        # No private key material in errors.
        print("error: cannot write key file", file=sys.stderr)
        return 1


def _node_command(args: argparse.Namespace) -> int:
    server_cfg = load_server_config(args.config)
    server_cfg = apply_cli_overrides_to_server(server_cfg, args)
    server_cfg = resolve_server_config(server_cfg)
    _configure_logging(server_cfg.verbosity)

    # Populate args so legacy code paths continue to use args.*
    args.host = server_cfg.network_host
    args.port = server_cfg.network_port
    args.bootstrap = server_cfg.network_bootstrap
    args.datastore_path = server_cfg.datastore_path
    args.mapsize = server_cfg.mapsize_bytes
    args.verbose = server_cfg.verbosity

    async def _async_node() -> int:
        endpoints = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"
        datastore = _make_datastore_from_args(args)
        async with Libp2pKadDHT(listen=listen, durable_store=datastore) as dht:
            node_peer_id = dht.host.get_id().to_string()
            logger.info("Node %s listening on %s", node_peer_id, dht.get_listen_multiaddr())
            ok = True
            if endpoints:
                ok_any = False
                for seed in endpoints:
                    try:
                        await dht.bootstrap(seed)
                        ok_any = True
                    except Exception as e:
                        logger.warning("Bootstrap seed failed: %s (%s)", seed, e)
                ok = ok_any
            if args.run_seconds is not None:
                await trio.sleep(args.run_seconds)
                return 0 if ok else 1
            with trio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                async for _ in signals:
                    break
            return 0 if ok else 1

    return trio.run(_async_node)


def _put_provider_command(args: argparse.Namespace) -> int:
    client_cfg = load_client_config(args.config)
    client_cfg = apply_cli_overrides_to_client(client_cfg, args)
    client_cfg = resolve_client_config(client_cfg)

    args.host = client_cfg.network_host
    args.port = client_cfg.network_port
    args.bootstrap = client_cfg.network_bootstrap
    args.datastore_path = client_cfg.datastore_path
    args.mapsize = client_cfg.mapsize_bytes
    args.verbose = client_cfg.verbosity

    args.owner_privkey = resolve_required_owner_privkey_pem_path(client_cfg)
    _configure_logging(client_cfg.verbosity)

    async def _async_put() -> int:
        endpoints = _parse_endpoints(args.endpoint or [])
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        datastore = _make_datastore_from_args(args)
        async with Libp2pKadDHT(listen=listen, durable_store=datastore) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            service = RegistryService(dht=dht)
            await service.put_provider(
                object_hash=args.object_hash,
                provider_id=args.provider_id,
                owner_privkey_pem_path=args.owner_privkey,
                seq=int(args.seq),
                endpoints=endpoints,
                alg="Ed25519",
                version=1,
            )
            print(1)
            return 0

    try:
        return trio.run(_async_put)
    except Exception:
        logger.error("put provider failed")
        print("put failed")
        return 1


def _get_provider_command(args: argparse.Namespace) -> int:
    client_cfg = load_client_config(args.config)
    client_cfg = apply_cli_overrides_to_client(client_cfg, args)
    client_cfg = resolve_client_config(client_cfg)

    args.host = client_cfg.network_host
    args.port = client_cfg.network_port
    args.bootstrap = client_cfg.network_bootstrap
    args.datastore_path = client_cfg.datastore_path
    args.mapsize = client_cfg.mapsize_bytes
    args.verbose = client_cfg.verbosity

    _configure_logging(client_cfg.verbosity)

    async def _async_get() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        datastore = _make_datastore_from_args(args)
        async with Libp2pKadDHT(listen=listen, durable_store=datastore) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            service = RegistryService(dht=dht)
            provider_payload = await service.get_provider(object_hash=args.object_hash)
            if provider_payload is None:
                print("not found")
                return 1

            payload = {
                "object_key": args.object_hash,
                "provider_id": provider_payload.provider_id,
                "endpoints": provider_payload.endpoints,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0

    return trio.run(_async_get)


def _put_identity_command(args: argparse.Namespace) -> int:
    client_cfg = load_client_config(args.config)
    client_cfg = apply_cli_overrides_to_client(client_cfg, args)
    client_cfg = resolve_client_config(client_cfg)

    args.host = client_cfg.network_host
    args.port = client_cfg.network_port
    args.bootstrap = client_cfg.network_bootstrap
    args.datastore_path = client_cfg.datastore_path
    args.mapsize = client_cfg.mapsize_bytes
    args.verbose = client_cfg.verbosity

    args.owner_privkey = resolve_required_owner_privkey_pem_path(client_cfg)
    _configure_logging(client_cfg.verbosity)

    async def _async_put() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        datastore = _make_datastore_from_args(args)
        async with Libp2pKadDHT(listen=listen, durable_store=datastore) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            service = RegistryService(dht=dht)
            await service.put_identity(
                owner_name_hex=args.owner_name,
                owner_privkey_pem_path=args.owner_privkey,
                seq=int(args.seq),
            )
            print(1)
            return 0

    try:
        return trio.run(_async_put)
    except Exception:
        logger.error("put identity failed")
        print("put failed")
        return 1


def _get_identity_command(args: argparse.Namespace) -> int:
    client_cfg = load_client_config(args.config)
    client_cfg = apply_cli_overrides_to_client(client_cfg, args)
    client_cfg = resolve_client_config(client_cfg)

    args.host = client_cfg.network_host
    args.port = client_cfg.network_port
    args.bootstrap = client_cfg.network_bootstrap
    args.datastore_path = client_cfg.datastore_path
    args.mapsize = client_cfg.mapsize_bytes
    args.verbose = client_cfg.verbosity

    _configure_logging(client_cfg.verbosity)

    async def _async_get() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        datastore = _make_datastore_from_args(args)
        async with Libp2pKadDHT(listen=listen, durable_store=datastore) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            service = RegistryService(dht=dht)
            record = await service.get_identity(owner_name_hex=args.owner_name)
            if record is None:
                print("not found")
                return 1

            print(json.dumps(record, indent=2, sort_keys=True))
            return 0

    return trio.run(_async_get)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-registry")
    parser.add_argument("-v", "--verbose", action="count", default=None)

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # node
    node_p = subparsers.add_parser("node", help="Run a DHT node")
    node_p.add_argument(
        "--config",
        default=str(DEFAULT_SERVER_CONFIG_PATH),
        help="Path to server YAML config file (default: ~/.decent/registry.yaml)",
    )
    _add_network_args(node_p)
    node_p.add_argument(
        "--run-seconds",
        type=float,
        default=None,
        help="If set, run bootstrap + listen for N seconds then exit",
    )
    _add_datastore_args(node_p)

    # put
    put_p = subparsers.add_parser("put", help="Publish a signed record")
    put_sub = put_p.add_subparsers(dest="record_type", required=True)

    put_provider_p = put_sub.add_parser(
        "provider",
        help="Publish a signed provider update",
        description=(
            "Publish a signed provider record under `--object-hash` (DHT key).\n\n"
            "Required:\n"
            "- --object-hash <64-hex>\n"
            "- --provider-id <64-hex>\n"
            "- --owner-privkey <owner_privkey_pem_path>\n"
            "- --seq <monotonic int>\n\n"
            "Optional:\n"
            "- --endpoint <multiaddr> (repeatable/comma-separated)"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    put_provider_p.add_argument(
        "--config",
        default=str(DEFAULT_CLI_CONFIG_PATH),
        help="Path to client YAML config (default: ~/.decent/registry_cli.yaml)",
    )
    _add_network_args(put_provider_p)
    _add_datastore_args(put_provider_p)
    put_provider_p.add_argument("--object-hash", dest="object_hash", required=True)
    put_provider_p.add_argument("--provider-id", required=True)
    put_provider_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=False,
        help="Path to an Ed25519 private key PEM file (optional if supplied in CLI config)",
    )
    put_provider_p.add_argument("--seq", type=int, default=1, help="Monotonic seq number")
    put_provider_p.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="Provider endpoint multiaddr starting with '/'; may repeat and/or be comma-separated",
    )

    put_identity_p = put_sub.add_parser(
        "identity",
        help="Publish a signed identity update",
        description=(
            "Publish a signed identity record.\n\n"
            "Lookup key derivation:\n"
            "- DHT key object_key = sha256(owner_name_bytes)\n\n"
            "Required:\n"
            "- --owner-name <hex bytes>\n"
            "- --owner-privkey <owner_privkey_pem_path>\n"
            "- --seq <monotonic int>"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    put_identity_p.add_argument(
        "--config",
        default=str(DEFAULT_CLI_CONFIG_PATH),
        help="Path to client YAML config (default: ~/.decent/registry_cli.yaml)",
    )
    _add_network_args(put_identity_p)
    _add_datastore_args(put_identity_p)
    put_identity_p.add_argument("--owner-name", dest="owner_name", required=True)
    put_identity_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=False,
        help="Path to an Ed25519 private key PEM file (optional if supplied in CLI config)",
    )
    put_identity_p.add_argument("--seq", type=int, default=1, help="Monotonic seq number")

    # get
    get_p = subparsers.add_parser("get", help="Resolve a signed record")
    get_sub = get_p.add_subparsers(dest="record_type", required=True)

    get_provider_p = get_sub.add_parser(
        "provider",
        help="Get a provider record by DHT key",
        description=(
            "Resolve a provider record by `--object-hash` (DHT key).\n\n"
            "Required:\n"
            "- --object-hash <64-hex>"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    get_provider_p.add_argument(
        "--config",
        default=str(DEFAULT_CLI_CONFIG_PATH),
        help="Path to client YAML config (default: ~/.decent/registry_cli.yaml)",
    )
    _add_network_args(get_provider_p)
    _add_datastore_args(get_provider_p)
    get_provider_p.add_argument("--object-hash", dest="object_hash", required=True)

    get_identity_p = get_sub.add_parser(
        "identity",
        help="Get an identity record by owner name",
        description=(
            "Resolve an identity record.\n\n"
            "Lookup key derivation:\n"
            "- DHT key object_key = sha256(owner_name_bytes)\n\n"
            "Required:\n"
            "- --owner-name <hex bytes>"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    get_identity_p.add_argument(
        "--config",
        default=str(DEFAULT_CLI_CONFIG_PATH),
        help="Path to client YAML config (default: ~/.decent/registry_cli.yaml)",
    )
    _add_network_args(get_identity_p)
    _add_datastore_args(get_identity_p)
    get_identity_p.add_argument("--owner-name", dest="owner_name", required=True)

    # keygen
    keygen_p = subparsers.add_parser(
        "keygen",
        help="Generate an Ed25519 private key (PKCS#8 PEM)",
        description=(
            "Generate an unencrypted Ed25519 private key in PKCS#8 PEM format.\n\n"
            "The file permissions are set to 0o600.\n\n"
            "Private key material is never printed or logged."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    keygen_p.add_argument(
        "--output",
        default="owner_privkey.pem",
        help="Output PEM file path (default: owner_privkey.pem)",
    )

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if args.cmd == "node":
        raise SystemExit(_node_command(args))
    if args.cmd == "keygen":
        raise SystemExit(_keygen_command(args))
    if args.cmd == "put":
        if args.record_type == "provider":
            raise SystemExit(_put_provider_command(args))
        if args.record_type == "identity":
            raise SystemExit(_put_identity_command(args))
        raise SystemExit(f"Unknown put record type: {args.record_type}")

    if args.cmd == "get":
        if args.record_type == "provider":
            raise SystemExit(_get_provider_command(args))
        if args.record_type == "identity":
            raise SystemExit(_get_identity_command(args))
        raise SystemExit(f"Unknown get record type: {args.record_type}")

    raise SystemExit(f"Unknown command: {args.cmd}")
