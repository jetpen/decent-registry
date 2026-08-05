import argparse
import json
import logging
import os
import signal
import sys
from pathlib import Path
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
from decent_registry.crypto_utils import load_ed25519_keypair_from_privkey_pem_path
from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_ORDINARY_UPDATE,
    OPERATION_REPLACE_SIGNERS,
    OPERATION_UPGRADE,
)
from decent_registry.multisig_bundle import (
    MultisignatureBundle,
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from libp2p.crypto.ed25519 import Ed25519PrivateKey, create_new_key_pair
from libp2p.crypto.keys import KeyPair

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


_OPERATION_NAMES = {
    "genesis": OPERATION_GENESIS,
    "ordinary-update": OPERATION_ORDINARY_UPDATE,
    "replace-signers": OPERATION_REPLACE_SIGNERS,
    "upgrade": OPERATION_UPGRADE,
}


def _parse_hex_value(value: str, *, name: str, length: int | None = None) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} must be hexadecimal") from None
    if length is not None and len(decoded) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return decoded


def _parse_signer_set(values: list[str]) -> list[dict[int, Any]]:
    if not values:
        raise ValueError("at least one --signer is required")
    entries: list[dict[int, Any]] = []
    seen_ids: set[str] = set()
    seen_keys: set[bytes] = set()
    for value in values:
        signer_id, separator, public_key_hex = value.partition("=")
        if not separator or not signer_id:
            raise ValueError("--signer must use ID=PUBLIC_KEY_HEX")
        if signer_id in seen_ids:
            raise ValueError("duplicate signer identifier")
        public_key = _parse_hex_value(
            public_key_hex, name=f"public key for signer {signer_id}", length=32
        )
        if public_key in seen_keys:
            raise ValueError("duplicate signer public key")
        seen_ids.add(signer_id)
        seen_keys.add(public_key)
        entries.append({1: signer_id, 2: public_key})
    return sorted(entries, key=lambda entry: entry[1].encode("utf-8"))


def _read_cli_bytes(path: str, *, description: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        raise ValueError(f"cannot read {description} file") from None


def _write_cli_bytes(path: str, value: bytes, *, description: str) -> None:
    try:
        Path(path).write_bytes(value)
    except OSError:
        raise ValueError(f"cannot write {description} file") from None


def _bundle_draft_command(args: argparse.Namespace) -> int:
    signer_set = _parse_signer_set(args.signer)
    owner_public_key = _parse_hex_value(
        args.owner_public_key, name="owner public key", length=32
    )
    predecessor_state_hash = _parse_hex_value(
        args.predecessor_state_hash, name="predecessor state hash", length=32
    )
    operation = _OPERATION_NAMES[args.operation]
    if args.record_type == "identity":
        owner_name = _parse_hex_value(args.owner_name, name="owner name")
        bundle = draft_identity_bundle(
            owner_name=owner_name,
            owner_public_key=owner_public_key,
            seq=args.seq,
            signer_set=signer_set,
            threshold=args.threshold,
            epoch=args.epoch,
            predecessor_state_hash=predecessor_state_hash,
            operation=operation,
        )
    else:
        object_hash = args.object_hash.lower()
        _parse_hex_value(object_hash, name="object hash", length=32)
        bundle = draft_provider_bundle(
            object_hash=object_hash,
            provider_url=args.provider_url,
            endpoints=_parse_endpoints(args.endpoint),
            owner_public_key=owner_public_key,
            seq=args.seq,
            signer_set=signer_set,
            threshold=args.threshold,
            epoch=args.epoch,
            predecessor_state_hash=predecessor_state_hash,
            operation=operation,
            alg=args.alg,
            version=args.payload_version,
        )
    _write_cli_bytes(args.output, bundle.to_cbor(), description="bundle output")
    return 0


def _bundle_sign_command(args: argparse.Namespace) -> int:
    bundle = MultisignatureBundle.from_cbor(
        _read_cli_bytes(args.input, description="bundle input")
    )
    signer_private_key, _public_key = load_ed25519_keypair_from_privkey_pem_path(
        args.signer_privkey
    )
    signed_bundle = merge_proof(bundle, sign_bundle(bundle, signer_private_key))
    _write_cli_bytes(args.output, signed_bundle.to_cbor(), description="signed bundle output")
    return 0


def _bundle_merge_command(args: argparse.Namespace) -> int:
    bundle = MultisignatureBundle.from_cbor(
        _read_cli_bytes(args.input, description="bundle input")
    )
    for proof_path in args.proof:
        proof_bundle = MultisignatureBundle.from_cbor(
            _read_cli_bytes(proof_path, description="proof input")
        )
        if not proof_bundle.proofs:
            raise ValueError("proof input contains no proofs")
        for proof in proof_bundle.proofs:
            bundle = merge_proof(bundle, proof)
    _write_cli_bytes(args.output, bundle.to_cbor(), description="merged bundle output")
    return 0


def _bundle_finalize_command(args: argparse.Namespace) -> int:
    bundle = MultisignatureBundle.from_cbor(
        _read_cli_bytes(args.input, description="bundle input")
    )
    finalized = finalize_bundle(bundle)
    _write_cli_bytes(args.output, finalized, description="SignedEnvelope output")
    return 0


def _bundle_command(args: argparse.Namespace) -> int:
    try:
        if args.bundle_action == "draft":
            return _bundle_draft_command(args)
        if args.bundle_action == "sign":
            return _bundle_sign_command(args)
        if args.bundle_action == "merge":
            return _bundle_merge_command(args)
        if args.bundle_action == "finalize":
            return _bundle_finalize_command(args)
        raise ValueError(f"unknown bundle operation: {args.bundle_action}")
    except (OSError, TypeError, ValueError) as exc:
        logger.error("bundle %s failed: %s", args.bundle_action, exc)
        print("bundle operation failed")
        return 1


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


_NODE_IDENTITY_KEY_FILENAME = "node_privkey.bin"


def _node_identity_key_path(datastore_path: str) -> Path:
    # Node identity key should live alongside the node's LMDB durable store.
    p = Path(datastore_path).expanduser()
    if p.name.endswith(".lmdb"):
        return p.parent / _NODE_IDENTITY_KEY_FILENAME
    return p / _NODE_IDENTITY_KEY_FILENAME


def _load_or_create_node_identity_key(datastore_path: str) -> KeyPair:
    key_path = _node_identity_key_path(datastore_path)

    if key_path.exists():
        raw = key_path.read_bytes()
        priv = Ed25519PrivateKey.from_bytes(raw)
        return KeyPair(private_key=priv, public_key=priv.get_public_key())

    key_path.parent.mkdir(parents=True, exist_ok=True)

    key_pair = create_new_key_pair()
    raw = key_pair.private_key.to_bytes()

    # Avoid overwriting existing keys (including races) with an atomic create.
    try:
        with open(key_path, "xb") as f:
            f.write(raw)
        os.chmod(key_path, 0o600)
    except FileExistsError:
        # Another process created it; load the persisted version.
        raw = key_path.read_bytes()
        priv = Ed25519PrivateKey.from_bytes(raw)
        return KeyPair(private_key=priv, public_key=priv.get_public_key())

    return key_pair



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
        node_key = _load_or_create_node_identity_key(str(args.datastore_path))
        async with Libp2pKadDHT(listen=listen, durable_store=datastore, key_pair=node_key) as dht:
            listen_maddr = dht.get_listen_multiaddr()
            node_peer_id = dht.host.get_id().to_string()
            logger.info("Node %s listening on %s", node_peer_id, listen_maddr)
            print(f"[BOOTSTRAP] {listen_maddr}/p2p/{node_peer_id}", flush=True)
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

    if args.finalized_envelope is None:
        if args.provider_url is None or args.seq is None:
            logger.error("legacy provider submission requires --provider-url and --seq")
            return 1
        args.owner_privkey = resolve_required_owner_privkey_pem_path(client_cfg)
    elif (
        args.provider_url is not None
        or args.owner_privkey is not None
        or args.endpoint
        or args.seq is not None
    ):
        logger.error("finalized provider submission cannot include legacy signing arguments")
        return 1
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
            if args.finalized_envelope is not None:
                await service.put_provider(
                    object_hash=args.object_hash,
                    envelope_cbor=_read_cli_bytes(
                        args.finalized_envelope, description="finalized SignedEnvelope"
                    ),
                )
            else:
                await service.put_provider(
                    object_hash=args.object_hash,
                    provider_url=args.provider_url,
                    owner_privkey_pem_path=args.owner_privkey,
                    seq=int(args.seq) if args.seq is not None else 1,
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
                "provider_url": provider_payload.provider_url,
                "endpoints": provider_payload.endpoints,
            }
            authorization = getattr(provider_payload, "authorization", None)
            seq = getattr(provider_payload, "seq", None)
            if authorization is not None and seq is not None:
                payload["seq"] = int(seq)
                payload["authorization"] = authorization.to_dict()
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

    if args.finalized_envelope is None:
        if args.seq is None:
            logger.error("legacy identity submission requires --seq")
            return 1
        args.owner_privkey = resolve_required_owner_privkey_pem_path(client_cfg)
    elif args.owner_privkey is not None or args.seq is not None:
        logger.error("finalized identity submission cannot include legacy signing arguments")
        return 1
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
            if args.finalized_envelope is not None:
                await service.put_identity(
                    owner_name_hex=args.owner_name,
                    envelope_cbor=_read_cli_bytes(
                        args.finalized_envelope, description="finalized SignedEnvelope"
                    ),
                )
            else:
                await service.put_identity(
                    owner_name_hex=args.owner_name,
                    owner_privkey_pem_path=args.owner_privkey,
                    seq=int(args.seq) if args.seq is not None else 1,
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

            record_payload: Any = record
            to_dict = getattr(record_payload, "to_dict", None)
            if callable(to_dict):
                record_payload = to_dict()
            print(json.dumps(record_payload, indent=2, sort_keys=True))
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

    # bundle
    bundle_p = subparsers.add_parser(
        "bundle", help="Create, sign, merge, and finalize a Multisignature Bundle"
    )
    bundle_sub = bundle_p.add_subparsers(dest="bundle_action", required=True)

    bundle_draft_p = bundle_sub.add_parser(
        "draft", help="Create an unsigned canonical Multisignature Bundle"
    )
    bundle_draft_sub = bundle_draft_p.add_subparsers(
        dest="record_type", required=True
    )

    def _add_bundle_draft_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--owner-public-key", required=True)
        p.add_argument("--seq", type=int, required=True)
        p.add_argument("--threshold", type=int, default=2)
        p.add_argument("--epoch", type=int, default=1)
        p.add_argument(
            "--predecessor-state-hash", default=(bytes(32).hex())
        )
        p.add_argument(
            "--operation",
            choices=sorted(_OPERATION_NAMES),
            default="genesis",
        )
        p.add_argument(
            "--signer",
            action="append",
            required=True,
            help="Signer Set member as ID=PUBLIC_KEY_HEX; may repeat",
        )
        p.add_argument("--output", required=True)

    bundle_draft_identity_p = bundle_draft_sub.add_parser(
        "identity", help="Draft an Identity Record Multisignature Bundle"
    )
    bundle_draft_identity_p.add_argument("--owner-name", required=True)
    _add_bundle_draft_common(bundle_draft_identity_p)

    bundle_draft_provider_p = bundle_draft_sub.add_parser(
        "provider", help="Draft a Provider Record Multisignature Bundle"
    )
    bundle_draft_provider_p.add_argument("--object-hash", required=True)
    bundle_draft_provider_p.add_argument("--provider-url", required=True)
    bundle_draft_provider_p.add_argument(
        "--endpoint", action="append", default=[], help="Provider multiaddr"
    )
    bundle_draft_provider_p.add_argument("--alg", default="Ed25519")
    bundle_draft_provider_p.add_argument("--payload-version", type=int, default=1)
    _add_bundle_draft_common(bundle_draft_provider_p)

    bundle_sign_p = bundle_sub.add_parser(
        "sign", help="Sign one local Multisignature Bundle"
    )
    bundle_sign_p.add_argument("--input", required=True)
    bundle_sign_p.add_argument("--signer-privkey", required=True)
    bundle_sign_p.add_argument("--output", required=True)

    bundle_merge_p = bundle_sub.add_parser(
        "merge", help="Merge detached proof bundle files"
    )
    bundle_merge_p.add_argument("--input", required=True)
    bundle_merge_p.add_argument(
        "--proof", action="append", required=True, help="Proof bundle file; may repeat"
    )
    bundle_merge_p.add_argument("--output", required=True)

    bundle_finalize_p = bundle_sub.add_parser(
        "finalize", help="Finalize a threshold-complete Multisignature Bundle"
    )
    bundle_finalize_p.add_argument("--input", required=True)
    bundle_finalize_p.add_argument("--output", required=True)

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
            "- legacy mode: --provider-url, --owner-privkey, and --seq\n"
            "- finalized mode: --finalized-envelope <path>\n\n"
            "Optional in legacy mode:\n"
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
    put_provider_p.add_argument("--provider-url", dest="provider_url", required=False)
    put_provider_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=False,
        help="Path to an Ed25519 private key PEM file (optional if supplied in CLI config)",
    )
    put_provider_p.add_argument(
        "--finalized-envelope",
        dest="finalized_envelope",
        default=None,
        help="Submit a finalized SignedEnvelope file without private-key material",
    )
    put_provider_p.add_argument("--seq", type=int, default=None, help="Monotonic seq number")
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
            "- legacy mode: --owner-privkey and --seq\n"
            "- finalized mode: --finalized-envelope <path>"
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
    put_identity_p.add_argument(
        "--finalized-envelope",
        dest="finalized_envelope",
        default=None,
        help="Submit a finalized SignedEnvelope file without private-key material",
    )
    put_identity_p.add_argument("--seq", type=int, default=None, help="Monotonic seq number")

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
    if args.cmd == "bundle":
        raise SystemExit(_bundle_command(args))
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
