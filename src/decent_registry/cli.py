import argparse
import hashlib
import json
import logging
import os
import signal
import sys
from typing import Any

import trio
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import make_signed_update_signature

logger = logging.getLogger("decent-registry.cli")


def _configure_logging(verbosity: int) -> None:
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


def _parse_hex_bytes(value: str, *, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except Exception as e:
        raise ValueError(f"{name} must be valid hex") from e


def _load_ed25519_keypair_from_privkey_pem_path(privkey_pem_path: str):
    """Load an Ed25519 private key from an OpenSSL-compatible PEM file.

    HARD RULE (ticket #27): private key material is a secret.
    - Never log or print private key material.
    - Never include private key material in exception messages.
    - Avoid exception chaining that could leak parser internals.
    """

    # Only the file path crosses the CLI boundary.
    pem_data: bytes | None = None
    private_key = None
    priv_raw: bytes | None = None

    class _OwnerPrivkeyFileReadError(ValueError):
        pass

    try:
        try:
            with open(privkey_pem_path, "rb") as f:
                pem_data = f.read()
        except Exception:
            raise _OwnerPrivkeyFileReadError("cannot read owner private key file") from None

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            load_pem_private_key,
        )

        if pem_data is None:
            raise RuntimeError("owner private key data missing")
        private_key = load_pem_private_key(pem_data, password=None)

        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("unsupported private key type")

        # libp2p expects raw Ed25519 private key bytes.
        priv_raw = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

        priv_cls = type(create_new_key_pair().private_key)
        priv_cls_any: Any = priv_cls  # type: ignore[assignment]
        owner_priv = priv_cls_any.from_bytes(priv_raw)
        owner_pub = owner_priv.get_public_key()
        return owner_priv, owner_pub.to_bytes()

    except _OwnerPrivkeyFileReadError:
        raise ValueError("cannot read owner private key file") from None
    except ValueError:
        raise ValueError("invalid owner private key file") from None
    except Exception:
        raise ValueError("invalid owner private key file") from None
    finally:
        # Reduce key material lifetime in-process.
        try:
            if pem_data is not None:
                del pem_data
            if priv_raw is not None:
                del priv_raw
            if private_key is not None:
                del private_key
        except Exception:
            pass


def _derive_identity_object_hash_from_owner_name_hex(owner_name_hex: str) -> str:
    owner_name_bytes = _parse_hex_bytes(owner_name_hex, name="owner_name")
    return hashlib.sha256(owner_name_bytes).hexdigest()


def _add_network_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help=(
            "libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated"
        ),
    )


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
    async def _async_node() -> int:
        endpoints = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"
        async with Libp2pKadDHT(listen=listen) as dht:
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
    async def _async_put() -> int:
        endpoints = _parse_endpoints(args.endpoint or [])
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            owner_priv, owner_pub_bytes = _load_ed25519_keypair_from_privkey_pem_path(
                args.owner_privkey
            )

            payload_dict: dict[int, Any] = build_provider_payload_dict(
                alg="Ed25519",
                version=1,
                object_hash=args.object_hash,
                provider_id=args.provider_id,
                endpoints=endpoints,
            )

            record_fields: dict[int, Any] = {1: owner_pub_bytes}

            signed_update_bytes = encode_signed_update(
                record_fields=record_fields,
                payload=payload_dict,
                seq=int(args.seq),
            )
            signature = make_signed_update_signature(
                signed_update_bytes_canonical=signed_update_bytes,
                owner_private_key=owner_priv,
            )
            envelope_cbor = encode_signed_envelope(
                signed_update_bytes=signed_update_bytes,
                signature=signature,
            )

            await dht.put_signed_provider_record(args.object_hash, envelope_cbor)
            print(1)
            return 0

    try:
        return trio.run(_async_put)
    except Exception:
        logger.error("put provider failed")
        print("put failed")
        return 1


def _get_provider_command(args: argparse.Namespace) -> int:
    async def _async_get() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            provider_payload = await dht.get_signed_provider_record(args.object_hash)
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
    async def _async_put() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
                args.owner_name
            )

            owner_priv, owner_pub_bytes = _load_ed25519_keypair_from_privkey_pem_path(
                args.owner_privkey
            )
            owner_name_bytes = _parse_hex_bytes(args.owner_name, name="owner_name")

            record_fields: dict[int, Any] = {
                1: owner_name_bytes,
                2: owner_pub_bytes,
            }

            signed_update_bytes = encode_signed_update(
                record_fields=record_fields,
                payload={},
                seq=int(args.seq),
            )
            signature = make_signed_update_signature(
                signed_update_bytes_canonical=signed_update_bytes,
                owner_private_key=owner_priv,
            )
            envelope_cbor = encode_signed_envelope(
                signed_update_bytes=signed_update_bytes,
                signature=signature,
            )

            await dht.put_signed_identity_record(object_key_hex, envelope_cbor)
            print(1)
            return 0

    try:
        return trio.run(_async_put)
    except Exception:
        logger.error("put identity failed")
        print("put failed")
        return 1


def _get_identity_command(args: argparse.Namespace) -> int:
    async def _async_get() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)
            await trio.sleep(1.0)

            object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
                args.owner_name
            )
            record = await dht.get_signed_identity_record(object_key_hex)
            if record is None:
                print("not found")
                return 1

            print(json.dumps(record, indent=2, sort_keys=True))
            return 0

    return trio.run(_async_get)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-registry")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # node
    node_p = subparsers.add_parser("node", help="Run a DHT node")
    node_p.add_argument("--host", default="127.0.0.1")
    node_p.add_argument("--port", type=int, required=True)
    node_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help=(
            "libp2p seed multiaddr(s) for bootstrapping; must include /p2p/<peerid> "
            "(may repeat and/or be comma-separated)"
        ),
    )
    node_p.add_argument(
        "--run-seconds",
        type=float,
        default=None,
        help="If set, run bootstrap + listen for N seconds then exit",
    )

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
    _add_network_args(put_provider_p)
    put_provider_p.add_argument("--object-hash", dest="object_hash", required=True)
    put_provider_p.add_argument("--provider-id", required=True)
    put_provider_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=True,
        help="Path to an Ed25519 private key PEM file",
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
    _add_network_args(put_identity_p)
    put_identity_p.add_argument("--owner-name", dest="owner_name", required=True)
    put_identity_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=True,
        help="Path to an Ed25519 private key PEM file",
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
    _add_network_args(get_provider_p)
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
    _add_network_args(get_identity_p)
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
