import argparse
import json
import logging
import signal
import time
from typing import Any

import trio

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
        # allow comma-separated
        parts = [p.strip() for p in v.split(",") if p.strip()]
        eps.extend(parts)
    return eps


def _derive_owner_keypair_from_privkey_hex(privkey_hex: str):
    from libp2p.crypto.ed25519 import create_new_key_pair

    priv_bytes = bytes.fromhex(privkey_hex)
    priv_cls = type(create_new_key_pair().private_key)

    # libp2p key types are runtime objects; keep typing permissive here.
    priv_cls_any: Any = priv_cls  # type: ignore[assignment]
    owner_priv = priv_cls_any.from_bytes(priv_bytes)

    owner_pub = owner_priv.get_public_key()
    return owner_priv, owner_pub.to_bytes()


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


def _put_command(args: argparse.Namespace) -> int:
    async def _async_put() -> int:
        endpoints = _parse_endpoints(args.endpoint or [])
        seeds = _parse_endpoints(args.bootstrap or [])
        listen = f"/ip4/{args.host}/tcp/{args.port}"

        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)

            # minimal routing settle
            await trio.sleep(1.0)

            owner_priv, owner_pub_bytes = _derive_owner_keypair_from_privkey_hex(
                args.owner_privkey
            )

            payload_dict: dict[int, Any] = build_provider_payload_dict(
                alg="Ed25519",
                version=1,
                object_hash=args.object_hash,
                provider_id=args.provider_id,
                endpoints=endpoints,
            )

            record_fields: dict[int, Any] = {
                1: owner_pub_bytes,
            }

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

            # legacy tests expect some output; keep minimal.
            print(1)
            return 0

    try:
        return trio.run(_async_put)
    except Exception as e:
        logger.error("put failed: %s", e)
        print(str(e))
        return 1


def _get_command(args: argparse.Namespace) -> int:
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-registry")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    subparsers = parser.add_subparsers(dest="cmd", required=True)

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

    put_p = subparsers.add_parser("put", help="Publish a signed provider update")
    put_p.add_argument("--host", default="127.0.0.1")
    put_p.add_argument("--port", type=int, required=True)
    put_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help=(
            "libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated"
        ),
    )
    put_p.add_argument("--object-hash", dest="object_hash", required=True)
    put_p.add_argument("--provider-id", required=True)
    put_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=True,
        help="Ed25519 private key bytes as 64 hex chars",
    )
    put_p.add_argument("--seq", type=int, default=1, help="Monotonic seq number")
    put_p.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="Provider endpoint multiaddr (must start with '/'); may repeat and/or be comma-separated",
    )

    get_p = subparsers.add_parser("get", help="Resolve an object hash")
    get_p.add_argument("--host", default="127.0.0.1")
    get_p.add_argument("--port", type=int, required=True)
    get_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated",
    )
    get_p.add_argument("--object-hash", dest="object_hash", required=True)

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if args.cmd == "node":
        raise SystemExit(_node_command(args))
    if args.cmd == "put":
        raise SystemExit(_put_command(args))
    if args.cmd == "get":
        raise SystemExit(_get_command(args))

    raise SystemExit(f"Unknown command: {args.cmd}")
