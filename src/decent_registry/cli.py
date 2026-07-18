import argparse
import json
import logging
import signal
import sys
import time

import trio

from decent_registry.dht.libp2p_dht import Libp2pKadDHT, ProviderRecord

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
                # seed must be an identify-style multiaddr with /p2p/<peerid>
                await dht.bootstrap(seed)

            # routing convergence (minimal)
            await trio.sleep(1.0)

            now = int(time.time())
            ttl_seconds = int(args.ttl_seconds)
            expires_at = now + ttl_seconds

            record = {
                "version": 1,
                "object_hash": args.object_hash,
                "ttl_seconds": ttl_seconds,
                "expires_at": expires_at,
                "providers": [
                    {
                        "provider_id": args.provider_id,
                        "endpoints": endpoints,
                        "last_seen": now,
                    }
                ],
            }

            await dht.put_provider_record(
                ProviderRecord(
                    object_hash=args.object_hash,
                    version=1,
                    ttl_seconds=ttl_seconds,
                    expires_at=expires_at,
                    providers=record["providers"],
                )
            )

            # minimal machine-readable output (kept for compatibility)
            print(1)
            return 0

    return trio.run(_async_put)


def _get_command(args: argparse.Namespace) -> int:
    async def _async_get() -> int:
        seeds = _parse_endpoints(args.bootstrap or [])

        listen = f"/ip4/{args.host}/tcp/{args.port}"
        async with Libp2pKadDHT(listen=listen) as dht:
            for seed in seeds:
                await dht.bootstrap(seed)

            # minimal routing settle
            await trio.sleep(1.0)

            record = await dht.get_provider_record(args.object_hash)
            if record is None:
                print("not found")
                return 1

            import json

            payload = {
                "version": record.version,
                "object_hash": record.object_hash,
                "ttl_seconds": record.ttl_seconds,
                "expires_at": record.expires_at,
                "providers": record.providers,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0

    return trio.run(_async_get)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-registry")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    node_p = subparsers.add_parser("node", help="Run a DHT node and optionally bootstrap")
    node_p.add_argument("--host", default="127.0.0.1")
    node_p.add_argument("--port", type=int, required=True)
    node_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s), must include /p2p/<peerid> (e.g. /ip4/127.0.0.1/tcp/1234/p2p/<peerid>); may repeat and/or be comma-separated",
    )
    node_p.add_argument(
        "--run-seconds",
        type=float,
        default=None,
        help="If set, run bootstrap + listen for N seconds then exit (test/smoke mode)",
    )

    put_p = subparsers.add_parser("put", help="Publish a provider record for an object hash")
    put_p.add_argument("--host", default="127.0.0.1")
    put_p.add_argument("--port", type=int, required=True)
    put_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s), must include /p2p/<peerid> (e.g. /ip4/127.0.0.1/tcp/1234/p2p/<peerid>); may repeat and/or be comma-separated",
    )
    put_p.add_argument("--object-hash", dest="object_hash", required=True)
    put_p.add_argument("--provider-id", required=True)
    put_p.add_argument("--ttl-seconds", type=int, default=172800)
    put_p.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="Provider endpoint like tcp://host:port. May repeat and/or be comma-separated.",
    )

    get_p = subparsers.add_parser("get", help="Resolve an object hash to provider endpoints")
    get_p.add_argument("--host", default="127.0.0.1")
    get_p.add_argument("--port", type=int, required=True)
    get_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s), must include /p2p/<peerid> (e.g. /ip4/127.0.0.1/tcp/1234/p2p/<peerid>); may repeat and/or be comma-separated",
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
