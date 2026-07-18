import argparse
import logging
import signal
import sys
import threading
import time

from decent_registry.dht.dht import DHTClient
from decent_registry.dht.protocol import DHTNode

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
    node = DHTNode(args.host, args.port, k=args.k)
    node.start()

    logger.info("Node %s listening on tcp://%s:%d", node.node_id, args.host, args.port)

    client = DHTClient(node, alpha=args.alpha)
    endpoints = _parse_endpoints(args.bootstrap or [])

    ok = True
    if endpoints:
        ok = client.bootstrap(endpoints)
        if ok:
            logger.info("Bootstrap succeeded (seed count=%d)", len(endpoints))
        else:
            logger.warning("Bootstrap failed (seed count=%d)", len(endpoints))

    if args.run_seconds is not None:
        # bounded run for smoke testing
        time.sleep(args.run_seconds)
        node.stop()
        return 0 if ok else 1

    stop_event = threading.Event()

    def _stop_handler(signum, frame):
        node.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, _stop_handler)
    signal.signal(signal.SIGTERM, _stop_handler)

    try:
        stop_event.wait()
    finally:
        node.stop()

    return 0 if ok else 1


def _put_command(args: argparse.Namespace) -> int:
    node = DHTNode(args.host, args.port, k=args.k)
    node.start()
    try:
        client = DHTClient(node, alpha=args.alpha)
        endpoints = _parse_endpoints(args.endpoint or [])
        seeds = _parse_endpoints(args.bootstrap or [])

        if seeds:
            ok = client.bootstrap(seeds)
            if not ok:
                return 1

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

        stored = client.store_value(args.object_hash, record)
        if stored <= 0:
            return 1

        # minimal machine-readable output
        print(stored)
        return 0
    finally:
        node.stop()


def _get_command(args: argparse.Namespace) -> int:
    node = DHTNode(args.host, args.port, k=args.k)
    node.start()
    try:
        client = DHTClient(node, alpha=args.alpha)
        seeds = _parse_endpoints(args.bootstrap or [])
        if seeds:
            ok = client.bootstrap(seeds)
            if not ok:
                return 1

        found_record, closer_nodes = client.iterative_find_value(args.object_hash)
        if found_record is None:
            print("not found")
            return 1

        import json

        print(json.dumps(found_record, indent=2, sort_keys=True))
        return 0
    finally:
        node.stop()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-registry")
    parser.add_argument("-v", "--verbose", action="count", default=0)

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    node_p = subparsers.add_parser("node", help="Run a DHT node and optionally bootstrap")
    node_p.add_argument("--host", default="127.0.0.1")
    node_p.add_argument("--port", type=int, required=True)
    node_p.add_argument("--k", type=int, default=20)
    node_p.add_argument("--alpha", type=int, default=3)
    node_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="TCP seed endpoint(s) like tcp://127.0.0.1:9000; may repeat and/or be comma-separated",
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
    put_p.add_argument("--k", type=int, default=20)
    put_p.add_argument("--alpha", type=int, default=3)
    put_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="TCP seed endpoint(s) like tcp://127.0.0.1:9000; may repeat and/or be comma-separated",
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
    get_p.add_argument("--k", type=int, default=20)
    get_p.add_argument("--alpha", type=int, default=3)
    get_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="TCP seed endpoint(s) like tcp://127.0.0.1:9000; may repeat and/or be comma-separated",
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
