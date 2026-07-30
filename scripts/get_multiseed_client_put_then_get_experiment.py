import json
import socket
import tempfile
import inspect
from dataclasses import dataclass

import trio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.registry_service import RegistryService


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def gen_owner_pem(tmpdir: str) -> str:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    path = f"{tmpdir}/owner_privkey.pem"
    with open(path, "wb") as f:
        f.write(pem)
    return path


def listen_tcp(port: int) -> str:
    return f"/ip4/127.0.0.1/tcp/{port}"


def bootstrap_dest(seed_dht: Libp2pKadDHT) -> str:
    # host.connect expects an identify-style destination containing /p2p/<peerid>.
    seed_tcp = seed_dht.get_listen_multiaddr()
    peer_id = seed_dht.host.get_id().to_string()
    if "/p2p/" in seed_tcp:
        return seed_tcp
    return f"{seed_tcp}/p2p/{peer_id}"


@dataclass
class PollResult:
    found: bool
    first_found_after_s: float | None


async def poll_get(
    service: RegistryService,
    *,
    object_hash: str,
    poll_interval_s: float,
    max_wait_s: float,
    quorum: int = 0,
) -> PollResult:
    t0 = trio.current_time()
    while trio.current_time() - t0 <= max_wait_s:
        res = await service.get_provider(object_hash=object_hash, quorum=quorum)
        if res is not None:
            return PollResult(
                found=True,
                first_found_after_s=trio.current_time() - t0,
            )
        await trio.sleep(poll_interval_s)
    return PollResult(found=False, first_found_after_s=None)


async def disconnect_peer_best_effort(host, peer_id) -> None:
    try:
        maybe = host.disconnect(peer_id)
        if inspect.isawaitable(maybe):
            await maybe
    except Exception:
        pass


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        owner_privkey_pem_path = gen_owner_pem(tmpdir)

        seed1_port, node1_port, seed2_port, node2_port, client_port = (
            free_port(),
            free_port(),
            free_port(),
            free_port(),
            free_port(),
        )

        endpoints_sorted = sorted(
            [
                "/ip4/127.0.0.1/tcp/1",
                "/ip4/127.0.0.1/tcp/2",
            ]
        )

        # Must be valid 64-hex (bytes.fromhex is used by the adapter).
        obj_hash_put = "b" * 64

        provider_url_put = "https://example.com/provider/put-then-get"

        async with (
            Libp2pKadDHT(listen=listen_tcp(seed1_port)) as seed1a,
            Libp2pKadDHT(listen=listen_tcp(node1_port)) as node1b,
            Libp2pKadDHT(listen=listen_tcp(seed2_port)) as seed2a,
            Libp2pKadDHT(listen=listen_tcp(node2_port)) as node2b,
        ):
            seed1_dest = bootstrap_dest(seed1a)
            seed2_dest = bootstrap_dest(seed2a)

            # Network1 bootstraps
            await node1b.bootstrap(seed1_dest)
            # Network2 bootstraps
            await node2b.bootstrap(seed2_dest)

            await trio.sleep(1.5)

            node1b_service = RegistryService(dht=node1b)
            node2b_service = RegistryService(dht=node2b)

            # Client bootstraps to one seed in each network.
            async with Libp2pKadDHT(listen=listen_tcp(client_port)) as client:
                client_service = RegistryService(dht=client)

                await client.bootstrap(seed1_dest)
                await client.bootstrap(seed2_dest)
                await trio.sleep(2.0)

                # PUT the record while connected to both seeds.
                await client_service.put_provider(
                    object_hash=obj_hash_put,
                    provider_url=provider_url_put,
                    owner_privkey_pem_path=owner_privkey_pem_path,
                    seq=2,
                    endpoints=endpoints_sorted,
                )

                # Probe where the PUT landed (sanity; should be Network2-only in this repo's observed behavior).
                node1b_after_put = await poll_get(
                    node1b_service,
                    object_hash=obj_hash_put,
                    poll_interval_s=0.6,
                    max_wait_s=10.0,
                    quorum=0,
                )
                node2b_after_put = await poll_get(
                    node2b_service,
                    object_hash=obj_hash_put,
                    poll_interval_s=0.6,
                    max_wait_s=10.0,
                    quorum=0,
                )

                # GET immediately while client is still connected to both seeds.
                client_get_while_connected = await poll_get(
                    client_service,
                    object_hash=obj_hash_put,
                    poll_interval_s=0.6,
                    max_wait_s=15.0,
                    quorum=0,
                )

                # Attempt to emulate “try Network1 seed first, then fallback to Network2 seed” by:
                # - disconnecting Network2 seed at GET time
                # - performing GET again
                seed2_peer_id = seed2a.host.get_id()
                await disconnect_peer_best_effort(client.host, seed2_peer_id)
                await trio.sleep(1.0)

                client_get_after_disconnect_seed2 = await poll_get(
                    client_service,
                    object_hash=obj_hash_put,
                    poll_interval_s=0.6,
                    max_wait_s=12.0,
                    quorum=0,
                )

                # Additionally disconnect Network1 seed and see whether GET still succeeds (routing/cache).
                seed1_peer_id = seed1a.host.get_id()
                await disconnect_peer_best_effort(client.host, seed1_peer_id)
                await trio.sleep(1.0)

                client_get_after_disconnect_both = await poll_get(
                    client_service,
                    object_hash=obj_hash_put,
                    poll_interval_s=0.6,
                    max_wait_s=8.0,
                    quorum=0,
                )

                print(
                    json.dumps(
                        {
                            "ticket_67": {
                                "sanity_put_landing": {
                                    "node1b_found": node1b_after_put.found,
                                    "node2b_found": node2b_after_put.found,
                                },
                                "client_get_while_connected_to_seed1_and_seed2": {
                                    "found": client_get_while_connected.found,
                                    "first_found_after_s": client_get_while_connected.first_found_after_s,
                                },
                                "client_get_after_disconnect_seed2": {
                                    "found": client_get_after_disconnect_seed2.found,
                                    "first_found_after_s": client_get_after_disconnect_seed2.first_found_after_s,
                                },
                                "client_get_after_disconnect_both_seeds": {
                                    "found": client_get_after_disconnect_both.found,
                                    "first_found_after_s": client_get_after_disconnect_both.first_found_after_s,
                                },
                            }
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )


if __name__ == "__main__":
    trio.run(main)
