import json
import socket
import tempfile
from dataclasses import dataclass

import trio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

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
class GetProbe:
    found: bool
    first_found_after_s: float | None


async def poll_get(
    service: RegistryService,
    *,
    object_hash: str,
    poll_interval_s: float,
    max_wait_s: float,
    quorum: int = 0,
) -> GetProbe:
    t0 = trio.current_time()
    while trio.current_time() - t0 <= max_wait_s:
        res = await service.get_provider(object_hash=object_hash, quorum=quorum)
        if res is not None:
            return GetProbe(
                found=True,
                first_found_after_s=trio.current_time() - t0,
            )
        await trio.sleep(poll_interval_s)
    return GetProbe(found=False, first_found_after_s=None)


async def main() -> None:
    # Two isolated-ish overlays:
    # - Network1: seed1a + node1b
    # - Network2: seed2a + node2b
    #
    # Ticket #67 question: does default client-side GET try alternate seeds,
    # i.e. recover from a miss by querying a different network overlay?
    #
    # Experiment design (non-transport partition):
    # 1) Put record into Network2 via node2b (not via client).
    # 2) Scenario A: client bootstraps to Network1 only; GET record.
    # 3) Scenario B: client bootstraps to both Network1 and Network2; GET record.
    # 4) Scenario C: client bootstraps to Network1 only; GET record fails; then
    #    client bootstraps to Network2 and retries GET in same session.
    with tempfile.TemporaryDirectory() as tmpdir:
        owner_privkey_pem_path = gen_owner_pem(tmpdir)

        seed1_port, node1_port, seed2_port, node2_port = (
            free_port(),
            free_port(),
            free_port(),
            free_port(),
        )
        client_port_a, client_port_b, client_port_c = (
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

        # Must be valid 64-hex (bytes.fromhex(object_hash) is used by the adapter).
        obj_hash = "b" * 64
        provider_url = "https://example.com/provider/get-fallback"

        async with (
            Libp2pKadDHT(listen=listen_tcp(seed1_port)) as seed1a,
            Libp2pKadDHT(listen=listen_tcp(node1_port)) as node1b,
            Libp2pKadDHT(listen=listen_tcp(seed2_port)) as seed2a,
            Libp2pKadDHT(listen=listen_tcp(node2_port)) as node2b,
        ):
            seed1_dest = bootstrap_dest(seed1a)
            seed2_dest = bootstrap_dest(seed2a)

            await node1b.bootstrap(seed1_dest)
            await node2b.bootstrap(seed2_dest)
            await trio.sleep(1.5)

            node1b_service = RegistryService(dht=node1b)
            node2b_service = RegistryService(dht=node2b)

            # PUT into Network2 overlay.
            await node2b_service.put_provider(
                object_hash=obj_hash,
                provider_url=provider_url,
                owner_privkey_pem_path=owner_privkey_pem_path,
                seq=2,
                endpoints=endpoints_sorted,
            )
            await trio.sleep(1.0)

            sanity_node2b = await poll_get(
                node2b_service,
                object_hash=obj_hash,
                poll_interval_s=0.6,
                max_wait_s=12.0,
                quorum=0,
            )
            sanity_node1b = await poll_get(
                node1b_service,
                object_hash=obj_hash,
                poll_interval_s=0.6,
                max_wait_s=8.0,
                quorum=0,
            )

            # Scenario A: client bootstraps to Network1 only.
            async with Libp2pKadDHT(listen=listen_tcp(client_port_a)) as client_a:
                client_a_service = RegistryService(dht=client_a)
                await client_a.bootstrap(seed1_dest)
                await trio.sleep(2.0)
                a_get = await poll_get(
                    client_a_service,
                    object_hash=obj_hash,
                    poll_interval_s=0.75,
                    max_wait_s=15.0,
                    quorum=0,
                )

            # Scenario B: client bootstraps to both seeds.
            async with Libp2pKadDHT(listen=listen_tcp(client_port_b)) as client_b:
                client_b_service = RegistryService(dht=client_b)
                await client_b.bootstrap(seed1_dest)
                await client_b.bootstrap(seed2_dest)
                await trio.sleep(2.0)
                b_get = await poll_get(
                    client_b_service,
                    object_hash=obj_hash,
                    poll_interval_s=0.75,
                    max_wait_s=15.0,
                    quorum=0,
                )

            # Scenario C: client bootstraps to Network1 only; GET fails; then bootstrap Network2 and retry.
            async with Libp2pKadDHT(listen=listen_tcp(client_port_c)) as client_c:
                client_c_service = RegistryService(dht=client_c)
                await client_c.bootstrap(seed1_dest)
                await trio.sleep(2.0)
                c_get_first = await poll_get(
                    client_c_service,
                    object_hash=obj_hash,
                    poll_interval_s=0.75,
                    max_wait_s=10.0,
                    quorum=0,
                )

                await client_c.bootstrap(seed2_dest)
                await trio.sleep(2.0)
                c_get_second = await poll_get(
                    client_c_service,
                    object_hash=obj_hash,
                    poll_interval_s=0.75,
                    max_wait_s=15.0,
                    quorum=0,
                )

            print(
                json.dumps(
                    {
                        "ticket_67": {
                            "sanity": {
                                "node2b_get": sanity_node2b.__dict__,
                                "node1b_get": sanity_node1b.__dict__,
                            },
                            "scenario_A_client_bootstrap_seed1_only_get": a_get.__dict__,
                            "scenario_B_client_bootstrap_seed1_and_seed2_get": b_get.__dict__,
                            "scenario_C_client_seed1_only_get_then_bootstrap_seed2_and_retry": {
                                "first_get_after_seed1": c_get_first.__dict__,
                                "second_get_after_bootstrap_seed2": c_get_second.__dict__,
                            },
                        }
                    },
                    indent=2,
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    trio.run(main)
