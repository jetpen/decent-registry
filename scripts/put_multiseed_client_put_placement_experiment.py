import os
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
    path = os.path.join(tmpdir, "owner_privkey.pem")
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)
    return path


def listen_tcp(port: int) -> str:
    return f"/ip4/127.0.0.1/tcp/{port}"


def bootstrap_dest(seed_dht: Libp2pKadDHT) -> str:
    seed_tcp = seed_dht.get_listen_multiaddr()
    peer_id = seed_dht.host.get_id().to_string()
    if "/p2p/" in seed_tcp:
        return seed_tcp
    return f"{seed_tcp}/p2p/{peer_id}"


@dataclass
class PutScenarioResult:
    node1b_found: bool
    node2b_found: bool
    node1b_first_found_after_s: float | None
    node2b_first_found_after_s: float | None


async def poll_get_until(
    service: RegistryService,
    *,
    object_hash: str,
    poll_interval_s: float,
    max_wait_s: float,
):
    deadline = trio.current_time() + max_wait_s
    first_found_after = None
    while trio.current_time() <= deadline:
        res = await service.get_provider(object_hash=object_hash)
        if res is not None:
            first_found_after = max(0.0, trio.current_time() - (deadline - max_wait_s))
            return True, first_found_after, res.provider_url, res.endpoints
        await trio.sleep(poll_interval_s)
    return False, None, None, None


async def run_scenario(
    *,
    client_dht: Libp2pKadDHT,
    seed1_dest: str,
    seed2_dest: str,
    owner_privkey_pem_path: str,
    endpoints_sorted: list[str],
    obj_hash_put: str,
    provider_url_put: str,
    node1b_service: RegistryService,
    node2b_service: RegistryService,
    bootstrap_to: list[str],
    max_wait_s: float = 18.0,
):
    # bootstrap_to entries: ["seed1", "seed2"]
    for dest in []:
        pass

    for target in bootstrap_to:
        if target == "seed1":
            await client_dht.bootstrap(seed1_dest)
        elif target == "seed2":
            await client_dht.bootstrap(seed2_dest)
        else:
            raise ValueError(f"unknown bootstrap target: {target}")

    await trio.sleep(1.0)

    t0 = trio.current_time()
    await RegistryService(dht=client_dht).put_provider(
        object_hash=obj_hash_put,
        provider_url=provider_url_put,
        owner_privkey_pem_path=owner_privkey_pem_path,
        seq=1 if obj_hash_put.startswith('a') else 2,
        endpoints=endpoints_sorted,
    )

    # Poll from both partitions for up to max_wait_s
    poll_interval_s = 0.75
    node1b_found, node1b_first_found_after, _, _ = await poll_get_until(
        node1b_service,
        object_hash=obj_hash_put,
        poll_interval_s=poll_interval_s,
        max_wait_s=max_wait_s,
    )
    node2b_found, node2b_first_found_after, _, _ = await poll_get_until(
        node2b_service,
        object_hash=obj_hash_put,
        poll_interval_s=poll_interval_s,
        max_wait_s=max_wait_s,
    )

    # Normalize first_found_after to seconds after PUT
    if node1b_first_found_after is not None:
        node1b_first_found_after = max(0.0, node1b_first_found_after)
    if node2b_first_found_after is not None:
        node2b_first_found_after = max(0.0, node2b_first_found_after)

    return PutScenarioResult(
        node1b_found=node1b_found,
        node2b_found=node2b_found,
        node1b_first_found_after_s=node1b_first_found_after,
        node2b_first_found_after_s=node2b_first_found_after,
    )


async def main():
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
            ["/ip4/127.0.0.1/tcp/1", "/ip4/127.0.0.1/tcp/2"]
        )

        obj_hash_a = "a" * 64
        obj_hash_b = "b" * 64

        provider_url_a = "https://example.com/provider/a"
        provider_url_b = "https://example.com/provider/b"

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

            # Scenario A: client connects only to seed1
            async with Libp2pKadDHT(listen=listen_tcp(client_port)) as client:
                res_a = await run_scenario(
                    client_dht=client,
                    seed1_dest=seed1_dest,
                    seed2_dest=seed2_dest,
                    owner_privkey_pem_path=owner_privkey_pem_path,
                    endpoints_sorted=endpoints_sorted,
                    obj_hash_put=obj_hash_a,
                    provider_url_put=provider_url_a,
                    node1b_service=node1b_service,
                    node2b_service=node2b_service,
                    bootstrap_to=["seed1"],
                    max_wait_s=15.0,
                )

            # Scenario B: client connects to seed1 and seed2 simultaneously
            # Use a fresh client instance to avoid cross-scenario state.
            async with Libp2pKadDHT(listen=listen_tcp(client_port + 1000)) as client2:
                res_b = await run_scenario(
                    client_dht=client2,
                    seed1_dest=seed1_dest,
                    seed2_dest=seed2_dest,
                    owner_privkey_pem_path=owner_privkey_pem_path,
                    endpoints_sorted=endpoints_sorted,
                    obj_hash_put=obj_hash_b,
                    provider_url_put=provider_url_b,
                    node1b_service=node1b_service,
                    node2b_service=node2b_service,
                    bootstrap_to=["seed1", "seed2"],
                    max_wait_s=15.0,
                )

            # Persistence probes after client2 disconnect: attempt node1b/node2b GET again.
            await trio.sleep(0.75)
            # Simple single-shot GET now; polling already indicates availability within 15s.
            after_a_node2b = await node2b_service.get_provider(object_hash=obj_hash_a)
            after_b_node2b = await node2b_service.get_provider(object_hash=obj_hash_b)

            print(
                {
                    "scenario_A_put_via_client_seed1_only": res_a.__dict__,
                    "scenario_B_put_via_client_seed1_and_seed2": res_b.__dict__,
                    "persistence_after_disconnect": {
                        "node2b_get_obj_hash_a": after_a_node2b is not None,
                        "node2b_get_obj_hash_b": after_b_node2b is not None,
                    },
                }
            )


if __name__ == "__main__":
    trio.run(main)
