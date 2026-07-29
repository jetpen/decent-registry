import os
import socket
import tempfile

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


async def get_with_retries(service: RegistryService, *, object_hash: str, tries: int = 6, sleep_s: float = 0.6):
    for _ in range(tries):
        res = await service.get_provider(object_hash=object_hash)
        if res is not None:
            return True, res.provider_url, res.endpoints
        await trio.sleep(sleep_s)
    return False, None, None


async def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        owner_privkey_path = gen_owner_pem(tmpdir)

        seed1_port, node1_port, seed2_port, node2_port, bridge_port = (
            free_port(),
            free_port(),
            free_port(),
            free_port(),
            free_port(),
        )

        endpoints_sorted = sorted(
            ["/ip4/127.0.0.1/tcp/1", "/ip4/127.0.0.1/tcp/2"]
        )
        provider_url1 = "https://example.com/provider/one"
        provider_url2 = "https://example.com/provider/two"
        obj_hash1 = "a" * 64
        obj_hash2 = "b" * 64

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

            service1b = RegistryService(dht=node1b)
            service2b = RegistryService(dht=node2b)

            async with Libp2pKadDHT(listen=listen_tcp(bridge_port)) as bridge:
                await bridge.bootstrap(seed1_dest)
                await bridge.bootstrap(seed2_dest)
                await trio.sleep(2.0)

                service_bridge = RegistryService(dht=bridge)

                await service_bridge.put_provider(
                    object_hash=obj_hash1,
                    provider_url=provider_url1,
                    owner_privkey_pem_path=owner_privkey_path,
                    seq=1,
                    endpoints=endpoints_sorted,
                )
                await trio.sleep(1.0)

                r_bridge = await get_with_retries(service_bridge, object_hash=obj_hash1)
                r_node1b = await get_with_retries(service1b, object_hash=obj_hash1)
                r_node2b = await get_with_retries(service2b, object_hash=obj_hash1)

                print(
                    {
                        "during_bridge": {
                            "bridge_found": r_bridge[0],
                            "bridge_provider_url": r_bridge[1],
                            "node1b_found": r_node1b[0],
                            "node2b_found": r_node2b[0],
                        }
                    }
                )

            # bridge disconnected
            await trio.sleep(0.9)
            await service1b.put_provider(
                object_hash=obj_hash2,
                provider_url=provider_url2,
                owner_privkey_pem_path=owner_privkey_path,
                seq=2,
                endpoints=endpoints_sorted,
            )
            await trio.sleep(1.0)
            r_node2b_after = await get_with_retries(service2b, object_hash=obj_hash2)
            print({"after_disconnect": {"node2b_obj_hash2_found": r_node2b_after[0]}})


if __name__ == "__main__":
    trio.run(main)
