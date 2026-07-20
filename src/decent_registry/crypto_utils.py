from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from libp2p.crypto.ed25519 import create_new_key_pair


def load_ed25519_keypair_from_privkey_pem_path(
    privkey_pem_path: str,
) -> tuple[Any, bytes]:
    """Return (owner_priv, owner_pub_bytes) for the libp2p keypair.

    Hardened against leaking key material in logs/errors.
    """

    pem_data: bytes | None = None
    private_key: Any | None = None
    priv_raw: bytes | None = None

    class _OwnerPrivkeyFileReadError(ValueError):
        pass

    try:
        try:
            with open(privkey_pem_path, "rb") as f:
                pem_data = f.read()
        except OSError:
            # Normalize message so we never leak internal filesystem details.
            raise _OwnerPrivkeyFileReadError(
                "cannot read owner private key file"
            ) from None

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
        owner_pub_bytes = owner_priv.get_public_key().to_bytes()
        return owner_priv, owner_pub_bytes
    except _OwnerPrivkeyFileReadError:
        raise ValueError("cannot read owner private key file") from None
    except Exception:
        # Normalize message so we never leak internal parsing details.
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
