from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from libp2p.crypto.ed25519 import create_new_key_pair


_ED25519_SEED_LENGTH = 32


class KeyGenerationError(ValueError):
    """Raised when an Ed25519 key cannot be generated safely."""


class _SystemCSRNG:
    """The sole production entropy boundary for client key generation.

    ``secrets.token_bytes`` delegates to Python's operating-system-backed
    cryptographic random source. The provider type check below is deliberate:
    key generation must fail closed if this boundary is replaced, rather than
    accepting a general-purpose PRNG or another unapproved source.
    """

    @staticmethod
    def token_bytes(length: int) -> bytes:
        return secrets.token_bytes(length)


_SYSTEM_CSRNG_PROVIDER = _SystemCSRNG()


def _is_system_csrng_provider(provider: object) -> bool:
    return (
        type(provider) is _SystemCSRNG
        and getattr(provider, "token_bytes", None) is _SystemCSRNG.token_bytes
    )


def _secure_ed25519_seed() -> bytes:
    provider = _SYSTEM_CSRNG_PROVIDER
    if not _is_system_csrng_provider(provider):
        raise KeyGenerationError("secure randomness provider is unavailable")

    try:
        seed = provider.token_bytes(_ED25519_SEED_LENGTH)
    except Exception:
        raise KeyGenerationError("secure randomness provider failed") from None

    if type(seed) is not bytes or len(seed) != _ED25519_SEED_LENGTH:
        raise KeyGenerationError("secure randomness provider returned invalid entropy")
    return seed


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    """Generate an Ed25519 key using only the OS-backed CSRNG boundary."""

    try:
        return Ed25519PrivateKey.from_private_bytes(_secure_ed25519_seed())
    except KeyGenerationError:
        raise
    except Exception:
        raise KeyGenerationError("secure key generation failed") from None


def write_ed25519_private_key_pem(output_path: str | os.PathLike[str]) -> None:
    """Create a restrictive, unencrypted PKCS#8 PEM key without overwriting.

    Entropy is acquired and the PEM is serialized before the output path is
    opened. Therefore CSRNG failures cannot create or modify the destination.
    The exclusive file creation and cleanup preserve the no-partial-output
    guarantee for later filesystem failures as well.
    """

    path = Path(output_path)
    try:
        private_key = generate_ed25519_private_key()
        pem_bytes = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    except KeyGenerationError:
        raise
    except Exception:
        raise KeyGenerationError("key serialization failed") from None

    temporary_path: str | None = None
    file_descriptor: int | None = None
    try:
        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        os.chmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "wb") as output:
            file_descriptor = None
            output.write(pem_bytes)
            output.flush()
            os.fsync(output.fileno())
        # Linking a complete temporary file is atomic and fails if the
        # destination exists, so an existing key can never be replaced.
        os.link(temporary_path, path)
        os.unlink(temporary_path)
        temporary_path = None
    except OSError:
        if path.exists():
            raise KeyGenerationError("key file already exists") from None
        raise KeyGenerationError("cannot write key file") from None
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


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
