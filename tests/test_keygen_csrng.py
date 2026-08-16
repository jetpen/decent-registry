from __future__ import annotations

from argparse import Namespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

import decent_registry.cli as cli
import decent_registry.crypto_utils as crypto_utils


class _NonSecurePRNG:
    @staticmethod
    def token_bytes(_length: int) -> bytes:
        return b"p" * 32


class _UnavailableCSRNG:
    @staticmethod
    def token_bytes(_length: int) -> bytes:
        raise OSError("entropy device unavailable")


class _MalformedCSRNG:
    value = b"short"

    @staticmethod
    def token_bytes(_length: int) -> bytes:
        return _MalformedCSRNG.value


def _keygen_args(path) -> Namespace:
    return Namespace(output=str(path))


def test_generate_ed25519_private_key_uses_real_csrng_boundary():
    private_key = crypto_utils.generate_ed25519_private_key()

    assert isinstance(private_key, Ed25519PrivateKey)
    assert len(
        private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
    ) == 32


def test_csrng_acquisition_failure_is_fatal(monkeypatch, tmp_path):
    monkeypatch.setattr(crypto_utils, "_SYSTEM_CSRNG_PROVIDER", _UnavailableCSRNG())
    output = tmp_path / "owner.pem"

    with pytest.raises(crypto_utils.KeyGenerationError, match="secure randomness"):
        crypto_utils.write_ed25519_private_key_pem(output)

    assert not output.exists()


def test_nonsecure_provider_replacement_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(crypto_utils, "_SYSTEM_CSRNG_PROVIDER", _NonSecurePRNG())
    output = tmp_path / "owner.pem"

    with pytest.raises(crypto_utils.KeyGenerationError, match="secure randomness"):
        crypto_utils.write_ed25519_private_key_pem(output)

    assert not output.exists()


@pytest.mark.parametrize("entropy", [b"short", b"e" * 33])
def test_malformed_csrng_entropy_is_fatal(monkeypatch, tmp_path, entropy):
    _MalformedCSRNG.value = entropy
    monkeypatch.setattr(crypto_utils, "_SYSTEM_CSRNG_PROVIDER", _MalformedCSRNG())
    output = tmp_path / "owner.pem"

    with pytest.raises(crypto_utils.KeyGenerationError, match="secure randomness"):
        crypto_utils.write_ed25519_private_key_pem(output)

    assert not output.exists()


def test_csrng_failure_does_not_modify_existing_output(monkeypatch, tmp_path):
    output = tmp_path / "owner.pem"
    original = b"existing key file"
    output.write_bytes(original)
    monkeypatch.setattr(crypto_utils, "_SYSTEM_CSRNG_PROVIDER", _UnavailableCSRNG())

    with pytest.raises(crypto_utils.KeyGenerationError):
        crypto_utils.write_ed25519_private_key_pem(output)

    assert output.read_bytes() == original


def test_cli_delegates_to_api_and_reports_csrng_failure_without_secrets(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(crypto_utils, "_SYSTEM_CSRNG_PROVIDER", _UnavailableCSRNG())
    output = tmp_path / "owner.pem"

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["keygen", "--output", str(output)])
    captured = capsys.readouterr()

    assert exc_info.value.code == 1
    assert "key generation failed" in captured.err
    assert "entropy device unavailable" not in captured.err
    assert "BEGIN" not in captured.out + captured.err
    assert not output.exists()


def test_api_output_is_valid_restricted_and_no_overwrite(tmp_path):
    output = tmp_path / "owner.pem"
    crypto_utils.write_ed25519_private_key_pem(output)

    assert output.stat().st_mode & 0o777 == 0o600
    loaded = load_pem_private_key(output.read_bytes(), password=None)
    assert isinstance(loaded, Ed25519PrivateKey)

    original = output.read_bytes()
    with pytest.raises(crypto_utils.KeyGenerationError, match="key file"):
        crypto_utils.write_ed25519_private_key_pem(output)
    assert output.read_bytes() == original


def test_filesystem_failure_does_not_leave_partial_output(monkeypatch, tmp_path):
    output = tmp_path / "owner.pem"

    def fail_link(source, destination):
        raise OSError("simulated link failure")

    monkeypatch.setattr(crypto_utils.os, "link", fail_link)

    with pytest.raises(crypto_utils.KeyGenerationError, match="cannot write"):
        crypto_utils.write_ed25519_private_key_pem(output)

    assert not output.exists()
    assert not list(tmp_path.glob(".owner.pem.*"))


def test_cli_success_writes_restricted_valid_pem(tmp_path, capsys):
    output = tmp_path / "owner.pem"
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["keygen", "--output", str(output)])
    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "wrote" in captured.out
    assert "BEGIN" not in captured.out + captured.err
    assert output.stat().st_mode & 0o777 == 0o600
    assert isinstance(
        load_pem_private_key(output.read_bytes(), password=None), Ed25519PrivateKey
    )


def test_no_general_purpose_random_module_is_used():
    source = open(crypto_utils.__file__, encoding="utf-8").read()
    assert "import random" not in source
    assert "random.Random" not in source


# The production boundary accepts only the exact internal provider type. Tests
# may replace it explicitly, but production has no injectable PRNG fallback.
assert crypto_utils._is_system_csrng_provider(crypto_utils._SYSTEM_CSRNG_PROVIDER)
assert not crypto_utils._is_system_csrng_provider(_NonSecurePRNG())
