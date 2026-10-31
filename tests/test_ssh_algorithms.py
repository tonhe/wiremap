"""Legacy SSH algorithm availability.

Forty devices in one field run failed with "no acceptable kex algorithm" --
Catalyst 2950/2960L/3750X and Nexus 5548 offering only SHA-1 key exchange,
ssh-rsa host keys and CBC ciphers. paramiko 4.0 removed those implementations
outright rather than deprioritising them, so no runtime setting restores them
and the only fix is the version pin.

paramiko is a transitive dependency of netmiko and was unpinned, so a rebuild
could change which devices are reachable without anything in the repo
changing. These tests make that regression loud.
"""
import pytest
from paramiko.transport import Transport

REQUIRED_KEX = [
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
]

REQUIRED_CIPHERS = ["aes128-cbc", "3des-cbc"]


@pytest.mark.parametrize("algorithm", REQUIRED_KEX)
def test_legacy_kex_is_offered(algorithm):
    assert algorithm in Transport._preferred_kex, (
        f"{algorithm} is not offered. Legacy Cisco cannot negotiate SSH "
        f"without it. Check the paramiko pin in requirements.txt."
    )


def test_legacy_host_key_is_offered():
    assert "ssh-rsa" in Transport._preferred_keys, (
        "ssh-rsa host keys not offered; devices predating rsa-sha2 will fail "
        "negotiation. Check the paramiko pin."
    )


@pytest.mark.parametrize("cipher", REQUIRED_CIPHERS)
def test_legacy_ciphers_are_offered(cipher):
    assert cipher in Transport._preferred_ciphers, (
        f"{cipher} not offered; devices without CTR support will fail.")


def test_modern_algorithms_still_preferred_first():
    """The pin must not weaken current gear -- modern exchanges have to win
    where the device offers them."""
    kex = list(Transport._preferred_kex)
    first_sha1 = min(kex.index(a) for a in REQUIRED_KEX if a in kex)
    modern = ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
              "diffie-hellman-group16-sha512"]
    for algorithm in modern:
        assert algorithm in kex, f"{algorithm} missing entirely"
        assert kex.index(algorithm) < first_sha1, (
            f"{algorithm} must be preferred over SHA-1 exchanges")


def test_paramiko_major_version_supports_legacy():
    import paramiko
    major = int(paramiko.__version__.split(".")[0])
    assert major == 3, (
        f"paramiko {paramiko.__version__}: 4.0 removed SHA-1 kex and ssh-rsa, "
        f"which strands legacy Cisco. Pin to 3.x in requirements.txt."
    )
