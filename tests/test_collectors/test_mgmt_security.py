import base64
import struct

import pytest

from app.collectors.mgmt_security import (
    MgmtSecurityCollector, parse_show_ip_ssh, parse_nxos_ssh, parse_vstack,
    rsa_bits_from_blob,
)


def _ssh_rsa_b64(bits):
    """A structurally valid ssh-rsa public key blob with a synthetic modulus."""
    def field(data):
        return struct.pack(">I", len(data)) + data
    modulus = b"\x00" + bytes([0xC5]) + bytes(range(256)) * (bits // 8 // 256 + 1)
    modulus = modulus[:1 + bits // 8]
    return base64.b64encode(field(b"ssh-rsa") + field(b"\x01\x00\x01")
                            + field(modulus)).decode()


def _wrap(text, width=64):
    return "\n".join(text[i:i + width] for i in range(0, len(text), width))


@pytest.fixture
def collector():
    return MgmtSecurityCollector()


def _ios_ssh(version, bits, wrapped=False):
    key = _ssh_rsa_b64(bits)
    if wrapped:
        key = _wrap(key)
    return (f"SSH Enabled - version {version}\n"
            "Authentication methods:publickey,keyboard-interactive,password\n"
            "Authentication timeout: 120 secs; Authentication retries: 3\n"
            "Minimum expected Diffie Hellman key size : 2048 bits\n"
            "IOS Keys in SECSH format(ssh-rsa, base64 encoded): lab-sw-01.example.net\n"
            f"ssh-rsa {key}\n")


def test_commands(collector):
    assert collector.get_commands("cisco_ios") == ["show ip ssh", "show vstack config"]
    assert collector.get_commands("cisco_nxos") == ["show ssh server", "show ssh key"]
    assert collector.get_commands("cisco_wlc") == []
    assert collector.switching_commands == {"show vstack config"}


@pytest.mark.parametrize("bits", [1024, 2048, 4096])
def test_rsa_bits_from_blob(bits):
    assert rsa_bits_from_blob(_ssh_rsa_b64(bits)) == bits


def test_rsa_bits_rejects_garbage():
    assert rsa_bits_from_blob("not base64 at all") is None
    assert rsa_bits_from_blob(base64.b64encode(b"\x00\x00\x00\x07ssh-dss").decode()) is None


def test_ssh_v2_2048():
    ssh = parse_show_ip_ssh(_ios_ssh("2.0", 2048))
    assert ssh == {"enabled": True, "version": "2.0", "v1_enabled": False,
                   "key_bits": 2048, "min_dh_bits": 2048}


def test_ssh_199_with_wrapped_1024_key():
    ssh = parse_show_ip_ssh(_ios_ssh("1.99", 1024, wrapped=True))
    assert ssh["v1_enabled"] is True
    assert ssh["key_bits"] == 1024


def test_ssh_modulus_line_wins():
    ssh = parse_show_ip_ssh("SSH Enabled - version 2.0\nModulus Size : 3072 bits\n")
    assert ssh["key_bits"] == 3072


def test_ssh_without_keys():
    ssh = parse_show_ip_ssh("%Please create RSA keys to enable SSH (and of atleast 768 bits for SSH v2).\n")
    assert ssh["enabled"] is False


def test_nxos_ssh():
    server = "ssh version 2 is enabled\nssh port 22\n"
    key = ("**************************************\n"
           "rsa Keys generated:Mon Jan  1 00:00:00 2024\n\n"
           f"ssh-rsa {_ssh_rsa_b64(1024)}\n\n"
           "bitcount:1024\nfingerprint:\nSHA256:AAAAexample\n"
           "**************************************\n"
           "could not retrieve dsa key information\n")
    ssh = parse_nxos_ssh(server, key)
    assert ssh["enabled"] is True
    assert ssh["version"] == "2"
    assert ssh["key_bits"] == 1024


def test_vstack_old_format_enabled():
    out = " Role: Client (SmartInstall enabled)\n Vstack Director IP address: 0.0.0.0\n"
    assert parse_vstack(out) == {"smart_install_enabled": True, "role": "Client"}


def test_vstack_old_format_disabled():
    out = " Role: Client (SmartInstall disabled)\n Vstack Director IP address: 0.0.0.0\n"
    assert parse_vstack(out)["smart_install_enabled"] is False


def test_vstack_new_format():
    out = ("Capability: Client\nOper Mode: Enabled\nRole: Client\n"
           "Vstack Director IP address: 0.0.0.0\n")
    assert parse_vstack(out)["smart_install_enabled"] is True
    out = out.replace("Oper Mode: Enabled", "Oper Mode: Disabled")
    assert parse_vstack(out)["smart_install_enabled"] is False


def test_vstack_rejected_is_not_a_failure(collector):
    invalid = "                ^\n% Invalid input detected at '^' marker."
    parsed = collector.parse_collected({"show ip ssh": _ios_ssh("2.0", 2048),
                                        "show vstack config": invalid}, "cisco_xe")
    assert parsed["ssh"]["key_bits"] == 2048
    assert parsed["smart_install"]["smart_install_enabled"] is None
    assert parsed["command_error_kinds"] == {"show vstack config": "not_applicable"}
