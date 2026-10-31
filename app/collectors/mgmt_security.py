"""
Management-plane security collector: SSH version and host key size, and
Smart Install (vstack) exposure.

The RSA key size is read from the public key itself: show ip ssh prints the
host key in SECSH (ssh-rsa base64) form on every IOS release, while the
"modulus size" line only exists on some. Only the public key is ever
parsed; nothing secret is in these outputs.
"""
import base64
import re
import struct

from .base import BaseCollector

_SHOW_IP_SSH = "show ip ssh"
_VSTACK = "show vstack config"
_NXOS_SSH_SERVER = "show ssh server"
_NXOS_SSH_KEY = "show ssh key"

_COMMANDS = {
    "cisco_ios": [_SHOW_IP_SSH, _VSTACK],
    "cisco_xe": [_SHOW_IP_SSH, _VSTACK],
    "cisco_nxos": [_NXOS_SSH_SERVER, _NXOS_SSH_KEY],
}

_B64_LINE = re.compile(r"^[A-Za-z0-9+/]+=*$")


def _ssh_rsa_blob(text):
    """Base64 of the first ssh-rsa key in text; older IOS wraps it over lines."""
    m = re.search(r"(?:^|\s)ssh-rsa\s+(AAAA\S+)", text)
    if not m:
        return ""
    parts = [m.group(1)]
    for line in text[m.end():].splitlines()[1:]:
        line = line.strip()
        if not line or not _B64_LINE.match(line) or parts[-1].endswith("="):
            break
        parts.append(line)
    return "".join(parts)


def rsa_bits_from_blob(b64):
    """Modulus length in bits of an ssh-rsa public key blob, or None."""
    try:
        data = base64.b64decode("".join(b64.split()), validate=False)
        fields = []
        pos = 0
        for _ in range(3):
            (length,) = struct.unpack(">I", data[pos:pos + 4])
            pos += 4
            fields.append(data[pos:pos + length])
            pos += length
        if fields[0] != b"ssh-rsa":
            return None
        modulus = fields[2].lstrip(b"\x00")
        if not modulus:
            return None
        return (len(modulus) - 1) * 8 + modulus[0].bit_length()
    except (struct.error, ValueError, IndexError):
        return None


def parse_show_ip_ssh(text):
    result = {"enabled": None, "version": "", "v1_enabled": False,
              "key_bits": None, "min_dh_bits": None}
    if not text or not text.strip():
        return result
    m = re.search(r"SSH\s+(Enabled|Disabled)\s*-\s*version\s+([\d.]+)", text, re.I)
    if m:
        result["enabled"] = m.group(1).lower() == "enabled"
        result["version"] = m.group(2)
        # 1.99 is the IOS way of saying "v1 and v2 both accepted".
        result["v1_enabled"] = m.group(2) in ("1.5", "1.99")
    elif re.search(r"create RSA keys", text, re.I):
        result["enabled"] = False
    m = re.search(r"Modulus Size\s*:\s*(\d+)\s*bits", text, re.I)
    if m:
        result["key_bits"] = int(m.group(1))
    else:
        blob = _ssh_rsa_blob(text)
        if blob:
            result["key_bits"] = rsa_bits_from_blob(blob)
    m = re.search(r"Diffie Hellman key size\s*:\s*(\d+)", text, re.I)
    if m:
        result["min_dh_bits"] = int(m.group(1))
    return result


def parse_nxos_ssh(server_text, key_text):
    result = {"enabled": None, "version": "", "v1_enabled": False,
              "key_bits": None, "min_dh_bits": None}
    if server_text and server_text.strip():
        m = re.search(r"ssh version\s+(\d)\s+is\s+(enabled|disabled)", server_text, re.I)
        if m:
            result["version"] = m.group(1)
            result["enabled"] = m.group(2).lower() == "enabled"
            result["v1_enabled"] = m.group(1) == "1" and result["enabled"]
    if key_text and key_text.strip():
        m = re.search(r"rsa Keys generated.*?bitcount\s*:\s*(\d+)", key_text, re.I | re.S)
        if m:
            result["key_bits"] = int(m.group(1))
    return result


def parse_vstack(text):
    """Smart Install state: True enabled, False disabled, None unknown."""
    result = {"smart_install_enabled": None, "role": ""}
    if not text or not text.strip():
        return result
    m = re.search(r"Role\s*:\s*(\w+)(?:\s*\(SmartInstall\s+(enabled|disabled)\))?", text, re.I)
    if m:
        result["role"] = m.group(1)
        if m.group(2):
            result["smart_install_enabled"] = m.group(2).lower() == "enabled"
    m = re.search(r"Oper Mode\s*:\s*(Enabled|Disabled)", text, re.I)
    if m:
        result["smart_install_enabled"] = m.group(1).lower() == "enabled"
    return result


class MgmtSecurityCollector(BaseCollector):
    name = "mgmt_security"
    label = "SSH & Smart Install"
    description = "Collect SSH version, host key size and Smart Install state"
    enabled_by_default = True
    # Smart Install is a switch feature; routers would only reject it.
    switching_commands = frozenset({_VSTACK})

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, []))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"mgmt_security: no commands for {device_type}"}
        if device_type == "cisco_nxos":
            ssh = parse_nxos_ssh(raw_outputs.get(_NXOS_SSH_SERVER, ""),
                                 raw_outputs.get(_NXOS_SSH_KEY, ""))
        else:
            ssh = parse_show_ip_ssh(raw_outputs.get(_SHOW_IP_SSH, ""))
        return {"ssh": ssh, "smart_install": parse_vstack(raw_outputs.get(_VSTACK, ""))}
