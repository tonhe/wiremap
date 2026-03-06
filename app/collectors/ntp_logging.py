"""
NTP, Logging & SNMP collector.
Gathers NTP sync status/peers, logging config, and SNMP settings.
SECURITY: SNMP community strings are NEVER stored — only boolean flags.
"""
import re

from .base import BaseCollector

_COMMANDS = {
    "cisco_ios": [
        "show ntp status",
        "show ntp associations",
        "show logging",
        "show snmp",
        "show aaa sessions",
        "show running-config | section aaa",
    ],
    "cisco_xe": [
        "show ntp status",
        "show ntp associations",
        "show logging",
        "show snmp",
        "show aaa sessions",
        "show running-config | section aaa",
    ],
    "cisco_nxos": [
        "show ntp status",
        "show ntp peer-status",
        "show logging",
        "show snmp",
        "show aaa sessions",
        "show running-config | section aaa",
    ],
}
_DEFAULT_COMMANDS = [
    "show ntp status",
    "show ntp associations",
    "show logging",
    "show snmp",
    "show aaa sessions",
    "show running-config | section aaa",
]


def _parse_ntp_status(output: str) -> dict:
    """Parse ``show ntp status`` output."""
    if not output.strip():
        return {"synchronized": False, "stratum": "", "reference": ""}

    synchronized = bool(
        re.search(r"Clock is synchronized", output, re.IGNORECASE)
    )
    stratum_match = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    stratum = int(stratum_match.group(1)) if stratum_match else ""

    ref_match = re.search(
        r"reference is\s+(\S+)", output, re.IGNORECASE
    )
    reference = ref_match.group(1) if ref_match else ""

    return {
        "synchronized": synchronized,
        "stratum": stratum,
        "reference": reference,
    }


def _parse_ntp_peers(output: str) -> list[dict]:
    """Parse ``show ntp associations`` or ``show ntp peer-status``."""
    peers = []
    if not output.strip():
        return peers

    for line in output.splitlines():
        # Match lines starting with optional status chars (*, +, -, ~, #, space)
        # Real output may have combos like "*~" before the address.
        m = re.match(
            r"^([*+\-~# ]{0,3}?)"      # status chars (0-3)
            r"(\d+\.\d+\.\d+\.\d+|\S+\.\S+)\s+"  # remote (IP or hostname)
            r"(\S+)\s+"                  # ref clock
            r"(\d+)\s+"                  # stratum
            r"(\S+)\s+"                  # when
            r"\S+\s+"                    # poll
            r"(\S+)",                    # reach
            line,
        )
        if m:
            status_char = m.group(1).strip()
            peers.append({
                "remote": m.group(2),
                "stratum": m.group(4),
                "when": m.group(5),
                "reach": m.group(6),
                "status": status_char,
            })

    return peers


def _parse_logging(output: str) -> dict:
    """Parse ``show logging`` output."""
    if not output.strip():
        return {
            "logging_on": False,
            "buffer_size": "",
            "hosts": [],
            "trap_level": "",
        }

    logging_on = bool(
        re.search(r"Logging\s+(is\s+)?on", output, re.IGNORECASE)
    )

    buf_match = re.search(
        r"Buffer logging.*?(\d+[\s\S]*?bytes?)", output, re.IGNORECASE
    )
    if not buf_match:
        buf_match = re.search(r"Log Buffer.*?:\s*(\d+)", output, re.IGNORECASE)
    buffer_size = buf_match.group(1).strip() if buf_match else ""

    hosts = re.findall(
        r"Logging to (\S+)",
        output,
        re.IGNORECASE,
    )
    # Also catch "Trap logging: level <x>, <n> message lines logged"
    trap_match = re.search(
        r"Trap logging:\s+level\s+(\w+)", output, re.IGNORECASE
    )
    trap_level = trap_match.group(1) if trap_match else ""

    return {
        "logging_on": logging_on,
        "buffer_size": buffer_size,
        "hosts": hosts,
        "trap_level": trap_level,
    }


def _parse_snmp(output: str) -> dict:
    """Parse ``show snmp`` output.

    SECURITY: Community strings are NEVER stored. We only record boolean
    flags and non-sensitive metadata (contact, location).
    """
    if not output.strip():
        return {
            "communities_detected": False,
            "v3_configured": False,
            "contact": "",
            "location": "",
        }

    communities_detected = bool(
        re.search(r"community", output, re.IGNORECASE)
    )
    v3_configured = bool(
        re.search(r"snmpv3|v3\s+group|engineID", output, re.IGNORECASE)
    )

    contact_match = re.search(
        r"contact:\s*(.+)", output, re.IGNORECASE
    )
    contact = contact_match.group(1).strip() if contact_match else ""

    location_match = re.search(
        r"location:\s*(.+)", output, re.IGNORECASE
    )
    location = location_match.group(1).strip() if location_match else ""

    return {
        "communities_detected": communities_detected,
        "v3_configured": v3_configured,
        "contact": contact,
        "location": location,
    }


def _parse_aaa(sessions_output: str, config_output: str) -> dict:
    """Parse AAA session and config data.

    SECURITY: Secrets/keys from AAA config are NOT stored.
    Only boolean flags and structural metadata are kept.
    """
    result = {
        "aaa_configured": False,
        "authentication_methods": [],
        "authorization_configured": False,
        "accounting_configured": False,
        "tacacs_configured": False,
        "radius_configured": False,
        "active_sessions": 0,
    }

    # Parse session count
    if sessions_output and sessions_output.strip():
        session_count = 0
        for line in sessions_output.splitlines():
            # Count data lines (skip headers/blanks)
            stripped = line.strip()
            if stripped and not stripped.startswith("Total") and not stripped.startswith("---"):
                # Check if line looks like a session entry (starts with a number or has session data)
                if re.match(r"^\s*\d+", stripped) or re.match(r"^\S+\s+\S+\s+\S+", stripped):
                    session_count += 1
        # Also check for "Total sessions: N" line
        total_m = re.search(r"Total\s+sessions:\s*(\d+)", sessions_output, re.IGNORECASE)
        if total_m:
            session_count = int(total_m.group(1))
        result["active_sessions"] = session_count

    # Parse AAA config section
    if config_output and config_output.strip():
        result["aaa_configured"] = True

        for line in config_output.splitlines():
            stripped = line.strip()

            # "aaa authentication login default group tacacs+ local"
            auth_m = re.match(r"aaa authentication\s+(\S+)\s+(\S+)\s+(.+)", stripped)
            if auth_m:
                methods = auth_m.group(3).strip()
                # Redact any key/secret values
                methods = re.sub(r"key\s+\S+", "key <REDACTED>", methods)
                result["authentication_methods"].append({
                    "type": auth_m.group(1),
                    "list_name": auth_m.group(2),
                    "methods": methods,
                })

            if stripped.startswith("aaa authorization"):
                result["authorization_configured"] = True
            if stripped.startswith("aaa accounting"):
                result["accounting_configured"] = True
            if "tacacs" in stripped.lower():
                result["tacacs_configured"] = True
            if "radius" in stripped.lower():
                result["radius_configured"] = True

    return result


class NtpLoggingCollector(BaseCollector):
    name = "ntp_logging"
    label = "NTP, Logging & SNMP"
    description = "Collect NTP sync status, logging config, SNMP settings, and AAA config"
    enabled_by_default = True
    needs_custom_collect = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        cmds = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)
        ntp_status_cmd = cmds[0]
        ntp_peers_cmd = cmds[1]
        logging_cmd = cmds[2]
        snmp_cmd = cmds[3]
        aaa_sessions_cmd = cmds[4]
        aaa_config_cmd = cmds[5]

        return {
            "ntp_status": _parse_ntp_status(
                raw_outputs.get(ntp_status_cmd, "")
            ),
            "ntp_peers": _parse_ntp_peers(
                raw_outputs.get(ntp_peers_cmd, "")
            ),
            "logging": _parse_logging(
                raw_outputs.get(logging_cmd, "")
            ),
            "snmp": _parse_snmp(
                raw_outputs.get(snmp_cmd, "")
            ),
            "aaa": _parse_aaa(
                raw_outputs.get(aaa_sessions_cmd, ""),
                raw_outputs.get(aaa_config_cmd, ""),
            ),
        }

    def collect(self, connection, device_type: str) -> dict:
        """Override collect to redact SNMP and AAA config raw output."""
        cmds = self.get_commands(device_type)
        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd)
            except Exception:
                raw_outputs[cmd] = ""

        parsed = self.parse(raw_outputs, device_type)

        # SECURITY: Redact raw outputs that may contain secrets
        raw_outputs[cmds[3]] = "<REDACTED>"  # show snmp
        raw_outputs[cmds[5]] = "<REDACTED>"  # show running-config | section aaa

        return {
            "raw": raw_outputs,
            "parsed": parsed,
        }
