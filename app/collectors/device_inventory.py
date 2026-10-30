"""
Device inventory collector (show version, show inventory, etc.).
Uses ntc-templates for parsing.
"""
import logging
import re

from .base import BaseCollector
from .errors import error_reason

logger = logging.getLogger(__name__)

# ntc-templates doesn't have cisco_xe templates; use cisco_ios instead
_NTC_PLATFORM_MAP = {
    "cisco_xe": "cisco_ios",
    "cisco_xr": "cisco_ios",
}

_COMMANDS = {
    # VSS (6500/4500) answers "show switch virtual"; StackWise Virtual (C9k)
    # answers "show stackwise-virtual". Everything else rejects them, which
    # means "not a virtual pair", not a collection failure.
    # Licensing and call-home: IOS-XE boxes are often typed cisco_ios by
    # autodetect, so both get the IOS-XE commands. Classic IOS rejects them,
    # which the parsers treat as "no licensing data".
    "cisco_ios": ["show version", "show inventory", "show switch detail", "show module",
                  "show switch virtual", "show switch virtual link",
                  "show license summary", "show license status",
                  "show call-home", "show call-home profile all"],
    "cisco_xe": ["show version", "show inventory", "show switch detail", "show module",
                 "show stackwise-virtual", "show stackwise-virtual link",
                 "show stackwise-virtual dual-active-detection",
                 "show license summary", "show license status",
                 "show call-home", "show call-home profile all"],
    "cisco_nxos": ["show version", "show inventory", "show module", "show vpc",
                   "show license usage", "show callhome"],
    "arista_eos": ["show version", "show inventory", "show module"],
    "juniper_junos": ["show version", "show chassis hardware", "show virtual-chassis"],
    "extreme": ["show version", "show switch"],
    "vyos": ["show version", "show hardware cpu"],
    # AireOS puts model, serial and software version in sysinfo, not version.
    "cisco_wlc": ["show sysinfo", "show inventory"],
    "watchguard_fireware": ["show system", "show version"],
    "paloalto_panos": ["show system info"],
}

# Platforms whose identity command is not named "... version ...". Sniffing
# for the word left PAN-OS and AireOS parsing nothing at all, which is why
# their rows carried no model, serial or software version.
_IDENTITY_COMMANDS = {
    "paloalto_panos": "show system info",
    "cisco_wlc": "show sysinfo",
    "watchguard_fireware": "show system",
}
_DEFAULT_COMMANDS = ["show version", "show inventory"]


def _ntc_parse(raw: str, device_type: str, command: str) -> list[dict]:
    if not raw:
        return []
    try:
        from ntc_templates.parse import parse_output
        platform = _NTC_PLATFORM_MAP.get(device_type, device_type)
        return parse_output(platform=platform, command=command, data=raw)
    except Exception:
        logger.debug(f"ntc-templates parse failed for {command} on {device_type}")
        return []


def _parse_show_switch_detail(raw: str) -> list[dict]:
    """Fallback parser for 'show switch detail' if ntc-templates lacks it."""
    if not raw:
        return []
    members = []
    pattern = re.compile(
        r'[* ]*(\d+)\s+'            # switch number (may have * prefix)
        r'(\w+)\s+'                  # role
        r'([0-9a-f.]+)\s+'          # mac address
        r'(\d+)\s+'                  # priority
        r'(\S+)\s+'                  # hw version
        r'(\S+)',                    # state
        re.IGNORECASE,
    )
    for m in pattern.finditer(raw):
        members.append({
            "switch": m.group(1),
            "role": m.group(2),
            "mac_address": m.group(3),
            "priority": m.group(4),
            "hw_ver": m.group(5),
            "state": m.group(6),
        })
    return members


def _usable(raw):
    """Raw output, or "" when the device rejected the command.

    The virtual-pair commands are probes: most boxes answer them with
    "% Invalid input", which means the feature is absent, not that the
    collector broke.
    """
    if not raw or error_reason(raw):
        return ""
    return raw


_INTF_RE = re.compile(r"\b([A-Za-z][A-Za-z-]*\d+(?:/\d+)+(?:\.\d+)?)\b")


def _parse_stackwise_virtual(config_raw, link_raw="", dad_raw=""):
    """Parse the three 'show stackwise-virtual' views of a C9k SVL pair.

    Returns None when the box is not running StackWise Virtual (disabled,
    unsupported, or the command was rejected).
    """
    config_raw = _usable(config_raw)
    if not config_raw:
        return None
    m = re.search(r"Stackwise\s+Virtual\s*:\s*(\w+)", config_raw, re.I)
    if not m or m.group(1).lower() != "enabled":
        return None

    domain = re.search(r"Domain\s+Number\s*:\s*(\d+)", config_raw, re.I)
    result = {
        "enabled": True,
        "domain": domain.group(1) if domain else "",
        "switches": [],
        "links": [],
        "dad_ports": [],
    }

    # Config table: "Switch  SVL  Ports" with continuation lines that carry
    # only a port, belonging to the switch above.
    switch = None
    for line in config_raw.splitlines():
        row = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s*$", line)
        if row:
            switch = row.group(1)
            if switch not in result["switches"]:
                result["switches"].append(switch)
            result["links"].append({"switch": switch, "svl": row.group(2),
                                    "port": row.group(3)})
            continue
        cont = re.match(r"^\s{8,}(\S+)\s*$", line)
        if cont and switch and _INTF_RE.match(cont.group(1)):
            result["links"].append({"switch": switch,
                                    "svl": result["links"][-1]["svl"],
                                    "port": cont.group(1)})

    # Link view adds per-port link and protocol status.
    link_raw = _usable(link_raw)
    if link_raw:
        status = {}
        switch = svl = None
        for line in link_raw.splitlines():
            row = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
            if row:
                switch, svl = row.group(1), row.group(2)
                status[row.group(3)] = (switch, svl, row.group(4), row.group(5))
                continue
            cont = re.match(r"^\s{8,}(\S+)\s+(\S+)\s+(\S+)\s*$", line)
            if cont and switch and _INTF_RE.match(cont.group(1)):
                status[cont.group(1)] = (switch, svl, cont.group(2),
                                         cont.group(3))
        known = {link["port"] for link in result["links"]}
        for link in result["links"]:
            if link["port"] in status:
                link["link_status"] = status[link["port"]][2]
                link["protocol_status"] = status[link["port"]][3]
        for port, (sw, svl_id, ls, ps) in status.items():
            if port not in known:
                result["links"].append({"switch": sw, "svl": svl_id,
                                        "port": port, "link_status": ls,
                                        "protocol_status": ps})
            if sw not in result["switches"]:
                result["switches"].append(sw)

    dad_raw = _usable(dad_raw)
    if dad_raw:
        for line in dad_raw.splitlines():
            row = re.match(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s*$", line)
            if row and _INTF_RE.match(row.group(2)):
                result["dad_ports"].append({"switch": row.group(1),
                                            "port": row.group(2),
                                            "status": row.group(3)})

    return result


def _parse_switch_virtual(raw, link_raw=""):
    """Parse 'show switch virtual' from a 6500/4500 VSS.

    Returns None for a standalone chassis or a rejected command.
    """
    raw = _usable(raw)
    if not raw:
        return None
    mode = re.search(r"Switch\s+mode\s*:\s*(.+)", raw, re.I)
    if not mode or "virtual" not in mode.group(1).lower():
        return None

    domain = re.search(r"Virtual\s+switch\s+domain\s+number\s*:\s*(\d+)",
                       raw, re.I)
    result = {
        "enabled": True,
        "domain": domain.group(1) if domain else "",
        "switches": {},
        "links": [],
        "vsl_status": "",
    }
    # Both "Local" and "Peer" lines carry a number and a role. The command
    # may be executed on each member, so the same pair can appear twice.
    for who in ("Local", "Peer"):
        nums = re.findall(rf"{who}\s+switch\s+number\s*:\s*(\d+)", raw, re.I)
        roles = re.findall(
            rf"{who}\s+switch\s+operational\s+role\s*:\s*(.+)", raw, re.I)
        for num, role in zip(nums, roles):
            role = re.sub(r"^\s*Virtual\s+Switch\s+", "", role.strip(),
                          flags=re.I)
            result["switches"].setdefault(num, role)

    link_raw = _usable(link_raw)
    if link_raw:
        status = re.search(r"VSL\s+Status\s*:\s*(\S+)", link_raw, re.I)
        if status:
            result["vsl_status"] = status.group(1)
        for line in link_raw.splitlines():
            if re.match(r"^\s*VSL\s+(Status|Uptime|Encryption)", line, re.I):
                continue
            for port in _INTF_RE.findall(line):
                if port not in result["links"]:
                    result["links"].append(port)
    return result


def _parse_vpc(raw):
    """Parse 'show vpc' on NX-OS. None when vPC is not configured."""
    raw = _usable(raw)
    if not raw:
        return None
    domain = re.search(r"vPC\s+domain\s+id\s*:\s*(\S+)", raw, re.I)
    if not domain or not domain.group(1).isdigit():
        return None

    def field(label):
        m = re.search(rf"{label}\s*:\s*(.+)", raw, re.I)
        return m.group(1).strip() if m else ""

    peer_link = re.search(r"^\s*\d+\s+(Po\d+)\s+(\S+)", raw, re.M)
    return {
        "domain": domain.group(1),
        "peer_status": field(r"Peer\s+status"),
        "keepalive_status": field(r"vPC\s+keep-alive\s+status"),
        "role": field(r"vPC\s+role"),
        "peer_link": peer_link.group(1) if peer_link else "",
        "peer_link_status": peer_link.group(2) if peer_link else "",
    }


def _parse_version_switch_table(raw):
    """Per-member rows from the C9k/3850 show version switch table.

    The '*' marks the member that owns the console, which on a two-member
    StackWise Virtual pair is the active.
    """
    rows = []
    for m in re.finditer(
        r"^\s*(\*?)\s*(\d+)\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
        raw or "", re.M,
    ):
        rows.append({"switch": m.group(2), "local": bool(m.group(1)),
                     "model": m.group(3), "sw_version": m.group(4),
                     "sw_image": m.group(5)})
    return rows


_LICENSE_LEVEL_RE = re.compile(r"^\s*License\s+Level\s*:\s*(\S+)", re.I | re.M)


def _parse_license(raw):
    """Licence level(s) from IOS / IOS-XE show version.

    C9k and ISR4k print a 'Technology Package License Information' table in
    different shapes; older images print 'License Level: x'.
    """
    if not raw:
        return ""
    levels = []
    block = re.search(r"Technology Package License Information:?(.*?)(?:\n\s*\n\s*\n|\Z)",
                      raw, re.S | re.I)
    if block:
        lines = block.group(1).splitlines()
        # ISR4k has a leading "Technology" column; C9k leads with the
        # current package.
        isr_layout = any(re.match(r"^\s*Technology\s+Technology-package", ln)
                         for ln in lines)
        dashes = [i for i, ln in enumerate(lines) if re.match(r"^\s*-{10,}", ln)]
        start = dashes[1] + 1 if len(dashes) >= 2 else None
        if start is not None:
            for ln in lines[start:]:
                if not ln.strip() or ":" in ln:
                    break
                tokens = ln.split()
                current = tokens[1] if isr_layout and len(tokens) > 1 else tokens[0]
                if current.lower() not in ("none", "n/a") and current not in levels:
                    levels.append(current)
    if not levels:
        levels = [m.group(1) for m in _LICENSE_LEVEL_RE.finditer(raw)]
    return ", ".join(levels)


def _parse_version_details(raw):
    """Fields ntc-templates misses or truncates, read straight from the text."""
    raw = _usable(raw)
    if not raw:
        return {}
    details = {}
    image = re.search(r'System image file is "([^"]+)"', raw)
    if not image:
        image = re.search(r"^\s*(?:NXOS|system)\s+image\s+file\s+is:\s*(\S+)",
                          raw, re.I | re.M)
    if image:
        details["image"] = image.group(1)
    uptime = re.search(r"^\S+\s+uptime\s+is\s+(.+)$", raw, re.M)
    if not uptime:
        uptime = re.search(r"^\s*Uptime:\s*(.+)$", raw, re.M | re.I)
    if uptime:
        details["uptime"] = uptime.group(1).strip()
    reload_reason = re.search(
        r"^\s*Last\s+(?:reload|reset)\s+reason:?\s*(.+)$", raw, re.M | re.I)
    if reload_reason:
        details["reload_reason"] = reload_reason.group(1).strip()
    license_level = _parse_license(raw)
    if license_level:
        details["license"] = license_level
    switches = _parse_version_switch_table(raw)
    if switches:
        details["switches"] = switches
    return details


# --- Licensing and call-home -------------------------------------------------

# "show license summary" usage table row (IOS-XE 16.x/17.x):
#   network-advantage       (C9300-48 Network Advan...)       1 IN USE
#   C9300 48P DNA Advantage (C9300-48 DNA Advantage)          1 AUTHORIZED
_LIC_SUMMARY_ROW_RE = re.compile(
    r"^\s+(\S.*?)\s+\((.*?)\)\s+(\d+)\s+(\S.*?)\s*$")
# NX-OS "show license usage" table row:
#   LAN_ENTERPRISE_SERVICES_PKG   Yes   -   In use never       -
_LIC_NXOS_ROW_RE = re.compile(
    r"^(\S+)\s+(Yes|No)\s+(\S+)\s+(In use|Unused|Grace\S*|Expired|Unlicensed)",
    re.I)
# Block form used by "show license usage" on newer IOS-XE and NX-OS:
#   network-advantage (C9300-48 Network Advantage):
#     Description: C9300-48 Network Advantage
#     Count: 1
#     Status: IN USE
_LIC_BLOCK_HEAD_RE = re.compile(r"^(\S[^:]*?)\s+\((.+)\):\s*$")


def _parse_license_usage(raw):
    """License rows from 'show license summary' or 'show license usage'."""
    raw = _usable(raw)
    if not raw:
        return []
    licenses = []
    in_table = False
    block = None
    for line in raw.splitlines():
        if re.match(r"^\s*-{10,}\s*$", line):
            in_table = True
            continue
        if not line.strip():
            in_table = False
            block = None
            continue
        m = _LIC_NXOS_ROW_RE.match(line)
        if m:
            licenses.append({"name": m.group(1), "entitlement": "",
                             "count": "" if m.group(3) == "-" else m.group(3),
                             "status": m.group(4)})
            continue
        if in_table:
            m = _LIC_SUMMARY_ROW_RE.match(line)
            if m:
                licenses.append({"name": m.group(1), "entitlement": m.group(2),
                                 "count": m.group(3), "status": m.group(4)})
                continue
        m = _LIC_BLOCK_HEAD_RE.match(line)
        if m and not line.startswith(" "):
            block = {"name": m.group(1).strip(), "entitlement": m.group(2).strip(),
                     "count": "", "status": ""}
            licenses.append(block)
            continue
        if block is not None:
            kv = re.match(r"^\s+(Count|Status):\s*(.+?)\s*$", line)
            if kv:
                block[kv.group(1).lower()] = kv.group(2)
    return licenses


def _section_status(raw, header):
    """Value of the 'Status:' line directly under a 'Header:' line."""
    m = re.search(rf"^\s*{header}:\s*\n\s*Status:\s*(.+?)\s*$", raw, re.M | re.I)
    return m.group(1) if m else ""


def _parse_smart_licensing(summary_raw, status_raw=""):
    """Smart Licensing mode and registration from IOS-XE show license output.

    Before 17.3.2 devices register to a Smart Account ("Registration:
    Status: REGISTERED"). From 17.3.2 Smart Licensing Using Policy has no
    registration; the useful facts are the transport and last usage ACK.
    """
    text = "\n".join(r for r in (_usable(summary_raw), _usable(status_raw)) if r)
    if not text:
        return None
    info = {"mode": "", "status": "", "registration": "", "authorization": "",
            "smart_account": "", "virtual_account": "", "transport": "",
            "last_ack": ""}
    slp = _section_status(text, "Smart Licensing Using Policy")
    classic = re.search(r"Smart Licensing is (ENABLED|DISABLED)", text, re.I)
    if slp:
        info["mode"] = "Smart Licensing Using Policy"
        info["status"] = slp
    elif classic:
        info["mode"] = "Smart Licensing"
        info["status"] = classic.group(1).upper()
    info["registration"] = _section_status(text, "Registration")
    info["authorization"] = _section_status(text, "License Authorization")
    for key, label in (("smart_account", "Smart Account"),
                       ("virtual_account", "Virtual Account")):
        m = re.search(rf"^\s*{label}:\s*(.+?)\s*$", text, re.M)
        if m:
            value = re.sub(r"\s+As of .*$", "", m.group(1))
            info[key] = "" if value == "<none>" else value
    transport = re.search(r"^\s*Transport:\s*\n\s*Type:\s*(.+?)\s*$", text, re.M)
    if transport:
        info["transport"] = transport.group(1)
    ack = re.search(r"^\s*Last ACK received:\s*(.+?)\s*$", text, re.M)
    if ack:
        info["last_ack"] = "" if ack.group(1) == "<none>" else ack.group(1)
    if not any(info.values()):
        return None
    return info


def _parse_call_home(raw, profiles_raw=""):
    """Call-home state from IOS-XE 'show call-home' or NX-OS 'show callhome'."""
    raw = _usable(raw)
    if not raw:
        return None
    enabled = None
    m = re.search(r"call home feature\s*:\s*(\w+)", raw, re.I)
    if m:
        enabled = m.group(1).lower().startswith("enable")
    else:
        m = re.search(r"^\s*callhome\s+(enabled|disabled)", raw, re.I | re.M)
        if m:
            enabled = m.group(1).lower() == "enabled"
    if enabled is None:
        return None

    info = {"enabled": enabled, "transport": "", "smart_licensing_messages": "",
            "profiles": []}
    sl = re.search(r"Smart licensing messages:\s*(\w+)", raw, re.I)
    if sl:
        info["smart_licensing_messages"] = sl.group(1).lower()

    profiles_raw = _usable(profiles_raw)
    current = None
    for line in (profiles_raw or "").splitlines():
        m = re.match(r"^\s*Profile Name:\s*(\S+)", line)
        if m:
            current = {"name": m.group(1), "status": "", "transport": ""}
            info["profiles"].append(current)
            continue
        if current is None:
            continue
        m = re.match(r"^\s*Profile status:\s*(\S+)", line, re.I)
        if m:
            current["status"] = m.group(1)
            continue
        m = re.match(r"^\s*Transport Method:\s*(\S+)", line, re.I)
        if m:
            current["transport"] = m.group(1)
    active = [p["transport"] for p in info["profiles"]
              if p["transport"] and p["status"].upper() == "ACTIVE"]
    info["transport"] = ", ".join(dict.fromkeys(active))
    if not info["transport"]:
        mail = re.search(r"Mail-server\s*:\s*(.+)", raw, re.I)
        if mail and "not yet set up" not in mail.group(1).lower():
            info["transport"] = "email"
    return info


def _inventory_chassis(inventory, number):
    """The show inventory entry for chassis/member N, or {}."""
    for item in inventory or []:
        it = {str(k).lower(): v for k, v in item.items()}
        name = (it.get("name") or "").strip()
        if re.match(rf"^(?:chassis|switch)\s*{number}(?:\s+system)?$", name, re.I):
            return it
        # VSS names chassis by PID plus member number: "WS-C6509-E 1"
        descr = (it.get("descr") or "").lower()
        if "chassis" in descr and re.search(rf"\s{number}$", name):
            return it
    return {}


def _list_item(value, index):
    if isinstance(value, list):
        return str(value[index]) if index < len(value) else ""
    return str(value) if value and index == 0 else ""


def _virtual_pair_members(kind, pair, version, inventory, version_details):
    """Stack Members rows for an SVL or VSS pair: one per chassis."""
    v = {str(k).lower(): val for k, val in (version[0].items() if version else [])}
    table = {row["switch"]: row for row in version_details.get("switches", [])}

    if kind == "stackwise-virtual":
        numbers = list(pair.get("switches") or table.keys())
        roles = {}
        for num in numbers:
            row = table.get(num)
            if row is not None:
                roles[num] = "Active" if row["local"] else "Standby"
    else:
        numbers = list(pair.get("switches", {}).keys())
        roles = dict(pair.get("switches", {}))

    members = []
    for index, num in enumerate(sorted(numbers, key=int)):
        inv = _inventory_chassis(inventory, num)
        row = table.get(num, {})
        members.append({
            "switch": num,
            "role": roles.get(num, ""),
            "model": (inv.get("pid") or "").strip() or row.get("model")
                     or _list_item(v.get("hardware"), index),
            "serial": (inv.get("sn") or "").strip()
                      or _list_item(v.get("serial"), index),
            "mac_address": _list_item(v.get("mac_address"), index),
            "priority": "",
            "state": "Ready" if roles.get(num) else "",
            "stack_type": kind,
        })
    return members


class DeviceInventoryCollector(BaseCollector):
    name = "device_inventory"
    label = "Device Inventory"
    description = "Collect hardware version, serial numbers, and module information"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        # show version, or the platform's own identity command
        version_cmd = _IDENTITY_COMMANDS.get(device_type) or next(
            (c for c in commands if "version" in c), None)
        version = _ntc_parse(
            raw_outputs.get(version_cmd, ""), device_type, version_cmd
        ) if version_cmd else []

        # show inventory / show chassis hardware
        inv_cmd = next(
            (c for c in commands if "inventory" in c or "chassis" in c),
            None,
        )
        inventory = _ntc_parse(
            raw_outputs.get(inv_cmd, ""), device_type, inv_cmd
        ) if inv_cmd else []

        # show module
        mod_cmd = next((c for c in commands if "module" in c), None)
        modules = _ntc_parse(
            raw_outputs.get(mod_cmd, ""), device_type, mod_cmd
        ) if mod_cmd else []

        # Stack members: show switch detail (Cisco), show virtual-chassis (Juniper),
        # show switch (Extreme)
        stack_cmd = next(
            (c for c in commands if "switch detail" in c or "virtual-chassis" in c),
            None,
        )
        stack_members = []
        if stack_cmd:
            stack_raw = raw_outputs.get(stack_cmd, "")
            stack_members = _ntc_parse(stack_raw, device_type, stack_cmd)
            if not stack_members and stack_raw:
                stack_members = _parse_show_switch_detail(stack_raw)

        # For Extreme, stack data comes from "show switch" which is also the inv_cmd
        if not stack_members and device_type == "extreme":
            stack_members = _ntc_parse(
                raw_outputs.get("show switch", ""), device_type, "show switch"
            )

        result = {
            "version": version,
            "inventory": inventory,
            "modules": modules,
            "stack_members": stack_members,
        }

        version_details = (_parse_version_details(raw_outputs.get(version_cmd, ""))
                           if version_cmd else {})
        if version_details:
            result["version_details"] = version_details

        # Virtual pairs: two chassis acting as one. "show switch detail" says
        # nothing useful on an SVL pair, so the chassis come from here.
        pair_kind, pair = None, None
        if "show stackwise-virtual" in commands:
            pair = _parse_stackwise_virtual(
                raw_outputs.get("show stackwise-virtual", ""),
                raw_outputs.get("show stackwise-virtual link", ""),
                raw_outputs.get("show stackwise-virtual dual-active-detection", ""),
            )
            if pair:
                pair_kind = "stackwise-virtual"
                result["stackwise_virtual"] = pair
        if not pair and "show switch virtual" in commands:
            pair = _parse_switch_virtual(
                raw_outputs.get("show switch virtual", ""),
                raw_outputs.get("show switch virtual link", ""),
            )
            if pair:
                pair_kind = "vss"
                result["vss"] = pair
        if pair:
            members = _virtual_pair_members(pair_kind, pair, version,
                                            inventory, version_details)
            if stack_members:
                # Keep what show switch reported, filling model/serial.
                by_num = {m["switch"]: m for m in members}
                for sm in stack_members:
                    sm_norm = {str(k).lower(): v for k, v in sm.items()}
                    num = str(sm_norm.get("switch") or "")
                    extra = by_num.get(num, {})
                    for key in ("model", "serial"):
                        if not sm_norm.get(key) and extra.get(key):
                            sm[key] = extra[key]
                    sm["stack_type"] = pair_kind
            else:
                result["stack_members"] = members

        if "show vpc" in commands:
            vpc = _parse_vpc(raw_outputs.get("show vpc", ""))
            if vpc:
                result["vpc"] = vpc

        licenses = (_parse_license_usage(raw_outputs.get("show license summary", ""))
                    or _parse_license_usage(raw_outputs.get("show license usage", "")))
        if licenses:
            result["licenses"] = licenses
        smart = _parse_smart_licensing(raw_outputs.get("show license summary", ""),
                                       raw_outputs.get("show license status", ""))
        if smart:
            result["smart_licensing"] = smart
        call_home = _parse_call_home(
            raw_outputs.get("show call-home", "") or raw_outputs.get("show callhome", ""),
            raw_outputs.get("show call-home profile all", ""))
        if call_home:
            result["call_home"] = call_home

        return result
