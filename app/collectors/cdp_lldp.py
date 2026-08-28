"""
CDP/LLDP neighbor discovery collector.
Wraps existing parsers from parsers.py.
"""
from .base import BaseCollector

try:
    from app.parsers import (
        parse_cdp_neighbors_detail,
        parse_lldp_neighbors_detail,
        merge_neighbor_info,
    )
except ImportError:
    from parsers import (
        parse_cdp_neighbors_detail,
        parse_lldp_neighbors_detail,
        merge_neighbor_info,
    )

# Commands per vendor
_COMMANDS = {
    "cisco_ios": ["show cdp neighbors detail", "show lldp neighbors detail"],
    "cisco_xe": ["show cdp neighbors detail", "show lldp neighbors detail"],
    "cisco_nxos": ["show cdp neighbors detail", "show lldp neighbors detail"],
    "arista_eos": ["show lldp neighbors detail"],
    "juniper_junos": ["show lldp neighbors"],
    # VyOS runs lldpd; there is no CDP.
    "vyos": ["show lldp neighbors detail"],
    # AireOS speaks CDP to the wired side, and LLDP only toward APs.
    "cisco_wlc": ["show cdp neighbors detail"],
    "paloalto_panos": ["show lldp neighbors all"],
}
_DEFAULT_COMMANDS = ["show cdp neighbors detail", "show lldp neighbors detail"]


class CdpLldpCollector(BaseCollector):
    name = "cdp_lldp"
    label = "CDP/LLDP Neighbors"
    description = "Discover neighbors via CDP and LLDP protocols"
    enabled_by_default = True
    # Fireware speaks neither CDP nor LLDP.
    unsupported_platforms = frozenset({"watchguard_fireware"})

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if device_type == "paloalto_panos":
            # No ntc-templates entry for "show lldp neighbors all", and the
            # Cisco LLDP parser does not understand PAN-OS output.
            try:
                from app.parsers_panos import parse_lldp_neighbors as _panos_lldp
            except ImportError:
                from parsers_panos import parse_lldp_neighbors as _panos_lldp
            raw = raw_outputs.get("show lldp neighbors all", "")
            return {"neighbors": _panos_lldp(raw)}

        cdp_output = raw_outputs.get("show cdp neighbors detail", "")
        lldp_output = raw_outputs.get(
            "show lldp neighbors detail",
            raw_outputs.get("show lldp neighbors", ""),
        )

        cdp_neighbors = parse_cdp_neighbors_detail(cdp_output) if cdp_output else []
        lldp_neighbors = parse_lldp_neighbors_detail(lldp_output) if lldp_output else []

        neighbors = merge_neighbor_info(cdp_neighbors, lldp_neighbors)
        return {"neighbors": neighbors}
