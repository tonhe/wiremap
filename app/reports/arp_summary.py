"""
ARP Summary report -- ARP tables by device with summary and detail tabs.

The global table comes from the arp collector; non-default VRF tables come
from the vrf collector's vrf_arp, so every row carries the VRF it was
learned in.
"""
import io
from collections import OrderedDict, defaultdict
from openpyxl import Workbook

from .base import BaseReport
from .xlsx_utils import create_sheet

DEFAULT_VRF = "default"


def _detail_row(hostname, vrf, intf, ip, mac, age, incomplete):
    # An unresolved entry has no MAC and normally no interface; say so
    # rather than leaving blank cells that read as a parsing gap.
    if incomplete:
        mac = "Incomplete"
        intf = intf or "(unresolved)"
    elif not intf:
        intf = "(none)"
    return [hostname, vrf, intf, ip, mac, age]


def _device_arp_rows(hostname, device):
    cd = device.get("collector_data", {})
    rows = []
    seen = set()
    for entry in cd.get("arp", {}).get("parsed", {}).get("entries", []):
        ip = entry.get("ip", "")
        intf = entry.get("interface", "")
        seen.add((ip, intf))
        rows.append(_detail_row(hostname, DEFAULT_VRF, intf, ip,
                                entry.get("mac", ""), entry.get("age", ""),
                                entry.get("incomplete")))

    vrf_arp = cd.get("vrf", {}).get("parsed", {}).get("vrf_arp") or {}
    for vrf in sorted(vrf_arp):
        # The global table already covers the default VRF.
        if not vrf or vrf == DEFAULT_VRF:
            continue
        for entry in vrf_arp[vrf] or []:
            ip = entry.get("ip_address", "")
            intf = entry.get("interface", "")
            # An interface belongs to one VRF, so the same IP on the same
            # interface is the same entry seen twice.
            if (ip, intf) in seen:
                continue
            seen.add((ip, intf))
            rows.append(_detail_row(hostname, vrf, intf, ip,
                                    entry.get("mac_address", ""),
                                    entry.get("age", ""),
                                    entry.get("incomplete")))
    return rows


class ArpSummaryReport(BaseReport):
    name = "arp_summary"
    label = "ARP Summary"
    description = "ARP table entries by device, VRF and interface"
    category = "Layer 3 & Routing"
    required_collectors = ["arp"]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def generate_tabular_data(self, inventory_data):
        detail_rows = []
        summary_counts = defaultdict(int)

        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            for row in _device_arp_rows(hostname, device):
                detail_rows.append(row)
                summary_counts[(row[0], row[1], row[2])] += 1

        summary_rows = [[host, vrf, intf, count]
                        for (host, vrf, intf), count in sorted(summary_counts.items())]

        return OrderedDict([
            ("Summary", (["Device", "VRF", "Interface", "Entry Count"], summary_rows)),
            ("Detail", (["Device", "VRF", "Interface", "IP", "MAC", "Age"], detail_rows)),
        ])

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        if fmt != "xlsx":
            return self._generate_for_format(inventory_data, fmt)

        tabular = self.generate_tabular_data(inventory_data)

        wb = Workbook()
        wb.remove(wb.active)

        for sheet_name, (headers, rows) in tabular.items():
            create_sheet(wb, sheet_name, headers, rows)

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()
