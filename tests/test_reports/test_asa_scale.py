"""A hub firewall's rule base reports in reasonable time (50,000 ACL lines)."""
import time

from app.reports.asa import build_tabular
from tests.test_collectors import asa_fixtures as fx

LINES = 50000


def _big_policy():
    config = ["interface GigabitEthernet0/0", " nameif outside", " security-level 0",
              "interface GigabitEthernet0/1", " nameif inside", " security-level 100"]
    hits = [f"access-list LAB-HUB; {LINES} elements; name hash: 0x1"]
    for i in range(LINES):
        host = f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}"
        config.append(f"access-list LAB-HUB extended permit tcp any host {host} eq https")
        hits.append(f"access-list LAB-HUB line {i + 1} extended permit tcp any host {host} "
                    f"eq https (hitcnt={i % 3}) 0x{i:08x}")
    config.append("access-group LAB-HUB in interface outside")
    return "\n".join(config) + "\n", "\n".join(hits) + "\n"


def test_fifty_thousand_line_acl_reports_quickly():
    config, hits = _big_policy()
    outputs = fx.single_mode_outputs()
    outputs.update({"show running-config": config, "show access-list": hits})
    device = {"hostname": "LAB-HUB-01", "asa_unit": {"hostname": "LAB-HUB-01",
                                                     "role": "standalone"},
              "collector_data": {"asa": {"raw": outputs, "parsed": {
                  "mode": "single", "contexts": {"": {"interfaces": [
                      {"interface": "GigabitEthernet0/0", "nameif": "outside",
                       "security_level": 0},
                      {"interface": "GigabitEthernet0/1", "nameif": "inside",
                       "security_level": 100}]}}}}}}
    started = time.monotonic()
    sheets = build_tabular({"devices": {"LAB-HUB-01": device}})
    elapsed = time.monotonic() - started
    assert len(sheets["ACL Lines"][1]) == LINES
    [acl] = sheets["Access Lists"][1]
    assert acl[-1].startswith("skipped")
    assert elapsed < 60, f"{elapsed:.1f}s"
