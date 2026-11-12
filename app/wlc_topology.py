"""
Access points as topology nodes.

APs are not logged into, but every controller knows the switch port each of
its APs sits on (show ap cdp neighbors all). The topology map and diagram
data add those APs and links, so branch drawings show which switch port each
AP uses even where the switch was not scanned.
"""
try:
    from app.collectors import wlc_wireless as W
    from app.collectors.errors import error_reason
except ImportError:
    from collectors import wlc_wireless as W
    from collectors.errors import error_reason


def _out(raw, cmd):
    text = raw.get(cmd)
    return None if text is None or error_reason(text) else text


def ap_links(inventory_data):
    """[{ap, ap_ip, ap_model, ap_mac, controller, switch, switch_ip, switch_port}]."""
    out = []
    for key, device in sorted((inventory_data.get("devices") or {}).items()):
        raw = ((device.get("collector_data") or {}).get("wlc") or {}).get("raw") or {}
        if not raw:
            continue
        summary = {r["name"]: r for r in W.parse_ap_summary(_out(raw, "show ap summary")) or []}
        base = {r["name"]: r["base_mac"]
                for r in W.parse_join_summary(_out(raw, "show ap join stats summary all")) or []
                if r.get("name")}
        for n in W.parse_ap_cdp(_out(raw, "show ap cdp neighbors all")) or []:
            if not n.get("neighbor"):
                continue
            ap = summary.get(n["ap_name"]) or {}
            out.append({"ap": n["ap_name"], "ap_ip": n.get("ap_ip") or ap.get("ip") or "",
                        "ap_model": ap.get("model") or "",
                        "ap_mac": base.get(n["ap_name"]) or "", "controller": key,
                        "switch": n["neighbor"], "switch_ip": n.get("neighbor_ip") or "",
                        "switch_port": n.get("port") or ""})
    return out
