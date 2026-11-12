"""
Cisco WLC report: configuration hygiene and the relationships between
controllers, APs, switches, servers and peers.
"""
from collections import defaultdict

from .wlc_services import services
from .wlc_wireless import wireless

try:
    from app.collectors import wlc_platform as P
    from app.identity import normalize_hostname
except ImportError:
    from collectors import wlc_platform as P
    from identity import normalize_hostname

NA = "n/a"
LEAD = ["Controller", "Site", "Model"]

HYGIENE_HEADERS = LEAD + ["Item", "Rule", "Count", "List"]


def _join(items, sep=", "):
    return sep.join(str(i) for i in items if i not in (None, ""))


def _list(items, limit=50):
    items = list(items)
    text = _join(items[:limit])
    return text + (f", +{len(items) - limit} more" if len(items) > limit else "")


def _row(c, item, rule, items):
    if items is None:
        return c.lead() + [item, rule, NA, NA]
    return c.lead() + [item, rule, len(items), _list(items)]


def _unused_interfaces(c, w):
    if c.interfaces is None or w.wlan_summary is None:
        return None
    used = set()
    for x in w.wlans:
        used.update(n for n in (x.get("interface"), x.get("interface_group")) if n)
    for g in w.apgroups or []:
        used.update(x.get("interface") for x in g.get("wlans") or [] if x.get("interface"))
    for group, members in (c.interface_groups or {}).items():
        if group in used:
            used.update(members)
    return [i["name"] for i in c.interfaces if i.get("type") == "Dynamic"
            and i["name"] not in used]


def _security_signature(x):
    return " ".join(filter(None, [x.get("l2_security") or "None",
                                  "/".join(x.get("encryption") or []),
                                  "/".join(x.get("akm") or []),
                                  x.get("l3_security") if (x.get("l3_security") or "none") != "none"
                                  else ""]))


def hygiene_rows(ctrl_list):
    rows = []
    for c in ctrl_list:
        w = wireless(c)
        configured = [a for a in w.aps if a["general"] is not None]
        rows.append(_row(c, "WLANs configured but disabled", "list", None if w.wlan_summary is None
                         else [f"{x['id']} {x.get('profile') or ''}".strip() for x in w.wlans
                               if (x.get("status") or "").lower() == "disabled"]))
        rows.append(_row(c, "Interfaces not used by any WLAN", "list", _unused_interfaces(c, w)))
        counts = defaultdict(int)
        for a in configured:
            counts[a["general"].get("ap_group")] += 1
        rows.append(_row(c, "AP groups with no APs", "list", None if w.apgroups is None else [
            g["name"] for g in w.apgroups
            if not counts.get(g["name"]) and not g.get("aps")]))
        rows.append(_row(c, "APs in default-group", "count", None if not configured else [
            a["name"] for a in configured if a["general"].get("ap_group") == "default-group"]))
        rows.append(_row(c, "APs with no primary controller", "count", None if not configured
                         else [a["name"] for a in configured
                               if not a["general"].get("primary_controller")]))
        images = defaultdict(list)
        for a in w.aps:
            ver = (a["general"] or {}).get("sw_version") or (a["image"] or {}).get("primary")
            if ver:
                images[ver].append(a["name"])
        rows.append(_row(c, "Mixed AP images on one controller", "list",
                         None if not w.aps else ([f"{v}: {len(n)} AP(s)"
                                                  for v, n in sorted(images.items())]
                                                 if len(images) > 1 else [])))

    groups = defaultdict(list)
    for c in ctrl_list:
        mob = services(c).mobility
        if mob and mob.get("group_name"):
            groups[mob["group_name"]].append(c)
    for name, members in sorted(groups.items()):
        versions = defaultdict(list)
        for c in members:
            versions[c.version or "unknown"].append(c.name)
        items = ([f"{v}: {_join(n)}" for v, n in sorted(versions.items())]
                 if len(versions) > 1 else [])
        rows.append([_join(c.name for c in members), "", "", f"Mixed AireOS versions in "
                     f"mobility group {name}", "list", len(items), _list(items)])

    by_ssid = defaultdict(lambda: defaultdict(list))
    for c in ctrl_list:
        for x in wireless(c).wlans:
            if x.get("_summary_only") or (x.get("status") or "").lower() != "enabled":
                continue
            by_ssid[x.get("ssid") or x.get("profile")][_security_signature(x)].append(c.name)
    mixed = [f"{ssid}: " + "; ".join(f"{sig} on {_join(sorted(set(n)))}"
                                     for sig, n in sorted(sigs.items()))
             for ssid, sigs in sorted(by_ssid.items()) if len(sigs) > 1]
    if ctrl_list:
        rows.append([_join(c.name for c in ctrl_list), "", "",
                     "Same SSID with different security across controllers", "list",
                     len(mixed), _list(mixed)])
    return rows


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

RELATION_HEADERS = LEAD + ["Side A", "Side B", "Relationship", "Side B In Wiremap", "Evidence"]


def _index(inventory_data):
    names, ips = set(), {}
    for key, d in (inventory_data.get("devices") or {}).items():
        names.add(normalize_hostname(key))
        for ip in (d.get("reached_ip"), d.get("mgmt_ip")):
            if ip:
                ips.setdefault(ip, key)
    return names, ips


def relationship_rows(ctrl_list, inventory_data):
    names, ips = _index(inventory_data)
    rows = []

    def add(c, a, b, rel, evidence, b_name=None, b_ip=None):
        if b_name:
            known = normalize_hostname(b_name) in names
        elif b_ip:
            known = b_ip in ips
        else:
            known = False
        if b_ip and b_ip in ips and not b_name:
            b = f"{b} ({ips[b_ip]})"
        rows.append(c.lead() + [a, b, rel, "Yes" if known else "No", evidence])

    for c in ctrl_list:
        for n in c.cdp or []:
            add(c, f"{c.name} port {n.get('local_port')}",
                f"{n.get('device_id')} {n.get('remote_port') or ''}".strip(), "uplink (CDP)",
                "show cdp neighbors detail", b_name=n.get("device_id"))
        w = wireless(c)
        for a in w.aps:
            cdp = a["cdp"]
            if cdp and cdp.get("neighbor"):
                add(c, f"{a['name']} {a['mac']}".strip(),
                    f"{cdp['neighbor']} {cdp.get('port') or ''}".strip(), "AP access port (AP CDP)",
                    "show ap cdp neighbors all", b_name=cdp["neighbor"])
        s = services(c)
        for p in (s.mobility or {}).get("peers") or []:
            add(c, c.name, f"{p.get('ip')} ({p.get('group') or ''})", "mobility peer",
                "show mobility summary", b_ip=p.get("ip"))
        for x in s.anchors or []:
            add(c, f"WLAN {x.get('wlan')}", x.get("anchor_ip") or "", "anchor",
                "show mobility anchor", b_ip=x.get("anchor_ip"))
        for srv in (s.radius or {}).get("servers", []):
            add(c, c.name, f"{srv['ip']}:{srv['port']}", f"AAA server (RADIUS {srv['use']})",
                "show radius summary", b_ip=srv["ip"])
        for srv in (s.tacacs or {}).get("servers", []):
            add(c, c.name, f"{srv['ip']}:{srv['port']}", f"AAA server (TACACS+ {srv['use']})",
                "show tacacs summary", b_ip=srv["ip"])
        for x in (c.time or {}).get("ntp_servers") or []:
            add(c, c.name, x["server"], "management target (NTP)", "show time",
                b_ip=x["server"])
        for ip in (s.logging or {}).get("syslog_hosts") or []:
            add(c, c.name, ip, "management target (syslog)", "show logging", b_ip=ip)
        for t in s.traps or []:
            add(c, c.name, t["ip"], "management target (SNMP trap)", "show snmptrap",
                b_ip=t["ip"])
        for x in s.nmsp or []:
            add(c, c.name, x["ip"], "management target (NMSP: Prime / CMX)", "show nmsp status",
                b_ip=x["ip"])
    return rows
