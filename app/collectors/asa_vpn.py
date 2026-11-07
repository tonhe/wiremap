"""
ASA site-to-site and remote-access VPN from running-config and vpn-sessiondb.

Pure functions over text. Usernames from session output are never kept.
"""
import ipaddress
import re
from collections import OrderedDict

from .asa_parsers import config_blocks

# Algorithms the assessment counts as weak, and the "only just acceptable" set.
WEAK_ALGOS = re.compile(r"(?:^|[-\s])(des|3des|md5)(?:$|[-\s])", re.I)
WEAK_DH = {"1", "2", "5"}
SHA1_ONLY = re.compile(r"^(?:sha|sha1|sha-1|esp-sha-hmac)$", re.I)


def _blocks(config, keyword):
    return {h.split()[2] if len(h.split()) > 2 else h: body
            for h, body in config_blocks(config, keyword)}


def parse_ike_policies(config):
    """{"ikev1": [{priority, auth, encryption, hash, group, lifetime}],
    "ikev2": [{priority, encryption, integrity, group, prf, lifetime}]}."""
    out = {"ikev1": [], "ikev2": []}
    for header, body in config_blocks(config, "crypto ikev"):
        m = re.match(r"crypto (ikev1|ikev2) policy (\d+)", header)
        if not m:
            continue
        p = {"priority": int(m.group(2)), "auth": "", "encryption": "", "hash": "",
             "integrity": "", "group": "", "prf": "", "lifetime": ""}
        for s in body:
            if mm := re.match(r"(authentication|encryption|hash|integrity|group|prf|lifetime)"
                              r"(?: seconds)? (.+)$", s):
                key = "auth" if mm.group(1) == "authentication" else mm.group(1)
                p[key] = mm.group(2).strip()
        out[m.group(1)].append(p)
    return out


def parse_transforms(config):
    """{name: {"version", "encryption", "integrity"}} for ikev1 transform-sets
    and ikev2 ipsec-proposals."""
    out = {}
    for line in (config or "").splitlines():
        if m := re.match(r"^crypto ipsec ikev1 transform-set (\S+) (\S+)(?: (\S+))?", line):
            out[m.group(1)] = {"version": "ikev1", "encryption": m.group(2),
                               "integrity": m.group(3) or ""}
    for header, body in config_blocks(config, "crypto ipsec ikev2 ipsec-proposal"):
        name = header.split()[-1]
        rec = {"version": "ikev2", "encryption": "", "integrity": ""}
        for s in body:
            if m := re.match(r"protocol esp (encryption|integrity) (.+)$", s):
                rec[m.group(1)] = m.group(2).strip()
        out[name] = rec
    return out


def parse_crypto_maps(config):
    """[{map, seq, interface, peers, acl, transforms, pfs, lifetime_s, lifetime_kb,
    aggressive, ikev1, ikev2, trustpoint}] from crypto map lines."""
    entries = OrderedDict()
    interfaces = {}
    for line in (config or "").splitlines():
        if m := re.match(r"^crypto map (\S+) interface (\S+)", line):
            interfaces[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^crypto map (\S+) (\d+) (.+)$", line)
        if not m:
            continue
        key = (m.group(1), int(m.group(2)))
        e = entries.setdefault(key, {
            "map": key[0], "seq": key[1], "interface": "", "peers": [], "acl": "",
            "transforms": [], "pfs": "", "lifetime_s": None, "lifetime_kb": None,
            "aggressive": False, "ikev1": False, "ikev2": False, "trustpoint": "",
            "dynamic": False})
        rest = m.group(3)
        if mm := re.match(r"match address (\S+)", rest):
            e["acl"] = mm.group(1)
        elif mm := re.match(r"set peer (.+)$", rest):
            e["peers"] = mm.group(1).split()
        elif mm := re.match(r"set (ikev1) transform-set (.+)$", rest):
            e["transforms"] += mm.group(2).split()
            e["ikev1"] = True
        elif mm := re.match(r"set (ikev2) ipsec-proposal (.+)$", rest):
            e["transforms"] += mm.group(2).split()
            e["ikev2"] = True
        elif mm := re.match(r"set pfs(?: (group\d+))?", rest):
            e["pfs"] = mm.group(1) or "group2"
        elif mm := re.match(r"set security-association lifetime seconds (\d+)", rest):
            e["lifetime_s"] = int(mm.group(1))
        elif mm := re.match(r"set security-association lifetime kilobytes (\S+)", rest):
            e["lifetime_kb"] = mm.group(1)
        elif re.match(r"set ikev1 phase1-mode aggressive", rest):
            e["aggressive"] = True
        elif mm := re.match(r"set trustpoint (\S+)", rest):
            e["trustpoint"] = mm.group(1)
        elif re.match(r"ipsec-isakmp dynamic", rest):
            e["dynamic"] = True
    for e in entries.values():
        e["interface"] = interfaces.get(e["map"], "")
    return list(entries.values())


def parse_tunnel_groups(config):
    """{name: {type, general: [...], ipsec: [...], webvpn: [...]}}."""
    groups = OrderedDict()
    for line in (config or "").splitlines():
        if m := re.match(r"^tunnel-group (\S+) type (\S+)", line):
            groups.setdefault(m.group(1), {"name": m.group(1), "general": [],
                                           "ipsec": [], "webvpn": []})["type"] = m.group(2)
    for header, body in config_blocks(config, "tunnel-group "):
        parts = header.split()
        if len(parts) < 3:
            continue
        g = groups.setdefault(parts[1], {"name": parts[1], "type": "", "general": [],
                                         "ipsec": [], "webvpn": []})
        kind = {"general-attributes": "general", "ipsec-attributes": "ipsec",
                "webvpn-attributes": "webvpn"}.get(parts[2])
        if kind:
            g[kind] += body
    return groups


def tunnel_auth(group):
    """PSK / certificate / both, from ipsec-attributes."""
    lines = group.get("ipsec", [])
    psk = any("pre-shared-key" in s for s in lines)
    cert = any(re.search(r"certificate|trust-point", s) for s in lines)
    return "PSK + certificate" if psk and cert else "PSK" if psk else \
        "certificate" if cert else ""


def parse_group_policies(config):
    """{name: {attr: value}} from group-policy attributes blocks."""
    out = OrderedDict()
    for line in (config or "").splitlines():
        if m := re.match(r"^group-policy (\S+) (internal|external)", line):
            out.setdefault(m.group(1), {})
    for header, body in config_blocks(config, "group-policy "):
        parts = header.split()
        if len(parts) > 2 and parts[2] == "attributes":
            attrs = out.setdefault(parts[1], {})
            for s in body:
                key, _, value = s.partition(" ")
                if value.startswith("value "):
                    value = value[6:]
                attrs.setdefault(key, value.strip())
    return out


def parse_pools(config):
    """{name: {range, mask, size}} from ip local pool."""
    out = {}
    for line in (config or "").splitlines():
        m = re.match(r"^ip local pool (\S+) (\S+)-(\S+)(?: mask (\S+))?", line)
        if not m:
            continue
        try:
            size = int(ipaddress.ip_address(m.group(3))) - int(
                ipaddress.ip_address(m.group(2))) + 1
        except ValueError:
            size = None
        out[m.group(1)] = {"range": f"{m.group(2)}-{m.group(3)}", "mask": m.group(4) or "",
                           "size": size}
    return out


def parse_pool_usage(text):
    """show ip local pool: {begin-end: {"free", "in_use"}} (pool name is not
    printed per row on every version, so rows key by range)."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)\s+(\d+)"
                     r"\s+(\d+)", line)
        if m:
            out[f"{m.group(1)}-{m.group(2)}"] = {"free": int(m.group(3)),
                                                 "in_use": int(m.group(5))}
    return out


def parse_sessions(text):
    """vpn-sessiondb output as a list of {field: value} per session. Username,
    public IP and audit session id are dropped."""
    sessions = []
    cur = None
    for line in (text or "").splitlines():
        for m in re.finditer(r"([A-Z][A-Za-z .-]*?)\s*:\s*(.*?)(?=\s{2,}[A-Z][A-Za-z .-]*?\s*:|$)",
                             line):
            key, value = m.group(1).strip(), m.group(2).strip()
            if key in ("Username", "Connection"):
                cur = {}
                sessions.append(cur)
                if key == "Connection":
                    cur["Connection"] = value
                continue
            if cur is None or key in ("Public IP", "Audt Sess ID", "Username"):
                continue
            cur[key] = value
    return sessions


def session_bytes(s, key):
    try:
        return int(str(s.get(key, "")).split()[0])
    except (ValueError, IndexError):
        return None


def weak_reasons(policies, transforms, entry):
    """Why a tunnel's crypto counts as weak (DES, 3DES, MD5, DH 1/2/5,
    aggressive mode); empty when it does not."""
    reasons = []
    versions = [v for v in ("ikev1", "ikev2") if entry.get(v)] or ["ikev1", "ikev2"]
    for v in versions:
        for p in policies.get(v, []):
            text = " ".join([p["encryption"], p["hash"], p["integrity"]])
            if WEAK_ALGOS.search(text):
                reasons.append(f"{v} policy {p['priority']}: {text.strip()}")
            groups = set(p["group"].split())
            if groups & WEAK_DH:
                reasons.append(f"{v} policy {p['priority']}: DH group "
                               f"{' '.join(sorted(groups & WEAK_DH))}")
    for name in entry.get("transforms", []):
        t = transforms.get(name) or {}
        text = f"{t.get('encryption', '')} {t.get('integrity', '')}"
        if WEAK_ALGOS.search(text):
            reasons.append(f"{name}: {text.strip()}")
    if entry.get("pfs") in ("group1", "group2", "group5"):
        reasons.append(f"PFS {entry['pfs']}")
    if entry.get("aggressive"):
        reasons.append("IKEv1 aggressive mode")
    return reasons


def marginal_reasons(policies, transforms, entry):
    """SHA-1 as the only integrity, or DH 14 as the only group."""
    reasons = []
    versions = [v for v in ("ikev1", "ikev2") if entry.get(v)] or ["ikev1", "ikev2"]
    for v in versions:
        for p in policies.get(v, []):
            integ = (p["integrity"] or p["hash"]).split()
            if integ and all(SHA1_ONLY.match(i) for i in integ):
                reasons.append(f"{v} policy {p['priority']}: SHA-1 only")
            if p["group"].split() == ["14"]:
                reasons.append(f"{v} policy {p['priority']}: DH 14 only")
    for name in entry.get("transforms", []):
        integ = (transforms.get(name) or {}).get("integrity", "").split()
        if integ and all(SHA1_ONLY.match(i) for i in integ):
            reasons.append(f"{name}: SHA-1 only")
    return reasons


def webvpn_packages(config):
    """AnyConnect packages from the webvpn block."""
    pkgs = []
    for _, body in config_blocks(config, "webvpn"):
        for s in body:
            if m := re.match(r"anyconnect image (\S+)", s):
                pkgs.append(m.group(1).rsplit("/", 1)[-1].rsplit(":", 1)[-1])
    return pkgs


def webvpn_posture(config):
    text = "\n".join(s for _, body in config_blocks(config, "webvpn") for s in body)
    return {"hostscan": bool(re.search(r"^(hostscan|csd) image", text, re.M)),
            "dap": sorted(set(re.findall(r"^dynamic-access-policy-record (\S+)",
                                         config or "", re.M)) - {"DfltAccessPolicy"})}
