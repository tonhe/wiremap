"""
ASA report: Access Lists, ACL Lines, Objects and NAT sheets and the rule-base
checks. Built per unit and context from the stored running-config,
show access-list and show nat detail, so scans re-report without the device.
"""
import re

from . import asa_checks as checks

try:
    from app.collectors import asa_policy as pol
except ImportError:
    from collectors import asa_policy as pol

NA = "n/a"
ZERO_HIT_MIN_DAYS = 30

ANY_ANY_INBOUND = "Any-any permit inbound on a lower-security interface"
ANY_PORT_INTERNAL = "Any-port permit to internal subnets"
ZERO_HITS = "Rules with zero hits"
SHADOWED = "Shadowed or redundant ACL lines"
UNUSED_OBJECTS = "Unused objects / object-groups"
NAT_EXPOSED = "Static NAT exposing internal hosts publicly with zero hits"


def uptime_days(text):
    """'1 year 34 days 3 hours' -> 399; None when unknown."""
    if not text:
        return None
    days = 0
    found = False
    for num, unit in re.findall(r"(\d+)\s+(year|week|day)", text):
        found = True
        days += int(num) * {"year": 365, "week": 7, "day": 1}[unit]
    if not found and re.search(r"\d+\s+(hour|min|sec)", text):
        return 0
    return days if found else None


class PolicyView:
    """Parsed policy for one unit context, built once per report."""

    def __init__(self, unit, context, ctx):
        outputs = unit.outputs_for(context)
        self.config = outputs.get("show running-config") or ""
        self.has_hits = bool(outputs.get("show access-list"))
        self.has_nat = "show nat detail" in outputs and bool(outputs.get("show nat detail"))
        self.objects = pol.parse_objects(self.config)
        self.expander = pol.Expander(self.objects)
        self.acls = pol.parse_acl_config(self.config, self.objects)
        self.hits, self.elements = pol.parse_acl_hits(outputs.get("show access-list"))
        self.bindings = pol.acl_bindings(self.config)
        self.directions = pol.interface_directions(self.config)
        self.levels = {i["nameif"]: i.get("security_level")
                       for i in ctx.get("interfaces") or [] if i.get("nameif")}
        self.refs = pol.object_references(self.config, self.objects)
        self.nat = pol.parse_nat_detail(outputs.get("show nat detail"))
        self._flags = {}

    def flags(self, acl):
        if acl not in self._flags:
            self._flags[acl] = pol.shadow_flags(self.acls[acl], self.expander)
        return self._flags[acl]

    def lower_security_inbound(self, acl):
        """nameifs this ACL filters inbound on where a higher-security
        interface exists in the same context."""
        levels = [lv for lv in self.levels.values() if lv is not None]
        top = max(levels) if levels else None
        return [n for n, d in self.directions.get(acl, [])
                if d == "in" and self.levels.get(n) is not None and top is not None
                and self.levels[n] < top]

    def hit(self, acl, line):
        if not self.has_hits:
            return None
        rec = self.hits.get((acl, line))
        return rec["hits"] if rec else None


def views(unit):
    if unit.is_standby:
        return []
    if not hasattr(unit, "_policy_views"):
        unit._policy_views = [(name, PolicyView(unit, name, ctx)) for name, ctx in unit.contexts]
    return unit._policy_views


def _is_any_any(e):
    return e["protocol"] in ("ip", "ipv4") and e["src_kind"] == "any" and e["dst_kind"] == "any"


def _any_port(view, e):
    if _is_any_any(e):
        return False
    svc = pol.LineView(e, view.expander).svc
    return any(p == "ip" or (p in ("tcp", "udp") and d == pol.ANY_PORTS) for p, _, d in svc)


# ---------------------------------------------------------------------------
# Sheets
# ---------------------------------------------------------------------------

ACL_HEADERS = ["Hostname", "Context", "Site", "ACL Name", "Bound To", "Lines (Config)",
               "Elements (Expanded)", "Permit Lines", "Deny Lines", "Zero-hit Lines",
               "Any-any Permit Lines", "Any + IP Lines", "Remarks", "Log Lines",
               "Inactive Lines", "Shadow Check"]
LINE_HEADERS = ["Hostname", "Context", "Site", "ACL Name", "Line", "Action",
                "Protocol / Service", "Source", "Source Expanded", "Destination",
                "Destination Expanded", "Ports / Service Group", "Ports Expanded",
                "Hit Count", "Hash", "Log", "Time-range / Inactive", "Remark Above", "Flags"]
OBJECT_HEADERS = ["Hostname", "Context", "Site", "Name", "Type", "Members",
                  "Expanded Prefixes or Ports", "Referenced By", "Unused", "Duplicate Of",
                  "Description"]
NAT_HEADERS = ["Hostname", "Context", "Site", "Section", "Rule", "Type", "Real Interface",
               "Mapped Interface", "Real Source", "Mapped Source", "Real Destination",
               "Mapped Destination", "Service", "Translate Hits", "Untranslate Hits",
               "Flags", "Public IP Exposed", "Zero Hits"]


def acl_rows(unit):
    rows = []
    for name, v in views(unit):
        for acl, lines in v.acls.items():
            entries = [e for e in lines if e.get("action")]
            flags = v.flags(acl)
            zero = [e for e in entries if not e["inactive"] and v.hit(acl, e["line"]) == 0]
            rows.append(unit.lead(name) + [
                acl, ", ".join(v.bindings.get(acl, [])) or "unbound", len(lines),
                v.elements.get(acl, NA) if v.has_hits else NA,
                sum(1 for e in entries if e["action"] == "permit"),
                sum(1 for e in entries if e["action"] == "deny"),
                len(zero) if v.has_hits else NA,
                sum(1 for e in entries if e["action"] == "permit" and _is_any_any(e)),
                sum(1 for e in entries if e["protocol"] in ("ip", "ipv4")
                    and "any" in (e["src_kind"], e["dst_kind"])),
                sum(1 for e in lines if e.get("remark") is not None),
                sum(1 for e in entries if e["log"]),
                sum(1 for e in entries if e["inactive"] or e["time_range"]),
                "done" if flags is not None else
                f"skipped ({len(entries)} lines, over {pol.SHADOW_CHECK_LIMIT})"])
    return rows


def line_rows(unit):
    rows = []
    for name, v in views(unit):
        for acl, lines in v.acls.items():
            flags = v.flags(acl) or {}
            remark = ""
            for e in lines:
                if e.get("remark") is not None:
                    remark = e["remark"]
                    continue
                if not e.get("action"):
                    continue
                view = pol.LineView(e, v.expander)
                tags = []
                if _is_any_any(e):
                    tags.append("any-any")
                elif _any_port(v, e):
                    tags.append("any-port")
                if e["line"] in flags:
                    kind, by = flags[e["line"]]
                    tags.append(f"{kind} by line {by}")
                hits = v.hit(acl, e["line"])
                if hits == 0 and not e["inactive"]:
                    tags.append("zero hits")
                rec = v.hits.get((acl, e["line"])) or {}
                rows.append(unit.lead(name) + [
                    acl, e["line"], e["action"], e["protocol"], e["src"],
                    pol.format_nets(view.src), e["dst"], pol.format_nets(view.dst),
                    " ".join(x for x in (e["src_port"], e["dst_port"]) if x),
                    pol.format_services(view.svc), NA if hits is None else hits,
                    rec.get("hash", ""), "Yes" if e["log"] else "No",
                    " ".join(x for x in (e["time_range"],
                                         "inactive" if e["inactive"] else "") if x),
                    remark, ", ".join(tags)])
    return rows


def object_rows(unit):
    rows = []
    for name, v in views(unit):
        sigs = {}
        for oname, obj in v.objects.items():
            sigs.setdefault(pol.object_signature(obj, v.expander), []).append(oname)
        for oname, obj in v.objects.items():
            if obj["type"] == "network":
                expanded = pol.format_nets(v.expander.nets(oname))
            elif obj["type"] == "service":
                expanded = pol.format_services(v.expander.services(oname))
            else:
                expanded = ""
            twins = [o for o in sigs[pol.object_signature(obj, v.expander)] if o != oname]
            refs = v.refs.get(oname, [])
            rows.append(unit.lead(name) + [
                oname, f"{obj['kind']} {obj['type']}", "; ".join(obj["members"]), expanded,
                ", ".join(refs), "Yes" if not refs else "No", ", ".join(twins),
                obj["description"]])
    return rows


def nat_rows(unit):
    rows = []
    for name, v in views(unit):
        if not v.has_nat:
            continue
        for r in v.nat:
            zero = (r["translate_hits"] == 0 and r["untranslate_hits"] == 0
                    if r["translate_hits"] is not None else None)
            rows.append(unit.lead(name) + [
                r["section"], r["rule"], r["type"], r["real_if"], r["mapped_if"],
                _named(r["real_src"], r["src_origin"]),
                _named(r["mapped_src"], r["src_translated"]),
                _named(r["real_dst"], r["dst_origin"]),
                _named(r["mapped_dst"], r["dst_translated"]), r["service"],
                NA if r["translate_hits"] is None else r["translate_hits"],
                NA if r["untranslate_hits"] is None else r["untranslate_hits"],
                ", ".join(r["flags"]),
                NA if r["public"] is None else ("Yes" if r["public"] else "No"),
                NA if zero is None else ("Yes" if zero else "No")])
    return rows


def _named(name, value):
    if not name:
        return ""
    return f"{name} ({value})" if value and value != name else name


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def findings(unit):
    out = []
    days = uptime_days((unit.parsed.get("version") or {}).get("uptime"))
    for name, v in views(unit):
        for acl, lines in v.acls.items():
            entries = [e for e in lines if e.get("action") and not e["inactive"]]
            lower = v.lower_security_inbound(acl)
            if lower:
                for e in entries:
                    if e["action"] != "permit":
                        continue
                    if _is_any_any(e):
                        out.append(checks.finding(
                            unit, checks.HIGH, ANY_ANY_INBOUND,
                            f"{acl} line {e['line']} permits ip any any inbound on "
                            f"{', '.join(lower)}.", obj=f"{acl} line {e['line']}",
                            context=name, config_lines=[e["text"]]))
                    elif _any_port(v, e):
                        dst = pol.LineView(e, v.expander).dst
                        if dst != pol.ANY_NETS and dst and all(
                                not isinstance(n, str) and pol.is_private(n) for n in dst):
                            out.append(checks.finding(
                                unit, checks.MEDIUM, ANY_PORT_INTERNAL,
                                f"{acl} line {e['line']} permits every port to "
                                f"{pol.format_nets(dst, 5)} inbound on {', '.join(lower)}.",
                                obj=f"{acl} line {e['line']}", context=name,
                                config_lines=[e["text"]]))
            zero = [e for e in entries if v.hit(acl, e["line"]) == 0]
            if zero and days is not None and days >= ZERO_HIT_MIN_DAYS:
                out.append(checks.finding(
                    unit, checks.LOW, ZERO_HITS,
                    f"{acl}: {len(zero)} of {len(entries)} lines have no hits in "
                    f"{days} days of uptime (lines "
                    f"{', '.join(str(e['line']) for e in zero[:20])}"
                    f"{', ...' if len(zero) > 20 else ''}).",
                    obj=acl, context=name))
            flags = v.flags(acl) or {}
            if flags:
                shadowed = sorted(n for n, (k, _) in flags.items() if k == "shadowed")
                redundant = sorted(n for n, (k, _) in flags.items() if k == "redundant")
                parts = []
                if shadowed:
                    parts.append(f"{len(shadowed)} shadowed (lines "
                                 f"{', '.join(map(str, shadowed[:20]))})")
                if redundant:
                    parts.append(f"{len(redundant)} redundant (lines "
                                 f"{', '.join(map(str, redundant[:20]))})")
                out.append(checks.finding(
                    unit, checks.LOW, SHADOWED, f"{acl}: " + "; ".join(parts) + ".",
                    obj=acl, context=name,
                    config_lines=[e["text"] for e in lines if e.get("line") in flags][:20]))
        unused = [n for n, refs in v.refs.items() if not refs]
        if unused:
            out.append(checks.finding(
                unit, checks.INFO_RATING, UNUSED_OBJECTS,
                f"{len(unused)} unused: {', '.join(unused[:15])}"
                f"{', ...' if len(unused) > 15 else ''}.", obj="objects", context=name))
        for r in v.nat if v.has_nat else []:
            if (r["type"] == "static" and r["public"] and pol.is_private(
                    (r["src_origin"] or "").split(",")[0].strip())
                    and r["translate_hits"] == 0 and r["untranslate_hits"] == 0
                    and "inactive" not in r["flags"]):
                out.append(checks.finding(
                    unit, checks.MEDIUM, NAT_EXPOSED,
                    f"Section {r['section']} rule {r['rule']}: {r['real_src']} "
                    f"({r['src_origin']}) is published as {r['src_translated']} on "
                    f"{r['mapped_if']} and has never been used.",
                    obj=f"NAT {r['section']}/{r['rule']}", context=name,
                    config_lines=[r["text"]]))
    return out


def totals(unit_list):
    lines = sum(len([e for e in ls if e.get("action")]) for u in unit_list
                for _, v in views(u) for ls in v.acls.values())
    return lines
