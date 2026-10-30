"""
Target reconciliation -- what became of every host the operator listed.

A target can be collected, fail, be skipped on purpose, never resolve, turn
out to be a device already collected under another address, or never be
reached at all (a cancelled run). Without an explicit outcome the last two
cases simply vanish from the results, which reads as "not on the list".
"""
try:
    from app.identity import normalize_hostname
except ImportError:
    from identity import normalize_hostname

COLLECTED = "collected"
MERGED = "merged_into"
FAILED = "failed"
SKIPPED = "skipped"
UNRESOLVED = "unresolved"
NOT_ATTEMPTED = "not_attempted"

OUTCOMES = [COLLECTED, MERGED, FAILED, UNRESOLVED, SKIPPED, NOT_ATTEMPTED]

OUTCOME_LABELS = {
    COLLECTED: "collected",
    MERGED: "merged",
    FAILED: "failed",
    SKIPPED: "skipped",
    UNRESOLVED: "unresolved",
    NOT_ATTEMPTED: "not attempted",
}

# Always shown in the summary line, even at zero; the rest only when present.
_ALWAYS_SHOWN = (COLLECTED, MERGED, FAILED, UNRESOLVED)


def target_list(target_resolution, target_hosts):
    """[{"input", "resolved_ip"}] for every requested host.

    Names come from the resolution; addresses listed directly have no
    resolution entry, so each one not already covered by a name is its own
    target. Unresolved names follow with resolved_ip None.
    """
    resolution = target_resolution or {}
    targets = [dict(t) for t in resolution.get("targets") or []]
    covered = {t.get("resolved_ip") for t in targets}
    for ip, _ in target_hosts or []:
        if ip not in covered:
            targets.append({"input": ip, "resolved_ip": ip})
            covered.add(ip)
    for entry in resolution.get("unresolved") or []:
        targets.append({"input": entry.get("input"), "resolved_ip": None,
                        "error": entry.get("error") or ""})
    return targets


def _surviving_name(devices, hostname, serial, ip):
    """The record a collected hostname lives in after duplicate folding."""
    if hostname in devices:
        return hostname
    if serial:
        for name, dev in devices.items():
            if (dev.get("serial") or "").strip() == serial:
                return name
    norm = normalize_hostname(hostname)
    for name in devices:
        if normalize_hostname(name) == norm:
            return name
    for name, dev in devices.items():
        if dev.get("mgmt_ip") == ip:
            return name
    return hostname


def _outcome_for(ip, devices, collected, merged, failed, skipped, cancelled):
    if ip in collected:
        info = collected[ip]
        hostname = info.get("hostname")
        survivor = _surviving_name(devices, hostname, info.get("serial"), ip)
        if survivor != hostname:
            return {"outcome": MERGED, "hostname": survivor}
        return {"outcome": COLLECTED, "hostname": hostname}
    if ip in merged:
        hostname = merged[ip]
        return {"outcome": MERGED,
                "hostname": _surviving_name(devices, hostname, None, None)}
    if ip in skipped:
        entry = skipped[ip] or {}
        return {"outcome": SKIPPED, "hostname": entry.get("hostname"),
                "reason": entry.get("reason") or "skipped"}
    if ip in failed:
        record = failed[ip] or {}
        if not isinstance(record, dict):
            record = {"message": str(record)}
        return {"outcome": FAILED, "hostname": record.get("hostname"),
                "reason": record.get("reason") or "other"}
    return {"outcome": NOT_ATTEMPTED,
            "reason": "scan cancelled" if cancelled else "no result recorded"}


def reconcile(targets, devices, collected, merged, failed, skipped,
              cancelled=False):
    """Give every target an outcome. Returns new target dicts.

    collected maps IP -> {"hostname", "serial"} for logins this run; merged
    maps IP -> hostname for logins that turned out to be a device already
    collected under another address; failed and skipped are the scan
    summary maps.
    """
    out = []
    for target in targets:
        entry = {k: v for k, v in target.items() if k != "error"}
        ip = target.get("resolved_ip")
        if not ip:
            entry["outcome"] = UNRESOLVED
            entry["reason"] = target.get("error") or "name did not resolve"
        else:
            result = _outcome_for(ip, devices or {}, collected or {},
                                  merged or {}, failed or {}, skipped or {},
                                  cancelled)
            entry.update({k: v for k, v in result.items() if v is not None})
        out.append(entry)
    return out


def outcome_counts(targets):
    counts = {o: 0 for o in OUTCOMES}
    for t in targets or []:
        outcome = t.get("outcome") or NOT_ATTEMPTED
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def summary_line(targets):
    """'Targets: 3 collected, 1 merged, 1 failed, 0 unresolved' -- None for
    a run with no target list."""
    if not targets:
        return None
    counts = outcome_counts(targets)
    parts = [f"{counts[o]} {OUTCOME_LABELS[o]}" for o in OUTCOMES
             if o in _ALWAYS_SHOWN or counts.get(o)]
    return "Targets: " + ", ".join(parts)
