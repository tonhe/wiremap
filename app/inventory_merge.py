"""Merge several scan inventories into one.

An engagement accumulates scans -- a discovery here, a targeted run there, an
edge assessment from a different seed -- and the as-built picture lives across
all of them. This folds them together using the same identity rules discovery
uses within a single scan, so a device named three ways is still one device.

Conflict rule, in order:
  1. A device that was logged into beats one only seen in a neighbour table.
  2. Between two collected records, the one carrying more collector data wins.
  3. Failing that, the newer scan wins.

The loser is never discarded -- it fills fields the winner lacks, and its
collector data and evidence are folded in. Sources are never modified.
"""
import copy
import logging
import os
from datetime import datetime, timezone

try:
    from app.failures import reason_counts, plain_failures
except ImportError:
    from failures import reason_counts, plain_failures
try:
    from app.source_access import refused_hint
except ImportError:
    from source_access import refused_hint
try:
    from app.inventory import refresh_categories
except ImportError:
    from inventory import refresh_categories
try:
    from app.target_outcomes import (COLLECTED, MERGED, FAILED, SKIPPED,
                                     UNRESOLVED, NOT_ATTEMPTED, outcome_counts,
                                     reconcile, target_list)
except ImportError:
    from target_outcomes import (COLLECTED, MERGED, FAILED, SKIPPED,
                                 UNRESOLVED, NOT_ATTEMPTED, outcome_counts,
                                 reconcile, target_list)

logger = logging.getLogger(__name__)


def _norm(hostname):
    try:
        from app.identity import normalize_hostname
    except ImportError:
        from identity import normalize_hostname
    return normalize_hostname(hostname)


def _serial(device):
    return (device.get("serial") or "").strip()


def _trusted_serial(device):
    """Serial usable as proof of a distinct chassis (see collected_serial)."""
    try:
        from app.identity import collected_serial
    except ImportError:
        from identity import collected_serial
    return collected_serial(device)


def _rank(device, timestamp):
    """Sort key -- lower is better."""
    return (
        not device.get("login_succeeded"),
        -len(device.get("collector_data") or {}),
        _negated_timestamp(timestamp),
    )


def _negated_timestamp(timestamp):
    """Newer sorts first. Unparseable timestamps sort last."""
    if not timestamp:
        return 0
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return -parsed.timestamp()
    except ValueError:
        return 0


def pick_winner(device_a, timestamp_a, device_b, timestamp_b):
    """Return whichever record should survive a conflict."""
    return min(
        ((device_a, timestamp_a), (device_b, timestamp_b)),
        key=lambda pair: _rank(pair[0], pair[1]),
    )[0]


def _fold(winner, loser):
    """Fill the winner's gaps from the loser without overwriting anything."""
    for field, value in loser.items():
        if field in ("hostname", "collector_data", "evidence",
                     "unresolved_neighbours"):
            continue
        if not winner.get(field) and value:
            winner[field] = value

    for name, data in (loser.get("collector_data") or {}).items():
        winner.setdefault("collector_data", {}).setdefault(name, data)

    existing = winner.setdefault("evidence", [])
    seen = {_evidence_key(e) for e in existing}
    for entry in loser.get("evidence") or []:
        key = _evidence_key(entry)
        if key not in seen:
            seen.add(key)
            existing.append(entry)

    unresolved = winner.setdefault("unresolved_neighbours", [])
    known = {_evidence_key(u) for u in unresolved}
    for entry in loser.get("unresolved_neighbours") or []:
        key = _evidence_key(entry)
        if key not in known:
            known.add(key)
            unresolved.append(entry)
    if not unresolved:
        winner.pop("unresolved_neighbours", None)


def _evidence_key(entry):
    if not isinstance(entry, dict):
        return str(entry)
    return tuple(sorted((k, str(v)) for k, v in entry.items()))


def _reason(winner, loser):
    """Which rule decided this conflict, in words."""
    if bool(winner.get("login_succeeded")) != bool(loser.get("login_succeeded")):
        return ("logged-in record preferred over a neighbour sighting, "
                "which carries no collected data")
    win_count = len(winner.get("collector_data") or {})
    lose_count = len(loser.get("collector_data") or {})
    if win_count != lose_count:
        return (f"more collector data ({win_count} collectors vs "
                f"{lose_count})")
    return "newer scan"


def _merge_group(group):
    """Fold one device's records together.

    Returns (hostname, device, conflicts). A conflict is recorded whenever
    two records described the same device, so a merge never silently picks a
    winner without saying what it set aside.
    """
    ordered = sorted(group, key=lambda r: _rank(r[1], r[2]))
    winner_name, winner, _ = ordered[0]
    winner_source = winner.get("source_scan", "")

    conflicts = []
    seen_sources = {winner_source}
    for loser_name, loser, _ in ordered[1:]:
        # Two records from the same scan are one record reached twice, e.g.
        # a scan merged again alongside a merge that already contains it.
        loser_source = loser.get("source_scan", "")
        if loser_source and loser_source in seen_sources:
            _fold(winner, loser)
            continue
        seen_sources.add(loser_source)
        conflicts.append({
            "hostname": winner_name,
            "also_named": loser_name if loser_name != winner_name else "",
            "kept_from": winner_source,
            "discarded_from": loser.get("source_scan", ""),
            "reason": _reason(winner, loser),
        })
        _fold(winner, loser)

    # The winner's mgmt_ip is whatever its own scan happened to see first.
    # With every sighting folded in, choose it by rule instead.
    if winner.get("login_succeeded"):
        try:
            from app.identity import resolve_mgmt_ip
        except ImportError:
            from identity import resolve_mgmt_ip
        ip, source = resolve_mgmt_ip(winner)
        if ip:
            winner["mgmt_ip"] = ip
            winner["mgmt_ip_source"] = source

    winner["hostname"] = winner_name
    return winner_name, winner, conflicts


def _source_entry(inventory, filename):
    # Source address, access check and run time belong to the run that
    # produced them, so they stay with that run rather than being blended.
    summary = inventory.get("scan_summary") or {}
    entry = {
        "discovery_id": inventory.get("discovery_id", "unknown"),
        "filename": filename or f"{inventory.get('discovery_id', 'unknown')}.json",
        "seed_ip": inventory.get("seed_ip", ""),
        "timestamp": inventory.get("timestamp", ""),
        "device_count": len(inventory.get("devices") or {}),
    }
    for field in _PER_RUN_FIELDS:
        if summary.get(field) is not None:
            entry[field] = copy.deepcopy(summary[field])
    return entry


_PER_RUN_FIELDS = ("source_ip", "source_ip_method", "source_access_line",
                   "source_access_warnings", "elapsed", "slowest")

# Settings that describe one run. Kept on the merge only when every input
# agrees, since a merged value would describe no run that happened.
_AGREED_FIELDS = ("source_ip", "source_ip_method", "source_access",
                  "source_access_line", "max_logins_per_minute")

_OUTCOME_RANK = {
    COLLECTED: 0,
    MERGED: 1,
    FAILED: 2,
    SKIPPED: 3,
    UNRESOLVED: 4,
    NOT_ATTEMPTED: 5,
}


def _agreed(summaries, field):
    values = [s.get(field) for s in summaries]
    if values and values[0] and all(v == values[0] for v in values):
        return values[0]
    return None


def _target_rank(target):
    return _OUTCOME_RANK.get(target.get("outcome"), 9)


def _target_key(target):
    return str(target.get("input") or target.get("resolved_ip") or "").strip().lower()


def _scan_targets(inventory):
    """The scan's requested hosts. Scans from before every target carried an
    outcome listed only resolved names in the summary, with address lines in
    params.target_ips, so those are rebuilt into one list."""
    summary = inventory.get("scan_summary") or {}
    targets = summary.get("targets") or []
    if any(t.get("outcome") for t in targets):
        return targets
    ips = (inventory.get("params") or {}).get("target_ips") or []
    return target_list({"targets": targets,
                        "unresolved": summary.get("unresolved") or []},
                       [(ip, None) for ip in ips])


def _merge_targets(inventories, reached_by_ip, failed, skipped):
    """One target per requested host across every scan.

    A host listed in several scans takes its best outcome, then is checked
    against the merged set: failed in one scan but collected in another is
    collected.
    """
    best = {}
    best_resolved = {}
    for inventory in inventories:
        for target in _scan_targets(inventory):
            key = _target_key(target)
            if not key:
                continue
            for pool, ok in ((best, True),
                             (best_resolved, bool(target.get("resolved_ip")))):
                if ok and (key not in pool or _target_rank(target)
                           < _target_rank(pool[key])):
                    pool[key] = dict(target)

    out = []
    for key, target in best.items():
        # A name that resolved in any scan does resolve; "unresolved" from
        # another scan would contradict the address we hold for it.
        if not target.get("resolved_ip") and key in best_resolved:
            target = best_resolved[key]
        ip = target.get("resolved_ip")
        hostname = reached_by_ip.get(ip) if ip else None
        if hostname:
            if target.get("outcome") != MERGED:
                target["outcome"] = COLLECTED
                target.pop("reason", None)
            target["hostname"] = hostname
        elif (target.get("outcome") == FAILED
              and ip in skipped and ip not in failed):
            entry = skipped[ip] if isinstance(skipped[ip], dict) else {}
            target["outcome"] = SKIPPED
            target["reason"] = entry.get("reason") or "skipped"
        elif not target.get("outcome"):
            # Rebuilt from an older scan, which never recorded one.
            target = reconcile([target], {}, {}, {}, failed, skipped)[0]
        out.append(target)
    return out


def _merge_unresolved(summaries, targets):
    """Names that failed to resolve in every scan that listed them."""
    resolved = {_target_key(t) for t in targets if t.get("resolved_ip")}
    out = {}
    for summary in summaries:
        for entry in summary.get("unresolved") or []:
            key = _target_key(entry)
            if key and key not in resolved and key not in out:
                out[key] = dict(entry)
    return list(out.values())


def _not_attempted_map(value):
    if isinstance(value, dict):
        return {ip: entry for ip, entry in value.items()}
    out = {}
    for entry in value or []:
        if isinstance(entry, dict):
            ip = entry.get("ip") or entry.get("mgmt_ip") or ""
            if ip:
                out[ip] = entry
        elif entry:
            out[str(entry)] = {}
    return out


def _merge_not_attempted(summaries, attempted):
    """Addresses no scan tried. One that any scan reached, failed or
    skipped was attempted, so it is not a gap in the merged view."""
    out = {}
    for summary in summaries:
        for ip, entry in _not_attempted_map(summary.get("not_attempted")).items():
            if ip not in attempted and ip not in out:
                out[ip] = entry
    return out


def _merge_warnings(summaries):
    out = []
    for summary in summaries:
        for warning in summary.get("source_access_warnings") or []:
            if warning not in out:
                out.append(warning)
    return out


def _sources(inventories, filenames):
    """merged_from for the new merge.

    An input that is itself a merge contributes its original scans, each
    tagged with the merge it came through, so lineage always names the scans
    that collected the data. A scan reached by two routes is listed once.
    """
    sources = []
    seen = set()
    for inventory, filename in zip(inventories, filenames):
        earlier = inventory.get("merged_from") or []
        if earlier:
            via = inventory.get("discovery_id", "unknown")
            entries = []
            for entry in earlier:
                entry = dict(entry)
                entry.setdefault("via", via)
                entries.append(entry)
        else:
            entries = [_source_entry(inventory, filename)]
        for entry in entries:
            if entry.get("discovery_id") in seen:
                continue
            seen.add(entry.get("discovery_id"))
            sources.append(entry)
    return sources


def _conflict_key(conflict):
    return (conflict.get("hostname", ""), conflict.get("also_named", ""),
            conflict.get("kept_from", ""), conflict.get("discarded_from", ""))


def _earlier_conflicts(inventories):
    """Conflicts already settled by merges among the inputs."""
    out = []
    seen = set()
    for inventory in inventories:
        for conflict in inventory.get("merge_conflicts") or []:
            key = _conflict_key(conflict)
            if key not in seen:
                seen.add(key)
                out.append(dict(conflict))
    return out


def claim_unused_id(merged, directory):
    """Give a merged scan an id no file in directory already uses.

    Merged ids are named to the second, so two merges in the same second
    would otherwise save over one another.
    """
    base = merged["discovery_id"]
    candidate, n = base, 2
    while os.path.exists(os.path.join(directory, f"{candidate}.json")):
        candidate = f"{base}-{n}"
        n += 1
    merged["discovery_id"] = candidate
    return candidate


def merge_inventories(inventories: list, filenames: list = None) -> dict:
    """Merge inventory dicts into a new one. Sources are not modified."""
    if not inventories or len(inventories) < 2:
        raise ValueError("Merging needs at least two inventories")

    now = datetime.now(timezone.utc)
    filenames = filenames or [None] * len(inventories)

    sources = _sources(inventories, filenames)
    # A record from an earlier merge belongs to the scan that collected it,
    # not to the merge file, which is stamped with the time of the merge.
    source_times = {s.get("discovery_id"): s.get("timestamp", "")
                    for s in sources}

    # (hostname, device, timestamp) for every record across every file. Each
    # device remembers which scan it came from, so a merged inventory can
    # answer "where did this come from" per device, not just per file. A
    # record from an earlier merge keeps the scan it names. Any other input
    # (a continuation of a merge, say) owns all of its records, since its
    # merged_from no longer lists those older scans.
    records = []
    for inventory in inventories:
        timestamp = inventory.get("timestamp", "")
        source_id = inventory.get("discovery_id", "unknown")
        is_merge = bool(inventory.get("merged_from"))
        for hostname, device in (inventory.get("devices") or {}).items():
            device = copy.deepcopy(device)
            if not (is_merge and device.get("source_scan")):
                device["source_scan"] = source_id
            # So an older scan's capability guess does not outvote the model.
            refresh_categories({"devices": {hostname: device}})
            records.append((hostname, device,
                            source_times.get(device["source_scan"], timestamp)))

    # Group by normalized hostname. A neighbour sighting carries no serial, so
    # grouping by serial first would never pair it with its collected twin.
    by_host = {}
    for record in records:
        by_host.setdefault(_norm(record[0]), []).append(record)

    groups = []
    for host_records in by_host.values():
        serials = {_trusted_serial(d) for _, d, _ in host_records}
        serials.discard("")
        if len(serials) <= 1:
            groups.append(host_records)
            continue
        # Conflicting serials under one name are genuinely different chassis.
        per_serial = {}
        unknown = []
        for record in host_records:
            serial = _trusted_serial(record[1])
            if serial:
                per_serial.setdefault(serial, []).append(record)
            else:
                unknown.append(record)
        groups.extend(per_serial.values())
        if unknown:
            groups.append(unknown)

    # A device renamed between scans still shares a serial, so fold those too.
    by_serial = {}
    final_groups = []
    for group in groups:
        serials = {_serial(d) for _, d, _ in group}
        serials.discard("")
        serial = next(iter(serials)) if len(serials) == 1 else None
        if serial and serial in by_serial:
            by_serial[serial].extend(group)
        elif serial:
            by_serial[serial] = list(group)
            final_groups.append(by_serial[serial])
        else:
            final_groups.append(group)

    merged_devices = {}
    merge_conflicts = _earlier_conflicts(inventories)
    seen_conflicts = {_conflict_key(c) for c in merge_conflicts}
    for group in final_groups:
        hostname, device, conflicts = _merge_group(group)
        # Two distinct chassis can still share a name; keep both.
        if hostname in merged_devices:
            hostname = f"{hostname} ({_serial(device) or len(merged_devices)})"
        merged_devices[hostname] = device
        for conflict in conflicts:
            key = _conflict_key(conflict)
            if key not in seen_conflicts:
                seen_conflicts.add(key)
                merge_conflicts.append(conflict)

    # Failures carry over, except for devices that were reached somewhere.
    reached_by_ip = {}
    for name, dev in merged_devices.items():
        if not dev.get("login_succeeded"):
            continue
        for field in ("mgmt_ip", "reached_ip"):
            if dev.get(field):
                reached_by_ip.setdefault(dev[field], name)
    reached = set(reached_by_ip)
    summaries = [inventory.get("scan_summary") or {} for inventory in inventories]
    failed = {}
    skipped = {}
    out_of_scope = []
    elapsed = 0.0
    for summary in summaries:
        elapsed += float(summary.get("elapsed") or 0)
        for ip, error in (summary.get("failed") or {}).items():
            if ip in reached:
                continue
            # A classified record beats an old bare string for the same host.
            if isinstance(failed.get(ip), dict) and not isinstance(error, dict):
                continue
            failed[ip] = error
        for ip, record in (summary.get("skipped") or {}).items():
            if ip not in reached:
                skipped[ip] = record
        for ip in summary.get("out_of_scope") or []:
            if ip not in reached and ip not in out_of_scope:
                out_of_scope.append(ip)
    # A controller-managed device skipped in one scan is not a failure in
    # the merged view just because an older scan tried and failed it.
    for ip in skipped:
        failed.pop(ip, None)

    targets = _merge_targets(inventories, reached_by_ip, failed, skipped)
    not_attempted = _merge_not_attempted(
        summaries, reached | set(failed) | set(skipped))

    seeds = [s.get("seed_ip", "") for s in sources if s.get("seed_ip")]
    discovery_id = f"{now.strftime('%Y-%m-%d_%H-%M-%S')}_merged"

    logger.info(
        f"Merged {len(inventories)} inventories into {len(merged_devices)} "
        f"device(s) from {sum(len(i.get('devices') or {}) for i in inventories)} "
        f"input record(s)"
    )

    # Timing and slowest-device lists are per run and stay on each
    # merged_from entry; elapsed is the sum of the runs, and says so.
    scan_summary = {
        "elapsed": round(elapsed, 1),
        "elapsed_summed": True,
        "failed_count": len(plain_failures(failed)),
        "failed": failed,
        "failure_reasons": reason_counts(failed),
        "skipped_count": len(skipped),
        "skipped": skipped,
        "out_of_scope": out_of_scope,
        "out_of_scope_count": len(out_of_scope),
        "device_ceiling_hit": any(s.get("device_ceiling_hit") for s in summaries),
        "not_attempted": not_attempted,
        "not_attempted_count": len(not_attempted),
        "source_access_warnings": _merge_warnings(summaries),
    }
    # Each run's own address, since the runs may not share one.
    source_ips = [{key: s[key] for key in ("filename", "source_ip",
                                          "source_ip_method") if s.get(key)}
                  for s in sources if s.get("source_ip")]
    if source_ips:
        scan_summary["source_ips"] = source_ips
    for field in _AGREED_FIELDS:
        value = _agreed(summaries, field)
        if value is not None:
            scan_summary[field] = copy.deepcopy(value)
    hint = refused_hint(failed, scan_summary.get("source_ip"))
    if hint:
        scan_summary["refused_hint"] = hint
    if targets:
        scan_summary["targets"] = targets
        scan_summary["unresolved"] = _merge_unresolved(summaries, targets)
        scan_summary["target_outcomes"] = outcome_counts(targets)

    return {
        "discovery_id": discovery_id,
        "seed_ip": seeds[0] if seeds else "",
        "timestamp": now.isoformat(),
        "params": {
            "merged": True,
            "source_seeds": seeds,
        },
        "merged_from": sources,
        "merge_conflicts": merge_conflicts,
        "devices": merged_devices,
        "scan_summary": scan_summary,
    }
