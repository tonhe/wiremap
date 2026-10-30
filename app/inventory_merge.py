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
from datetime import datetime, timezone

try:
    from app.failures import reason_counts
except ImportError:
    from failures import reason_counts

logger = logging.getLogger(__name__)


def _norm(hostname):
    try:
        from app.identity import normalize_hostname
    except ImportError:
        from identity import normalize_hostname
    return normalize_hostname(hostname)


def _serial(device):
    return (device.get("serial") or "").strip()


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
    for loser_name, loser, _ in ordered[1:]:
        conflicts.append({
            "hostname": winner_name,
            "also_named": loser_name if loser_name != winner_name else "",
            "kept_from": winner_source,
            "discarded_from": loser.get("source_scan", ""),
            "reason": _reason(winner, loser),
        })
        _fold(winner, loser)

    winner["hostname"] = winner_name
    return winner_name, winner, conflicts


def merge_inventories(inventories: list, filenames: list = None) -> dict:
    """Merge inventory dicts into a new one. Sources are not modified."""
    if not inventories or len(inventories) < 2:
        raise ValueError("Merging needs at least two inventories")

    now = datetime.now(timezone.utc)
    filenames = filenames or [None] * len(inventories)

    sources = []
    for inventory, filename in zip(inventories, filenames):
        sources.append({
            "discovery_id": inventory.get("discovery_id", "unknown"),
            "filename": filename or f"{inventory.get('discovery_id', 'unknown')}.json",
            "seed_ip": inventory.get("seed_ip", ""),
            "timestamp": inventory.get("timestamp", ""),
            "device_count": len(inventory.get("devices") or {}),
        })

    # (hostname, device, timestamp) for every record across every file. Each
    # device remembers which scan it came from, so a merged inventory can
    # answer "where did this come from" per device, not just per file.
    records = []
    for inventory in inventories:
        timestamp = inventory.get("timestamp", "")
        source_id = inventory.get("discovery_id", "unknown")
        for hostname, device in (inventory.get("devices") or {}).items():
            device = copy.deepcopy(device)
            device["source_scan"] = source_id
            records.append((hostname, device, timestamp))

    # Group by normalized hostname. A neighbour sighting carries no serial, so
    # grouping by serial first would never pair it with its collected twin.
    by_host = {}
    for record in records:
        by_host.setdefault(_norm(record[0]), []).append(record)

    groups = []
    for host_records in by_host.values():
        serials = {_serial(d) for _, d, _ in host_records}
        serials.discard("")
        if len(serials) <= 1:
            groups.append(host_records)
            continue
        # Conflicting serials under one name are genuinely different chassis.
        per_serial = {}
        unknown = []
        for record in host_records:
            serial = _serial(record[1])
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
    merge_conflicts = []
    for group in final_groups:
        hostname, device, conflicts = _merge_group(group)
        # Two distinct chassis can still share a name; keep both.
        if hostname in merged_devices:
            hostname = f"{hostname} ({_serial(device) or len(merged_devices)})"
        merged_devices[hostname] = device
        merge_conflicts.extend(conflicts)

    # Failures carry over, except for devices that were reached somewhere.
    reached = {
        dev.get("mgmt_ip") for dev in merged_devices.values()
        if dev.get("login_succeeded") and dev.get("mgmt_ip")
    }
    failed = {}
    skipped = {}
    elapsed = 0.0
    for inventory in inventories:
        summary = inventory.get("scan_summary") or {}
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
    # A controller-managed device skipped in one scan is not a failure in
    # the merged view just because an older scan tried and failed it.
    for ip in skipped:
        failed.pop(ip, None)

    seeds = [inv.get("seed_ip", "") for inv in inventories if inv.get("seed_ip")]
    discovery_id = f"{now.strftime('%Y-%m-%d_%H-%M-%S')}_merged"

    logger.info(
        f"Merged {len(inventories)} inventories into {len(merged_devices)} "
        f"device(s) from {sum(len(i.get('devices') or {}) for i in inventories)} "
        f"input record(s)"
    )

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
        "scan_summary": {
            "elapsed": round(elapsed, 1),
            "failed_count": len(failed),
            "failed": failed,
            "failure_reasons": reason_counts(failed),
            "skipped_count": len(skipped),
            "skipped": skipped,
            "out_of_scope": [],
            "out_of_scope_count": 0,
            "device_ceiling_hit": False,
        },
    }
