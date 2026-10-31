"""Generate reports and work with saved scans from the command line.

Runs the same report code as the Reports tab, without the web app.

    python app/wiremap_cli.py                                  # menu: pick scan and reports
    python app/wiremap_cli.py list scan.json
    python app/wiremap_cli.py report scan.json                 # every report that applies
    python app/wiremap_cli.py report scan.json -r device_inventory -f csv -o out/
    python app/wiremap_cli.py report a.json b.json             # merged first, then reported
    python app/wiremap_cli.py summary scan.json
    python app/wiremap_cli.py merge a.json b.json -o merged.json

Inside the container:

    docker compose exec wiremap python wiremap_cli.py report \
        /app/inventories/<scan>.json -o /app/inventories/reports

The EoX report reads the Cisco API credentials saved in Settings from the
config directory (/app/config in the container, ./config next to app/ on a
host checkout, or --config-dir). Without them it is skipped. --offline skips
it regardless, since it is the only report that makes network calls.
"""
import argparse
import json
import os
import sys

if __name__ == "__main__":
    # Run as a script, this directory is first on sys.path and app.py would
    # shadow the app package. Block it so every import falls back to flat.
    sys.modules.setdefault("app", None)

try:
    from app import merge_scans
    from app.inventory import DiscoveryInventory
    from app.inventory_merge import merge_inventories
    from app.reports import get_registry
    from app.target_outcomes import summary_line
except ImportError:
    import merge_scans
    from inventory import DiscoveryInventory
    from inventory_merge import merge_inventories
    from reports import get_registry
    from target_outcomes import summary_line

# Reports that call out to an external API.
NETWORK_REPORTS = {"eox_lifecycle"}


def default_config_dir():
    env = os.environ.get("WIREMAP_CONFIG_DIR")
    if env:
        return env
    if os.path.isdir("/app/config"):
        return "/app/config"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "config")


def use_config_dir(config_dir):
    """Point plugin config lookups at config_dir. The EoX report imports
    plugins flat, so both import paths are set."""
    for name in ("plugins", "app.plugins"):
        try:
            module = __import__(name, fromlist=["DEFAULT_CONFIG_DIR"])
        except ImportError:
            continue
        module.DEFAULT_CONFIG_DIR = config_dir


def load_scan(path):
    """Return the scan dict at path, or raise ValueError with the reason."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError(f"could not read {path}: {e}")
    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(f"{path} is not a wiremap scan (no devices key)")
    return data


def load_inputs(paths):
    """One scan, or several merged into one. Returns (inventory dict, files)."""
    files = merge_scans.expand_paths(paths)
    if not files:
        raise ValueError("no scan files found")
    scans = [load_scan(p) for p in files]
    if len(scans) == 1:
        return DiscoveryInventory(scans[0]).to_dict(), files
    merged = merge_inventories(scans, filenames=[os.path.basename(p) for p in files])
    return DiscoveryInventory(merged).to_dict(), files


def pick_format(report, requested):
    """The requested format when the report supports it, else its native one."""
    if requested and requested in report.supported_formats:
        return requested
    return report.supported_formats[0]


def select_reports(registry, names):
    """Reports to run, in registry order. Unknown names raise ValueError."""
    if not names:
        return list(registry.values())
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(f"unknown report(s): {', '.join(unknown)} "
                         f"(see the list command)")
    return [registry[n] for n in names]


def cmd_list(args):
    registry = get_registry()
    data = None
    if args.paths:
        data, _ = load_inputs(args.paths)
    width = max(len(n) for n in registry)
    for report in registry.values():
        formats = ",".join(report.supported_formats)
        status = ""
        if data is not None:
            status = "yes" if report.can_generate(data) else "no "
            status = f"{status}  "
        print(f"{status}{report.name:<{width}}  {formats:<18}  {report.label}")
    return 0


def cmd_report(args):
    data, files = load_inputs(args.paths)
    registry = get_registry()
    reports = select_reports(registry, args.report)
    explicit = bool(args.report)
    key = data.get("discovery_id") or "scan"
    outdir = args.output or key
    os.makedirs(outdir, exist_ok=True)

    if len(files) > 1:
        print(f"Merged {len(files)} scans into {len(data.get('devices') or {})} devices")

    written, skipped, failed = [], [], []
    for report in reports:
        if args.offline and report.name in NETWORK_REPORTS:
            skipped.append((report.name, "--offline"))
            continue
        if not report.can_generate(data):
            reason = "not enough data in this scan"
            if report.name in NETWORK_REPORTS:
                reason += " or Cisco API credentials not configured"
            skipped.append((report.name, reason))
            continue
        if args.format and args.format not in report.supported_formats and explicit:
            print(f"  note: {report.name} has no {args.format} output, "
                  f"writing {report.supported_formats[0]}")
        fmt = pick_format(report, args.format)
        try:
            content = report.generate(data, fmt)
        except Exception as e:
            failed.append((report.name, f"{type(e).__name__}: {e}"))
            continue
        path = os.path.join(outdir, f"{report.name}_{key}.{fmt}")
        with open(path, "wb") as f:
            f.write(content)
        written.append(path)

    for path in written:
        print(f"  wrote   {path}")
    for name, reason in skipped:
        print(f"  skipped {name}: {reason}")
    for name, reason in failed:
        print(f"  FAILED  {name}: {reason}")
    print(f"{len(written)} written, {len(skipped)} skipped, {len(failed)} failed")

    if failed:
        return 1
    # Asking for a report by name and not getting it is a failure; skipping
    # the inapplicable ones in an "everything" run is not.
    if explicit and skipped:
        return 1
    return 0


def cmd_summary(args):
    data, files = load_inputs(args.paths)
    inventory = DiscoveryInventory(data)
    s = inventory.get_summary()
    stored = data.get("scan_summary") or {}
    devices = data.get("devices") or {}
    logged_in = sum(1 for d in devices.values() if d.get("login_succeeded"))

    print(f"Scan:      {data.get('discovery_id', '-')}")
    if len(files) > 1:
        print(f"Merged:    {len(files)} files")
    print(f"Seed:      {s['seed_ip'] or '-'}")
    print(f"Started:   {s['timestamp'] or '-'}")
    if s["elapsed"] is not None:
        print(f"Elapsed:   {s['elapsed']}s")
    print(f"Devices:   {s['device_count']} ({logged_in} logged into)")
    if s["failed_count"]:
        reasons = ", ".join(f"{r['count']} {r['label']}" for r in s["failure_reasons"])
        print(f"Failed:    {s['failed_count']} ({reasons})")
        for r in s["failure_reasons"]:
            if r["hint"]:
                print(f"  {r['label']}: {r['hint']}")
    if s["skipped_count"]:
        print(f"Skipped:   {s['skipped_count']}")
    if stored.get("not_attempted_count"):
        print(f"Not attempted: {stored['not_attempted_count']}")
    line = summary_line(stored.get("targets"))
    if line:
        print(line)
    if s["source_ip"]:
        method = f" ({s['source_ip_method']})" if s["source_ip_method"] else ""
        print(f"Source IP: {s['source_ip']}{method}")
    if s["source_access_line"]:
        print(s["source_access_line"])
    for warning in s["source_access_warnings"]:
        print(f"  warning: {warning}")
    if s["refused_hint"]:
        print(s["refused_hint"])
    return 0


def cmd_merge(args):
    return merge_scans.main(args.merge_args)


def default_inventory_dir():
    if os.path.isdir("/app/inventories"):
        return "/app/inventories"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "inventories")


def parse_choice(text, count):
    """'1,3-5' -> [0, 2, 3, 4]. 'a'/'all' or blank -> every item. Raises
    ValueError on anything out of range."""
    text = (text or "").strip().lower()
    if text in ("", "a", "all"):
        return list(range(count))
    picked = []
    for part in text.replace(" ", ",").split(","):
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            nums = range(int(lo), int(hi) + 1)
        else:
            nums = [int(part)]
        for n in nums:
            if not 1 <= n <= count:
                raise ValueError(f"{n} is not between 1 and {count}")
            if n - 1 not in picked:
                picked.append(n - 1)
    return picked


def ask(prompt, count, input_fn):
    while True:
        try:
            return parse_choice(input_fn(prompt), count)
        except ValueError as e:
            print(f"  {e}")


def cmd_menu(args, input_fn=input):
    """Pick scans, reports and format from numbered lists."""
    scan_dir = args.inventory_dir or default_inventory_dir()
    files = sorted(merge_scans.expand_paths([scan_dir]),
                   key=os.path.getmtime, reverse=True) if os.path.isdir(scan_dir) else []
    if not files:
        print(f"No scans in {scan_dir} (set one with --inventory-dir)")
        return 1

    print(f"Scans in {scan_dir}, newest first:")
    for i, path in enumerate(files, 1):
        print(f"  {i:>2}. {os.path.basename(path)}")
    picked = ask("Scan(s) to use, e.g. 1 or 1,3 (several are merged) [1]: ",
                 len(files), lambda p: input_fn(p) or "1")
    paths = [files[i] for i in picked]
    data, _ = load_inputs(paths)

    registry = get_registry()
    ready = [r for r in registry.values() if r.can_generate(data)]
    if not ready:
        print("No report applies to this scan")
        return 1
    print("Reports that apply:")
    for i, report in enumerate(ready, 1):
        print(f"  {i:>2}. {report.label} ({','.join(report.supported_formats)})")
    chosen = [ready[i] for i in ask("Reports, e.g. 1,4-6 [all]: ", len(ready), input_fn)]

    formats = ["native", "xlsx", "csv", "json", "xml"]
    print("Format: " + ", ".join(f"{i}. {f}" for i, f in enumerate(formats, 1)))
    fmt_idx = ask("Format [1]: ", len(formats), lambda p: input_fn(p) or "1")[0]
    key = data.get("discovery_id") or "scan"
    outdir = input_fn(f"Output directory [{key}]: ").strip() or key

    report_args = argparse.Namespace(
        paths=paths, report=[r.name for r in chosen],
        format=None if fmt_idx == 0 else formats[fmt_idx],
        output=outdir, offline=False)
    return cmd_report(report_args)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wiremap_cli",
        description="Generate wiremap reports and work with saved scans.")
    parser.add_argument("--config-dir",
                        help="directory holding plugins.json and plugins.key "
                             "(default: %(default)s)",
                        default=default_config_dir())
    parser.add_argument("--inventory-dir",
                        help="where the menu looks for scans (default: "
                             "/app/inventories, or ./inventories on a host)")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("menu", help="choose scans and reports from a menu "
                                    "(the default with no command)")
    p.set_defaults(func=cmd_menu)

    p = sub.add_parser("list", help="list reports, and which apply to a scan")
    p.add_argument("paths", nargs="*", help="scan JSON files or directories")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("report", help="generate reports from a scan")
    p.add_argument("paths", nargs="+",
                   help="scan JSON files or directories; several are merged first")
    p.add_argument("-r", "--report", action="append", metavar="NAME",
                   help="report to generate, repeatable (default: every one "
                        "that applies)")
    p.add_argument("-f", "--format", choices=["xlsx", "csv", "json", "xml"],
                   help="output format where the report supports it "
                        "(default: each report's native format)")
    p.add_argument("-o", "--output",
                   help="output directory (default: ./<scan id>)")
    p.add_argument("--offline", action="store_true",
                   help="skip reports that call external APIs (EoX)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("summary", help="print how a scan went")
    p.add_argument("paths", nargs="+", help="scan JSON files or directories")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("merge", add_help=False,
                       help="merge scan files (same options as merge_scans.py)")
    p.add_argument("merge_args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_merge)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    use_config_dir(args.config_dir)
    func = getattr(args, "func", cmd_menu)
    try:
        return func(args)
    except ValueError as e:
        parser.error(str(e))
    except (KeyboardInterrupt, EOFError):
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
