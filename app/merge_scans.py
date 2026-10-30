"""Merge saved scan JSON files from the command line.

Same merge the Saved Scans tab runs, for files that never went through the
UI -- scans copied off another host, or run on different boxes at one site.

    python app/merge_scans.py scan-a.json scan-b.json -o merged.json
    python app/merge_scans.py inventories/             # every .json in it

Inside the container:

    docker compose exec wiremap python merge_scans.py \
        /app/inventories/a.json /app/inventories/b.json -o /app/inventories

Configs are redacted in the output by default, since a merged file is
usually the one that gets passed around. Older scans predate collection-time
redaction and may carry secrets in clear text.
"""
import argparse
import glob
import json
import os
import sys

try:
    from app.inventory import DiscoveryInventory
    from app.inventory_merge import merge_inventories
    from app.redact import redact_config
except ImportError:
    from inventory import DiscoveryInventory
    from inventory_merge import merge_inventories
    from redact import redact_config


def expand_paths(paths):
    """Files as given; directories expand to the .json files inside them."""
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(sorted(glob.glob(os.path.join(path, "*.json"))))
        else:
            files.append(path)
    # The same file named twice would merge with itself.
    seen = set()
    unique = []
    for path in files:
        key = os.path.realpath(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def redact_configs(inventory):
    """Redact every collected running-config in place. Returns hosts touched."""
    touched = []
    for hostname, device in (inventory.get("devices") or {}).items():
        config = (device.get("collector_data") or {}).get("config")
        if not isinstance(config, dict):
            continue
        raw = config.get("raw")
        if isinstance(raw, dict):
            config["raw"] = {cmd: redact_config(out) if isinstance(out, str) else out
                             for cmd, out in raw.items()}
        parsed = config.get("parsed")
        if isinstance(parsed, dict) and isinstance(parsed.get("config"), str):
            parsed["config"] = redact_config(parsed["config"])
            parsed["redacted"] = True
        touched.append(hostname)
    return touched


def write_output(merged, output):
    """Write to a file path, or into a directory under the merged scan's id."""
    if output and not os.path.isdir(output) and output.endswith(".json"):
        parent = os.path.dirname(os.path.abspath(output))
        os.makedirs(parent, exist_ok=True)
        with open(output, "w") as f:
            json.dump(merged, f, indent=2, default=str)
        return output
    return DiscoveryInventory(merged).save(output or ".")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Merge two or more wiremap scan JSON files into one.")
    parser.add_argument("paths", nargs="+",
                        help="scan JSON files, or directories of them")
    parser.add_argument("-o", "--output",
                        help="output .json file, or a directory (default: "
                             "current directory, named after the merged scan)")
    parser.add_argument("--no-redact", action="store_true",
                        help="keep configs exactly as stored in the sources")
    args = parser.parse_args(argv)

    files = expand_paths(args.paths)
    if len(files) < 2:
        parser.error(f"need at least two scan files, got {len(files)}")

    loaded = []
    for path in files:
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            parser.error(f"could not read {path}: {e}")
        if not isinstance(data, dict) or "devices" not in data:
            parser.error(f"{path} is not a wiremap scan (no devices key)")
        loaded.append(data)

    merged = merge_inventories(loaded, filenames=[os.path.basename(p) for p in files])
    redacted = [] if args.no_redact else redact_configs(merged)
    out_path = write_output(merged, args.output)

    inputs = sum(len(d.get("devices") or {}) for d in loaded)
    print(f"Merged {len(files)} scans ({inputs} device records) "
          f"into {len(merged['devices'])} devices")
    for source in merged.get("merged_from", []):
        print(f"  {source['filename']}: {source['device_count']} devices, "
              f"seed {source['seed_ip'] or '-'}")
    conflicts = merged.get("merge_conflicts") or []
    if conflicts:
        print(f"{len(conflicts)} device records folded together "
              f"(see merge_conflicts in the output)")
    if redacted:
        print(f"Redacted configs for {len(redacted)} devices")
    elif args.no_redact:
        print("Configs left unredacted (--no-redact)")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
