import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.jsonio import load_json
from app.merge_scans import expand_paths, main


def _scan(discovery_id, devices, seed="192.0.2.1"):
    return {
        "discovery_id": discovery_id,
        "seed_ip": seed,
        "timestamp": "2026-10-30T10:00:00+00:00",
        "params": {},
        "devices": devices,
    }


def _device(hostname, ip, config=None):
    device = {"hostname": hostname, "mgmt_ip": ip, "login_succeeded": True,
              "serial": None, "evidence": [], "collector_data": {}}
    if config is not None:
        device["collector_data"]["config"] = {
            "raw": {"show running-config": config},
            "parsed": {"config": config},
        }
    return device


def _write(path, data):
    path.write_text(json.dumps(data))
    return str(path)


def test_merges_two_files_to_named_output(tmp_path, capsys):
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1")}))
    b = _write(tmp_path / "b.json", _scan("b", {"SW2": _device("SW2", "192.0.2.2")}))
    out = tmp_path / "merged.json"

    assert main([a, b, "-o", str(out)]) == 0

    merged = json.loads(out.read_text())
    assert set(merged["devices"]) == {"SW1", "SW2"}
    assert [s["filename"] for s in merged["merged_from"]] == ["a.json", "b.json"]
    assert "into 2 devices" in capsys.readouterr().out


def test_directory_output_uses_merged_scan_id(tmp_path):
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1")}))
    b = _write(tmp_path / "b.json", _scan("b", {"SW2": _device("SW2", "192.0.2.2")}))
    outdir = tmp_path / "out"
    outdir.mkdir()

    main([a, b, "-o", str(outdir)])

    written = list(outdir.glob("*_merged.json.gz"))
    assert len(written) == 1


def test_directory_input_expands_and_skips_duplicates(tmp_path):
    a = _write(tmp_path / "a.json", _scan("a", {}))
    b = _write(tmp_path / "b.json", _scan("b", {}))
    assert expand_paths([str(tmp_path), a]) == [a, b]


def test_configs_redacted_by_default(tmp_path):
    config = "hostname SW1\nsnmp-server community s3cr3tComm RO\n"
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1", config)}))
    b = _write(tmp_path / "b.json", _scan("b", {"SW2": _device("SW2", "192.0.2.2")}))
    out = tmp_path / "merged.json"

    main([a, b, "-o", str(out)])

    text = out.read_text()
    assert "s3cr3tComm" not in text
    parsed = json.loads(text)["devices"]["SW1"]["collector_data"]["config"]["parsed"]
    assert parsed["redacted"] is True
    # Sources are never modified.
    assert "s3cr3tComm" in (tmp_path / "a.json").read_text()


def test_no_redact_keeps_configs(tmp_path):
    config = "snmp-server community s3cr3tComm RO\n"
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1", config)}))
    b = _write(tmp_path / "b.json", _scan("b", {}))
    out = tmp_path / "merged.json"

    main([a, b, "-o", str(out), "--no-redact"])

    assert "s3cr3tComm" in out.read_text()


def test_rejects_single_file(tmp_path):
    a = _write(tmp_path / "a.json", _scan("a", {}))
    with pytest.raises(SystemExit):
        main([a])


def test_rejects_non_scan_json(tmp_path):
    a = _write(tmp_path / "a.json", _scan("a", {}))
    bad = _write(tmp_path / "bad.json", {"something": "else"})
    with pytest.raises(SystemExit):
        main([a, bad])


def test_runs_as_a_script_without_loading_the_web_app(tmp_path):
    """Run as `python app/merge_scans.py`, app/app.py used to shadow the app
    package and the script died opening the web app's log file."""
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1")}))
    b = _write(tmp_path / "b.json", _scan("b", {"SW2": _device("SW2", "192.0.2.2")}))
    out = tmp_path / "merged.json"
    script = Path(__file__).resolve().parent.parent / "app" / "merge_scans.py"

    result = subprocess.run([sys.executable, str(script), a, b, "-o", str(out)],
                            capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert "flask" not in result.stderr.lower()
    assert set(json.loads(out.read_text())["devices"]) == {"SW1", "SW2"}


def test_two_merges_in_one_second_do_not_overwrite(tmp_path, monkeypatch):
    a = _write(tmp_path / "a.json", _scan("a", {"SW1": _device("SW1", "192.0.2.1")}))
    b = _write(tmp_path / "b.json", _scan("b", {"SW2": _device("SW2", "192.0.2.2")}))
    c = _write(tmp_path / "c.json", _scan("c", {"SW3": _device("SW3", "192.0.2.3")}))
    outdir = tmp_path / "out"
    outdir.mkdir()
    import app.inventory_merge as im
    from datetime import datetime, timezone
    fixed = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed
    monkeypatch.setattr(im, "datetime", _Clock)

    main([a, b, "-o", str(outdir)])
    main([a, c, "-o", str(outdir)])

    written = sorted(p.name for p in outdir.glob("*.json.gz"))
    assert written == ["2026-10-31_12-00-00_merged-2.json.gz",
                       "2026-10-31_12-00-00_merged.json.gz"]
    second = load_json(str(outdir / written[0]))
    assert second["discovery_id"] == "2026-10-31_12-00-00_merged-2"
    assert set(second["devices"]) == {"SW1", "SW3"}
