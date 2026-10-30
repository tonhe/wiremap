import json

import pytest

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

    written = list(outdir.glob("*_merged.json"))
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
