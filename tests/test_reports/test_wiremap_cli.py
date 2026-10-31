import json
import subprocess
import sys
from pathlib import Path

import pytest

from app import wiremap_cli
from app.wiremap_cli import main, parse_choice

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def scan_file(tmp_path, sample_inventory):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(sample_inventory))
    return path


@pytest.fixture
def no_plugins(tmp_path):
    """Config dir with no saved Cisco credentials."""
    d = tmp_path / "config"
    d.mkdir()
    return ["--config-dir", str(d)]


def test_report_all_writes_every_applicable_report(scan_file, tmp_path, no_plugins, capsys):
    out = tmp_path / "out"

    assert main(no_plugins + ["report", str(scan_file), "-o", str(out)]) == 0

    names = {p.name.split("_2026")[0] for p in out.iterdir()}
    assert {"device_inventory", "link_inventory", "config_archive",
            "topology_map"} <= names
    assert (out / "config_archive_2026-03-05_10-00-00_192.168.1.1.zip").exists()
    assert (out / "topology_map_2026-03-05_10-00-00_192.168.1.1.html").exists()
    text = capsys.readouterr().out
    assert "skipped eox_lifecycle" in text
    assert "0 failed" in text


def test_format_applies_where_supported_and_native_elsewhere(scan_file, tmp_path, no_plugins):
    out = tmp_path / "out"

    main(no_plugins + ["report", str(scan_file), "-f", "csv", "-o", str(out),
                       "-r", "device_inventory", "-r", "topology_map"])

    suffixes = {p.suffix for p in out.iterdir()}
    assert suffixes == {".csv", ".html"}


def test_named_report_that_cannot_run_exits_nonzero(scan_file, tmp_path, no_plugins, capsys):
    rc = main(no_plugins + ["report", str(scan_file), "-r", "eox_lifecycle",
                            "-o", str(tmp_path / "out")])

    assert rc == 1
    assert "Cisco API credentials" in capsys.readouterr().out


def test_offline_skips_network_reports(scan_file, tmp_path, no_plugins, monkeypatch, capsys):
    eox = wiremap_cli.get_registry()["eox_lifecycle"]
    monkeypatch.setattr(eox, "can_generate", lambda data: True)
    monkeypatch.setattr(eox, "generate", lambda *a: pytest.fail("called the API"))

    main(no_plugins + ["report", str(scan_file), "--offline", "-o", str(tmp_path / "out")])

    assert "skipped eox_lifecycle: --offline" in capsys.readouterr().out


def test_report_failure_is_reported_and_exits_nonzero(scan_file, tmp_path, no_plugins,
                                                      monkeypatch, capsys):
    report = wiremap_cli.get_registry()["link_inventory"]

    def boom(*a):
        raise RuntimeError("bad data")
    monkeypatch.setattr(report, "generate", boom)

    rc = main(no_plugins + ["report", str(scan_file), "-o", str(tmp_path / "out")])

    assert rc == 1
    assert "FAILED  link_inventory: RuntimeError: bad data" in capsys.readouterr().out


def test_unknown_report_name_is_a_usage_error(scan_file, no_plugins):
    with pytest.raises(SystemExit) as e:
        main(no_plugins + ["report", str(scan_file), "-r", "nope"])
    assert e.value.code == 2


def test_several_inputs_are_merged_before_reporting(tmp_path, sample_inventory,
                                                     no_plugins, capsys):
    a = dict(sample_inventory, discovery_id="a")
    b = dict(sample_inventory, discovery_id="b",
             devices={"SW9": dict(sample_inventory["devices"]["SW1"],
                                  hostname="SW9", mgmt_ip="192.0.2.9", serial="SYNTH0009")})
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    pa.write_text(json.dumps(a))
    pb.write_text(json.dumps(b))
    out = tmp_path / "out"

    assert main(no_plugins + ["report", str(pa), str(pb), "-o", str(out),
                              "-r", "device_inventory", "-f", "json"]) == 0

    assert "Merged 2 scans" in capsys.readouterr().out
    written = next(out.glob("device_inventory_*.json")).read_text()
    assert "SW9" in written
    assert "SW1" in written


def test_list_marks_applicable_reports(scan_file, no_plugins, capsys):
    assert main(no_plugins + ["list", str(scan_file)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert any(l.startswith("yes  device_inventory") for l in lines)
    assert any(l.startswith("no   eox_lifecycle") for l in lines)


def test_summary_prints_counts_and_targets(tmp_path, sample_inventory, no_plugins, capsys):
    sample_inventory["scan_summary"] = {
        "failed": {"192.0.2.50": "Authentication failed"},
        "failed_count": 1,
        "not_attempted_count": 3,
        "targets": [{"host": "192.0.2.1", "resolved_ip": "192.0.2.1",
                     "outcome": "collected"},
                    {"host": "192.0.2.50", "resolved_ip": "192.0.2.50",
                     "outcome": "failed"}],
    }
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(sample_inventory))

    assert main(no_plugins + ["summary", str(path)]) == 0

    text = capsys.readouterr().out
    assert "Failed:    1 (1 Authentication failed)" in text
    assert "Not attempted: 3" in text
    assert "Targets: 1 collected" in text


def test_merge_subcommand_calls_merge_scans(tmp_path, sample_inventory, no_plugins):
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    pa.write_text(json.dumps(dict(sample_inventory, discovery_id="a")))
    pb.write_text(json.dumps(dict(sample_inventory, discovery_id="b")))
    out = tmp_path / "merged.json"

    assert main(no_plugins + ["merge", str(pa), str(pb), "-o", str(out)]) == 0

    assert set(json.loads(out.read_text())["devices"]) == set(sample_inventory["devices"])


def test_config_dir_reaches_flat_plugins_import(tmp_path):
    sys.path.insert(0, str(REPO / "app"))
    try:
        import plugins
        wiremap_cli.use_config_dir(str(tmp_path))
        assert plugins.DEFAULT_CONFIG_DIR == str(tmp_path)
    finally:
        sys.path.remove(str(REPO / "app"))
        wiremap_cli.use_config_dir("/app/config")


@pytest.mark.parametrize("text,count,expected", [
    ("", 4, [0, 1, 2, 3]),
    ("all", 2, [0, 1]),
    ("2", 4, [1]),
    ("1,3-4", 5, [0, 2, 3]),
    ("3 1 3", 4, [2, 0]),
])
def test_parse_choice(text, count, expected):
    assert parse_choice(text, count) == expected


@pytest.mark.parametrize("text", ["0", "5", "x", "2-9"])
def test_parse_choice_rejects_out_of_range(text):
    with pytest.raises(ValueError):
        parse_choice(text, 4)


def test_menu_runs_selected_reports(tmp_path, sample_inventory, no_plugins, capsys):
    scans = tmp_path / "inventories"
    scans.mkdir()
    (scans / "scan.json").write_text(json.dumps(sample_inventory))
    out = tmp_path / "out"
    answers = iter(["", "1", "3", str(out)])  # newest scan, first report, csv

    args = wiremap_cli.build_parser().parse_args(
        no_plugins + ["--inventory-dir", str(scans)])
    rc = wiremap_cli.cmd_menu(args, input_fn=lambda prompt: next(answers))

    assert rc == 0
    assert {p.suffix for p in out.iterdir()} == {".csv"}
    assert all(p.name.startswith("arp_summary_") for p in out.iterdir())


def test_menu_reprompts_on_bad_choice(tmp_path, sample_inventory, no_plugins, capsys):
    scans = tmp_path / "inventories"
    scans.mkdir()
    (scans / "scan.json").write_text(json.dumps(sample_inventory))
    answers = iter(["7", "1", "1", "1", str(tmp_path / "out")])

    args = wiremap_cli.build_parser().parse_args(
        no_plugins + ["--inventory-dir", str(scans)])
    wiremap_cli.cmd_menu(args, input_fn=lambda prompt: next(answers))

    assert "7 is not between 1 and 1" in capsys.readouterr().out


def test_runs_with_only_app_on_path_like_the_container(scan_file, tmp_path):
    """The container runs it as `python wiremap_cli.py` from a flat /app."""
    out = tmp_path / "out"
    result = subprocess.run(
        [sys.executable, "wiremap_cli.py", "--config-dir", str(tmp_path),
         "report", str(scan_file), "-r", "device_inventory", "-o", str(out)],
        cwd=REPO / "app", capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert len(list(out.glob("device_inventory_*.xlsx"))) == 1


def test_multi_sheet_csv_writes_one_readable_file_per_sheet(scan_file, tmp_path, no_plugins):
    import csv as csvmod
    out = tmp_path / "out"

    main(no_plugins + ["report", str(scan_file), "-r", "device_inventory",
                       "-f", "csv", "-o", str(out)])

    files = sorted(out.glob("device_inventory_*.csv"))
    assert len(files) > 1
    assert any(f.name.endswith("_devices.csv") for f in files)
    for f in files:
        text = f.read_text()
        assert "--- Sheet:" not in text
        rows = list(csvmod.reader(text.splitlines()))
        assert rows and all(len(r) == len(rows[0]) for r in rows)


def test_summary_counts_collected_devices_on_old_scans(tmp_path, sample_inventory,
                                                       no_plugins, capsys):
    """Scans from before login_succeeded was recorded reported 0 logged into."""
    for device in sample_inventory["devices"].values():
        device.pop("login_succeeded", None)
    path = tmp_path / "old.json"
    path.write_text(json.dumps(sample_inventory))

    main(no_plugins + ["summary", str(path)])

    collected = sum(1 for d in sample_inventory["devices"].values()
                    if d.get("collector_data"))
    assert collected
    assert f"({collected} logged into)" in capsys.readouterr().out


def test_summary_prints_warning_message_not_dict(tmp_path, sample_inventory,
                                                 no_plugins, capsys):
    sample_inventory["scan_summary"] = {"source_access_warnings": [
        {"kind": "snmp", "acl": "10", "device": "SW1", "source_ip": "192.0.2.10",
         "message": "SW1: SNMP ACL 10 does not permit 192.0.2.10"}]}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(sample_inventory))

    main(no_plugins + ["summary", str(path)])

    text = capsys.readouterr().out
    assert "  warning: SW1: SNMP ACL 10 does not permit 192.0.2.10" in text
    assert "{'kind'" not in text


def _menu_args(tmp_path, sample_inventory, no_plugins):
    scans = tmp_path / "inventories"
    scans.mkdir()
    (scans / "scan.json").write_text(json.dumps(sample_inventory))
    return wiremap_cli.build_parser().parse_args(
        no_plugins + ["--inventory-dir", str(scans)])


@pytest.mark.parametrize("answers", [["q"], ["", "quit"], ["", "", "q"],
                                     ["", "", "", "q"]])
def test_menu_quits_cleanly(tmp_path, sample_inventory, no_plugins, answers):
    args = _menu_args(tmp_path, sample_inventory, no_plugins)
    it = iter(answers)

    assert wiremap_cli.cmd_menu(args, input_fn=lambda p: next(it)) == 0
    assert not (tmp_path / sample_inventory["discovery_id"]).exists()


def test_menu_exits_zero_on_end_of_input(tmp_path, sample_inventory, no_plugins):
    args = _menu_args(tmp_path, sample_inventory, no_plugins)

    def eof(prompt):
        raise EOFError

    assert wiremap_cli.cmd_menu(args, input_fn=eof) == 0


def test_menu_explains_non_numeric_input(tmp_path, sample_inventory, no_plugins, capsys):
    args = _menu_args(tmp_path, sample_inventory, no_plugins)
    it = iter(["x", "q"])

    wiremap_cli.cmd_menu(args, input_fn=lambda p: next(it))

    out = capsys.readouterr().out
    assert "'x' is not a number or range" in out
    assert "invalid literal" not in out
