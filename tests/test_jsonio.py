"""Scan files saved and read as gzip-compressed or plain JSON."""
import gzip
import io
import json
import os

from app.inventory import DiscoveryInventory
from app.jsonio import find_scan, load_json, strip_suffix, write_json
from app.merge_scans import main as merge_main
from app.wiremap_cli import load_scan


def _scan(discovery_id, hostname="LAB-SW-01", ip="192.0.2.1"):
    return {"discovery_id": discovery_id, "seed_ip": ip,
            "timestamp": "2026-11-01T10:00:00+00:00", "params": {},
            "devices": {hostname: {"hostname": hostname, "mgmt_ip": ip,
                                   "login_succeeded": True, "serial": None,
                                   "evidence": [], "collector_data": {}}}}


def test_write_and_load_round_trip(tmp_path):
    data = _scan("lab")
    gz = write_json(data, str(tmp_path / "lab.json.gz"))
    plain = write_json(data, str(tmp_path / "lab.json"))
    with open(gz, "rb") as f:
        assert f.read(2) == b"\x1f\x8b"
    assert load_json(gz) == data
    assert load_json(plain) == data
    assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []


def test_load_detects_gzip_by_content_not_name(tmp_path):
    path = tmp_path / "renamed.json"
    path.write_bytes(gzip.compress(json.dumps(_scan("lab")).encode()))
    assert load_json(str(path))["discovery_id"] == "lab"
    assert load_json(io.BytesIO(path.read_bytes()))["discovery_id"] == "lab"
    assert load_json(io.StringIO('{"a": 1}')) == {"a": 1}


def test_strip_suffix_and_find_scan(tmp_path):
    assert strip_suffix("scan.json.gz") == "scan"
    assert strip_suffix("scan.json") == "scan"
    assert find_scan(str(tmp_path), "scan") is None
    write_json({}, str(tmp_path / "scan.json"))
    assert find_scan(str(tmp_path), "scan.json.gz").endswith("scan.json")
    write_json({}, str(tmp_path / "scan.json.gz"))
    assert find_scan(str(tmp_path), "scan").endswith("scan.json.gz")
    assert find_scan(str(tmp_path), "../scan").endswith("scan.json.gz")


def test_save_writes_gzip_and_replaces_an_older_plain_copy(tmp_path):
    write_json(_scan("lab"), str(tmp_path / "lab.json"))
    path = DiscoveryInventory(_scan("lab")).save(str(tmp_path))
    assert path.endswith("lab.json.gz")
    assert sorted(os.listdir(tmp_path)) == ["lab.json.gz"]
    assert DiscoveryInventory.load(path).discovery_id == "lab"


def test_list_inventories_reads_both_forms(tmp_path):
    write_json(_scan("old"), str(tmp_path / "old.json"))
    write_json(_scan("new"), str(tmp_path / "new.json.gz"))
    (tmp_path / "broken.json.gz").write_bytes(b"\x1f\x8bnot gzip")
    listed = DiscoveryInventory.list_inventories(str(tmp_path))
    assert sorted(i["discovery_id"] for i in listed) == ["new", "old"]


def test_merge_reads_gzip_inputs_and_writes_named_gzip_output(tmp_path):
    a = write_json(_scan("a"), str(tmp_path / "a.json.gz"))
    b = write_json(_scan("b", "LAB-SW-02", "192.0.2.2"), str(tmp_path / "b.json"))
    out = tmp_path / "merged.json.gz"
    merge_main([a, b, "-o", str(out)])
    assert set(load_json(str(out))["devices"]) == {"LAB-SW-01", "LAB-SW-02"}


def test_merge_directory_input_includes_gzip_scans(tmp_path):
    scans = tmp_path / "scans"
    write_json(_scan("a"), str(scans / "a.json.gz"))
    write_json(_scan("b", "LAB-SW-02", "192.0.2.2"), str(scans / "b.json"))
    out = tmp_path / "merged.json"
    merge_main([str(scans), "-o", str(out)])
    assert len(load_json(str(out))["devices"]) == 2


def test_cli_loads_gzip_scan(tmp_path):
    path = write_json(_scan("lab"), str(tmp_path / "lab.json.gz"))
    assert "LAB-SW-01" in load_scan(path)["devices"]
