import io
import zipfile
from app.reports.config_archive import ConfigArchiveReport


def test_report_attrs():
    r = ConfigArchiveReport()
    assert r.name == "config_archive"
    assert "config" in r.required_collectors
    assert "zip" in r.supported_formats


def test_generate_zip(sample_inventory):
    r = ConfigArchiveReport()
    data = r.generate(sample_inventory)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    assert "SW1.txt" in names
    assert "SW2.txt" in names
    content = zf.read("SW1.txt").decode()
    assert "hostname SW1" in content


def _inventory(**configs):
    return {"devices": {
        host: {"collector_data": {"config": {"raw": {}, "parsed": parsed}}}
        for host, parsed in configs.items()
    }}


def _zip(data):
    return zipfile.ZipFile(io.BytesIO(ConfigArchiveReport().generate(data)))


def test_summary_says_redacted(sample_inventory):
    zf = _zip(sample_inventory)
    summary = zf.read("SUMMARY.txt").decode()
    assert "Secrets redacted: yes" in summary


def test_legacy_unflagged_config_is_redacted_on_export():
    inv = _inventory(R1={"config": "hostname R1\nenable secret 5 $1$abcd\n"})
    content = _zip(inv).read("R1.txt").decode()
    assert "$1$abcd" not in content
    assert "enable secret 5 <REDACTED>" in content


def test_opt_out_config_kept_and_flagged_in_summary():
    inv = _inventory(
        R1={"config": "enable secret 5 $1$abcd\n", "redacted": False},
        R2={"config": "enable secret 5 <REDACTED>\n", "redacted": True},
    )
    zf = _zip(inv)
    assert "$1$abcd" in zf.read("R1.txt").decode()
    summary = zf.read("SUMMARY.txt").decode()
    assert "Secrets redacted: no" in summary
    assert "R1" in summary
    assert "R2" not in summary.split("WARNING", 1)[1]


def test_no_configs_no_summary():
    zf = _zip(_inventory(R1={"config": ""}))
    assert zf.namelist() == []
