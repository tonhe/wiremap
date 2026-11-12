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


def test_leftover_secrets_in_redacted_config_are_scrubbed_and_counted():
    inv = _inventory(
        R1={"config": ("hostname R1\n"
                        "enable secret 5 <REDACTED>\n"
                        "username admin password 0 Plain123 $1$abcd$efgh role network-admin\n"
                        " glbp 10 authentication text Plain123\n"),
            "redacted": True},
        R2={"config": "hostname R2\nenable secret 5 <REDACTED>\n", "redacted": True},
    )
    zf = _zip(inv)
    content = zf.read("R1.txt").decode()
    assert "Plain123" not in content
    assert "$1$" not in content
    assert "hostname R1\n" in content
    summary = zf.read("SUMMARY.txt").decode()
    assert "Secrets redacted: yes" in summary
    assert "3 secret tokens survived" in summary
    assert "  R1: 3" in summary
    assert "R2" not in summary


def test_clean_redacted_config_has_no_leftover_warning():
    inv = _inventory(R1={"config": "enable secret 5 <REDACTED>\n", "redacted": True})
    summary = _zip(inv).read("SUMMARY.txt").decode()
    assert "WARNING" not in summary


def _asa(raw, config=None):
    cd = {"asa": {"raw": raw, "parsed": {}}}
    if config is not None:
        cd["config"] = {"raw": {}, "parsed": {"config": config, "redacted": True}}
    return {"collector_data": cd}


def test_asa_units_and_contexts_get_their_own_files():
    data = {"devices": {
        "LAB-FW-01": _asa({"show running-config": "hostname LAB-FW-01\n"}),
        "LAB-FW-01/stby": _asa({"show running-config": "hostname LAB-FW-01\n"}),
        "LAB-CTX-01": _asa({
            "show running-config": "hostname system\n",
            "context lab-ctx-a: show running-config": "hostname lab-ctx-a\n"
                                                     "snmp-server community Plain123\n",
            "context lab-ctx-a: show nameif": "x"}),
    }}
    report = ConfigArchiveReport()
    assert report.can_generate(data)
    zf = _zip(data)
    assert set(zf.namelist()) == {"LAB-FW-01.txt", "LAB-FW-01_stby.txt", "LAB-CTX-01.txt",
                                  "LAB-CTX-01_lab-ctx-a.txt", "SUMMARY.txt"}
    ctx = zf.read("LAB-CTX-01_lab-ctx-a.txt").decode()
    assert "Plain123" not in ctx and "hostname lab-ctx-a" in ctx


def test_config_collector_text_wins_over_the_asa_copy():
    data = {"devices": {"LAB-FW-01": _asa({"show running-config": "asa copy\n"},
                                            config="config collector copy\n")}}
    assert _zip(data).read("LAB-FW-01.txt").decode() == "config collector copy\n"


def test_nothing_to_archive():
    data = {"devices": {"LAB-SW-01": {"collector_data": {"config": {"parsed": {}}}}}}
    assert not ConfigArchiveReport().can_generate(data)



def test_controller_config_comes_from_the_wlc_collector():
    data = {"devices": {
        "lab-wlc-01": {"collector_data": {"wlc": {"raw": {
            "show run-config commands": "config sysname lab-wlc-01\n"
                                          "config radius auth add 1 192.0.2.50 1812 ascii Plain123\n"}}}},
        "lab-wlc-02": {"collector_data": {"wlc": {"raw": {
            "show run-config commands": "Incorrect usage. Use the '?' or <TAB> key to list commands."}}}},
    }}
    assert ConfigArchiveReport().can_generate(data)
    zf = _zip(data)
    assert set(zf.namelist()) == {"lab-wlc-01.txt", "SUMMARY.txt"}
    text = zf.read("lab-wlc-01.txt").decode()
    assert "Plain123" not in text and "config sysname lab-wlc-01" in text
