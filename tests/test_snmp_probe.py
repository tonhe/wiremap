import pytest
from app.snmp_probe import SnmpCredentials, parse_sysdescr, probe, SYS_OIDS


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Enrichment walks are best effort and hit the network. Stub them by
    default so no test can reach a real host; individual tests override."""
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_walk_first", lambda *a, **k: None)


def test_credentials_v2c_requires_community():
    with pytest.raises(ValueError):
        SnmpCredentials(version="v2c", community="")


def test_credentials_v3_requires_username():
    with pytest.raises(ValueError):
        SnmpCredentials(version="v3", username="")


def test_credentials_rejects_unknown_version():
    with pytest.raises(ValueError):
        SnmpCredentials(version="v1", community="public")


def test_credentials_v2c_valid():
    creds = SnmpCredentials(version="v2c", community="public")
    assert creds.version == "v2c"
    assert creds.is_configured() is True


def test_credentials_v3_valid():
    creds = SnmpCredentials(version="v3", username="admin",
                            auth_key="authpass", priv_key="privpass")
    assert creds.is_configured() is True


def test_unconfigured_credentials():
    assert SnmpCredentials().is_configured() is False


def test_parse_sysdescr_cisco_ios():
    descr = ("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), "
             "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)")
    facts = parse_sysdescr(descr)
    assert facts["device_type"] == "cisco_ios"
    assert facts["software_version"] == "15.0(2)SE11"


def test_parse_sysdescr_nxos():
    descr = "Cisco NX-OS(tm) n5000, Software (n5000-uk9), Version 7.3(8)N1(1)"
    facts = parse_sysdescr(descr)
    assert facts["device_type"] == "cisco_nxos"


def test_parse_sysdescr_vyos():
    facts = parse_sysdescr("VyOS 1.4-rolling-202401 x86_64")
    assert facts["device_type"] == "vyos"


def test_parse_sysdescr_arista():
    facts = parse_sysdescr("Arista Networks EOS version 4.28.3M running on an Arista DCS-7280SR")
    assert facts["device_type"] == "arista_eos"


def test_parse_sysdescr_unknown_returns_none_type():
    facts = parse_sysdescr("Some Unknown Vendor Appliance")
    assert facts["device_type"] is None
    assert facts["software_version"] is None


def test_parse_sysdescr_empty():
    facts = parse_sysdescr("")
    assert facts == {"device_type": None, "software_version": None}


def test_probe_returns_none_without_credentials():
    assert probe("10.0.0.1", SnmpCredentials()) is None


def test_probe_builds_record_from_oids(monkeypatch):
    import app.snmp_probe as mod

    def fake_get(host, creds, oids, timeout, port):
        return {
            SYS_OIDS["sysName"]: "SW1.example.local",
            SYS_OIDS["sysDescr"]: "Cisco IOS Software, Version 15.0(2)SE11",
            SYS_OIDS["sysObjectID"]: "1.3.6.1.4.1.9.1.516",
            SYS_OIDS["sysUpTime"]: "12345678",
        }

    monkeypatch.setattr(mod, "_snmp_get", fake_get)
    result = probe("10.0.0.1", SnmpCredentials(version="v2c", community="public"))

    assert result["hostname"] == "SW1"
    assert result["mgmt_ip"] == "10.0.0.1"
    assert result["device_type"] == "cisco_ios"
    assert result["software_version"] == "15.0(2)SE11"
    assert result["discovery_source"] == "snmp"
    assert result["login_succeeded"] is False


def test_probe_returns_none_when_device_silent(monkeypatch):
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda *a, **k: {})
    assert probe("10.0.0.1", SnmpCredentials(version="v2c", community="public")) is None


def test_probe_survives_transport_error(monkeypatch):
    import app.snmp_probe as mod

    def boom(*a, **k):
        raise OSError("no route to host")

    monkeypatch.setattr(mod, "_snmp_get", boom)
    assert probe("10.0.0.1", SnmpCredentials(version="v2c", community="public")) is None


def test_probe_without_sysname_still_reports(monkeypatch):
    """A device that answers sysDescr but not sysName is still evidence."""
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda *a, **k: {
        SYS_OIDS["sysDescr"]: "VyOS 1.4-rolling",
    })
    result = probe("10.0.0.9", SnmpCredentials(version="v2c", community="public"))
    assert result is not None
    assert result["hostname"] == "10.0.0.9"
    assert result["device_type"] == "vyos"


def test_entity_and_vendor_oids_are_defined():
    from app.snmp_probe import ENTITY_COLUMNS, VENDOR_OIDS
    assert ENTITY_COLUMNS["entPhysicalSerialNum"] == "1.3.6.1.2.1.47.1.1.1.1.11"
    assert ENTITY_COLUMNS["entPhysicalModelName"] == "1.3.6.1.2.1.47.1.1.1.1.13"
    # PAN-COMMON-MIB, enterprise 25461
    assert all(o.startswith("1.3.6.1.4.1.25461") for o in VENDOR_OIDS["paloalto"].values())


def test_probe_fills_model_and_serial_from_entity_mib(monkeypatch):
    """PAN-OS leaves sysDescr uninformative; ENTITY-MIB carries the facts."""
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda *a, **k: {
        SYS_OIDS["sysName"]: "pa-trmc-mdf-campus-fw01",
        SYS_OIDS["sysDescr"]: "Palo Alto Networks",
    })
    monkeypatch.setattr(mod, "_snmp_walk_first", lambda host, creds, oid, t, p: {
        "1.3.6.1.2.1.47.1.1.1.1.13": "PA-440",
        "1.3.6.1.2.1.47.1.1.1.1.11": "012345678901",
    }.get(oid))

    r = probe("172.21.0.13", SnmpCredentials(version="v2c", community="public"))
    assert r["model"] == "PA-440"
    assert r["serial"] == "012345678901"
    assert r["device_type"] == "paloalto_panos"


def test_probe_uses_vendor_oids_when_entity_is_empty(monkeypatch):
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda host, creds, oids, t, p: (
        {SYS_OIDS["sysName"]: "pa-fw", SYS_OIDS["sysDescr"]: "Palo Alto Networks",
         SYS_OIDS["sysObjectID"]: "1.3.6.1.4.1.25461.2.3.20"}
        if oids[0] == SYS_OIDS["sysDescr"] or SYS_OIDS["sysName"] in oids
        else {"1.3.6.1.4.1.25461.2.1.2.1.1.0": "10.2.3",
              "1.3.6.1.4.1.25461.2.1.2.1.3.0": "0123456789"}))
    monkeypatch.setattr(mod, "_snmp_walk_first", lambda *a, **k: None)

    r = probe("172.21.0.13", SnmpCredentials(version="v2c", community="public"))
    assert r["serial"] == "0123456789"
    assert r["software_version"] == "10.2.3"


def test_probe_survives_entity_walk_failure(monkeypatch):
    """A best-effort enrichment must never lose the identification."""
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda *a, **k: {
        SYS_OIDS["sysName"]: "SW1", SYS_OIDS["sysDescr"]: "Cisco IOS Software"})

    def boom(*a, **k):
        raise OSError("timeout")

    monkeypatch.setattr(mod, "_snmp_walk_first", boom)
    r = probe("10.0.0.1", SnmpCredentials(version="v2c", community="public"))
    assert r is not None
    assert r["hostname"] == "SW1"


def test_probe_keeps_sysdescr_version_when_entity_has_none(monkeypatch):
    import app.snmp_probe as mod
    monkeypatch.setattr(mod, "_snmp_get", lambda *a, **k: {
        SYS_OIDS["sysName"]: "SW1",
        SYS_OIDS["sysDescr"]: "Cisco IOS Software, Version 15.0(2)SE11"})
    monkeypatch.setattr(mod, "_snmp_walk_first", lambda *a, **k: None)
    r = probe("10.0.0.1", SnmpCredentials(version="v2c", community="public"))
    assert r["software_version"] == "15.0(2)SE11"
