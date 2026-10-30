from app.collectors.device_inventory import (
    DeviceInventoryCollector,
    _parse_call_home,
    _parse_license_usage,
    _parse_smart_licensing,
)
from app.device_facts import extract_version_details

# IOS-XE 17.6 (Smart Licensing Using Policy)
XE17_LICENSE_SUMMARY = """\
Account Information:
  Smart Account: Example Org As of Mar 02 10:15:22 2026 UTC
  Virtual Account: Campus

License Usage:
  License                 Entitlement Tag               Count Status
  -----------------------------------------------------------------------------
  network-advantage       (C9300-48 Network Advan...)       2 IN USE
  dna-advantage           (C9300-48 DNA Advantage)          2 IN USE
  C9300 48P DNA Advantage (C9300-48 DNA Advantage)          0 NOT IN USE

"""

XE17_LICENSE_STATUS = """\
Utility:
  Status: DISABLED

Smart Licensing Using Policy:
  Status: ENABLED

Account Information:
  Smart Account: Example Org As of Mar 02 10:15:22 2026 UTC
  Virtual Account: Campus

Data Privacy:
  Sending Hostname: yes
    Callhome hostname privacy: DISABLED
    Smart Licensing hostname privacy: DISABLED
  Version privacy: DISABLED

Transport:
  Type: Smart
  URL: https://smartreceiver.example.com/licservice/license
  Proxy:
    Not Configured
  VRF:
    Not Configured

Policy:
  Policy in use: Merged from multiple sources.
  Reporting ACK required: yes (CISCO default)

Usage Reporting:
  Last ACK received: Mar 01 08:00:12 2026 UTC
  Next ACK deadline: May 30 08:00:12 2026 UTC
  Reporting push interval: 30  days

Trust Code Installed: Feb 10 09:12:44 2026 UTC
"""

# IOS-XE 16.x (classic Smart Licensing with registration)
XE16_LICENSE_SUMMARY = """\

Smart Licensing is ENABLED

Registration:
  Status: REGISTERED
  Smart Account: Example Org
  Virtual Account: Default
  Export-Controlled Functionality: ALLOWED
  Last Renewal Attempt: None
  Next Renewal Attempt: Aug 21 14:02:11 2026 UTC

License Authorization:
  Status: AUTHORIZED
  Last Communication Attempt: SUCCEEDED
  Next Communication Attempt: Apr 01 14:05:40 2026 UTC

License Usage:
  License                 Entitlement tag               Count Status
  -----------------------------------------------------------------------------
  C9300 48P Network Ad... (C9300-48 Network Advan...)       1 AUTHORIZED
  C9300 48P DNA Advantage (C9300-48 DNA Advantage)          1 AUTHORIZED
"""

NXOS_LICENSE_USAGE = """\
Feature                      Ins  Lic   Status Expiry Date Comments
                                 Count
--------------------------------------------------------------------------------
FCOE_NPV_PKG                  No    -   Unused             -
LAN_ENTERPRISE_SERVICES_PKG   Yes   -   In use never       -
NETWORK_SERVICES_PKG          No    -   Unused             -
--------------------------------------------------------------------------------
"""

NXOS_LICENSE_USAGE_BLOCKS = """\
License Authorization:
  Status: Not Applicable

NXOS_ADVANTAGE_XF (NX-OS Advantage for 9500 & 9300-XF):
  Description: NX-OS Advantage for 9500 & 9300-XF
  Count: 1
  Version: 1.0
  Status: IN USE
  Export status: NOT RESTRICTED
  Feature Name: NXOS_ADVANTAGE_XF
  Enforcement type: NOT ENFORCED
"""

XE_CALL_HOME = """\
Current call home settings:
    call home feature : enable
    call home message's from address: Not yet set up
    call home message's reply-to address: Not yet set up
    vrf for call-home messages: Not yet set up
    contact person's email address: noc@example.com
    contact person's phone number: Not yet set up
    street address: Not yet set up
    customer ID: Not yet set up
    contract ID: Not yet set up
    site ID: Not yet set up
    source ip address: Not yet set up
    source interface: Not yet set up
    Mail-server: Not yet set up
    http proxy: Not yet set up
    Smart licensing messages: enabled
      Smart licensing message profile: CiscoTAC-1
    aaa-authorization: disable
    aaa-authorization username: callhome (default)
    data-privacy: normal
    syslog throttling: enable
    Rate-limit: 20 message(s) per minute

Available alert groups:
    Keyword                  State   Description
    ------------------------ ------- -------------------------------
    configuration            Enable  configuration info
    diagnostic               Enable  diagnostic info

Profiles:
    Profile Name: CiscoTAC-1
"""

XE_CALL_HOME_PROFILES = """\
Profile Name: CiscoTAC-1
    Profile status: ACTIVE
    Profile mode: Full Reporting
    Reporting Data: Smart Call Home, Smart Licensing
    Preferred Message Format: xml
    Message Size Limit: 3145728 Bytes
    Transport Method: http
    HTTP  address(es): https://tools.example.com/its/service/oddce/services/DDCEService
    Other address(es): default

Profile Name: OPS-MAIL
    Profile status: INACTIVE
    Transport Method: email
"""

NXOS_CALLHOME = """\
callhome disabled
Callhome Information:
contact person name(sysContact):
contact person's email:
contact person's phone number:
street addr:
site id:
customer id:
contract id:
switch priority:7
duplicate message throttling : enabled
periodic inventory : enabled
"""

REJECTED = "% Invalid input detected at '^' marker."


def test_license_summary_17x_rows():
    rows = _parse_license_usage(XE17_LICENSE_SUMMARY)
    assert [r["name"] for r in rows] == [
        "network-advantage", "dna-advantage", "C9300 48P DNA Advantage"]
    assert rows[0]["entitlement"] == "C9300-48 Network Advan..."
    assert rows[0]["count"] == "2"
    assert rows[0]["status"] == "IN USE"
    assert rows[2]["status"] == "NOT IN USE"


def test_license_summary_16x_rows():
    rows = _parse_license_usage(XE16_LICENSE_SUMMARY)
    assert len(rows) == 2
    assert rows[1]["name"] == "C9300 48P DNA Advantage"
    assert rows[1]["status"] == "AUTHORIZED"


def test_nxos_license_usage_table():
    rows = _parse_license_usage(NXOS_LICENSE_USAGE)
    by_name = {r["name"]: r for r in rows}
    assert by_name["LAN_ENTERPRISE_SERVICES_PKG"]["status"] == "In use"
    assert by_name["FCOE_NPV_PKG"]["status"] == "Unused"
    assert by_name["FCOE_NPV_PKG"]["count"] == ""
    assert "Feature" not in by_name


def test_license_usage_block_form():
    rows = _parse_license_usage(NXOS_LICENSE_USAGE_BLOCKS)
    assert rows == [{"name": "NXOS_ADVANTAGE_XF",
                     "entitlement": "NX-OS Advantage for 9500 & 9300-XF",
                     "count": "1", "status": "IN USE"}]


def test_license_usage_rejected_or_empty():
    assert _parse_license_usage(REJECTED) == []
    assert _parse_license_usage("") == []


def test_smart_licensing_using_policy():
    info = _parse_smart_licensing(XE17_LICENSE_SUMMARY, XE17_LICENSE_STATUS)
    assert info["mode"] == "Smart Licensing Using Policy"
    assert info["status"] == "ENABLED"
    assert info["registration"] == ""
    assert info["smart_account"] == "Example Org"
    assert info["virtual_account"] == "Campus"
    assert info["transport"] == "Smart"
    assert info["last_ack"] == "Mar 01 08:00:12 2026 UTC"


def test_smart_licensing_classic_registration():
    info = _parse_smart_licensing(XE16_LICENSE_SUMMARY, REJECTED)
    assert info["mode"] == "Smart Licensing"
    assert info["status"] == "ENABLED"
    assert info["registration"] == "REGISTERED"
    assert info["authorization"] == "AUTHORIZED"


def test_smart_licensing_absent():
    assert _parse_smart_licensing(REJECTED, REJECTED) is None
    assert _parse_smart_licensing("", "") is None


def test_call_home_ios_xe():
    info = _parse_call_home(XE_CALL_HOME, XE_CALL_HOME_PROFILES)
    assert info["enabled"] is True
    assert info["smart_licensing_messages"] == "enabled"
    # Only active profiles count toward the transport in use.
    assert info["transport"] == "http"
    assert [p["name"] for p in info["profiles"]] == ["CiscoTAC-1", "OPS-MAIL"]


def test_call_home_nxos_disabled():
    info = _parse_call_home(NXOS_CALLHOME)
    assert info["enabled"] is False
    assert info["transport"] == ""


def test_call_home_rejected():
    assert _parse_call_home(REJECTED) is None


def test_commands_per_platform():
    c = DeviceInventoryCollector()
    for dt in ("cisco_xe", "cisco_ios"):
        cmds = c.get_commands(dt)
        assert "show license summary" in cmds
        assert "show call-home" in cmds
    nx = c.get_commands("cisco_nxos")
    assert "show license usage" in nx
    assert "show callhome" in nx
    assert not any("license" in cmd for cmd in c.get_commands("arista_eos"))


def test_collector_parse_ios_xe_licensing():
    c = DeviceInventoryCollector()
    raw = {cmd: "" for cmd in c.get_commands("cisco_xe")}
    raw["show license summary"] = XE17_LICENSE_SUMMARY
    raw["show license status"] = XE17_LICENSE_STATUS
    raw["show call-home"] = XE_CALL_HOME
    raw["show call-home profile all"] = XE_CALL_HOME_PROFILES
    result = c.parse(raw, "cisco_xe")
    assert len(result["licenses"]) == 3
    assert result["smart_licensing"]["mode"] == "Smart Licensing Using Policy"
    assert result["call_home"]["enabled"] is True


def test_collector_parse_nxos_licensing():
    c = DeviceInventoryCollector()
    raw = {cmd: "" for cmd in c.get_commands("cisco_nxos")}
    raw["show license usage"] = NXOS_LICENSE_USAGE
    raw["show callhome"] = NXOS_CALLHOME
    result = c.parse(raw, "cisco_nxos")
    assert len(result["licenses"]) == 3
    assert result["call_home"]["enabled"] is False
    assert "smart_licensing" not in result


def test_collector_rejected_license_commands_leave_no_keys():
    c = DeviceInventoryCollector()
    raw = {cmd: REJECTED for cmd in c.get_commands("cisco_ios")}
    raw["show version"] = "Cisco IOS Software, C2960X Software, Version 15.2(7)E8"
    result = c.parse_collected(raw, "cisco_ios")
    assert "licenses" not in result
    assert "smart_licensing" not in result
    assert "call_home" not in result


def test_license_column_enriched_with_in_use_licenses_and_state():
    parsed = {
        "version_details": {"license": "network-advantage"},
        "licenses": _parse_license_usage(XE17_LICENSE_SUMMARY),
        "smart_licensing": _parse_smart_licensing(XE17_LICENSE_SUMMARY,
                                                  XE17_LICENSE_STATUS),
    }
    text = extract_version_details(parsed)["license"]
    assert text == "network-advantage, dna-advantage [SLP: ENABLED]"


def test_license_column_classic_registration_state():
    parsed = {
        "licenses": _parse_license_usage(XE16_LICENSE_SUMMARY),
        "smart_licensing": _parse_smart_licensing(XE16_LICENSE_SUMMARY),
    }
    text = extract_version_details(parsed)["license"]
    assert text.endswith("[Smart: REGISTERED]")
    assert "C9300 48P DNA Advantage" in text


def test_license_column_unchanged_without_license_data():
    parsed = {"version_details": {"license": "ipbasek9"}}
    assert extract_version_details(parsed)["license"] == "ipbasek9"
