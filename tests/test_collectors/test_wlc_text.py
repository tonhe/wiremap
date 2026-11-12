"""AireOS dotted-label and dash-ruled table readers."""
from app.collectors import wlc_text as t

SYSINFO = """\
Manufacturer's Name.............................. Cisco Systems Inc.
Product Name..................................... Cisco Controller
Product Version.................................. 8.10.185.0
System Name...................................... lab-wlc-01
System Up Time................................... 12 days 3 hrs 4 mins 5 secs
Product Version.................................. 9.9.9.9
"""

AP_SUMMARY = """\
Number of APs.................................... 3

Global AP User Name.............................. Not Configured

AP Name             Slots  AP Model              Ethernet MAC       Location          Country     IP Address       Clients   DSE Location
------------------  -----  --------------------  -----------------  ----------------  ----------  ---------------  --------  --------------
lab-ap-01            2     AIR-AP2802I-B-K9      00:11:22:33:44:01  default location  US          10.1.1.10          3       [0 ,0 ,0 ]
lab-ap-with-a-long-name-02   2     AIR-CAP2602I-A-K9     00:11:22:33:44:02  floor 2           US          10.1.1.11          0       [0 ,0 ,0 ]
lab-ap-03            3     AIR-AP3802I-B-K9      00:11:22:33:44:03  lobby             US          10.1.1.12          12      [0 ,0 ,0 ]
"""


def test_dotted_keeps_first_and_all():
    d = t.dotted(SYSINFO)
    assert d["System Name"] == "lab-wlc-01"
    assert d["Product Version"] == "8.10.185.0"
    assert d["Manufacturer's Name"] == "Cisco Systems Inc."
    assert [v for k, v in t.dotted_all(SYSINFO) if k == "Product Version"] == [
        "8.10.185.0", "9.9.9.9"]
    assert t.lookup(d, "system name") == "lab-wlc-01"
    assert t.lookup(d, "missing", default="x") == "x"


def test_table_positional_and_overflow():
    rows = t.table(AP_SUMMARY)
    assert len(rows) == 3
    assert rows[0]["AP Name"] == "lab-ap-01"
    assert rows[0]["Location"] == "default location"
    assert rows[0]["Clients"] == "3"
    # A name longer than its column pushes the row out of line.
    assert rows[1]["AP Name"] == "lab-ap-with-a-long-name-02"
    assert rows[1]["AP Model"] == "AIR-CAP2602I-A-K9"
    assert rows[1]["Ethernet MAC"] == "00:11:22:33:44:02"
    assert rows[1]["Location"] == "floor 2" and rows[1]["Clients"] == "0"
    assert rows[2]["Location"] == "lobby" and rows[2]["Clients"] == "12"


def test_multiple_tables():
    text = ("A    B\n---  ---\n1    2\n\nC    D\n---  ---\n3    4\n5    6\n")
    found = t.tables(text)
    assert found == [[{"A": "1", "B": "2"}], [{"C": "3", "D": "4"}, {"C": "5", "D": "6"}]]
    assert t.table("") == []


def test_helpers():
    assert t.norm_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert t.norm_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert t.norm_mac("junk") == ""
    assert t.macs_in("client 00:11:22:33:44:55 and aa:bb:cc:dd:ee:ff") == [
        "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
    assert t.enabled("Enabled") is True and t.enabled("Disabled") is False
    assert t.enabled("") is None
    assert t.to_int("1,234 APs") == 1234 and t.to_int("none") is None
    assert t.to_float("45.5%") == 45.5
