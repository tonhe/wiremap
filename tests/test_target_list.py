import socket
import threading

import pytest

from app.target_list import parse_targets, resolve_targets

TYPES = {"cisco_ios", "paloalto_panos"}


def fake_resolver(table):
    """getaddrinfo stand-in: name -> IPv4, anything else raises gaierror."""
    def resolve(host, port, family=0, type=0):
        if host not in table:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], 0))]
    return resolve


def test_lines_accept_ips_and_hostnames():
    entries = parse_targets(
        "# comment\n\n192.0.2.1\nAB001-IDF-SWA-01.example.net cisco_ios\nsw1\n",
        TYPES)
    assert entries == [
        {"ip": "192.0.2.1", "hostname": None, "device_type": None},
        {"ip": None, "hostname": "AB001-IDF-SWA-01.example.net",
         "device_type": "cisco_ios"},
        {"ip": None, "hostname": "sw1", "device_type": None},
    ]


def test_lines_reject_bad_address_and_type():
    with pytest.raises(ValueError, match="Line 1: invalid IP address"):
        parse_targets("192.0.2.300", TYPES)
    with pytest.raises(ValueError, match="Line 2: unknown device type"):
        parse_targets("192.0.2.1\nsw1.example.com junos", TYPES)
    with pytest.raises(ValueError, match="invalid host"):
        parse_targets("sw1/example", TYPES)


def test_trailing_dot_fqdn_is_normalised():
    assert parse_targets("sw1.example.com.", TYPES)[0]["hostname"] == "sw1.example.com"


def test_csv_with_hostname_ip_and_type_columns():
    text = ("Hostname,IP,Device Type,Location\n"
            "sw1.example.com,192.0.2.10,cisco_ios,lab\n"
            "sw2.example.com,,,lab\n"
            ",192.0.2.12,,\n"
            ",,,\n")
    assert parse_targets(text, TYPES, filename="hosts.csv") == [
        {"ip": "192.0.2.10", "hostname": "sw1.example.com", "device_type": "cisco_ios"},
        {"ip": None, "hostname": "sw2.example.com", "device_type": None},
        {"ip": "192.0.2.12", "hostname": None, "device_type": None},
    ]


def test_csv_detected_from_header_without_extension():
    entries = parse_targets("fqdn,type\nsw1.example.com,paloalto_panos\n", TYPES)
    assert entries == [{"ip": None, "hostname": "sw1.example.com",
                        "device_type": "paloalto_panos"}]


def test_csv_without_host_column_is_rejected():
    with pytest.raises(ValueError, match="CSV header"):
        parse_targets("serial,model\nX,Y\n", TYPES, filename="hosts.csv")


def test_csv_errors_name_the_row():
    with pytest.raises(ValueError, match="CSV row 3"):
        parse_targets("ip\n192.0.2.1\nnot-an-ip\n", TYPES, filename="h.csv")


def test_resolution_records_names_and_reports_failures():
    entries = parse_targets("sw1.example.com cisco_ios\ngone.example.com\n192.0.2.5\n",
                            TYPES)
    hosts, targets, unresolved = resolve_targets(
        entries, resolver=fake_resolver({"sw1.example.com": "192.0.2.1"}))
    assert hosts == [("192.0.2.1", "cisco_ios"), ("192.0.2.5", None)]
    assert targets == [{"input": "sw1.example.com", "resolved_ip": "192.0.2.1"}]
    assert [u["input"] for u in unresolved] == ["gone.example.com"]
    assert unresolved[0]["error"]


def test_names_resolving_to_one_address_are_collected_once():
    entries = parse_targets("sw1.example.com\nsw1-alias.example.com cisco_ios\n192.0.2.1\n",
                            TYPES)
    hosts, targets, _ = resolve_targets(entries, resolver=fake_resolver({
        "sw1.example.com": "192.0.2.1", "sw1-alias.example.com": "192.0.2.1"}))
    # One host; the type given on the duplicate is kept.
    assert hosts == [("192.0.2.1", "cisco_ios")]
    assert len(targets) == 2


def test_csv_row_with_ip_is_not_resolved():
    entries = parse_targets("hostname,ip\nsw1.example.com,192.0.2.7\n", TYPES,
                            filename="h.csv")

    def boom(*a, **k):
        raise AssertionError("resolver should not be called")

    hosts, targets, unresolved = resolve_targets(entries, resolver=boom)
    assert hosts == [("192.0.2.7", None)]
    assert targets == [{"input": "sw1.example.com", "resolved_ip": "192.0.2.7"}]
    assert unresolved == []


def test_slow_lookups_time_out_as_unresolved():
    release = threading.Event()

    def slow(host, *a, **k):
        if host == "slow.example.com":
            release.wait(5)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.9", 0))]

    entries = parse_targets("fast.example.com\nslow.example.com\n", TYPES)
    try:
        hosts, _, unresolved = resolve_targets(entries, resolver=slow, timeout=0.2)
    finally:
        release.set()
    assert hosts == [("192.0.2.9", None)]
    assert unresolved == [{"input": "slow.example.com", "error": "lookup timed out"}]


def test_lookups_run_concurrently():
    seen = []
    barrier = threading.Barrier(4, timeout=2)

    def resolver(host, *a, **k):
        barrier.wait()  # only passes if four lookups are in flight together
        seen.append(host)
        octet = 10 + int(host[2])
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{octet}", 0))]

    entries = parse_targets("\n".join(f"sw{i}.example.com" for i in range(4)), TYPES)
    hosts, _, unresolved = resolve_targets(entries, resolver=resolver, workers=8)
    assert unresolved == []
    assert len(hosts) == 4
