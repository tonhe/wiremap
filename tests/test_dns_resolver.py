"""Host-list names resolved against a customer DNS server or search
suffix, without touching the wiremap host's resolv.conf."""
import socket
import sys
import types

import pytest

import app.target_list as tl
from app.settings import get_discovery_settings, save_discovery_settings


def _addr(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_bare_names_try_each_suffix_first():
    assert tl._candidates("sw1", ["corp.example.com", "example.net"]) == [
        "sw1.corp.example.com", "sw1.example.net", "sw1"]


def test_dotted_names_are_tried_as_given_first():
    assert tl._candidates("sw1.site", ["example.com"]) == [
        "sw1.site", "sw1.site.example.com"]


def test_suffix_with_the_host_resolver(monkeypatch):
    asked = []

    def fake(name, *a, **k):
        asked.append(name)
        if name == "sw1.corp.example.com":
            return _addr("192.0.2.11")
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    resolver, description = tl.make_resolver(None, ["corp.example.com"])
    assert "search corp.example.com" in description
    hosts, targets, unresolved = tl.resolve_targets(
        tl.parse_targets("sw1\ngone\n", {"cisco_ios"}), resolver=resolver)
    assert hosts == [("192.0.2.11", None)]
    assert targets == [{"input": "sw1", "resolved_ip": "192.0.2.11"}]
    assert [u["input"] for u in unresolved] == ["gone"]
    assert "sw1.corp.example.com" in asked


def test_dns_server_is_queried_directly(monkeypatch):
    """The configured server is asked, never the host's resolver."""
    queries = []

    class Answer:
        def __init__(self, ip):
            self.address = ip

    class Resolver:
        def __init__(self, configure=True):
            assert configure is False
            self.nameservers = []

        def resolve(self, name, rdtype):
            queries.append((tuple(self.nameservers), name, rdtype))
            if name == "rtr1.corp.example.com":
                return [Answer("192.0.2.21")]
            raise Exception("The DNS query name does not exist")

    fake_dns = types.ModuleType("dns")
    fake_dns.resolver = types.SimpleNamespace(Resolver=Resolver)
    monkeypatch.setitem(sys.modules, "dns", fake_dns)
    monkeypatch.setitem(sys.modules, "dns.resolver", fake_dns.resolver)

    def no_host_resolver(*a, **k):
        raise AssertionError("host resolver used")
    monkeypatch.setattr(socket, "getaddrinfo", no_host_resolver)

    resolver, description = tl.make_resolver("198.51.100.53",
                                             ["corp.example.com"])
    assert description.startswith("DNS server 198.51.100.53")
    hosts, _, unresolved = tl.resolve_targets(
        tl.parse_targets("rtr1\n", {"cisco_ios"}), resolver=resolver)
    assert hosts == [("192.0.2.21", None)]
    assert unresolved == []
    assert queries[0] == (("198.51.100.53",), "rtr1.corp.example.com", "A")


def test_host_resolver_description_names_its_servers(tmp_path, monkeypatch):
    conf = tmp_path / "resolv.conf"
    conf.write_text("search example.com\nnameserver 198.51.100.1\n")
    assert tl._system_nameservers(str(conf)) == ["198.51.100.1"]
    assert tl._system_nameservers(str(tmp_path / "missing")) == []


def test_dns_settings_are_validated(tmp_path):
    save_discovery_settings({"dns_server": " 198.51.100.53 ",
                             "dns_search": "corp.example.com, example.net."},
                            config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["dns_server"] == "198.51.100.53"
    assert settings["dns_search"] == ["corp.example.com", "example.net"]
    with pytest.raises(ValueError, match="dns_server"):
        save_discovery_settings({"dns_server": "ns.example.com"},
                                config_dir=str(tmp_path))
    with pytest.raises(ValueError, match="dns_search"):
        save_discovery_settings({"dns_search": "bad domain!"},
                                config_dir=str(tmp_path))


def test_connect_timeout_setting_is_bounded(tmp_path):
    save_discovery_settings({"connect_timeout_s": 30}, config_dir=str(tmp_path))
    assert get_discovery_settings(
        config_dir=str(tmp_path))["connect_timeout_s"] == 30
    with pytest.raises(ValueError, match="connect_timeout_s"):
        save_discovery_settings({"connect_timeout_s": 1},
                                config_dir=str(tmp_path))
