import pytest
from app.neighbors.scope import CrawlScope


def test_rfc1918_allowed_by_default():
    scope = CrawlScope()
    assert scope.allows("10.1.1.1") is True
    assert scope.allows("172.16.5.5") is True
    assert scope.allows("192.168.1.1") is True


def test_public_address_blocked_by_default():
    """Next-hop crawling must not walk into ISP space."""
    scope = CrawlScope()
    assert scope.allows("8.8.8.8") is False
    assert scope.allows("104.16.0.1") is False


def test_loopback_and_linklocal_blocked():
    scope = CrawlScope()
    assert scope.allows("127.0.0.1") is False
    assert scope.allows("169.254.1.1") is False


def test_multicast_and_broadcast_blocked():
    scope = CrawlScope()
    assert scope.allows("224.0.0.5") is False
    assert scope.allows("255.255.255.255") is False


def test_zero_address_blocked():
    scope = CrawlScope()
    assert scope.allows("0.0.0.0") is False


def test_allow_list_permits_public_space():
    scope = CrawlScope(allow_cidrs=["203.0.113.0/24"])
    assert scope.allows("203.0.113.7") is True
    assert scope.allows("8.8.8.8") is False


def test_allow_list_restricts_rfc1918_too():
    """An explicit allow list is the whole scope, not an addition to it."""
    scope = CrawlScope(allow_cidrs=["10.1.0.0/16"])
    assert scope.allows("10.1.5.5") is True
    assert scope.allows("10.2.5.5") is False
    assert scope.allows("192.168.1.1") is False


def test_deny_list_overrides_everything():
    scope = CrawlScope(deny_cidrs=["10.99.0.0/16"])
    assert scope.allows("10.1.1.1") is True
    assert scope.allows("10.99.1.1") is False


def test_deny_beats_allow():
    scope = CrawlScope(allow_cidrs=["10.0.0.0/8"], deny_cidrs=["10.99.0.0/16"])
    assert scope.allows("10.1.1.1") is True
    assert scope.allows("10.99.1.1") is False


def test_rfc1918_only_can_be_disabled():
    scope = CrawlScope(rfc1918_only=False)
    assert scope.allows("8.8.8.8") is True


def test_garbage_input_blocked():
    scope = CrawlScope()
    assert scope.allows("not-an-ip") is False
    assert scope.allows("") is False
    assert scope.allows(None) is False


def test_device_ceiling():
    scope = CrawlScope(max_devices=2)
    assert scope.under_ceiling(0) is True
    assert scope.under_ceiling(1) is True
    assert scope.under_ceiling(2) is False
    assert scope.under_ceiling(50) is False


def test_no_ceiling_by_default():
    scope = CrawlScope()
    assert scope.under_ceiling(100000) is True


def test_invalid_cidr_is_rejected_loudly():
    with pytest.raises(ValueError):
        CrawlScope(allow_cidrs=["not-a-cidr"])
