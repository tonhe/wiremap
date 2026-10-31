"""A neighbour's category comes from its advertised model when wiremap knows
the model, before any login."""
from app.device_detector import DeviceTypeDetector
from app.discovery_engine import DiscoveryEngine
from app.inventory import refresh_categories


def _category(platform, caps):
    return DeviceTypeDetector()._categorize_device(set(caps), platform, "")[0]


def test_cube_router_advertising_switch_is_a_router():
    assert _category("cisco ISR4351/K9", ["ROUTER", "SWITCH", "IGMP"]) == "router"


def test_voice_gateways_advertising_router_are_voice_gateways():
    assert _category("Cisco VG310", ["ROUTER"]) == "voice-gateway"
    assert _category("cisco VG224", ["ROUTER", "SWITCH"]) == "voice-gateway"


def test_unknown_platform_still_uses_capabilities():
    assert _category("cisco AIR-AP2802I-B-K9", ["TRANS-BRIDGE"]) == "access_point"
    assert _category("Cisco IP Phone 8851", ["HOST", "PHONE"]) == "phone"


def test_voice_gateways_are_crawled_with_routers():
    engine = DiscoveryEngine.__new__(DiscoveryEngine)
    engine.filters = {"include_routers": True, "include_other": False}
    assert engine._should_include("voice-gateway")


def test_old_scan_neighbour_only_devices_take_category_from_platform():
    data = {"devices": {
        "VG-B": {"login_succeeded": False, "device_category": "router",
                 "platform": "cisco VG310"},
        "CUBE-B": {"login_succeeded": False, "device_category": "switch",
                   "platform": "cisco ISR4351/K9"},
        "AP-B": {"login_succeeded": False, "device_category": "access_point",
                 "platform": "cisco AIR-AP2802I-B-K9"},
    }}
    assert sorted(refresh_categories(data)) == ["CUBE-B", "VG-B"]
    assert data["devices"]["VG-B"]["device_category"] == "voice-gateway"
    assert data["devices"]["CUBE-B"]["device_category"] == "router"
    assert data["devices"]["AP-B"]["device_category"] == "access_point"
