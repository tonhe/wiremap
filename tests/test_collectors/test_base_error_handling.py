from app.collectors.base import BaseCollector


class _Fake(BaseCollector):
    name = "fake"

    def get_commands(self, device_type):
        return ["show ip ospf"]

    def parse(self, raw_outputs, device_type):
        return {"rows": [line.split() for line
                         in raw_outputs["show ip ospf"].splitlines() if line]}


class _TwoCommand(BaseCollector):
    name = "two"

    def get_commands(self, device_type):
        return ["good", "bad"]

    def parse(self, raw_outputs, device_type):
        return {"good": raw_outputs["good"], "bad": raw_outputs["bad"]}


class _Conn:
    def __init__(self, output):
        self._output = output

    def send_command(self, cmd):
        if isinstance(self._output, dict):
            return self._output[cmd]
        return self._output


def test_error_output_is_not_parsed():
    collector = _Fake()
    result = collector.collect(_Conn("% Invalid input detected at '^' marker."),
                               "cisco_ios")
    assert result["parsed"]["collector_failed"] is True
    assert "Invalid input" in result["parsed"]["collector_error"]
    assert result["parsed"].get("rows") in (None, [])


def test_clean_output_is_parsed_normally():
    collector = _Fake()
    result = collector.collect(_Conn("Gi0/1 up up"), "cisco_ios")
    assert result["parsed"].get("collector_failed") is not True
    assert result["parsed"]["rows"] == [["Gi0/1", "up", "up"]]


def test_raw_output_is_preserved_on_failure():
    """The raw error text stays available for diagnosis."""
    collector = _Fake()
    result = collector.collect(_Conn("% Invalid input detected at '^' marker."),
                               "cisco_ios")
    assert "Invalid input" in result["raw"]["show ip ospf"]


def test_partial_failure_still_parses_good_output():
    collector = _TwoCommand()
    conn = _Conn({"good": "data here", "bad": "% Invalid input detected"})
    result = collector.collect(conn, "cisco_ios")
    assert result["parsed"].get("collector_failed") is not True
    assert result["parsed"]["good"] == "data here"
    assert result["parsed"]["bad"] == ""


def test_failed_commands_are_listed():
    collector = _Fake()
    result = collector.collect(_Conn("% Invalid input detected"), "cisco_ios")
    assert result["parsed"]["failed_commands"] == ["show ip ospf"]


def test_partial_failure_preserves_raw_error_text():
    """The rejected command is blanked for the parser but kept in raw."""
    collector = _TwoCommand()
    conn = _Conn({"good": "data here", "bad": "% Invalid input detected"})
    result = collector.collect(conn, "cisco_ios")
    assert "Invalid input" in result["raw"]["bad"]
    assert result["parsed"]["failed_commands"] == ["bad"]


class _NoCmd(BaseCollector):
    name = "nocmd"
    unsupported_platforms = frozenset({"vyos"})

    def get_commands(self, device_type):
        return ["show ip arp"]

    def parse(self, raw_outputs, device_type):
        return {"parsed": True}


class _EmptyCmd(BaseCollector):
    name = "emptycmd"

    def get_commands(self, device_type):
        return []

    def parse(self, raw_outputs, device_type):
        raise AssertionError("parse must not run with no commands")


def test_unsupported_platform_is_not_collected():
    """A collector that cannot serve a platform must not run Cisco commands
    at it and produce a wall of errors."""
    result = _NoCmd().collect(_Conn("irrelevant"), "vyos")
    assert result["parsed"]["not_applicable"] is True
    assert result["raw"] == {}


def test_supported_platform_still_collects():
    result = _NoCmd().collect(_Conn("Gi0/1 up"), "cisco_ios")
    assert result["parsed"].get("not_applicable") is not True


def test_empty_command_list_short_circuits():
    result = _EmptyCmd().collect(_Conn("x"), "cisco_ios")
    assert result["parsed"]["not_applicable"] is True
