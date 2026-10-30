from app.collectors.errors import is_error_output, error_reason


def test_detects_invalid_input():
    assert is_error_output("% Invalid input detected at '^' marker.") is True


def test_detects_incomplete_command():
    assert is_error_output("% Incomplete command.") is True


def test_detects_ambiguous_command():
    assert is_error_output('% Ambiguous command: "show ip"') is True


def test_detects_nxos_invalid():
    assert is_error_output("Invalid command at '^' marker.") is True


def test_detects_permission_denied():
    assert is_error_output("% Permission denied") is True


def test_allows_normal_output():
    normal = (
        "Interface    IP-Address      OK? Method Status\n"
        "Gi0/1        10.0.0.1        YES NVRAM  up\n"
    )
    assert is_error_output(normal) is False


def test_percent_sign_in_data_is_not_an_error():
    """Utilisation figures contain % and must not trip the detector."""
    assert is_error_output("CPU utilization for five seconds: 5%/0%") is False


def test_empty_output_is_not_an_error():
    assert is_error_output("") is False
    assert is_error_output("   \n  ") is False


def test_error_reason_returns_the_line():
    reason = error_reason("% Invalid input detected at '^' marker.")
    assert "Invalid input" in reason


def test_error_reason_none_when_clean():
    assert error_reason("Gi0/1 up up") is None


def test_error_after_echoed_command():
    """The device echoes the command before rejecting it."""
    output = "show ip ospf\n           ^\n% Invalid input detected at '^' marker.\n"
    assert is_error_output(output) is True


def test_ospf_topology_symptom():
    """The exact output that produced Area=Invalid, Interface=%, Cost=command."""
    assert is_error_output("% Invalid input detected at '^' marker.") is True


def test_long_whitespace_runs_stay_linear():
    """Every show output passes through the detector; padded tables and
    blank runs must not make it backtrack quadratically."""
    import time
    text = (" " * 50000 + "x\n") + ("\n" * 50000) + ("\t" * 50000 + "y\n")
    started = time.perf_counter()
    assert is_error_output(text) is False
    assert time.perf_counter() - started < 0.5


def test_error_on_indented_line_still_detected():
    assert is_error_output("show ip vrf\n   % Invalid input detected\n") is True
