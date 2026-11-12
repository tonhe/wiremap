"""AireOS paging, timeouts and the controller's name."""
import pytest

from app import wlc_session as ws

PROMPT = "(lab-wlc-01) >"


class FakeChannel:
    """Replays scripted output; each write unlocks the next chunk."""

    RETURN = "\n"

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.written = []
        self.ready = []

    def write_channel(self, data):
        self.written.append(data)
        if self.chunks:
            self.ready.append(self.chunks.pop(0))

    def read_channel(self):
        return self.ready.pop(0) if self.ready else ""


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _send(chunks, cmd="show ap summary", timeout=None):
    ch = FakeChannel(chunks)
    clock = Clock()
    out = ws.send_paged(ch, cmd, timeout, clock=clock, sleep=clock.sleep)
    return out, ch


def test_plain_output_strips_echo_and_prompt():
    out, ch = _send([f"show ap summary\nline one\nline two\n{PROMPT}"])
    assert out == "line one\nline two"
    assert ch.written == ["show ap summary\n"]


def test_every_pause_is_answered_and_removed():
    out, ch = _send([
        "show ap summary\nrow 1\n--More-- or (q)uit",
        "\x08\x08\x08\x08    \x08\x08\x08\x08row 2\nWould you like to display the next 15 entries? (y/n) ",
        "\nrow 3\nPress Enter to continue...",
        "\nrow 4\nPress any key to continue",
        f"\nrow 5\n{PROMPT}",
    ])
    assert ch.written == ["show ap summary\n", " ", "y\n", "\n", " "]
    assert out.split() == ["row", "1", "row", "2", "row", "3", "row", "4", "row", "5"]
    assert "More" not in out and "display the next" not in out


def test_unknown_question_is_answered_no():
    out, ch = _send(["show sysinfo\nReally? (y/N)", f"\ndone\n{PROMPT}"], cmd="show sysinfo")
    assert ch.written[1] == "n\n"
    assert out.endswith("done")


@pytest.mark.parametrize("pager", [
    "--More-- or (q)uit",
    "--More or (q)uit current module or <ctrl-z> to abort",
    # As a slow link can deliver it: cut off mid-line.
    "--More or (q)uit current module or <ctrl-z> to ab",
    "Press Enter to continue or <Ctrl-Z> to abort",
    "Press any key to continue (Q to quit)",
])
def test_every_pager_wording_is_answered(pager):
    out, ch = _send([f"show sysinfo\nSystem Name.... lab-wlc-01\n{pager}",
                     f"\nProduct Version.... 8.10.185.0\n{PROMPT}"], cmd="show sysinfo")
    assert ch.written[1] in (" ", "\n")
    assert "lab-wlc-01" in out and "8.10.185.0" in out
    assert "More" not in out and "continue" not in out


def test_a_stuck_pager_is_left_after_a_timeout():
    with pytest.raises(ws.WlcReadTimeout) as err:
        _send(["show sysinfo\nrow\nHit (q)uit to stop", f"\n{PROMPT}"], cmd="show sysinfo",
              timeout=5)
    assert "session recovered; last line: 'Hit (q)uit to stop'" in str(err.value)


def test_a_stuck_question_is_declined_after_a_timeout():
    ch = FakeChannel(["show sysinfo\nProceed? (yes/no)", f"\n{PROMPT}"])
    clock = Clock()
    with pytest.raises(ws.WlcReadTimeout) as err:
        ws.send_paged(ch, "show sysinfo", 5, clock=clock, sleep=clock.sleep)
    assert ch.written[1] == "n\n"
    assert "session recovered" in str(err.value)


def test_silence_with_nothing_to_back_out_of_is_not_recovered():
    with pytest.raises(ws.WlcReadTimeout) as err:
        _send(["show sysinfo\nrow 1\n"], cmd="show sysinfo", timeout=5)
    assert "session not recovered" in str(err.value)


def test_a_pager_that_never_lets_go_is_not_recovered():
    with pytest.raises(ws.WlcReadTimeout) as err:
        _send(["show sysinfo\nHit (q)uit to stop"], cmd="show sysinfo", timeout=5)
    assert "session not recovered" in str(err.value)


def test_unknown_question_is_reported_and_known_pauses_are_not():
    seen = []
    ch = FakeChannel(["show sysinfo\nrow\n--More-- or (q)uit", "\nReally? (y/N)",
                      f"\ndone\n{PROMPT}"])
    clock = Clock()
    ws.send_paged(ch, "show sysinfo", clock=clock, sleep=clock.sleep, on_question=seen.append)
    assert seen == ["Really? (y/N)"]


def test_wrapper_keeps_questions_until_taken():
    ch = FakeChannel(["show sysinfo\nReally? (y/N)", f"\ndone\n{PROMPT}"])
    conn = ws.WlcConnection(ch)
    conn.send_command("show sysinfo")
    assert conn.take_notes() == ["Really? (y/N)"]
    assert conn.take_notes() == []


def test_silence_times_out_from_the_last_data():
    with pytest.raises(ws.WlcReadTimeout):
        _send(["show ap summary\nrow 1\n"], timeout=5)


def test_timeout_names_the_last_line_printed():
    with pytest.raises(ws.WlcReadTimeout) as err:
        _send(["show ap summary\nCollecting AP data, please wait\r\n"], timeout=5)
    assert str(err.value).endswith("last line: 'Collecting AP data, please wait'")


def test_last_line():
    assert ws.last_line("a\r\nb\r\n\r\n") == "b"
    assert ws.last_line("") == ""
    assert ws.last_line("x" * 300) == "x" * 120


def test_only_show_commands_are_sent():
    with pytest.raises(ValueError):
        _send([], cmd="config ap reset all")
    with pytest.raises(ValueError):
        _send([], cmd="save config")
    out, _ = _send([f"config paging disable\nIncorrect usage.\n{PROMPT}"],
                   cmd="config paging disable")
    assert out == "Incorrect usage."


def test_timeouts():
    assert ws.timeout_for("show run-config commands") == ws.LONG_TIMEOUT
    assert ws.timeout_for("show ap summary") == ws.SHORT_TIMEOUT


def test_wrapper_lengthens_short_timeouts_and_delegates():
    ch = FakeChannel([f"show time\nTime....... now\n{PROMPT}"])
    ch.base_prompt = "(lab-wlc-01)"
    conn = ws.WlcConnection(ch)
    assert conn.send_command("show time", read_timeout=30) == "Time....... now"
    assert conn.base_prompt == "(lab-wlc-01)"


def test_system_name():
    text = ("Manufacturer's Name.............................. Cisco Systems Inc.\n"
            "System Name...................................... lab-wlc-01\n")
    assert ws.system_name(text) == "lab-wlc-01"
    assert ws.system_name("") == ""
