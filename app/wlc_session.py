"""
Talking to an AireOS controller once netmiko has logged in.

A read-only account cannot run "config paging disable", so long outputs stop
at --More-- and a handful of other questions. Every command therefore goes
through send_paged, which answers each pause the way the operator would and
waits for the controller's prompt rather than for a quiet line.

The prompt carries "(Cisco Controller)" until someone names the box, so the
controller is keyed by the System Name show sysinfo reports instead.
"""
import re
import time

WLC_TYPE = "cisco_wlc"
SYSINFO = "show sysinfo"

LONG_TIMEOUT = 300
SHORT_TIMEOUT = 120
_LONG = ("show run-config",)

PROMPT_RE = re.compile(r"\([^()\n]*\)\s*>\s*$")

# Checked in order against the end of the output. Nothing is ever confirmed:
# any question not listed here is answered no.
PAUSES = [
    (re.compile(r"--More--\s*or\s*\(q\)uit\s*$", re.I), " "),
    (re.compile(r"Would you like to display the next.*\(y/n\)\s*$", re.I), "y\n"),
    (re.compile(r"Press Enter to continue\.*\s*$", re.I), "\n"),
    (re.compile(r"Press any key to continue\.*\s*$", re.I), " "),
    (re.compile(r"\(y/n\)\s*$", re.I), "n\n"),
]

# Read only. Paging is the one setting a session may change, and only for
# itself; nothing else that alters the controller is ever sent.
_ALLOWED = re.compile(r"^(show|grep)\b|^config paging disable$")


class WlcReadTimeout(Exception):
    pass


def timeout_for(command):
    return LONG_TIMEOUT if command.startswith(_LONG) else SHORT_TIMEOUT


def _clean(buf, command):
    # A pause is erased with backspaces and blanks before output resumes.
    text = re.sub(r"\x08+ *\x08*", "", buf).replace("\r", "")
    lines = text.split("\n")
    if lines and lines[0].strip().endswith(command.strip()):
        lines = lines[1:]
    if lines and PROMPT_RE.search(lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


def last_line(buf, limit=120):
    """The last thing the controller printed, to name a question nobody answered."""
    lines = [ln.strip() for ln in re.sub(r"\x08+ *\x08*", "", buf).replace("\r", "\n").split("\n")]
    lines = [ln for ln in lines if ln]
    return lines[-1][:limit] if lines else ""


def send_paged(conn, command, read_timeout=None, clock=time.monotonic, sleep=time.sleep):
    """Run command and return its output, answering every pause.

    read_timeout counts from the last data received: a slow controller that
    is still printing is never cut off, a silent one gives up.
    """
    if not _ALLOWED.match(command.strip()):
        raise ValueError(f"refusing to send a non-show command: {command}")
    timeout = read_timeout or timeout_for(command)
    newline = getattr(conn, "RETURN", "\n")
    conn.write_channel(command + newline)
    buf = ""
    seen = 0
    last_data = clock()
    while True:
        chunk = conn.read_channel()
        if chunk:
            buf += chunk
            last_data = clock()
            tail = buf[seen:]
            answered = False
            for pattern, answer in PAUSES:
                m = pattern.search(tail)
                if m:
                    conn.write_channel(answer.replace("\n", newline))
                    # The pause line is the controller's, not the output's.
                    buf = buf[:seen] + tail[:m.start()]
                    seen = len(buf)
                    answered = True
                    break
            if not answered and PROMPT_RE.search(buf[-200:]):
                return _clean(buf, command)
            continue
        if clock() - last_data > timeout:
            raise WlcReadTimeout(
                f"no prompt after {timeout}s waiting for output of {command}; "
                f"last line: {last_line(buf)!r}")
        sleep(0.1)


class WlcConnection:
    """A netmiko connection whose send_command answers AireOS pauses."""

    def __init__(self, conn):
        self._conn = conn

    def send_command(self, command_string, read_timeout=None, **kwargs):
        timeout = max(read_timeout or 0, timeout_for(command_string))
        return send_paged(self._conn, command_string, timeout)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def system_name(sysinfo):
    m = re.search(r"^\s*System Name\.+\s*(\S.*?)\s*$", sysinfo or "", re.M)
    return m.group(1) if m else ""


def prompt_name(prompt):
    """'(lab-wlc-01) >' -> 'lab-wlc-01'; the factory default names nothing."""
    m = re.match(r"^\s*\(([^()]*)\)", str(prompt or ""))
    name = m.group(1).strip() if m else ""
    return "" if name.lower() == "cisco controller" else name
