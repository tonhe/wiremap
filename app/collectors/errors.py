"""Detection of device CLI error responses.

A collector must not parse an error string into data columns. When a device
rejected "show ip ospf", the error text was tokenised into the OSPF Topology
sheet and produced rows like Area="Invalid", Interface="%", Cost="command".

Errors are also classified, because they mean different things:

- not_applicable: the CLI rejected the syntax. The command does not exist on
  this platform or image (show ip vrf on a LAN Base 2960-X, show interfaces
  switchport on a router). Nothing was lost.
- unauthorized: the command exists but AAA refused it. It should have worked.
- failed: the command was sent but no answer came back (timeout, prompt
  desync, dropped session), or the device reported a generic error.
"""
import re

NOT_APPLICABLE = "not_applicable"
UNAUTHORIZED = "unauthorized"
FAILED = "failed"

KIND_LABELS = {
    NOT_APPLICABLE: "not applicable",
    UNAUTHORIZED: "unauthorized",
    FAILED: "failed",
}

# Stored as a command's output when sending it raised, so the failure stays
# distinguishable from a command that legitimately printed nothing. The
# double percent cannot be produced by a device.
SEND_FAILED_PREFIX = "%% command not completed"

# Ordered: AAA refusals and send failures are checked before syntax errors
# so a combined output is never downgraded to not applicable.
_ERROR_PATTERNS = [
    (re.compile(r"^[ \t]*%[ \t]*permission denied", re.I | re.M), UNAUTHORIZED),
    (re.compile(r"^[ \t]*(?:%[ \t]*)?(?:command\s+)?authorization failed", re.I | re.M),
     UNAUTHORIZED),
    (re.compile(r"^" + re.escape(SEND_FAILED_PREFIX), re.M), FAILED),
    (re.compile(r"^[ \t]*%[ \t]*invalid input", re.I | re.M), NOT_APPLICABLE),
    # ASA prefixes the IOS syntax errors with "ERROR: ".
    (re.compile(r"^[ \t]*ERROR:[ \t]*%[ \t]*(?:invalid input|incomplete command|"
                r"ambiguous command)", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*%[ \t]*incomplete command", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*%[ \t]*ambiguous command", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*%[ \t]*unknown command", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*(?:%[ \t]*)?invalid command", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*syntax error", re.I | re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*command not found", re.I | re.M), NOT_APPLICABLE),
    # AireOS answers both an unknown command and one hidden from a read-only
    # account with "Incorrect usage", and a bad argument with "Incorrect input!".
    (re.compile(r"^[ \t]*Incorrect (?:usage|input)\b", re.M), NOT_APPLICABLE),
    (re.compile(r"^[ \t]*ERROR:\s", re.M), FAILED),
]


def classify_error(text: str):
    """Return (offending line, kind) if text is a CLI error response, else None.

    Patterns are anchored to line start so utilisation figures like 5%/0%
    do not register as errors.
    """
    if not text or not text.strip():
        return None
    for pattern, kind in _ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            return text[line_start:line_end].strip(), kind
    return None


def error_reason(text: str):
    """Return the offending line if text is a CLI error response, else None."""
    found = classify_error(text)
    return found[0] if found else None


def error_kind(text: str):
    """not_applicable, unauthorized or failed; None when text is not an error."""
    found = classify_error(text)
    return found[1] if found else None


def is_error_output(text: str) -> bool:
    return error_reason(text) is not None


def send_failure_output(exc) -> str:
    """Output recorded for a command whose send raised."""
    detail = str(exc).strip().splitlines()
    detail = detail[0][:200] if detail else ""
    name = type(exc).__name__
    return f"{SEND_FAILED_PREFIX} ({name}: {detail})" if detail else \
        f"{SEND_FAILED_PREFIX} ({name})"
