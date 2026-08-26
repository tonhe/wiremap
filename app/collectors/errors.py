"""Detection of device CLI error responses.

A collector must not parse an error string into data columns. When a device
rejected "show ip ospf", the error text was tokenised into the OSPF Topology
sheet and produced rows like Area="Invalid", Interface="%", Cost="command".
"""
import re

_ERROR_PATTERNS = [
    re.compile(r"^\s*%\s*invalid input", re.I | re.M),
    re.compile(r"^\s*%\s*incomplete command", re.I | re.M),
    re.compile(r"^\s*%\s*ambiguous command", re.I | re.M),
    re.compile(r"^\s*%\s*unknown command", re.I | re.M),
    re.compile(r"^\s*%\s*permission denied", re.I | re.M),
    re.compile(r"^\s*%\s*authorization failed", re.I | re.M),
    re.compile(r"^\s*invalid command", re.I | re.M),
    re.compile(r"^\s*syntax error", re.I | re.M),
    re.compile(r"^\s*command not found", re.I | re.M),
    re.compile(r"^\s*ERROR:\s", re.M),
]


def error_reason(text: str):
    """Return the offending line if text is a CLI error response, else None.

    Patterns are anchored to line start so utilisation figures like 5%/0%
    do not register as errors.
    """
    if not text or not text.strip():
        return None
    for pattern in _ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            return text[line_start:line_end].strip()
    return None


def is_error_output(text: str) -> bool:
    return error_reason(text) is not None
