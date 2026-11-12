"""
Readers for the two shapes AireOS prints almost everything in.

Settings come as dotted label lines:

    System Name...................................... wlc01
    Product Version.................................. 8.10.185.0

and lists as tables whose header sits on a row of dash groups:

    AP Name             Slots  AP Model              Ethernet MAC
    ------------------  -----  --------------------  -----------------
    ap01                 2     AIR-AP2802I-B-K9      00:11:22:33:44:55

A value longer than its column pushes the rest of the row right, so a row
whose column boundaries fall inside text is split on runs of spaces instead.
"""
import re

_DOTTED_RE = re.compile(r"^\s*(\S[^\n]*?)\s*\.{3,}\s*(.*?)\s*$")
_DASHES_RE = re.compile(r"^\s*-{2,}(\s+-{2,})*\s*$")
_MAC_RE = re.compile(r"\b([0-9a-f]{2}([:.-])[0-9a-f]{2}(\2[0-9a-f]{2}){4})\b", re.I)


def dotted(text):
    """{label: value} from dotted label lines. The first occurrence of a
    label wins; repeated sections are read with dotted_sections."""
    out = {}
    for line in (text or "").splitlines():
        m = _DOTTED_RE.match(line)
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2)
    return out


def dotted_all(text):
    """[(label, value)] in order, keeping repeats."""
    out = []
    for line in (text or "").splitlines():
        m = _DOTTED_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def lookup(values, *labels, default=None):
    """First value whose label matches one of labels, ignoring case."""
    lowered = {k.lower(): v for k, v in (values or {}).items()}
    for label in labels:
        value = lowered.get(label.lower())
        if value is not None:
            return value
    return default


def _spans(dash_line):
    return [(m.start(), m.end()) for m in re.finditer(r"-+", dash_line)]


def _split_row(line, spans):
    starts = [s for s, _ in spans]
    boundaries_clean = all(b == 0 or b > len(line) or line[b - 1] == " " or line[b] == " "
                           for b in starts[1:] if b < len(line))
    if boundaries_clean:
        cells = []
        for i, start in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else None
            cells.append(line[start:end].strip() if start < len(line) else "")
        return cells
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < len(starts):
        parts += [""] * (len(starts) - len(parts))
    return parts[:len(starts) - 1] + [" ".join(parts[len(starts) - 1:])]


def tables(text):
    """Every table in text, as a list of row dicts keyed by header."""
    lines = (text or "").splitlines()
    out = []
    i = 0
    while i < len(lines):
        if i > 0 and _DASHES_RE.match(lines[i]):
            spans = _spans(lines[i])
            header = _split_row(lines[i - 1].ljust(spans[-1][1]), spans)
            rows = []
            i += 1
            while i < len(lines) and lines[i].strip() and not _DASHES_RE.match(lines[i]):
                if i + 1 < len(lines) and _DASHES_RE.match(lines[i + 1]):
                    break
                cells = _split_row(lines[i], spans)
                rows.append(dict(zip(header, cells)))
                i += 1
            out.append(rows)
            continue
        i += 1
    return out


def table(text):
    """Rows of the first table in text."""
    found = tables(text)
    return found[0] if found else []


def to_int(value):
    m = re.search(r"-?\d+", str(value or "").replace(",", ""))
    return int(m.group()) if m else None


def to_float(value):
    m = re.search(r"-?\d+(\.\d+)?", str(value or ""))
    return float(m.group()) if m else None


def norm_mac(value):
    """'00:11:22:33:44:55', '0011.2233.4455' or '00-11-...' -> '00:11:22:33:44:55'."""
    digits = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(digits) != 12:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def macs_in(text):
    return [m.group(1) for m in _MAC_RE.finditer(text or "")]


def enabled(value):
    """True / False for Enabled/Disabled, Yes/No, On/Off; None otherwise."""
    v = str(value or "").strip().lower()
    if v.startswith(("enable", "yes", "on", "true", "up")):
        return True
    if v.startswith(("disable", "no", "off", "false", "down")):
        return False
    return None
