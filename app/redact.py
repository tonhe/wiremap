"""
Secret redaction for device configuration text.

Running configs carry SNMP communities, enable/user secrets, AAA server
keys, routing-protocol keys and VPN pre-shared keys. The config archive and
the JSON inventory get mailed around, so those tokens are replaced with
REDACTED before anything is stored.

Redaction is line based: every line is kept and only the secret token is
swapped out, so line counts, diffs and the config-reading reports still work.
"""
import re

REDACTED = "<REDACTED>"

# Optional encryption-type token in front of a secret: "7", "5", "9",
# "10" (IOS-XR), "encrypted"/"clear" (IOS-XR), "sha512" (Arista).
_T = r"(?:(?:\d+|encrypted|clear|sha512)\s+)?"
# The secret itself: a quoted string (NX-OS quotes keys) or one token.
_S = r"(?P<s>\"[^\"]*\"|'[^']*'|\S+?(?=;?\s*$|\s))"
# Same, but stops at ';' for brace-style configs (Junos, PAN-OS).
_S_BRACE = r"(?P<s>\"[^\"]*\"|'[^']*'|[^\s;]+)"

_I = re.IGNORECASE

_RULES = [
    # --- SNMP -----------------------------------------------------------
    # snmp-server community <c> [view V] [RO|RW] [acl]
    re.compile(r"^\s*snmp-server\s+community\s+" + _T + _S, _I),
    # ASA: snmp-server host <if> <ip> community <c> version 2c
    re.compile(r"^\s*snmp-server\s+host\s+.*?\bcommunity\s+" + _T + _S, _I),
    # snmp-server user U G v3 auth sha <k> priv aes 128 <k>
    re.compile(r"^\s*snmp-server\s+user\s+.*?\bauth\s+(?:md5|sha\S*)\s+"
               + _T + _S, _I),
    re.compile(r"^\s*snmp-server\s+user\s+.*?\bpriv\s+"
               r"(?:(?:des\S*|3des|aes\S*)\s+)?(?:(?:128|192|256)\s+)?"
               + _T + _S, _I),

    # --- Local accounts ---------------------------------------------------
    re.compile(r"^\s*enable\s+(?:algorithm-type\s+\S+\s+)?(?:secret|password)\s+"
               r"(?:level\s+\d+\s+)?" + _T + _S, _I),
    re.compile(r"^\s*username\s+\S+\s+(?:.*?\s)?(?:secret|password)\s+"
               + _T + _S, _I),
    # Block-level password/secret: line vty/con, IOS-XR username blocks.
    # Global knobs like "password encryption aes" are not secrets.
    re.compile(r"^\s*(?:password|secret)\s+"
               r"(?!(?:encryption|strength-check|secure-mode|policy)\b)"
               + _T + _S, _I),
    # Anything typed "password 7 <x>" / "secret 5 <x>" (ppp chap, pki, ...).
    re.compile(r"\b(?:password|secret)\s+\d+\s+" + _S, _I),
    # ASA telnet/ssh password.
    re.compile(r"^\s*passwd\s+" + _S, _I),
    # IOS master key: "key config-key password-encrypt <x>".
    re.compile(r"\bpassword-encrypt\s+" + _S, _I),

    # --- AAA --------------------------------------------------------------
    re.compile(r"^\s*(?:tacacs-server|radius-server)\b.*?\bkey\s+" + _T + _S, _I),
    re.compile(r"\bserver-private\s+\S+\s+(?:.*?\s)?key\s+" + _T + _S, _I),
    # "tacacs server X" / "radius server X" block: " key 7 <x>". A bare
    # " key 1" is a key-chain key id, not a secret.
    re.compile(r"^\s+key\s+(?!\d+\s*$)" + _T + _S, _I),
    # Any "key 7 <x>" / "key 0 <x>".
    re.compile(r"(?<![\w-])key\s+\d\s+" + _S, _I),

    # --- Routing protocols --------------------------------------------------
    re.compile(r"\bkey-string\s+(?:password\s+)?" + _T + _S, _I),
    re.compile(r"\bneighbor\s+\S+\s+password\s+" + _T + _S, _I),
    re.compile(r"\bmessage-digest-key\s+\d+\s+md5\s+" + _T + _S, _I),
    re.compile(r"\bip\s+ospf\s+authentication-key\s+" + _T + _S, _I),
    # IOS-XR / NX-OS block form; "authentication-key 1 md5 ..." is NTP.
    re.compile(r"^\s+authentication-key\s+(?!\d+\s+\S+\s+\S)" + _T + _S, _I),
    re.compile(r"\b(?:area|domain)-password\s+" + _T + _S, _I),
    re.compile(r"\bisis\s+password\s+" + _T + _S, _I),
    re.compile(r"\bntp\s+authentication-key\s+\d+\s+\S+\s+(?:(?:encrypted|clear)\s+)?" + _S, _I),

    # --- First-hop redundancy -------------------------------------------------
    re.compile(r"\b(?:standby|vrrp)\s+(?:\d+\s+)?authentication\s+(?:text\s+)?"
               r"(?!(?:md5|text)\b)" + _S, _I),
    re.compile(r"^\s+authentication\s+text\s+" + _S, _I),

    # --- VPN / tunnels ----------------------------------------------------------
    re.compile(r"\bcrypto\s+isakmp\s+key\s+" + _T + _S, _I),
    # IKEv1 keyring: "pre-shared-key address 192.0.2.1 key <x>"
    re.compile(r"\bpre-shared-key\s+(?:address|hostname)\s+.*?\bkey\s+" + _T + _S, _I),
    # IKEv2 keyring / ASA tunnel-group / PAN-OS "pre-shared-key key <x>"
    re.compile(r"\bpre-shared-key\s+(?!(?:address|hostname)\b)"
               r"(?:(?:local|remote|key)\s+)?" + _T + _S, _I),
    re.compile(r"\bpre-share\s+key\s+" + _T + _S, _I),
    re.compile(r"^\s*tunnel\s+key\s+" + _S, _I),

    # --- Wireless -------------------------------------------------------------
    re.compile(r"\bwpa-psk\s+(?:ascii|hex)\s+" + _T + _S, _I),
    re.compile(r"\bset-key\s+(?:ascii|hex)\s+" + _S, _I),
    # AireOS run-config
    re.compile(r"^\s*config\s+snmp\s+community\s+create\s+" + _S, _I),
    re.compile(r"^\s*config\s+radius\s+(?:auth|acct)\s+add\s+\S+\s+\S+\s+\S+\s+"
               r"(?:ascii|hex)\s+" + _S, _I),
    re.compile(r"^\s*config\s+mgmtuser\s+add\s+\S+\s+" + _S, _I),
]

# PAN-OS / VyOS "set ..." lines and brace-style lines ending in ';'.
_SET_KEYWORDS = (r"(?:password|secret|phash|encrypted-password|plaintext-password|"
                 r"authentication-key|shared-secret|pre-shared-secret|private-key|"
                 r"snmp-community-string|community-string|key)")
_SET_RULES = [
    re.compile(r"(?<![\w-])" + _SET_KEYWORDS + r"\s+" + _S_BRACE, _I),
    re.compile(r"\bsnmp\s+community\s+" + _S_BRACE, _I),
]
_BRACE_RULE = re.compile(r"^\s*" + _SET_KEYWORDS + r"\s+" + _S_BRACE + r"\s*;", _I)

# Junos marks secret lines itself.
_JUNOS_SECRET = re.compile(r"\"[^\"]*\"")

# "snmp-server host" keywords that may sit between the address and the
# community. A host line carrying one of the _HOST_NO_COMMUNITY keywords is
# an NX-OS side setting and has no community on it.
_HOST_SKIP_ONE = {"informs", "traps", "inform", "trap", "poll"}
_HOST_SKIP_TWO = {"vrf", "version"}
_HOST_NO_COMMUNITY = {"use-vrf", "filter-vrf", "source-interface"}
_ADDR = re.compile(r"^[0-9A-Fa-f.:]+$")


def _snmp_host_span(line):
    """Span of the community on a positional 'snmp-server host' line."""
    tokens = list(re.finditer(r"\S+", line))
    words = [t.group(0).lower() for t in tokens]
    if words[:2] != ["snmp-server", "host"] or len(words) < 4:
        return None
    if "community" in words:
        return None  # keyword form, handled by the regex rule
    i = 3
    # ASA: snmp-server host <ifname> <ip> ...
    if not _ADDR.match(words[2]) and _ADDR.match(words[3]):
        i = 4
    while i < len(words):
        w = words[i]
        if w in _HOST_NO_COMMUNITY:
            return None
        if w in _HOST_SKIP_ONE:
            i += 1
        elif w == "version":
            if i + 1 < len(words) and words[i + 1] == "3":
                return None  # v3: the next token is a user name
            i += 2
        elif w in _HOST_SKIP_TWO:
            i += 2
        elif w in ("encrypted", "clear"):
            i += 1
        else:
            return tokens[i].span()
    return None


def _secret_spans(line):
    spans = []
    for rule in _RULES:
        for m in rule.finditer(line):
            spans.append(m.span("s"))
    host = _snmp_host_span(line)
    if host:
        spans.append(host)
    stripped = line.lstrip()
    if stripped.lower().startswith("set "):
        for rule in _SET_RULES:
            for m in rule.finditer(line):
                spans.append(m.span("s"))
    elif stripped.rstrip().endswith(";"):
        m = _BRACE_RULE.match(line)
        if m:
            spans.append(m.span("s"))
    if "## SECRET-DATA" in line:
        for m in _JUNOS_SECRET.finditer(line):
            spans.append(m.span())
    return spans


def redact_line(line):
    spans = sorted(s for s in _secret_spans(line) if s[1] > s[0])
    if not spans:
        return line
    merged = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    out = []
    pos = 0
    for start, end in merged:
        out.append(line[pos:start])
        out.append(REDACTED)
        pos = end
    out.append(line[pos:])
    return "".join(out)


def redact_config(text):
    """Return text with secret tokens replaced by REDACTED, line by line."""
    if not text:
        return text
    return "".join(redact_line(line) for line in text.splitlines(keepends=True))
