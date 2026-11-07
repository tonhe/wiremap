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
    # snmp mib community-map <c> context <ctx> [...]
    re.compile(r"^\s*snmp\s+mib\s+community-map\s+" + _S, _I),
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
    # Untyped "... password <x>" mid-line: ip ftp, ppp chap/pap, ip http
    # client, l2tp tunnel, cts credentials, LDAP bind. Policy knobs that
    # take a keyword after "password" are not secrets.
    re.compile(r"(?<![\w-])password\s+"
               r"(?!(?:encryption|strength-check|secure-mode|policy|restriction|"
               r"prompt|history|length|min-length|max-length|lifetime|reuse|"
               r"change|expire|expiry|required|complexity|aging|lockout|"
               r"management)\b)" + _T + _S, _I),
    # ASA: "failover key [hex] <x>", "ldap-login-password <x>".
    re.compile(r"^\s*failover\s+key\s+(?:hex\s+)?" + _T + _S, _I),
    re.compile(r"\bldap-login-password\s+" + _S, _I),
    # Credentials embedded in a URL: archive path, copy targets, kron.
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^:/@\s]+:(?P<s>[^@\s]+)@", _I),
    # ASA telnet/ssh password.
    re.compile(r"^\s*passwd\s+" + _S, _I),
    # IOS master key: "key config-key password-encrypt <x>".
    re.compile(r"\bpassword-encrypt\s+" + _S, _I),

    # --- AAA --------------------------------------------------------------
    re.compile(r"^\s*(?:tacacs-server|radius-server)\b.*?\bkey\s+" + _T + _S, _I),
    re.compile(r"\bserver-private\s+\S+\s+(?:.*?\s)?key\s+" + _T + _S, _I),
    # CoA: "aaa server radius dynamic-author" block, " server-key [7] <x>"
    # and " client <ip> server-key [7] <x>".
    re.compile(r"\bserver-key\s+" + _T + _S, _I),
    # "tacacs server X" / "radius server X" block: " key 7 <x>". A bare
    # " key 1" is a key-chain key id, not a secret.
    re.compile(r"^\s+key\s+(?!\d+\s*$)" + _T + _S, _I),
    # Any "key 7 <x>" / "key 0 <x>".
    re.compile(r"(?<![\w-])key\s+\d\s+" + _S, _I),

    # --- Routing protocols --------------------------------------------------
    re.compile(r"\bkey-string\s+(?:password\s+)?" + _T + _S, _I),
    re.compile(r"\bneighbor\s+\S+\s+password\s+" + _T + _S, _I),
    re.compile(r"\bmessage-digest-key\s+\d+\s+md5\s+" + _T + _S, _I),
    # IOS "ip ospf authentication-key", NX-OS "ospf authentication-key".
    re.compile(r"\bospf\s+authentication-key\s+" + _T + _S, _I),
    # OSPFv3 IPsec: "ipv6 ospf authentication ipsec spi 256 sha1 [0|7] <hex>"
    re.compile(r"\bauthentication\s+ipsec\s+spi\s+\d+\s+(?:md5|sha1)\s+"
               + _T + _S, _I),
    # EIGRP named mode: "authentication mode hmac-sha-256 [0|7] <x>"
    re.compile(r"\bauthentication\s+mode\s+hmac-sha-256\s+" + _T + _S, _I),
    # IS-IS (IOS-XR): "hello-password|lsp-password [hmac-md5|text] <x>"
    re.compile(r"\b(?:hello|lsp)-password\s+(?:(?:hmac-\S+|text)\s+)?"
               r"(?!keychain\b)" + _T + _S, _I),
    # BFD: "... key-id 1 key <x>"
    re.compile(r"\bkey-id\s+\d+\s+key\s+" + _T + _S, _I),
    # DMVPN: "ip nhrp authentication <x>"
    re.compile(r"\bip\s+nhrp\s+authentication\s+" + _S, _I),
    # IOS-XR / NX-OS block form; "authentication-key 1 md5 ..." is NTP.
    re.compile(r"^\s+authentication-key\s+(?!\d+\s+\S+\s+\S)" + _T + _S, _I),
    re.compile(r"\b(?:area|domain)-password\s+" + _T + _S, _I),
    re.compile(r"\bisis\s+password\s+" + _T + _S, _I),
    re.compile(r"\bntp\s+authentication-key\s+\d+\s+\S+\s+(?:(?:encrypted|clear)\s+)?" + _S, _I),

    # --- First-hop redundancy -------------------------------------------------
    re.compile(r"\b(?:standby|vrrp|glbp)\s+(?:\d+\s+)?authentication\s+(?:text\s+)?"
               r"(?!(?:md5|text)\b)" + _S, _I),
    re.compile(r"^\s+authentication\s+text\s+" + _S, _I),

    # --- VPN / tunnels ----------------------------------------------------------
    re.compile(r"\bcrypto\s+isakmp\s+key\s+" + _T + _S, _I),
    # IKEv1 keyring: "pre-shared-key address 192.0.2.1 key <x>"
    re.compile(r"\bpre-shared-key\s+(?:address|hostname)\s+.*?\bkey\s+" + _T + _S, _I),
    # IKEv2 keyring / ASA tunnel-group / PAN-OS "pre-shared-key key <x>"
    re.compile(r"\bpre-shared-key\s+(?!(?:address|hostname|key-chain)\b)"
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

# Safety net: a crypt-style hash ($1$ MD5, $5$/$6$ SHA, $8$ PBKDF2, $9$
# scrypt, $14$, $sha512$, ...) is a secret whatever line it sits on, so any
# such token left over after the rules above is redacted too.
_CRYPT_HASH = re.compile(r"(?<![\w$])\$(?:[0-9a-z]{1,2}|sha\d+|apr1)\$[^\s;\"']+", _I)

# Second net: a bare 32/40/64-hex token (MD5 / SHA-1 / SHA-256 sized) after
# a key/password/secret-ish word on the same line. Hex alone is not enough:
# certificate chain bodies are 8-hex groups, MACs are dotted, and engine IDs
# and serials sit on lines with no such word, so those stay intact.
_HEX_BLOB = re.compile(r"(?<![0-9A-Fa-f.:])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|"
                       r"[0-9A-Fa-f]{32})(?![0-9A-Fa-f.:])")
_SECRETISH = re.compile(r"key|passw|secret|auth|psk", _I)

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
    for m in _CRYPT_HASH.finditer(line):
        spans.append(m.span())
    for m in _HEX_BLOB.finditer(line):
        if _SECRETISH.search(line, 0, m.start()):
            spans.append(m.span())
    return spans


_MASKED = re.compile(r"\*+")
# Older ASA code prints an unset enable password as this fixed encrypted form
# of the empty string. It is public knowledge, and keeping it lets the ASA
# report flag an enable password that was never set.
_ASA_BLANK_ENABLE = "8Ry2YjIyt7RRXU24"


def _not_secret(token):
    return bool(_MASKED.fullmatch(token)) or token == _ASA_BLANK_ENABLE


def _merged_spans(line):
    # ASA show running-config already prints most secrets as *****; that is
    # not a secret and stays as the device printed it.
    spans = sorted(s for s in _secret_spans(line)
                   if s[1] > s[0] and not _not_secret(line[s[0]:s[1]]))
    merged = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _replace(line, merged):
    out = []
    pos = 0
    for start, end in merged:
        out.append(line[pos:start])
        out.append(REDACTED)
        pos = end
    out.append(line[pos:])
    return "".join(out)


def redact_line(line):
    merged = _merged_spans(line)
    if not merged:
        return line
    return _replace(line, merged)


def redact_config_counted(text):
    """Redact text and count the secret tokens that were still in clear.

    Tokens already reading REDACTED are not counted, so running this over a
    config redacted at collection time counts only what that pass missed.
    """
    if not text:
        return text, 0
    out = []
    count = 0
    for line in text.splitlines(keepends=True):
        merged = _merged_spans(line)
        count += sum(1 for s, e in merged if line[s:e] != REDACTED)
        out.append(_replace(line, merged) if merged else line)
    return "".join(out), count


def redact_config(text):
    """Return text with secret tokens replaced by REDACTED, line by line."""
    if not text:
        return text
    return "".join(redact_line(line) for line in text.splitlines(keepends=True))
