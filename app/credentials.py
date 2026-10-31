"""
Login credential sets for a scan.

A site often has more than one account in play: a TACACS account, a local
fallback account, a separate account on a legacy segment. A scan takes up to
MAX_CREDENTIAL_SETS username/password pairs. Set 1 is the form's plain
username/password fields; sets 2..N arrive as username_N / password_N.

Passwords live only in memory for the length of the scan. Nothing here
logs, prints or serialises one: Credential's repr shows the username and
set number only, and summaries carry usernames at most.
"""
import threading

MAX_CREDENTIAL_SETS = 5


class Credential:
    """One username/password pair and its set number (1-based, as the
    operator numbered it on the form)."""

    __slots__ = ("number", "username", "password")

    def __init__(self, number, username, password):
        self.number = int(number)
        self.username = username
        self.password = password

    def label(self):
        return f"{self.username} (set {self.number})"

    def __repr__(self):
        return f"Credential(number={self.number}, username={self.username!r})"

    def __eq__(self, other):
        # Compared by value, not class: app.credentials and a bare
        # credentials import are different module objects.
        try:
            return ((self.number, self.username, self.password)
                    == (other.number, other.username, other.password))
        except AttributeError:
            return False

    def __hash__(self):
        return hash((self.number, self.username))


def _field_names(number):
    if number == 1:
        return "username", "password"
    return f"username_{number}", f"password_{number}"


def parse_credential_form(form):
    """Credential list from a scan form, in configured order.

    Fully blank rows are ignored. A row with only one half filled in is an
    error rather than a silent skip, so a typo never quietly drops an
    account. An exact duplicate of an earlier set is dropped: it would only
    cost another AAA failure. Raises ValueError with an operator-facing
    message.
    """
    credentials = []
    seen = set()
    for number in range(1, MAX_CREDENTIAL_SETS + 1):
        user_field, pass_field = _field_names(number)
        username = (form.get(user_field) or "").strip()
        password = form.get(pass_field) or ""
        if not username and not password:
            continue
        if not password:
            raise ValueError(f"Credential set {number}: password is required")
        if not username:
            raise ValueError(f"Credential set {number}: username is required")
        key = (username, password)
        if key in seen:
            continue
        seen.add(key)
        credentials.append(Credential(number, username, password))
    if not credentials:
        raise ValueError("Username and password are required")
    return credentials


class CredentialChain:
    """Per-scan try order for the credential sets.

    The set that most recently logged in goes first; the rest follow in the
    order the operator configured them. Devices on one site mostly share an
    account, so after the first success the right set is usually tried
    first and the others cost nothing. Shared by every worker thread.
    """

    def __init__(self, credentials):
        self._credentials = list(credentials)
        if not self._credentials:
            raise ValueError("at least one credential set is required")
        self._preferred = None
        self._lock = threading.Lock()

    def __len__(self):
        return len(self._credentials)

    def ordered(self):
        with self._lock:
            preferred = self._preferred
        if preferred is None:
            return list(self._credentials)
        return [preferred] + [c for c in self._credentials if c != preferred]

    def mark_success(self, credential):
        if credential is None or credential not in self._credentials:
            return
        with self._lock:
            self._preferred = credential

    def usernames(self):
        return [c.username for c in self._credentials]

    @property
    def first(self):
        return self._credentials[0]
