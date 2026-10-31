import sys
from pathlib import Path

# Ensure the project root is on sys.path so `from app.xxx import ...` works.
_root = Path(__file__).resolve().parent
sys.path.insert(0, str(_root))
# Append app/ so bare imports in app.py (designed for Docker workdir) resolve,
# but after the project root so `app` still resolves as a package first.
_app_dir = str(_root / "app")
if _app_dir not in sys.path:
    sys.path.append(_app_dir)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_tcp_probe(monkeypatch):
    """Report every probed port as open, so no test opens a real socket.
    Probe tests replace this with their own stub or exercise the real
    function against a monkeypatched socket."""
    for name in ("app.connection_manager", "connection_manager"):
        module = sys.modules.get(name)
        if module is None:
            try:
                module = __import__(name, fromlist=["_tcp_probe"])
            except ImportError:
                continue
        monkeypatch.setattr(module, "_tcp_probe",
                            lambda host, port, timeout=None: None)
