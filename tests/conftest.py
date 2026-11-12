"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def _no_aireos_look_ahead(monkeypatch):
    """A failed untyped login would otherwise open a real SSH session to the
    test address to look for an AireOS controller. Tests that exercise the
    look-ahead replace this stub themselves."""
    try:
        import app.connection_manager as cm
    except ImportError:
        return
    monkeypatch.setattr(cm, "_aireos_probe", lambda *a, **kw: False)
