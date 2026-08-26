from app.mock_devices import is_mock_mode


def test_mock_disabled_by_default(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    assert is_mock_mode("192.168.1.1") is False


def test_mock_enabled_by_env(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    assert is_mock_mode("192.168.1.1") is True


def test_mock_enabled_but_host_unknown(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    assert is_mock_mode("10.99.99.99") is False


def test_mock_env_other_values_do_not_enable(monkeypatch):
    for value in ("0", "", "false", "no"):
        monkeypatch.setenv("WIREMAP_MOCK", value)
        assert is_mock_mode("192.168.1.1") is False
