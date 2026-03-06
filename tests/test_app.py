import json
import os
from unittest.mock import patch

import pytest

# Patch the FileHandler before importing app.app so the module-level
# logging.basicConfig() call doesn't try to open /app/logs/app.log.
with patch("logging.FileHandler"):
    from app.app import app
    import app.app as app_module


@pytest.fixture
def inventory_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def client(inventory_dir):
    app.config["TESTING"] = True
    original_dir = app_module.INVENTORY_DIR
    app_module.INVENTORY_DIR = inventory_dir
    try:
        with app.test_client() as c:
            yield c
    finally:
        app_module.INVENTORY_DIR = original_dir


def test_delete_inventory(inventory_dir, client):
    """Test DELETE /inventories/<filename> removes the file."""
    filepath = os.path.join(inventory_dir, "test123.json")
    with open(filepath, "w") as f:
        json.dump({"devices": {}}, f)

    assert os.path.exists(filepath)

    resp = client.delete("/inventories/test123.json")
    assert resp.status_code == 200
    assert not os.path.exists(filepath)


def test_delete_inventory_not_found(client):
    """Test DELETE /inventories/<filename> returns 404 for missing file."""
    resp = client.delete("/inventories/nonexistent.json")
    assert resp.status_code == 404


def test_delete_inventory_path_traversal(client):
    """Test DELETE /inventories/<filename> rejects path traversal."""
    # Flask decodes %2F to / before routing, so use a filename with '..'
    # that still matches the <filename> route segment.
    resp = client.delete("/inventories/..secret.json")
    assert resp.status_code == 400
