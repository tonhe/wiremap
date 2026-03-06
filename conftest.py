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
