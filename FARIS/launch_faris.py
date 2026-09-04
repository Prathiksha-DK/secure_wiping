import sys
from pathlib import Path

# Add FARIS root to Python module search path
FARIS_ROOT = Path(__file__).resolve().parent
if str(FARIS_ROOT) not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT))

from ui.desktop_app import launch_ui

if __name__ == "__main__":
    print("==================================================")
    print(" FARIS — Forensic Adaptive Recovery & Integrity System")
    print(" Mode: Standalone Offline Desktop Application")
    print("==================================================")
    launch_ui()
