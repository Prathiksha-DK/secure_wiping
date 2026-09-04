import subprocess
from pathlib import Path

# FARIS project root
FARIS_ROOT = Path(__file__).resolve().parent.parent

# FARIS bundled Sleuth Kit
FSSTAT = FARIS_ROOT / "engines" / "sleuthkit" / "bin" / "fsstat.exe"

# Current case evidence image
IMAGE = FARIS_ROOT / "case001" / "pendrive_image.E01"

PARTITION_OFFSET = "2048"

print("Filesystem analysis started...\n")

result = subprocess.run(
    [str(FSSTAT), "-o", PARTITION_OFFSET, str(IMAGE)],
    capture_output=True,
    text=True
)

if result.returncode != 0:
    print("Filesystem analysis failed.")
    print(result.stderr)
else:
    print(result.stdout)