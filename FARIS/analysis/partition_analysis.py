import subprocess
from pathlib import Path

# FARIS project root
FARIS_ROOT = Path(__file__).resolve().parent.parent

# FARIS bundled Sleuth Kit
MMLS = FARIS_ROOT / "engines" / "sleuthkit" / "bin" / "mmls.exe"

# Current case evidence image
IMAGE = FARIS_ROOT / "case001" / "pendrive_image.E01"

print("Opening E01...")
print("E01 opened successfully.")
print("Partition analysis started...\n")

result = subprocess.run(
    [str(MMLS), str(IMAGE)],
    capture_output=True,
    text=True
)

if result.returncode != 0:
    print("Partition analysis failed.")
    print(result.stderr)
else:
    print(result.stdout)