import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
FARIS_DB_PATH = os.path.join(DATA_DIR, "faris.db")
FARIS_EVIDENCE_DIR = os.path.join(DATA_DIR, "faris_evidence")
FARIS_REPORTS_DIR = os.path.join(DATA_DIR, "faris_reports")
FARIS_LAB_DIR = os.path.join(DATA_DIR, "faris_lab")

# Ensure directories exist
for directory in [DATA_DIR, FARIS_EVIDENCE_DIR, FARIS_REPORTS_DIR, FARIS_LAB_DIR]:
    os.makedirs(directory, exist_ok=True)

# Forensic scanner configurations
SUPPORTED_PAGE_SIZES = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB for hashing/streaming
MAX_UPLOAD_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB max evidence file

# Forensic confidence weights
WEIGHT_PAGE_HEADER = 0.25
WEIGHT_CELL_POINTERS = 0.20
WEIGHT_RECORD_STRUCTURE = 0.25
WEIGHT_DATA_TYPE_VALIDITY = 0.15
WEIGHT_FRAGMENT_CORRELATION = 0.15

FARIS_VERSION = "1.0.0"
ENGINE_VERSION = "FARIS-Carver-2026.1"
