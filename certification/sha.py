import hashlib
import os
import json
import random
import subprocess
import platform

def file_hash(path, chunk_size=1024*1024):
    """Compute SHA256 hash of a file (by chunks)."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_drives():
    """Detect drives (Windows) or root (Linux/Mac)."""
    drives = []
    if os.name == "nt":  # Windows
        output = subprocess.check_output("wmic logicaldisk get name", shell=True).decode()
        for line in output.splitlines():
            line = line.strip()
            if line and ":" in line:
                drives.append(line + "\\")
    else:  # Linux / Mac
        drives = ["/"]
    return drives

def pick_files_from_different_locations(max_files=10):
    selected = {}
    drives = get_drives()
    random.shuffle(drives)

    for drive in drives:
        try:
            top_folders = [os.path.join(drive, d) for d in os.listdir(drive) if os.path.isdir(os.path.join(drive, d))]
            random.shuffle(top_folders)

            for folder in top_folders:
                try:
                    files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
                    if files:
                        fpath = os.path.join(folder, random.choice(files))
                        selected[fpath] = file_hash(fpath)
                        if len(selected) >= max_files:
                            return selected
                except Exception:
                    continue
        except Exception:
            continue

    return selected

if __name__ == "__main__":
    print("🔍 Collecting up to 10 files from different drives/locations...")
    file_hashes = pick_files_from_different_locations(max_files=10)

    # Display paths with hashes in terminal
    for f, h in file_hashes.items():
        print(f"{f} -> {h}")

    # Store only hash values in JSON
    hash_values = list(file_hashes.values())
    with open("diverse_drive_hashes.json", "w") as f:
        json.dump(hash_values, f, indent=4)

    print(f"\n✅ {len(hash_values)} hashes saved in diverse_drive_hashes.json")
