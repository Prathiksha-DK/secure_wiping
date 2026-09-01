import os
import sys
import json
import uuid
import time
import mmap
import shutil
import subprocess
import re
from typing import List, Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks


def _sanitize_device_name(name: str) -> str:
    # Remove trailing size in parentheses, e.g., "hp v220w (14.9GB)" -> "hp v220w"
    return re.sub(r"\s*\(.*?\)\s*$", "", name or "").strip()


def _parse_size_from_name(name: str) -> int:
    """Parse a trailing size like (14.9 GB) or (14.9GB) to bytes, else 0."""
    if not name:
        return 0
    m = re.search(r"\(([^)]+)\)\s*$", name)
    if not m:
        return 0
    s = m.group(1).strip()
    # Accept forms like "14.9 GB", "14.9GB", "16 GiB"
    m2 = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?i?B)", s, re.IGNORECASE)
    if not m2:
        return 0
    val = float(m2.group(1))
    unit = m2.group(2).upper()
    # Map units to multipliers (use decimal for non-iB, binary for iB)
    mult = {
        "KB": 1000**1, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4, "PB": 1000**5,
        "KIB": 1024**1, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4, "PIB": 1024**5,
        "B": 1,
    }.get(unit, 0)
    if mult == 0:
        return 0
    try:
        return int(val * mult)
    except Exception:
        return 0


def _windows_list_disks() -> List[Dict[str, Any]]:
    ps = r"""
$ErrorActionPreference = 'Stop'
Get-Disk | Select-Object Number, Size, FriendlyName, Model, SerialNumber, BusType | ConvertTo-Json -Depth 3
"""
    try:
        c = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
        if c.returncode != 0:
            return []
        raw = (c.stdout or '').strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        out: List[Dict[str, Any]] = []
        for d in data:
            out.append({
                "Number": d.get("Number"),
                "Size": int(d.get("Size") or 0),
                "FriendlyName": str(d.get("FriendlyName") or ""),
                "Model": str(d.get("Model") or ""),
                "SerialNumber": str(d.get("SerialNumber") or ""),
                "BusType": str(d.get("BusType") or ""),
            })
        return out
    except Exception:
        return []


def _windows_disk_from_drive_letter(letter: str) -> Optional[int]:
    letter = letter.strip().rstrip(':').upper()
    if not re.match(r"^[A-Z]$", letter):
        return None
    ps = f"$p=Get-Partition -DriveLetter '{letter}' | Select-Object -First 1 DiskNumber; if ($p) {{ $p.DiskNumber }}"
    try:
        c = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
        if c.returncode != 0:
            return None
        s = (c.stdout or '').strip()
        return int(s) if s else None
    except Exception:
        return None


def _pick_disk_by_name_or_size(device_name: str) -> Optional[Dict[str, Any]]:
    """Pick a disk dict by matching name/model/serial, drive letter, or approximate size."""
    if not device_name:
        return None

    # Drive letter targeting (e.g., "E", "E:")
    if re.match(r"^[A-Za-z]:?$", device_name.strip()):
        dn = _windows_disk_from_drive_letter(device_name)
        if dn is not None:
            disks = _windows_list_disks()
            for d in disks:
                if int(d.get("Number")) == dn:
                    return d

    disks = _windows_list_disks()
    if not disks:
        return None

    name_san = _sanitize_device_name(device_name).lower()
    name_orig = (device_name or "").lower()

    # First pass: substring match on FriendlyName/Model/SerialNumber
    for cand in (name_san, name_orig):
        if not cand:
            continue
        for d in disks:
            if (cand in (d.get("FriendlyName", "").lower()) or
                cand in (d.get("Model", "").lower()) or
                cand in (d.get("SerialNumber", "").lower())):
                return d

    # Second pass: approximate size match
    target_size = _parse_size_from_name(device_name)
    if target_size > 0:
        for d in disks:
            sz = int(d.get("Size") or 0)
            if sz <= 0:
                continue
            # Allow 15% tolerance
            if abs(sz - target_size) <= max(int(0.15 * target_size), CHUNK_SIZE):
                return d

    return None


def _windows_resolve_mounts(device_name: str) -> List[str]:
    """Resolve a Windows device friendly name to accessible volume roots.

    Returns a list of paths like ['E:\\', '\\\\?\\VolumeGUID\\'].
    """
    disk = _pick_disk_by_name_or_size(device_name)
    if not disk:
        return []
    dn = int(disk.get("Number"))
    ps_script = f"$ErrorActionPreference='Stop'; Get-Partition -DiskNumber {dn} | Get-Volume | Select-Object DriveLetter, Path | ConvertTo-Json -Depth 3"
    try:
        completed = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            return []
        raw = completed.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        mounts: List[str] = []
        for v in data:
            dl = v.get("DriveLetter")
            p = v.get("Path")
            if dl:
                mounts.append(f"{dl}:\\")
            elif p:
                # Ensure trailing backslash
                if not p.endswith("\\"):
                    p = p + "\\"
                mounts.append(p)
        return mounts
    except Exception:
        return []


def _resolve_mounts_cross_platform(device_name: str) -> List[str]:
    if sys.platform.startswith("win"):
        return _windows_resolve_mounts(device_name)
    # TODO: Implement for Linux/macOS (e.g., by mapping from /dev/disk/by-id to mountpoints)
    return []


def _is_system_volume(path: str) -> bool:
    try:
        if sys.platform.startswith("win"):
            system_drive = os.environ.get("SystemDrive", "C:")
            # Normalize like 'C:' vs 'C:\\'
            sd = system_drive.rstrip('\\\\/')
            vol = path.rstrip('\\\\/')
            # Consider both drive-letter roots and Volume GUIDs for C:
            if vol.upper().startswith(sd.upper()):
                return True
            # Resolve C: volume GUID and compare (best-effort)
            try:
                ps = "(Get-Volume -DriveLetter '" + sd.replace(':', '') + "').Path"
                c = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
                guid_path = (c.stdout or '').strip()
                if guid_path and vol.upper().startswith(guid_path.upper().rstrip('\\/')):
                    return True
            except Exception:
                pass
            return False
        else:
            # On POSIX, treat '/' as system volume
            return os.path.abspath(path) == '/'
    except Exception:
        return False


def _random_aes256_key() -> bytearray:
    # Use bytearray so we can overwrite in-place later
    return bytearray(os.urandom(32))


def _random_nonce() -> bytes:
    # 128-bit nonce for CTR
    return os.urandom(16)


def _secure_zero(buf: bytearray) -> None:
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def _encrypt_overwrite_file(path: str, key_bytes: bytes) -> Tuple[bool, str]:
    try:
        # Generate a fresh random nonce per file
        nonce = _random_nonce()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(path, 'rb+', buffering=0) as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                # Move back by len(ct) to overwrite the chunk we just read
                f.seek(-len(ct), os.SEEK_CUR)
                f.write(ct)
        # Finalize (not strictly necessary for CTR, but keep API consistent)
        encryptor.finalize()

        # Best-effort: randomize filename to reduce metadata leakage
        try:
            dir_name = os.path.dirname(path)
            new_name = uuid.uuid4().hex
            new_path = os.path.join(dir_name, new_name)
            os.replace(path, new_path)
            path = new_path
        except Exception:
            pass

        # Best-effort: adjust timestamps
        try:
            now = time.time()
            os.utime(path, (now, now))
        except Exception:
            pass

        return True, "ok"
    except Exception as e:
        return False, str(e)


def _windows_resolve_physical_drive(device_name: str) -> Tuple[str, int]:
    """Return (\\\\.\\PhysicalDriveN, size_bytes) for the matched disk, or ("", 0)."""
    disk = _pick_disk_by_name_or_size(device_name)
    if not disk:
        return "", 0
    dn = int(disk.get("Number"))
    size = int(disk.get("Size") or 0)
    return f"\\\\.\\PhysicalDrive{dn}", size


def _encrypt_overwrite_physical_device(dev_path: str, total_size: int, key_bytes: bytes) -> Tuple[bool, str]:
    """Encrypt and overwrite the entire physical device in-place.

    Requires Administrator privileges on Windows.
    """
    try:
        nonce = _random_nonce()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Try raw open on device
        fd = os.open(dev_path, os.O_RDWR | getattr(os, 'O_BINARY', 0))
        try:
            offset = 0
            while offset < total_size:
                to_read = min(CHUNK_SIZE, total_size - offset)
                # Move file pointer
                os.lseek(fd, offset, os.SEEK_SET)
                chunk = os.read(fd, to_read)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                os.lseek(fd, offset, os.SEEK_SET)
                os.write(fd, ct)
                offset += len(chunk)
            encryptor.finalize()
        finally:
            os.close(fd)
        return True, "ok"
    except PermissionError:
        return False, "Access denied opening raw device. Please run the backend as Administrator."
    except Exception as e:
        return False, str(e)


def encrypt_and_wipe(device_name: str) -> Tuple[bool, str]:
    """Encrypts and overwrites data on the target device.

    Strategy:
    1) Attempt file-level in-place encryption on any accessible volumes (drive letters or Volume GUID paths).
    2) If no volumes are accessible, fall back to raw physical device encryption (entire device), which overwrites all data and metadata.

    Safety measures:
    - Refuses to operate on the system volume (e.g., C:\\ on Windows or / on POSIX) when doing file-level pass.
    - Raw device encryption requires Administrator privileges and targets the matched disk.
    """
    mounts = _resolve_mounts_cross_platform(device_name)

    # Generate ephemeral AES-256 key
    key = _random_aes256_key()
    try:
        key_bytes = bytes(key)

        did_any = False
        # Pass 1: file-level on volumes
        for root in mounts:
            # Avoid C:\ or its Volume GUID counterpart
            if _is_system_volume(root):
                return False, f"Refusing to operate on system volume: {root}"

            # Only attempt file walk if it's a directory-like path
            if os.path.isdir(root):
                did_any = True
                for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
                    base = os.path.basename(dirpath).lower()
                    if base in {"system volume information", "$recycle.bin", "$recycler"}:
                        dirnames[:] = []
                        continue

                    for name in filenames:
                        file_path = os.path.join(dirpath, name)
                        try:
                            if not os.path.isfile(file_path):
                                continue
                            _encrypt_overwrite_file(file_path, key_bytes)
                        except Exception:
                            continue

        if did_any:
            return True, "Secure Encrypt-and-Wipe completed on accessible volumes."

        # Pass 2: raw device if volumes were not accessible
        if sys.platform.startswith("win"):
            dev_path, size = _windows_resolve_physical_drive(device_name)
            if not dev_path or size <= 0:
                return False, f"No mounted or raw device found for '{device_name}'.";
            ok, msg = _encrypt_overwrite_physical_device(dev_path, size, key_bytes)
            if ok:
                return True, "Secure Encrypt-and-Wipe completed on raw device."
            else:
                return False, msg

        return False, "Raw device encryption is not implemented for this platform."
    finally:
        _secure_zero(key)
        del key

