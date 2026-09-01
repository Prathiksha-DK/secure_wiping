import os
import re
import json
import time
import uuid
from typing import List, Tuple, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Reuse helpers from the wipe module
from secure_encrypt_wipe import _resolve_mounts_cross_platform, _is_system_volume, CHUNK_SIZE

BACKUP_ROOT = os.path.join(os.path.dirname(__file__), "backups")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _slugify(name: str) -> str:
    name = name.strip()
    name = re.sub(r"\s+", "_", name)
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)


def _now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _mount_id(root: str) -> str:
    # Examples: 'E:\\' => 'E', '\\?\Volume{GUID}\\' => 'VOL_GUID'
    m = re.match(r"^([A-Za-z]):\\\\$", root)
    if m:
        return m.group(1).upper()
    m2 = re.match(r"^\\\\\?\\Volume\{([0-9A-Fa-f-]+)\}\\\\$", root)
    if m2:
        return f"VOL_{m2.group(1)}"
    return uuid.uuid4().hex[:8].upper()


def _write_key_file(backup_dir: str, key: bytes) -> str:
    key_hex = key.hex()
    path = os.path.join(backup_dir, "decryption_key.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(key_hex + "\n")
    return path


def _encrypt_file_to_backup(src_path: str, dst_path: str, key: bytes) -> None:
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    _ensure_dir(os.path.dirname(dst_path))
    with open(src_path, "rb", buffering=0) as fin, open(dst_path, "wb", buffering=0) as fout:
        # Write header: magic(4) + nonce(12) + tag(16 placeholder)
        fout.write(b"GCM1")
        fout.write(nonce)
        fout.write(b"\x00" * 16)
        total = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
                total += len(ct)
        encryptor.finalize()
        # Seek back and write tag
        fout.seek(4 + 12)
        fout.write(encryptor.tag)


def _decrypt_backup_file_to(dst_plain: str, enc_path: str, key: bytes) -> None:
    with open(enc_path, "rb", buffering=0) as fin:
        magic = fin.read(4)
        if magic != b"GCM1":
            raise ValueError("Unsupported backup format")
        nonce = fin.read(12)
        tag = fin.read(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt to a temporary file first; only move into place if tag verifies
        out_dir = os.path.dirname(dst_plain)
        _ensure_dir(out_dir)
        tmp_path = dst_plain + ".tmpdec-" + uuid.uuid4().hex
        try:
            with open(tmp_path, "wb", buffering=0) as fout:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    pt = decryptor.update(chunk)
                    if pt:
                        fout.write(pt)
                # Verify tag before exposing plaintext
                decryptor.finalize()
            # Atomic replace into final location
            os.replace(tmp_path, dst_plain)
        except Exception:
            # Cleanup on failure
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            raise


def encrypt_backup_and_wipe(device_name: str) -> Tuple[bool, str]:
    mounts = _resolve_mounts_cross_platform(device_name)
    if not mounts:
        return False, f"No accessible volumes found for device '{device_name}'."

    # Prepare backup directory and key
    device_slug = _slugify(device_name)
    backup_dir = os.path.join(BACKUP_ROOT, f"{device_slug}_{_now_ts()}")
    _ensure_dir(backup_dir)
    key = os.urandom(32)
    key_path = _write_key_file(backup_dir, key)

    encrypted_count = 0
    deleted_count = 0

    try:
        for root in mounts:
            if _is_system_volume(root):
                return False, f"Refusing to operate on system volume: {root}"
            if not os.path.isdir(root):
                continue
            mid = _mount_id(root)
            for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
                base = os.path.basename(dirpath).lower()
                if base in {"system volume information", "$recycle.bin", "$recycler"}:
                    dirnames[:] = []
                    continue
                for name in filenames:
                    src = os.path.join(dirpath, name)
                    if not os.path.isfile(src):
                        continue
                    # Compute destination path within backup dir
                    rel = os.path.relpath(src, start=root)
                    # Normalize Windows separators to os.sep for backup tree
                    rel_norm = rel.replace("/", os.sep).replace("\\", os.sep)
                    dst = os.path.join(backup_dir, mid, rel_norm) + ".enc"
                    try:
                        _encrypt_file_to_backup(src, dst, key)
                        encrypted_count += 1
                        # Delete original only after encryption succeeds
                        try:
                            os.remove(src)
                            deleted_count += 1
                        except Exception:
                            pass
                    except Exception:
                        continue
        if encrypted_count == 0:
            return False, "No files were encrypted."
        return True, f"Encrypted {encrypted_count} files, deleted {deleted_count}. Key saved to: {key_path}"
    except Exception as e:
        return False, str(e)


def _find_latest_backup_dir(device_name: str) -> Optional[str]:
    if not os.path.isdir(BACKUP_ROOT):
        return None
    device_slug = _slugify(device_name)
    candidates = []
    for name in os.listdir(BACKUP_ROOT):
        p = os.path.join(BACKUP_ROOT, name)
        if not os.path.isdir(p):
            continue
        if name.startswith(device_slug + "_"):
            candidates.append((os.path.getmtime(p), p))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def decrypt_and_restore(device_name: str, key_hex: str) -> Tuple[bool, str]:
    backup_dir = _find_latest_backup_dir(device_name)
    if not backup_dir:
        return False, f"No backup found for '{device_name}'."
    try:
        key = bytes.fromhex(key_hex.strip())
    except Exception:
        return False, "Invalid decryption key format; expected hex string."
    if len(key) != 32:
        return False, "Invalid key length; expected 256-bit (32 bytes) key in hex."

    mounts = _resolve_mounts_cross_platform(device_name)
    if not mounts:
        return False, f"No accessible volumes for restore on '{device_name}'."

    # Prefer the first mount that is not a system volume
    target_root = None
    for m in mounts:
        if not _is_system_volume(m) and os.path.isdir(m):
            target_root = m
            break
    if not target_root:
        return False, "No suitable target volume for restore."

    restored = 0
    errors = 0

    for dirpath, _, filenames in os.walk(backup_dir):
        for name in filenames:
            if not name.lower().endswith(".enc"):
                continue
            enc_path = os.path.join(dirpath, name)
            # Reconstruct relative path under backup_dir (strip mount id folder and .enc)
            rel = os.path.relpath(enc_path, start=backup_dir)
            parts = rel.split(os.sep)
            if len(parts) < 2:
                continue
            rel_under_mount = os.path.join(*parts[1:])
            plain_rel = re.sub(r"\.enc$", "", rel_under_mount)
            dst_plain = os.path.join(target_root, plain_rel)
            try:
                _decrypt_backup_file_to(dst_plain, enc_path, key)
                restored += 1
            except Exception:
                errors += 1
                continue

    if restored == 0:
        return False, "No files restored from backup."
    msg = f"Restored {restored} file(s)"
    if errors:
        msg += f", {errors} failed"
    return True, msg

