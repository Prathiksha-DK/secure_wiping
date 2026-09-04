"""
Virtual / Remote Wipe - Standalone Remote Agent
================================================
Run this file on the FRIEND's computer (Computer B).

It has NO dependency on the backend project files (devices.py,
sanitization_engine.py, etc.).  Only standard-library modules plus
the 'requests' package are required.

Install requirements on Computer B:
    pip install requests

Configure the backend URL (Computer A's Tailscale IP) before running:

  Windows PowerShell:
      $env:REMOTE_WIPE_SERVER_URL = "http://<TAILSCALE_IP>:9758"
      python agent_standalone.py

  Windows CMD:
      set REMOTE_WIPE_SERVER_URL=http://<TAILSCALE_IP>:9758
      python agent_standalone.py

  Linux / macOS:
      export REMOTE_WIPE_SERVER_URL="http://<TAILSCALE_IP>:9758"
      python agent_standalone.py

Leave the variable unset to fall back to localhost (local testing only).
"""

import os
import sys
import time
import uuid
import platform
import threading
import subprocess
import tkinter as tk

try:
    import requests
except ImportError:
    print("[!] 'requests' package not found.")
    print("    Install it with:  pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration  (only thing you need to change for Tailscale)
# ---------------------------------------------------------------------------
BASE_URL    = os.environ.get("REMOTE_WIPE_SERVER_URL", "http://localhost:9758").rstrip("/")
BACKEND_URL = f"{BASE_URL}/api/remote-wipe"

# Unique, persistent identity for this agent session
COMPUTER_ID = f"COMP-{uuid.uuid4().hex[:6].upper()}"

# DRY-RUN: no actual destructive operations will be executed
DRY_RUN = True

# ---------------------------------------------------------------------------
# Physical drive discovery (no external dependencies)
# ---------------------------------------------------------------------------

def _discover_drives_windows():
    """
    Use PowerShell Get-PhysicalDisk (primary, works on Windows 10/11).
    Falls back to wmic for older systems.
    """
    drives = []

    # --- Primary: PowerShell Get-PhysicalDisk ---
    ps_script = (
        "Get-PhysicalDisk | "
        "Select-Object DeviceId,FriendlyName,Size,MediaType,BusType | "
        "ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            stderr=subprocess.DEVNULL,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        ).decode(errors="replace").strip()

        import json as _json
        disks = _json.loads(raw)
        if isinstance(disks, dict):        # single disk → wrap in list
            disks = [disks]

        for disk in disks:
            dev_id  = str(disk.get("DeviceId", "0"))
            name    = disk.get("FriendlyName", f"Disk {dev_id}") or f"Disk {dev_id}"
            media   = (disk.get("MediaType") or "").strip()
            bus     = (disk.get("BusType")   or "").strip().upper()
            raw_sz  = disk.get("Size", 0) or 0
            try:
                size_str = f"{round(int(raw_sz) / (1024**3), 1)} GB"
            except (ValueError, TypeError):
                size_str = "Unknown"

            if "USB" in bus:
                dev_type = "Removable"
                strategy = "NIST 800-88 Rev.1 — Clear"
            elif "NVMe" in bus or "NVMe" in name.upper():
                dev_type = "NVMe SSD"
                strategy = "Cryptographic Erase (IEEE 2883)"
            elif "SSD" in media or "Solid" in media:
                dev_type = "SSD"
                strategy = "Cryptographic Erase (IEEE 2883)"
            else:
                dev_type = "HDD"
                strategy = "DoD 5220.22-M (3-Pass)"

            drives.append({
                "id":                  f"PhysicalDrive{dev_id}",
                "name":                name,
                "size":                size_str,
                "type":                dev_type,
                "letter":              "",
                "recommendedStrategy": strategy,
            })

        if drives:
            return drives
        # Fall through to wmic if PS returned nothing
    except Exception as e:
        print(f"[!] PowerShell discovery error: {e}. Trying wmic fallback...")

    # --- Fallback: wmic (Windows 8/10 legacy) ---
    try:
        out = subprocess.check_output(
            ["wmic", "diskdrive", "get",
             "Index,Caption,Size,MediaType,InterfaceType", "/format:csv"],
            stderr=subprocess.DEVNULL,
            timeout=10
        ).decode(errors="replace")

        for line in out.strip().splitlines():
            line = line.strip()
            if not line or line.lower().startswith("node"):
                continue
            parts = line.split(",")
            if len(parts) < 6:
                continue
            _, index, caption, size_bytes, media_type, interface = parts[:6]
            try:
                size_str = f"{round(int(size_bytes.strip()) / (1024**3), 1)} GB"
            except ValueError:
                size_str = "Unknown"

            caption = caption.strip()
            iface   = interface.strip().upper()

            if "USB" in iface or "USB" in caption.upper():
                dev_type, strategy = "Removable", "NIST 800-88 Rev.1 — Clear"
            elif "NVME" in caption.upper():
                dev_type, strategy = "NVMe SSD", "Cryptographic Erase (IEEE 2883)"
            elif "SSD" in caption.upper():
                dev_type, strategy = "SSD", "Cryptographic Erase (IEEE 2883)"
            else:
                dev_type, strategy = "HDD", "DoD 5220.22-M (3-Pass)"

            drives.append({
                "id":                  f"PhysicalDrive{index.strip()}",
                "name":                caption or f"Disk {index.strip()}",
                "size":                size_str,
                "type":                dev_type,
                "letter":              "",
                "recommendedStrategy": strategy,
            })
    except Exception as e:
        print(f"[!] wmic fallback error: {e}")

    return drives


def _discover_drives_linux():
    """Use lsblk on Linux/macOS to list physical disks."""
    drives = []
    try:
        out = subprocess.check_output(
            ["lsblk", "-d", "-o", "NAME,SIZE,ROTA,TRAN,MODEL", "--noheadings"],
            stderr=subprocess.DEVNULL,
            timeout=10
        ).decode(errors="replace")

        for line in out.strip().splitlines():
            parts = line.split()
            if not parts:
                continue
            name  = parts[0]
            size  = parts[1] if len(parts) > 1 else "Unknown"
            rota  = parts[2] if len(parts) > 2 else "1"   # 1=HDD, 0=SSD
            tran  = parts[3].upper() if len(parts) > 3 else ""
            model = " ".join(parts[4:]) if len(parts) > 4 else name

            if "USB" in tran:
                dev_type = "Removable"
                strategy = "NIST 800-88 Rev.1 — Clear"
            elif rota == "0" or "NVME" in tran:
                dev_type = "NVMe SSD" if "NVME" in tran else "SSD"
                strategy = "Cryptographic Erase (IEEE 2883)"
            else:
                dev_type = "HDD"
                strategy = "DoD 5220.22-M (3-Pass)"

            drives.append({
                "id":                  f"/dev/{name}",
                "name":                model,
                "size":                size,
                "type":                dev_type,
                "letter":              "",
                "recommendedStrategy": strategy,
            })
    except Exception as e:
        print(f"[!] Drive discovery error: {e}")
    return drives


def get_physical_devices():
    """Return list of physical storage devices, cross-platform."""
    if sys.platform.startswith("win"):
        return _discover_drives_windows()
    else:
        return _discover_drives_linux()


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def _print_diagnostics(error):
    print("\n" + "="*55)
    print("  DIAGNOSTIC: CANNOT REACH BACKEND")
    print("="*55)
    print(f"  Backend URL : {BACKEND_URL}")
    print(f"  Error       : {error}")
    print()
    print("  Checklist:")
    print("  1. Is Computer A's Flask backend running on port 9758?")
    print("  2. Are both computers connected to the same Tailscale network?")
    print("  3. Is REMOTE_WIPE_SERVER_URL set to Computer A's Tailscale IP?")
    print("     e.g.  http://100.x.y.z:9758")
    print("  4. Does Computer A's firewall allow port 9758?")
    print()

    # Try to detect Tailscale status on this machine
    try:
        ts = subprocess.check_output(
            ["tailscale", "status", "--json"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        if '"Self"' in ts:
            print("  Tailscale: Connected (self entry found)")
        else:
            print("  Tailscale: Running but no peers visible")
    except FileNotFoundError:
        print("  Tailscale: Not installed or not on PATH")
    except Exception:
        print("  Tailscale: Could not determine status")
    print("="*55 + "\n")


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------

def register_agent():
    print(f"[*] Agent ID : {COMPUTER_ID}")
    print(f"[*] Backend  : {BASE_URL}")
    print(f"[*] Dry-Run  : {'YES — no destructive operations will run' if DRY_RUN else 'NO'}")
    print("[*] Discovering physical drives...")

    drives = get_physical_devices()
    print(f"[*] Found {len(drives)} physical drive(s):")
    for d in drives:
        print(f"    {d['id']:25s}  {d['size']:10s}  {d['type']:12s}  {d['name']}")

    payload = {
        "id":            COMPUTER_ID,
        "name":          os.environ.get("COMPUTERNAME") or platform.node() or "FRIEND-LAPTOP",
        "os":            f"{platform.system()} {platform.release()}",
        "agent_version": "2.0-standalone",
        "devices":       drives,
    }

    try:
        r = requests.post(f"{BACKEND_URL}/register", json=payload, timeout=8)
        r.raise_for_status()
        print(f"[+] Registered successfully → {BASE_URL}\n")
        return True
    except requests.exceptions.RequestException as e:
        _print_diagnostics(e)
        return False


# ---------------------------------------------------------------------------
# Owner consent dialog (Tkinter — runs on Computer B's screen)
# ---------------------------------------------------------------------------

def show_auth_dialog(job_id: str, target: str):
    root = tk.Tk()
    root.title("REMOTE SANITIZATION REQUEST")
    root.geometry("480x340")
    root.configure(bg="#1a1a2e")
    root.attributes("-topmost", True)
    root.resizable(False, False)

    result = {"action": "deny"}

    def on_approve():
        result["action"] = "approve"
        root.destroy()

    def on_deny():
        result["action"] = "deny"
        root.destroy()

    # Header
    tk.Label(root, text="⚠  REMOTE SANITIZATION REQUEST",
             font=("Helvetica", 14, "bold"), fg="#ff4757", bg="#1a1a2e").pack(pady=(20, 4))

    # Info frame
    frame = tk.Frame(root, bg="#16213e", bd=1, relief="solid", padx=16, pady=12)
    frame.pack(fill="x", padx=20, pady=6)

    tk.Label(frame, text=f"Administrator:  System Admin",
             font=("Courier", 10), fg="#a8b2d8", bg="#16213e", anchor="w").pack(fill="x")
    tk.Label(frame, text=f"Target Device:  {target}",
             font=("Courier", 10, "bold"), fg="#ffffff", bg="#16213e", anchor="w").pack(fill="x", pady=(4, 0))
    tk.Label(frame, text=f"Mode:           {'DRY-RUN (safe demo)' if DRY_RUN else 'LIVE — DESTRUCTIVE'}",
             font=("Courier", 10), fg="#ffa502" if DRY_RUN else "#ff4757",
             bg="#16213e", anchor="w").pack(fill="x")

    # Warning
    tk.Label(root,
             text="WARNING: Approving this request grants the administrator\n"
                  "permission to sanitize the listed storage device.",
             font=("Helvetica", 9), fg="#ff6b81", bg="#1a1a2e",
             justify="center").pack(pady=8)

    # Buttons
    btn = tk.Frame(root, bg="#1a1a2e")
    btn.pack(pady=10)
    tk.Button(btn, text="  APPROVE  ", command=on_approve,
              bg="#e84393", fg="white", font=("Helvetica", 11, "bold"),
              relief="flat", padx=10, pady=6).pack(side="left", padx=12)
    tk.Button(btn, text="  DENY  ", command=on_deny,
              bg="#2d3561", fg="white", font=("Helvetica", 11, "bold"),
              relief="flat", padx=10, pady=6).pack(side="left", padx=12)

    root.mainloop()

    # Send response back to Flask
    try:
        requests.post(f"{BACKEND_URL}/agent/auth-response",
                      json={"job_id": job_id, "action": result["action"]},
                      timeout=8)
        print(f"[+] Auth response sent: {result['action'].upper()}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Could not send auth response: {e}")


# ---------------------------------------------------------------------------
# Simulated dry-run wipe (no disk writes)
# ---------------------------------------------------------------------------

def perform_wipe(job_id: str, target: str):
    steps = [
        (10,  "Re-discovering physical devices on endpoint..."),
        (20,  f"Verifying identity of target: {target}"),
        (30,  "Identity confirmed — authorization validated."),
        (40,  "[DRY-RUN] Invoking sanitization strategy..."),
        (55,  "[DRY-RUN] Simulating sector overwrite pass 1/1..."),
        (70,  "[DRY-RUN] Simulating verification read-back..."),
        (85,  "[DRY-RUN] Cryptographic hash check..."),
        (100, "Dry-run complete. No data was modified."),
    ]

    for pct, msg in steps:
        print(f"[{pct:3d}%] {msg}")
        try:
            requests.post(f"{BACKEND_URL}/agent/job-update",
                          json={"job_id": job_id, "log": msg, "progress": pct},
                          timeout=5)
        except Exception:
            pass
        time.sleep(1.2)

    try:
        requests.post(f"{BACKEND_URL}/agent/job-update",
                      json={"job_id": job_id, "complete": True},
                      timeout=5)
        print("[+] Job reported complete.")
    except Exception as e:
        print(f"[-] Could not report job completion: {e}")


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

def poll_server():
    last_diag = 0
    while True:
        try:
            res = requests.get(
                f"{BACKEND_URL}/agent/poll?computer_id={COMPUTER_ID}",
                timeout=6
            )
            if res.status_code == 200:
                data   = res.json()
                action = data.get("action")

                if action == "request_auth":
                    print(f"\n[*] Auth request received for: {data.get('target')}")
                    show_auth_dialog(data["job_id"], data.get("target", "Unknown"))

                elif action == "start_wipe":
                    print(f"\n[*] Wipe command received for: {data.get('target')}")
                    threading.Thread(
                        target=perform_wipe,
                        args=(data["job_id"], data.get("target", "Unknown")),
                        daemon=True
                    ).start()

        except requests.exceptions.RequestException as e:
            now = time.time()
            if now - last_diag > 10:
                _print_diagnostics(e)
                last_diag = now

        time.sleep(2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  Virtual / Remote Wipe  —  Standalone Agent v2.0")
    print("  Consent-based · Transparent · DRY-RUN mode")
    print("=" * 55)
    print()

    if not register_agent():
        print("[!] Registration failed. Retrying every 10 seconds...")
        while not register_agent():
            time.sleep(10)

    print("[*] Polling for commands. Press Ctrl+C to stop.\n")
    try:
        poll_server()
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")
