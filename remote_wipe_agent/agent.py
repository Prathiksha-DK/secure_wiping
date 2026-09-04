import os
import sys
import time
import json
import uuid
import threading
import requests
import tkinter as tk
from tkinter import messagebox

# Add backend to path to reuse existing sanitization strategy and device listing
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
try:
    from devices import list_devices
    from sanitization_engine import run_adaptive_sanitization
except ImportError as e:
    print(f"Error importing backend modules: {e}")
    sys.exit(1)

# The Tailscale or Local network address of the Flask Backend
# Example: REMOTE_WIPE_SERVER_URL=http://100.95.x.y:9758
BASE_URL = os.environ.get("REMOTE_WIPE_SERVER_URL", "http://localhost:9758").rstrip('/')
BACKEND_URL = f"{BASE_URL}/api/remote-wipe"
COMPUTER_ID = f"COMP-{uuid.uuid4().hex[:6].upper()}"

def get_physical_devices():
    # Use existing backend function
    return list_devices()

def register_agent():
    print(f"[*] Registering agent {COMPUTER_ID}...")
    devices = get_physical_devices()
    
    # Format devices for the UI
    ui_devices = []
    for d in devices:
        ui_devices.append({
            "id": d.get("name", "Unknown"),
            "name": d.get("friendlyName", "Unknown Device"),
            "size": d.get("size", "Unknown Size"),
            "type": d.get("type", "Disk"),
            "letter": "",
            "recommendedStrategy": "DoD 5220.22-M (3-Pass)" if "hdd" in d.get("type", "").lower() else "Cryptographic Erase (IEEE 2883)"
        })

    payload = {
        "id": COMPUTER_ID,
        "name": os.environ.get("COMPUTERNAME", "FRIEND-LAPTOP"),
        "os": "Windows 11",
        "agent_version": "1.0.0",
        "devices": ui_devices
    }
    
    try:
        requests.post(f"{BACKEND_URL}/register", json=payload, timeout=5)
        print(f"[+] Registration successful via {BASE_URL}")
    except requests.exceptions.RequestException as e:
        print("\n[!] DIAGNOSTIC: CONNECTION FAILURE")
        print(f"    Target URL: {BACKEND_URL}/register")
        print(f"    Error: {e}")
        print("    - Are you on the same Tailscale network?")
        print("    - Did you set REMOTE_WIPE_SERVER_URL correctly?")
        print("    - Is the Flask backend running on the admin machine?\n")

def show_auth_dialog(job_id, target):
    root = tk.Tk()
    root.title("REMOTE SANITIZATION REQUEST")
    root.geometry("400x300")
    root.attributes("-topmost", True)
    
    result = {"action": "deny"}
    
    def on_approve():
        result["action"] = "approve"
        root.destroy()
        
    def on_deny():
        result["action"] = "deny"
        root.destroy()

    tk.Label(root, text="REMOTE SANITIZATION REQUEST", font=("Helvetica", 14, "bold"), fg="red").pack(pady=10)
    tk.Label(root, text=f"Administrator: System Admin").pack()
    tk.Label(root, text=f"Target Device: {target}", font=("Helvetica", 12, "bold")).pack(pady=10)
    tk.Label(root, text="WARNING: This operation may permanently destroy data.", fg="red").pack(pady=10)
    
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=20)
    tk.Button(btn_frame, text="APPROVE", command=on_approve, bg="red", fg="white", width=15).pack(side="left", padx=10)
    tk.Button(btn_frame, text="DENY", command=on_deny, width=15).pack(side="left", padx=10)
    
    root.mainloop()
    
    # Send response
    try:
        requests.post(f"{BACKEND_URL}/agent/auth-response", json={
            "job_id": job_id,
            "action": result["action"]
        })
    except Exception as e:
        print(f"[-] Failed to send auth response: {e}")

def perform_wipe(job_id, target):
    print(f"[*] Starting wipe for {target}...")
    
    def progress_cb(msg, pct=None):
        payload = {"job_id": job_id, "log": msg}
        if pct is not None:
            payload["progress"] = pct
        try:
            requests.post(f"{BACKEND_URL}/agent/job-update", json=payload)
        except:
            pass
            
    try:
        run_adaptive_sanitization(
            target=target,
            method="dod-3pass",
            max_iterations=1,
            operator="Remote Admin",
            progress_cb=progress_cb
        )
        requests.post(f"{BACKEND_URL}/agent/job-update", json={"job_id": job_id, "complete": True})
        print("[+] Wipe complete.")
    except Exception as e:
        print(f"[-] Wipe failed: {e}")

def poll_server():
    while True:
        try:
            res = requests.get(f"{BACKEND_URL}/agent/poll?computer_id={COMPUTER_ID}")
            if res.status_code == 200:
                data = res.json()
                action = data.get("action")
                
                if action == "request_auth":
                    print(f"[*] Received auth request for {data['target']}")
                    # Run UI in main thread (this is polling thread, so we dispatch)
                    # For simplicity in this demo agent, we just run it blocking
                    show_auth_dialog(data['job_id'], data['target'])
                    
                elif action == "start_wipe":
                    print(f"[*] Received command to start wipe for {data['target']}")
                    # Run wipe in background
                    threading.Thread(target=perform_wipe, args=(data['job_id'], data['target'])).start()
                    
        except requests.exceptions.RequestException as e:
            # Print diagnostic only occasionally to avoid spam
            if int(time.time()) % 10 == 0:
                print(f"[!] Polling failed ({BASE_URL}). Check Tailscale connectivity.")
            
        time.sleep(2)

if __name__ == "__main__":
    print("="*50)
    print("  Virtual / Remote Wipe Agent")
    print("="*50)
    register_agent()
    print("[*] Polling for commands...")
    poll_server()
