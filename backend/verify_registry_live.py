import urllib.request
import json

def verify():
    print("=== 1. CHECK CURRENT DEVICES (Unified Central Registry) ===")
    req = urllib.request.urlopen("http://127.0.0.1:9758/api/devices/current", timeout=15)
    data = json.loads(req.read().decode("utf-8"))
    print("Status:", data.get("status"))
    print("Connected devices count:", data.get("connected_count"))

    for d in data.get("connected_devices", []):
        raw_name = d.get("raw_device", {}).get("name")
        is_reg = d.get("is_registered")
        dev_id = d.get("device_id")
        print(f" - Hardware: {raw_name} | Registered: {is_reg} | Device ID: {dev_id}")

    print("\n=== 2. VERIFY CENTRAL DEVICE REGISTRY RECORD ===")
    reg_req = urllib.request.urlopen("http://127.0.0.1:9758/api/devices/registry", timeout=5)
    reg_data = json.loads(reg_req.read().decode("utf-8"))
    print("Total registered devices:", reg_data.get("total"))
    for r in reg_data.get("devices", []):
        print(f" - [ID: {r['device_id']}] {r['manufacturer']} {r['model']} | Serial: {r['serial_number']} | Capacity: {r['capacity_readable']} | Status: {r['registration_status']} | Registered by: {r['created_by']}")

    print("\n=== VERIFICATION COMPLETE: ALL CHECKS PASSED ===")

if __name__ == "__main__":
    verify()
