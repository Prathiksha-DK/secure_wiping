from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time
import os
import psutil
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


class BoomWiper:
    def __init__(self):
        self.active_wipes = {}
        self.overwrite_passes = 3  # Number of times to overwrite file
        self.demo_mode = False  # Real deletion mode
        self.device_files = {}

    def resolve_mountpoint(self, device_label):
        """Hardcoded mapping"""
        if device_label.lower().startswith("hp v220w"):
            return "F:\\"  # Change this to your pendrive drive letter
        logger.warning(f"Could not map device label '{device_label}', using it as-is")
        return device_label

    def scan_device_files(self, drive_letter):
        """Scan all files on the drive"""
        files_list = []
        try:
            if not os.path.exists(drive_letter):
                logger.warning(f"Drive {drive_letter} not accessible")
                return []

            logger.info(f"📁 Scanning files on drive {drive_letter}...")
            for root, dirs, files in os.walk(drive_letter):
                for file_name in files:
                    try:
                        file_path = os.path.join(root, file_name)
                        relative_path = os.path.relpath(file_path, drive_letter)
                        file_size = os.path.getsize(file_path)
                        files_list.append({
                            "path": file_path,
                            "relative_path": relative_path,
                            "name": file_name,
                            "size": file_size,
                            "deleted": False
                        })
                    except Exception as e:
                        logger.debug(f"Error accessing {file_name}: {e}")
                        continue

            logger.info(f"✅ Found {len(files_list)} files")
            return files_list

        except Exception as e:
            logger.error(f"Error scanning device files: {e}")
            return []

    def real_delete_files(self, wipe_id, bomb_id):
        """Overwrite and delete files, updating progress per file"""
        if wipe_id not in self.device_files:
            return

        files = self.device_files[wipe_id]
        total_files = len(files)

        for file_info in files:
            if file_info.get("deleted", False):
                continue

            file_path = file_info["path"]
            try:
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    # Overwrite file multiple times
                    with open(file_path, "r+b") as f:
                        for _ in range(self.overwrite_passes):
                            f.seek(0)
                            f.write(os.urandom(size))
                            f.flush()
                            os.fsync(f.fileno())
                        f.truncate()
                    # Delete file
                    os.remove(file_path)

                    file_info["deleted"] = True
                    file_info["deleted_by_bomb"] = bomb_id
                    # Update progress
                    self.active_wipes[wipe_id]["deleted_count"] += 1
                    self.active_wipes[wipe_id]["files_remaining"] = total_files - self.active_wipes[wipe_id]["deleted_count"]
                    self.active_wipes[wipe_id]["progress"] = (self.active_wipes[wipe_id]["deleted_count"] / total_files) * 100

                    logger.info(f"💥 FILE DELETED: {file_info['relative_path']} ({size/1024:.1f} KB)")

            except Exception as e:
                logger.error(f"⚠️ Failed to delete {file_path}: {e}")
                continue

    def place_bomb(self, bomb_id, wipe_id):
        """Single-threaded deletion; files are updated per file"""
        logger.info(f"🧨 Bomb {bomb_id} running...")
        self.real_delete_files(wipe_id, bomb_id)

    def execute_boom_wipe(self, device_name, wipe_id):
        """Main wipe function"""
        logger.info(f"🚀 Starting Boom Wipe on {device_name}")
        mountpoint = self.resolve_mountpoint(device_name)

        self.active_wipes[wipe_id] = {
            "status": "initializing",
            "device": device_name,
            "progress": 0,
            "deleted_count": 0,
            "files_remaining": 0
        }

        files = self.scan_device_files(mountpoint)
        self.device_files[wipe_id] = files
        total_files = len(files)
        self.active_wipes[wipe_id]["files_remaining"] = total_files

        if total_files == 0:
            self.active_wipes[wipe_id].update({"status": "completed", "progress": 100})
            logger.info("No files found. Wipe completed.")
            return

        self.active_wipes[wipe_id]["status"] = "wiping"
        # Only one thread needed now; updates happen per file
        self.place_bomb(1, wipe_id)

        self.active_wipes[wipe_id].update({"status": "completed", "progress": 100})
        logger.info(f"✅ Boom Wipe completed on {device_name}")


boom_wiper = BoomWiper()


@app.route("/boom-wipe", methods=["POST"])
def boom_wipe():
    data = request.get_json()
    if not data or "device" not in data:
        return jsonify({"status": "error", "message": "Missing device parameter"}), 400

    device_name = data["device"]
    wipe_id = f"wipe_{int(time.time())}_{os.getpid()}"

    threading.Thread(target=boom_wiper.execute_boom_wipe, args=(device_name, wipe_id), daemon=True).start()

    return jsonify({"status": "success", "wipe_id": wipe_id, "demo_mode": boom_wiper.demo_mode})


@app.route("/wipe-status/<wipe_id>", methods=["GET"])
def get_wipe_status(wipe_id):
    if wipe_id in boom_wiper.active_wipes:
        return jsonify({"status": "success", "wipe_status": boom_wiper.active_wipes[wipe_id]})
    return jsonify({"status": "error", "message": "Wipe ID not found"}), 404


@app.route("/devices", methods=["GET"])
def list_devices():
    devices = []
    for p in psutil.disk_partitions():
        if "removable" in p.opts.lower():
            usage = psutil.disk_usage(p.mountpoint)
            devices.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "size_gb": usage.total // (1024**3),
                "used_gb": usage.used // (1024**3),
                "free_gb": usage.free // (1024**3)
            })
    return jsonify({"status": "success", "devices": devices})


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "success", "message": "Main Boom Wipe service is running"}), 200


if __name__ == "__main__":
    logger.info("🚀 Starting Boom Wipe on port 5695 (REAL DELETE MODE)")
    app.run(host="0.0.0.0", port=5695)
