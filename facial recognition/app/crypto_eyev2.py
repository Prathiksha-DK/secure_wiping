import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="face_recognition_models")

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import threading
import time
import psutil
import win32api
import win32con
import subprocess
import os
from datetime import datetime
import json
import cv2
import numpy as np
import face_recognition
import joblib
import platform
import tkinter as tk
from tkinter import ttk
import pyautogui
from PIL import Image, ImageFilter, ImageTk
import ctypes
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Try multiple notification libraries
try:
    from plyer import notification as plyer_notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    print("Warning: plyer not available for notifications")

try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
    toaster = ToastNotifier()
except ImportError:
    TOAST_AVAILABLE = False
    print("Warning: win10toast not available for notifications")

app = Flask(__name__)
CORS(app)

class EncryptedFileMonitor(FileSystemEventHandler):
    """Monitor encrypted file access attempts"""
    def __init__(self, monitor_ref):
        self.monitor = monitor_ref
        self.monitored_file = r"C:\Users\hp\Downloads\AttendanceList(I).doc.enc"
        
    def on_modified(self, event):
        if event.src_path == self.monitored_file:
            self.monitor.handle_encrypted_file_access()
    
    def on_opened(self, event):
        if hasattr(event, 'src_path') and event.src_path == self.monitored_file:
            self.monitor.handle_encrypted_file_access()

class IntegratedSecurityMonitor:
    def __init__(self):
        # USB Monitoring flags
        self.usb_monitoring = False
        self.usb_monitoring_thread = None
        
        # Face Recognition flags
        self.face_monitoring = False
        self.face_monitoring_thread = None
        
        # Known USB devices baseline
        self.known_devices = set()
        self.alerts = []
        self.activity_log = []
        self.suspicious_processes = []
        self.current_usb_devices = []
        
        # Face Recognition data
        self.last_face_detection = {"label": "None", "distance": None, "timestamp": None}
        self.admin_encodings = []
        self.face_threshold = 0.6
        self.webcam = None
        self.face_encodings_loaded = False
        
        # Encrypted file monitoring
        self.encrypted_file_path = r"C:\Users\hp\Downloads\AttendanceList(I).doc.enc"
        self.file_access_attempts = defaultdict(int)
        self.unauthorized_file_attempts = 0
        self.max_file_attempts = 5
        self.shutdown_timer = None
        self.file_monitor_observer = None
        self.is_shutting_down = False
        self.file_monitoring_active = False
        
        # Security tracking
        self.unauthorized_attempts = 0
        self.last_admin_seen = None
        self.current_user_authorized = False
        
        # Enhanced notification settings
        self.notification_settings = {
            'enabled': True,
            'cooldown': 10,
            'sound_enabled': True,
            'test_on_start': True,
            'auto_start_face_monitor': True  # Auto-start face monitoring
        }
        
        self.initialize_known_devices()
        self.load_face_encodings()
        self.start_file_monitoring()
        
        # Test notification on startup
        if self.notification_settings['test_on_start']:
            self.test_notification()
        
        # Auto-start face monitoring after a short delay
        if self.notification_settings['auto_start_face_monitor']:
            self.log_message("Auto-starting face monitoring in 3 seconds...")
            threading.Timer(3.0, self.auto_start_face_monitoring).start()
    
    def auto_start_face_monitoring(self):
        """Automatically start face monitoring on startup"""
        if self.start_face_monitoring():
            self.log_message("Face monitoring auto-started successfully")
        else:
            self.log_message("Failed to auto-start face monitoring")
    
    def start_file_monitoring(self):
        """Start monitoring the encrypted file"""
        try:
            if os.path.exists(self.encrypted_file_path):
                self.log_message(f"Monitoring encrypted file: {self.encrypted_file_path}")
                self.file_monitoring_active = True
                
                # Setup file system watcher
                event_handler = EncryptedFileMonitor(self)
                self.file_monitor_observer = Observer()
                self.file_monitor_observer.schedule(
                    event_handler, 
                    os.path.dirname(self.encrypted_file_path), 
                    recursive=False
                )
                self.file_monitor_observer.start()
                
                # Also monitor process access
                self.monitor_file_access_thread = threading.Thread(
                    target=self.monitor_file_access_loop, 
                    daemon=True
                )
                self.monitor_file_access_thread.start()
            else:
                self.log_message(f"Encrypted file not found: {self.encrypted_file_path}")
                self.file_monitoring_active = False
        except Exception as e:
            self.log_message(f"Error starting file monitoring: {e}")
            self.file_monitoring_active = False
    
    def monitor_file_access_loop(self):
        """Monitor processes accessing the encrypted file"""
        last_check_time = 0
        check_interval = 2  # Check every 2 seconds
        
        while self.file_monitoring_active:
            try:
                current_time = time.time()
                if current_time - last_check_time < check_interval:
                    time.sleep(0.5)
                    continue
                
                last_check_time = current_time
                
                # Check if file was recently modified
                try:
                    file_stat = os.stat(self.encrypted_file_path)
                    if current_time - file_stat.st_mtime < 5:  # Modified in last 5 seconds
                        self.handle_encrypted_file_access()
                except FileNotFoundError:
                    pass
                
                # Check processes that might be accessing the file
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        # Check for common programs that might open encrypted files
                        if any(prog in proc_name for prog in ['notepad', 'wordpad', 'winword', 'excel', 'powerpnt', 'explorer']):
                            # Check if process has the file open
                            try:
                                for item in proc.open_files():
                                    if self.encrypted_file_path.lower() in item.path.lower():
                                        self.handle_encrypted_file_access()
                                        break
                            except (psutil.AccessDenied, AttributeError):
                                pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(1)
            except Exception as e:
                self.log_message(f"File access monitoring error: {e}")
                time.sleep(5)
    
    def handle_encrypted_file_access(self):
        """Handle when encrypted file is accessed"""
        if not self.current_user_authorized:
            self.unauthorized_file_attempts += 1
            timestamp = datetime.now()
            
            self.log_message(f"UNAUTHORIZED FILE ACCESS ATTEMPT #{self.unauthorized_file_attempts}")
            
            # Create alert
            alert = {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "encrypted_file_access",
                "message": f"Unauthorized access to encrypted file (Attempt #{self.unauthorized_file_attempts})",
                "severity": "critical",
                "attempts": self.unauthorized_file_attempts
            }
            self.alerts.append(alert)
            
            # Send warning notification
            remaining_attempts = self.max_file_attempts - self.unauthorized_file_attempts
            
            if remaining_attempts > 0:
                self.send_notification(
                    title=f"⚠️ SECURITY WARNING ({self.unauthorized_file_attempts}/{self.max_file_attempts})",
                    message=f"Unauthorized access to encrypted file!\n{remaining_attempts} attempts remaining before system lockdown",
                    urgency='high'
                )
            
            # Check if max attempts reached
            if self.unauthorized_file_attempts >= self.max_file_attempts:
                self.initiate_system_shutdown()
    
    def initiate_system_shutdown(self):
        """Initiate system shutdown after max attempts"""
        if self.is_shutting_down:
            return
            
        self.is_shutting_down = True
        
        # Log critical event
        self.log_message("CRITICAL: Maximum unauthorized attempts reached - INITIATING SYSTEM SHUTDOWN")
        
        # Send final warning
        self.send_notification(
            title="🚨 SYSTEM SHUTDOWN IMMINENT",
            message=f"Maximum security attempts exceeded!\nSystem will shut down in 5 seconds!",
            urgency='critical'
        )
        
        # Create critical alert
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "system_shutdown",
            "message": "SYSTEM SHUTDOWN - Maximum unauthorized file access attempts",
            "severity": "critical"
        }
        self.alerts.append(alert)
        
        # Show countdown window
        self.show_shutdown_countdown()
        
        # Schedule shutdown
        self.shutdown_timer = threading.Timer(5.0, self.execute_shutdown)
        self.shutdown_timer.start()
    
    def show_shutdown_countdown(self):
        """Show countdown window before shutdown"""
        def create_countdown_window():
            try:
                root = tk.Tk()
                root.title("SYSTEM SHUTDOWN")
                root.attributes('-topmost', True)
                root.geometry("600x400")
                root.configure(bg='red')
                
                # Center the window
                root.update_idletasks()
                x = (root.winfo_screenwidth() // 2) - (600 // 2)
                y = (root.winfo_screenheight() // 2) - (400 // 2)
                root.geometry(f"600x400+{x}+{y}")
                
                # Warning label
                warning_label = tk.Label(
                    root,
                    text="⚠️ CRITICAL SECURITY BREACH ⚠️",
                    font=("Arial", 24, "bold"),
                    fg="white",
                    bg="red"
                )
                warning_label.pack(pady=20)
                
                # Message
                message_label = tk.Label(
                    root,
                    text="Maximum unauthorized file access attempts exceeded\nSystem entering BRICK MODE",
                    font=("Arial", 16),
                    fg="white",
                    bg="red",
                    justify=tk.CENTER
                )
                message_label.pack(pady=20)
                
                # Countdown label
                countdown_label = tk.Label(
                    root,
                    text="5",
                    font=("Arial", 72, "bold"),
                    fg="yellow",
                    bg="red"
                )
                countdown_label.pack(pady=20)
                
                # Countdown function
                def update_countdown(count):
                    if count > 0:
                        countdown_label.config(text=str(count))
                        root.after(1000, lambda: update_countdown(count - 1))
                    else:
                        countdown_label.config(text="SHUTTING DOWN...")
                        root.after(500, root.destroy)
                
                update_countdown(5)
                
                # Prevent closing
                root.protocol("WM_DELETE_WINDOW", lambda: None)
                root.mainloop()
                
            except Exception as e:
                print(f"Error showing countdown: {e}")
        
        countdown_thread = threading.Thread(target=create_countdown_window, daemon=True)
        countdown_thread.start()
    
    def execute_shutdown(self):
        """Execute system shutdown"""
        try:
            self.log_message("Executing system shutdown...")
            
            # Windows shutdown command (DISABLED FOR DEVELOPMENT SAFETY)
            if platform.system() == 'Windows':
                self.log_message("DEVELOPMENT BYPASS: Windows shutdown command simulated (os.system('shutdown /s /t 0 /f') prevented)")
            else:
                self.log_message("DEVELOPMENT BYPASS: POSIX shutdown command simulated (os.system('sudo shutdown now') prevented)")
                
        except Exception as e:
            self.log_message(f"Shutdown error: {e}")
            # Try alternative shutdown method (DISABLED FOR DEVELOPMENT SAFETY)
            try:
                self.log_message("DEVELOPMENT BYPASS: Alternative shutdown prevented")
            except:
                pass
    
    def cancel_shutdown(self):
        """Cancel pending shutdown (if admin is verified)"""
        if self.shutdown_timer and self.shutdown_timer.is_alive():
            self.shutdown_timer.cancel()
            self.is_shutting_down = False
            self.log_message("Shutdown cancelled - Admin verified")
            
            self.send_notification(
                title="✅ Shutdown Cancelled",
                message="Admin verified - System shutdown cancelled",
                urgency='normal'
            )
    
    def test_notification(self):
        """Test notification system on startup"""
        self.log_message("Testing notification system...")
        success = self.send_notification(
            title="Security Monitor Started",
            message=f"Monitoring encrypted file:\n{self.encrypted_file_path}",
            urgency='normal',
            test=True
        )
        if success:
            self.log_message("Notification test successful")
        else:
            self.log_message("Notification test failed - check system settings")
    
    def send_notification(self, title, message, urgency='normal', test=False):
        """Enhanced notification sender with multiple methods"""
        if not self.notification_settings['enabled'] and not test:
            return False
        
        success = False
        system = platform.system()
        
        # Method 1: Try Windows 10 Toast (Windows only)
        if system == 'Windows' and TOAST_AVAILABLE:
            try:
                icon_path = None
                duration = 10 if urgency == 'high' else 5
                
                toaster.show_toast(
                    title,
                    message,
                    icon_path=icon_path,
                    duration=duration,
                    threaded=True
                )
                success = True
                self.log_message(f"Notification sent via win10toast: {title}")
            except Exception as e:
                self.log_message(f"win10toast error: {e}")
        
        # Method 2: Try plyer
        if not success and PLYER_AVAILABLE:
            try:
                plyer_notification.notify(
                    title=title,
                    message=message,
                    app_name='Security Monitor',
                    app_icon=None,
                    timeout=10 if urgency == 'high' else 5,
                )
                success = True
                self.log_message(f"Notification sent via plyer: {title}")
            except Exception as e:
                self.log_message(f"plyer error: {e}")
        
        # Method 3: Sound alert
        if self.notification_settings['sound_enabled']:
            try:
                import winsound
                if urgency == 'critical':
                    for _ in range(5):
                        winsound.Beep(1500, 300)
                        time.sleep(0.1)
                elif urgency == 'high':
                    for _ in range(3):
                        winsound.Beep(1000, 300)
                        time.sleep(0.1)
                else:
                    winsound.Beep(800, 200)
            except:
                pass
        
        return success
    
    def load_face_encodings(self):
        """Load admin face encodings from joblib file or create default"""
        try:
            possible_paths = [
                r"E:\Keylogging\facial recognition\embeddings\admin_encodings.joblib",
                r"admin_encodings.joblib",
                r"encodings\admin_encodings.joblib",
                r"facial_recognition\admin_encodings.joblib"
            ]
            
            encodings_loaded = False
            
            for joblib_file in possible_paths:
                if os.path.exists(joblib_file):
                    try:
                        admin_encodings = joblib.load(joblib_file)
                        
                        if isinstance(admin_encodings, np.ndarray):
                            if admin_encodings.ndim == 2 and admin_encodings.shape[1] == 128:
                                self.admin_encodings = [enc for enc in admin_encodings]
                            elif admin_encodings.ndim == 1 and admin_encodings.shape[0] % 128 == 0:
                                self.admin_encodings = admin_encodings.reshape(-1, 128).tolist()
                        elif isinstance(admin_encodings, list):
                            self.admin_encodings = admin_encodings
                        
                        if len(self.admin_encodings) > 0:
                            self.log_message(f"Loaded {len(self.admin_encodings)} admin face encodings from {joblib_file}")
                            self.face_encodings_loaded = True
                            encodings_loaded = True
                            break
                            
                    except Exception as e:
                        self.log_message(f"Error loading from {joblib_file}: {e}")
                        continue
            
            if not encodings_loaded:
                self.log_message("No admin encodings file found. Creating test mode with camera check...")
                # Create a dummy encoding for testing
                dummy_encoding = np.random.random(128).tolist()
                self.admin_encodings = [dummy_encoding]
                self.face_encodings_loaded = True
                self.log_message("WARNING: Using dummy face encoding for testing. Replace with real admin faces!")
                
        except Exception as e:
            self.log_message(f"Error in face encodings setup: {e}")
            self.face_encodings_loaded = False
    
    def test_camera(self):
        """Test if camera is available"""
        try:
            # Try different camera indices
            for camera_index in [0, 1, 2]:
                self.log_message(f"Testing camera index {camera_index}...")
                cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)  # Use DirectShow on Windows
                
                if cap.isOpened():
                    ret, frame = cap.read()
                    cap.release()
                    if ret and frame is not None:
                        self.log_message(f"Camera test successful on index {camera_index}")
                        return True
                    else:
                        self.log_message(f"Camera {camera_index} opened but no frame captured")
                else:
                    self.log_message(f"Cannot open camera {camera_index}")
            
            self.log_message("No working camera found")
            return False
            
        except Exception as e:
            self.log_message(f"Camera test error: {e}")
            return False
    
    def initialize_known_devices(self):
        """Initialize baseline of known USB devices"""
        try:
            drives = win32api.GetLogicalDrives()
            for i in range(26):
                if drives & (1 << i):
                    drive_letter = chr(65 + i) + ':'
                    try:
                        drive_type = win32api.GetDriveType(drive_letter + '\\')
                        if drive_type == win32con.DRIVE_REMOVABLE:
                            self.known_devices.add(drive_letter)
                    except:
                        pass
        except Exception as e:
            self.log_message(f"Error initializing known devices: {e}")
    
    def log_message(self, message):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "message": message
        }
        self.activity_log.append(log_entry)
        print(f"[{timestamp}] {message}")
        
        if len(self.activity_log) > 100:
            self.activity_log = self.activity_log[-100:]
    
    def start_usb_monitoring(self):
        """Start USB monitoring"""
        if not self.usb_monitoring:
            self.usb_monitoring = True
            self.usb_monitoring_thread = threading.Thread(target=self.usb_monitoring_loop, daemon=True)
            self.usb_monitoring_thread.start()
            self.log_message("USB Security monitoring started")
            return True
        return False
    
    def stop_usb_monitoring(self):
        """Stop USB monitoring"""
        if self.usb_monitoring:
            self.usb_monitoring = False
            self.log_message("USB Security monitoring stopped")
            return True
        return False
    
    def start_face_monitoring(self):
        """Start face recognition monitoring"""
        if self.face_monitoring:
            self.log_message("Face monitoring already running")
            return False
            
        # Test camera before starting
        if not self.test_camera():
            self.log_message("Cannot start face monitoring - camera not available")
            self.log_message("Please check:")
            self.log_message("1. Camera is connected and not being used by another application")
            self.log_message("2. Camera drivers are installed")
            self.log_message("3. Camera permissions are enabled for this application")
            return False
            
        if not self.face_encodings_loaded:
            self.log_message("Cannot start face monitoring - no admin faces loaded")
            return False
            
        self.face_monitoring = True
        self.face_monitoring_thread = threading.Thread(target=self.face_monitoring_loop, daemon=True)
        self.face_monitoring_thread.start()
        self.log_message("Face recognition monitoring started")
        return True
    
    def stop_face_monitoring(self):
        """Stop face recognition monitoring"""
        if self.face_monitoring:
            self.face_monitoring = False
            if self.webcam:
                try:
                    self.webcam.release()
                    self.webcam = None
                except:
                    pass
            self.log_message("Face recognition monitoring stopped")
            return True
        return False
    
    def usb_monitoring_loop(self):
        """USB monitoring loop"""
        while self.usb_monitoring:
            try:
                self.check_usb_devices()
                self.check_suspicious_processes()
                time.sleep(2)
            except Exception as e:
                self.log_message(f"USB monitoring error: {e}")
                time.sleep(5)
    
    def face_monitoring_loop(self):
        """Enhanced face recognition monitoring"""
        last_notification_time = 0
        notification_cooldown = self.notification_settings['cooldown']
        consecutive_unauthorized = 0
        frames_without_face = 0
        camera_index = 0  # Default camera
        
        try:
            # Try to open camera with different backends
            self.log_message(f"Opening webcam (index {camera_index})...")
            self.webcam = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)  # DirectShow for Windows
            
            # Set camera properties
            self.webcam.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.webcam.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            self.webcam.set(cv2.CAP_PROP_FPS, 30)
            
            # Wait a moment for camera to initialize
            time.sleep(1)
            
            if not self.webcam.isOpened():
                self.log_message("Error: Cannot open webcam in monitoring loop")
                self.face_monitoring = False
                return
            
            self.log_message("Webcam opened successfully, starting face detection...")
            
            # Test read a frame
            ret, test_frame = self.webcam.read()
            if not ret or test_frame is None:
                self.log_message("Error: Cannot read from webcam")
                self.face_monitoring = False
                return
            
            self.log_message(f"Camera working: Frame shape {test_frame.shape}")
            
            frame_count = 0
            frame_skip = 3  # Process every 3rd frame for performance
            
            if len(self.admin_encodings) > 0:
                admin_array = np.stack(self.admin_encodings)
                self.log_message(f"Admin encodings ready: {admin_array.shape}")
            else:
                self.log_message("No admin encodings available")
                self.face_monitoring = False
                return
            
            while self.face_monitoring:
                try:
                    ret, frame = self.webcam.read()
                    if not ret or frame is None:
                        self.log_message("Failed to read frame from webcam")
                        frames_without_face += 1
                        if frames_without_face > 30:  # If no frames for ~10 seconds
                            self.log_message("Too many failed frames, restarting camera...")
                            break
                        time.sleep(0.1)
                        continue
                    
                    frames_without_face = 0  # Reset counter on successful frame
                    
                    frame_count += 1
                    if frame_count % frame_skip != 0:
                        continue
                    
                    # Resize frame for faster processing
                    small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
                    rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)
                    
                    # Detect faces
                    face_locations = face_recognition.face_locations(rgb_small_frame, model="hog")
                    
                    if len(face_locations) == 0:
                        frames_without_face += 1
                        self.last_face_detection = {
                            "label": "No Face",
                            "distance": None,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Mark user as unauthorized if no face detected for a while
                        if frames_without_face > 10:
                            self.current_user_authorized = False
                        
                        time.sleep(0.1)
                        continue
                    
                    # Face detected, process it
                    if frame_count % 30 == 0:  # Log every second
                        self.log_message(f"Processing {len(face_locations)} face(s)")
                    
                    frames_without_face = 0
                    face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations, model="small")
                    
                    for enc in face_encodings:
                        distances = np.linalg.norm(admin_array - enc, axis=1)
                        min_distance = float(np.min(distances)) if len(distances) > 0 else None
                        
                        if len(distances) > 0 and np.min(distances) < self.face_threshold:
                            # Admin detected
                            label = "Admin"
                            consecutive_unauthorized = 0
                            self.last_admin_seen = datetime.now()
                            self.current_user_authorized = True
                            
                            # Reset file access attempts if admin verified
                            if self.unauthorized_file_attempts > 0:
                                self.unauthorized_file_attempts = 0
                                self.log_message("Admin verified - File access attempts reset")
                            
                            # Cancel any pending shutdown
                            if self.is_shutting_down:
                                self.cancel_shutdown()
                            
                            if frame_count % 150 == 0:  # Log every 5 seconds
                                self.log_message(f"Admin face detected (distance: {min_distance:.3f})")
                                
                        else:
                            # Unauthorized person detected
                            label = "Unauthorized"
                            consecutive_unauthorized += 1
                            self.unauthorized_attempts += 1
                            self.current_user_authorized = False
                            current_time = time.time()
                            
                            # Send notification if cooldown passed
                            if current_time - last_notification_time >= notification_cooldown:
                                self.send_notification(
                                    title='⚠️ Unauthorized User Detected',
                                    message=f'Unauthorized face detected!\nEncrypted file access restricted.',
                                    urgency='high'
                                )
                                last_notification_time = current_time
                            
                            # Create security alert
                            alert = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "unauthorized_face",
                                "message": f"Unauthorized face detected (distance: {min_distance:.3f})",
                                "severity": "high"
                            }
                            self.alerts.append(alert)
                            self.log_message(f"Unauthorized face detected (distance: {min_distance:.3f})")
                        
                        self.last_face_detection = {
                            "label": label,
                            "distance": min_distance,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "authorized": self.current_user_authorized
                        }
                    
                    time.sleep(0.1)  # Small delay to prevent CPU overuse
                    
                except Exception as e:
                    self.log_message(f"Face monitoring loop error: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.log_message(f"Face monitoring setup error: {e}")
        finally:
            if self.webcam:
                try:
                    self.webcam.release()
                    cv2.destroyAllWindows()
                    self.webcam = None
                    self.log_message("Webcam released")
                except:
                    pass
            self.face_monitoring = False
    
    def check_usb_devices(self):
        """Check for new USB devices"""
        try:
            current_devices = set()
            drives = win32api.GetLogicalDrives()
            
            self.current_usb_devices = []
            
            for i in range(26):
                if drives & (1 << i):
                    drive_letter = chr(65 + i) + ':'
                    try:
                        drive_type = win32api.GetDriveType(drive_letter + '\\')
                        if drive_type == win32con.DRIVE_REMOVABLE:
                            current_devices.add(drive_letter)
                            
                            try:
                                volume_info = win32api.GetVolumeInformation(drive_letter + '\\')
                                volume_name = volume_info[0] if volume_info[0] else "Unknown"
                                device_info = {
                                    "drive_letter": drive_letter,
                                    "volume_name": volume_name,
                                    "status": "known" if drive_letter in self.known_devices else "new"
                                }
                                self.current_usb_devices.append(device_info)
                            except:
                                device_info = {
                                    "drive_letter": drive_letter,
                                    "volume_name": "Access Denied",
                                    "status": "known" if drive_letter in self.known_devices else "new"
                                }
                                self.current_usb_devices.append(device_info)
                    except:
                        pass
            
            new_devices = current_devices - self.known_devices
            if new_devices:
                for device in new_devices:
                    self.log_message(f"NEW USB DEVICE DETECTED: {device}")
                    
                    self.send_notification(
                        title='USB Device Alert',
                        message=f'New USB device detected: {device}',
                        urgency='medium'
                    )
                    
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "new_usb_device",
                        "message": f"New USB: {device}",
                        "severity": "medium"
                    }
                    self.alerts.append(alert)
                    self.check_device_security(device)
                
                self.known_devices.update(new_devices)
            
            removed_devices = self.known_devices - current_devices
            if removed_devices:
                for device in removed_devices:
                    self.log_message(f"USB DEVICE REMOVED: {device}")
                
                self.known_devices = current_devices
                
        except Exception as e:
            self.log_message(f"Error checking USB devices: {e}")
    
    def check_device_security(self, drive_letter):
        """Perform security checks on new USB device"""
        try:
            drive_path = drive_letter + '\\'
            
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
            autorun_files = ['autorun.inf', 'autorun.exe', 'setup.exe']
            
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    if file.lower() in [f.lower() for f in autorun_files]:
                        alert_msg = f"SUSPICIOUS: Autorun file found on {drive_letter}: {file}"
                        self.log_message(alert_msg)
                        
                        self.send_notification(
                            title='⚠️ AUTORUN DETECTED',
                            message=f'Autorun file found on {drive_letter}: {file}',
                            urgency='high'
                        )
                        
                        alert = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "autorun_file",
                            "message": f"Autorun: {file}",
                            "severity": "high",
                            "device": drive_letter
                        }
                        self.alerts.append(alert)
                    
                    if any(file.lower().endswith(ext) for ext in suspicious_extensions):
                        alert_msg = f"WARNING: Executable file on {drive_letter}: {file}"
                        self.log_message(alert_msg)
                        alert = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "executable_file",
                            "message": f"Executable: {file}",
                            "severity": "medium",
                            "device": drive_letter
                        }
                        self.alerts.append(alert)
                
                if len(root.split(os.sep)) - len(drive_path.split(os.sep)) > 2:
                    break
                    
        except Exception as e:
            self.log_message(f"Error scanning device {drive_letter}: {e}")
    
    def check_suspicious_processes(self):
        """Check for suspicious processes"""
        try:
            suspicious_keywords = [
                'keylog', 'logger', 'capture', 'record', 'monitor', 
                'spy', 'stealth', 'hidden', 'hook', 'inject'
            ]
            
            self.suspicious_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                    proc_exe = proc_info['exe'].lower() if proc_info['exe'] else ''
                    
                    if any(keyword in proc_name or keyword in proc_exe 
                           for keyword in suspicious_keywords):
                        
                        process_data = {
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "exe": proc_info['exe'],
                            "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        self.suspicious_processes.append(process_data)
                        
                        alert_exists = any(
                            alert.get('pid') == proc_info['pid'] 
                            for alert in self.alerts 
                            if alert.get('type') == 'suspicious_process'
                        )
                        
                        if not alert_exists:
                            self.send_notification(
                                title='Suspicious Process Detected',
                                message=f'Process: {proc_info["name"]}\nPID: {proc_info["pid"]}',
                                urgency='high'
                            )
                            
                            alert = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "suspicious_process",
                                "message": f"Suspicious Process: PID {proc_info['pid']}: {proc_info['name']}",
                                "severity": "high",
                                "pid": proc_info['pid']
                            }
                            self.alerts.append(alert)
                            self.log_message(f"SUSPICIOUS PROCESS DETECTED: PID {proc_info['pid']}: {proc_info['name']}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
        except Exception as e:
            self.log_message(f"Error checking processes: {e}")
    
    def manual_scan(self):
        """Perform manual scan of system"""
        self.log_message("Manual scan initiated...")
        self.check_usb_devices()
        self.check_suspicious_processes()
        camera_available = self.test_camera()
        self.log_message("Manual scan completed")
        
        return {
            "usb_devices": len(self.current_usb_devices),
            "suspicious_processes": len(self.suspicious_processes),
            "total_alerts": len(self.alerts),
            "face_status": "Active" if self.face_monitoring else "Inactive",
            "camera_available": camera_available,
            "admin_faces_loaded": len(self.admin_encodings),
            "unauthorized_file_attempts": self.unauthorized_file_attempts,
            "max_file_attempts": self.max_file_attempts,
                        "current_user_authorized": self.current_user_authorized
        }

# Initialize the monitor
monitor = IntegratedSecurityMonitor()

# HTML template with encrypted file monitoring
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Integrated Security Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; color: #333; margin-bottom: 30px; }
        .shutdown-warning {
            display: none;
            background-color: #dc3545;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
            border-radius: 5px;
            animation: pulse 0.5s infinite;
        }
        .shutdown-active { display: block; }
        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.05); }
            100% { opacity: 1; transform: scale(1); }
        }
        .status-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin: 20px 0; }
        .status { padding: 15px; border-radius: 5px; text-align: center; font-weight: bold; }
        .status.active { background-color: #d4edda; color: #155724; }
        .status.inactive { background-color: #f8d7da; color: #721c24; }
        .status.warning { background-color: #fff3cd; color: #856404; }
        .status.critical { background-color: #dc3545; color: white; animation: pulse 1s infinite; }
        .controls { text-align: center; margin: 20px 0; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        .btn-success { background-color: #28a745; color: white; }
        .btn-danger { background-color: #dc3545; color: white; }
        .btn-info { background-color: #17a2b8; color: white; }
        .btn-warning { background-color: #ffc107; color: black; }
        .btn-primary { background-color: #007bff; color: white; }
        .grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 20px; margin: 20px 0; }
        .panel { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .panel h3 { margin-top: 0; color: #333; }
        .list-item { padding: 5px; border-bottom: 1px solid #eee; font-size: 14px; }
        .alert-high { color: #dc3545; font-weight: bold; }
        .alert-medium { color: #ffc107; font-weight: bold; }
        .alert-critical { color: #dc3545; font-weight: bold; background-color: #f8d7da; padding: 5px; }
        .face-detection { background: white; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .face-status { font-size: 18px; font-weight: bold; padding: 10px; border-radius: 5px; }
        .face-admin { background-color: #d4edda; color: #155724; }
        .face-unauthorized { background-color: #f8d7da; color: #721c24; }
        .face-none { background-color: #e2e3e5; color: #383d41; }
        .log-area { background: white; padding: 15px; border-radius: 5px; margin-top: 20px; max-height: 300px; overflow-y: auto; }
        .system-info { background: #e7f3ff; padding: 10px; border-radius: 5px; margin: 10px 0; font-size: 14px; }
        .notification-settings { background: white; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .security-stats { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .file-monitor { background: #ffebee; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .file-attempts-bar {
            width: 100%;
            height: 30px;
            background-color: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
            margin: 10px 0;
        }
        .file-attempts-fill {
            height: 100%;
            background-color: #4caf50;
            transition: width 0.5s ease, background-color 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        .file-attempts-critical {
            background-color: #dc3545;
            animation: pulse 0.5s infinite;
        }
        .camera-status {
            display: inline-block;
            padding: 5px 10px;
            margin-left: 10px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .camera-status.active {
            background-color: #28a745;
            color: white;
        }
        .camera-status.inactive {
            background-color: #dc3545;
            color: white;
        }
        @keyframes blink {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">Integrated Security Monitor - USB & Face Recognition</h1>
        
        <div id="shutdown-warning" class="shutdown-warning">
            🚨 SYSTEM SHUTDOWN IMMINENT - MAXIMUM SECURITY ATTEMPTS EXCEEDED 🚨
        </div>
        
        <div class="system-info">
            <div id="system-info">Loading system information...</div>
        </div>
        
        <div class="file-monitor">
            <h3>Encrypted File Protection Status</h3>
            <div>Monitoring: C:\Users\hp\Downloads\AttendanceList(I).doc.enc</div>
            <div id="file-access-status">Loading...</div>
            <div class="file-attempts-bar">
                <div id="file-attempts-fill" class="file-attempts-fill">0 / 5 attempts</div>
            </div>
            <div id="file-warning" style="color: red; font-weight: bold; display: none;">
                ⚠️ WARNING: System will shut down after 5 unauthorized attempts!
            </div>
        </div>
        
        <div class="security-stats">
            <div id="security-stats">Loading security statistics...</div>
        </div>
        
        <div class="status-grid">
            <div id="usb-status" class="status inactive">USB Monitoring: Disabled</div>
            <div id="face-status" class="status inactive">
                Face Recognition: Disabled
                <span id="camera-status" class="camera-status inactive">Camera OFF</span>
            </div>
            <div id="file-status" class="status inactive">File Protection: Inactive</div>
        </div>
        
        <div class="controls">
            <button class="btn btn-success" onclick="startUSBMonitoring()">Start USB Monitor</button>
            <button class="btn btn-danger" onclick="stopUSBMonitoring()">Stop USB Monitor</button>
            <button class="btn btn-success" onclick="startFaceMonitoring()">Start Face Monitor</button>
            <button class="btn btn-danger" onclick="stopFaceMonitoring()">Stop Face Monitor</button>
            <button class="btn btn-info" onclick="manualScan()">Manual Scan</button>
            <button class="btn btn-info" onclick="refreshData()">Refresh</button>
            <button class="btn btn-warning" onclick="clearAlerts()">Clear Alerts</button>
            <button class="btn btn-primary" onclick="testNotification()">Test Notification</button>
            <button class="btn btn-warning" onclick="resetFileAttempts()">Reset File Attempts</button>
            <button class="btn btn-primary" onclick="testCamera()">Test Camera</button>
        </div>
        
        <div class="notification-settings">
            <h3>Security Settings</h3>
            <label>
                <input type="checkbox" id="notifications-enabled" checked onchange="toggleNotifications()">
                Enable Desktop Notifications
            </label>
            <br>
            <label>
                <input type="checkbox" id="auto-start-face" checked onchange="toggleAutoStart()">
                Auto-start Face Recognition
            </label>
        </div>
        
        <div class="face-detection">
            <h3>Current Face Detection Status</h3>
            <div id="face-detection-status" class="face-status face-none">No detection</div>
        </div>
        
        <div class="grid">
            <div class="panel">
                <h3>USB Devices</h3>
                <div id="usb-devices">No devices detected</div>
            </div>
            <div class="panel">
                <h3>Suspicious Processes</h3>
                <div id="suspicious-processes">No suspicious processes</div>
            </div>
            <div class="panel">
                <h3>Security Alerts</h3>
                <div id="alerts">No alerts</div>
            </div>
            <div class="panel">
                <h3>System Stats</h3>
                <div id="system-stats">Loading...</div>
            </div>
        </div>
        
        <div class="log-area">
            <h3>Activity Log</h3>
            <div id="activity-log">Loading...</div>
        </div>
    </div>

    <script>
        let lastAlertTime = 0;
        let shutdownImminent = false;
        
        function updateFileAttempts() {
            fetch('/api/file-attempts')
                .then(response => response.json())
                .then(data => {
                    const fillBar = document.getElementById('file-attempts-fill');
                    const warning = document.getElementById('file-warning');
                    const fileStatus = document.getElementById('file-status');
                    const shutdownWarning = document.getElementById('shutdown-warning');
                    
                    const percentage = (data.attempts / data.max_attempts) * 100;
                    fillBar.style.width = percentage + '%';
                    fillBar.textContent = `${data.attempts} / ${data.max_attempts} attempts`;
                    
                    // Update file status div
                    const statusText = data.user_authorized ? 
                        '✅ User Authorized - File Access Allowed' : 
                        '⚠️ User NOT Authorized - File Access Restricted';
                    document.getElementById('file-access-status').innerHTML = statusText;
                    
                    // Update file protection status
                    if (data.file_monitoring_active) {
                        if (data.user_authorized) {
                            fileStatus.textContent = 'File Protection: Active (Authorized)';
                            fileStatus.className = 'status active';
                        } else {
                            fileStatus.textContent = `File Protection: Active (${data.attempts} violations)`;
                            fileStatus.className = 'status warning';
                        }
                    } else {
                        fileStatus.textContent = 'File Protection: Inactive';
                        fileStatus.className = 'status inactive';
                    }
                    
                    if (percentage >= 80) {
                        fillBar.classList.add('file-attempts-critical');
                        warning.style.display = 'block';
                        fileStatus.className = 'status critical';
                    } else if (percentage >= 60) {
                        fillBar.style.backgroundColor = '#ff9800';
                        warning.style.display = 'block';
                    } else if (percentage >= 40) {
                        fillBar.style.backgroundColor = '#ffc107';
                    }
                    
                    if (data.attempts >= data.max_attempts) {
                        shutdownWarning.classList.add('shutdown-active');
                        document.body.style.backgroundColor = '#ffcccc';
                        shutdownImminent = true;
                    } else {
                        shutdownWarning.classList.remove('shutdown-active');
                        if (!shutdownImminent) {
                            document.body.style.backgroundColor = '#f0f0f0';
                        }
                    }
                })
                .catch(error => console.error('Error updating file attempts:', error));
        }
        
        function updateSecurityStats() {
            fetch('/api/security-stats')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('security-stats');
                    container.innerHTML = `
                        <strong>Security Status:</strong> 
                        ${shutdownImminent ? '🚨 SHUTDOWN PENDING' : '✅ Normal'} | 
                        Unauthorized Attempts: ${data.unauthorized_attempts} | 
                        Last Admin Seen: ${data.last_admin_seen || 'Never'} | 
                        Active Alerts: ${data.critical_alerts}
                    `;
                })
                .catch(error => console.error('Error updating security stats:', error));
        }
        
        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const usbStatusDiv = document.getElementById('usb-status');
                    const faceStatusDiv = document.getElementById('face-status');
                    const cameraStatus = document.getElementById('camera-status');
                    
                    if (data.usb_monitoring) {
                        usbStatusDiv.textContent = 'USB Monitoring: Active';
                        usbStatusDiv.className = 'status active';
                    } else {
                        usbStatusDiv.textContent = 'USB Monitoring: Disabled';
                        usbStatusDiv.className = 'status inactive';
                    }
                    
                    if (data.face_monitoring) {
                        faceStatusDiv.innerHTML = 'Face Recognition: Active <span id="camera-status" class="camera-status active">Camera ON</span>';
                        faceStatusDiv.className = 'status active';
                    } else {
                        if (data.admin_faces_loaded) {
                            faceStatusDiv.innerHTML = 'Face Recognition: Disabled (Ready) <span id="camera-status" class="camera-status inactive">Camera OFF</span>';
                            faceStatusDiv.className = 'status inactive';
                        } else {
                            faceStatusDiv.innerHTML = 'Face Recognition: No Admin Faces <span id="camera-status" class="camera-status inactive">Camera OFF</span>';
                            faceStatusDiv.className = 'status warning';
                        }
                    }
                })
                .catch(error => console.error('Error updating status:', error));
        }
        
        function updateSystemInfo() {
            fetch('/api/system-info')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('system-info');
                    container.innerHTML = `
                        Admin Faces: ${data.admin_faces_loaded} loaded | 
                        Face Threshold: ${data.face_threshold} | 
                        USB Devices: ${data.total_usb_devices} | 
                        Total Alerts: ${data.total_alerts} | 
                        Notifications: ${data.notifications_enabled ? 'Enabled' : 'Disabled'} | 
                        Encrypted File: ${data.encrypted_file_exists ? 'Found' : 'Not Found'} | 
                        Last Update: ${new Date().toLocaleTimeString()}
                    `;
                })
                .catch(error => console.error('Error updating system info:', error));
        }
        
        function toggleNotifications() {
            const enabled = document.getElementById('notifications-enabled').checked;
            fetch('/api/notifications/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: enabled })
            })
            .then(response => response.json())
            .then(data => {
                console.log('Notifications:', data.enabled ? 'Enabled' : 'Disabled');
            });
        }
        
        function toggleAutoStart() {
            const enabled = document.getElementById('auto-start-face').checked;
            // This would save preference for next restart
            console.log('Auto-start face recognition:', enabled ? 'Enabled' : 'Disabled');
        }
        
        function testCamera() {
            fetch('/api/test-camera', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                });
        }
        
        function resetFileAttempts() {
            if (confirm('Reset file access attempts? This should only be done by authorized personnel.')) {
                fetch('/api/file-attempts/reset', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert(data.message);
                        updateFileAttempts();
                    });
            }
        }
        
        function clearAlerts() {
            if (confirm('Clear all security alerts?')) {
                fetch('/api/alerts/clear', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert(`Cleared ${data.cleared} alerts`);
                        refreshData();
                    });
            }
        }
        
        function testNotification() {
            fetch('/api/test-notification', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(`Notification test: ${data.success ? 'Success' : 'Failed'}`);
                });
        }
        
        function startUSBMonitoring() {
            fetch('/api/usb/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    updateStatus();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error starting USB monitoring');
                });
        }
        
        function stopUSBMonitoring() {
            fetch('/api/usb/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    updateStatus();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error stopping USB monitoring');
                });
        }
        
        function startFaceMonitoring() {
            fetch('/api/face/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    updateStatus();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error starting face monitoring');
                });
        }
        
        function stopFaceMonitoring() {
            fetch('/api/face/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    updateStatus();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error stopping face monitoring');
                });
        }
        
        function manualScan() {
            fetch('/api/scan', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    let message = `Scan completed:\n`;
                    message += `USB devices: ${data.usb_devices}\n`;
                    message += `Suspicious processes: ${data.suspicious_processes}\n`;
                    message += `Total alerts: ${data.total_alerts}\n`;
                    message += `Face monitoring: ${data.face_status}\n`;
                    message += `Camera: ${data.camera_available ? 'Available' : 'Not Available'}\n`;
                    message += `Admin faces: ${data.admin_faces_loaded}\n`;
                    message += `File access attempts: ${data.unauthorized_file_attempts}/${data.max_file_attempts}\n`;
                    message += `User authorized: ${data.current_user_authorized ? 'Yes' : 'No'}`;
                    
                    alert(message);
                    refreshData();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error performing manual scan');
                });
        }
        
        function updateFaceDetection() {
            fetch('/api/face/detection')
                .then(response => response.json())
                .then(data => {
                    const statusDiv = document.getElementById('face-detection-status');
                    const detection = data.current_detection;
                    
                    if (!detection || !detection.label) {
                        statusDiv.className = 'face-status face-none';
                        statusDiv.textContent = 'No detection data';
                        return;
                    }
                    
                    let statusClass = 'face-none';
                    let statusText = '';
                    
                    switch(detection.label) {
                        case 'Admin':
                            statusClass = 'face-admin';
                            statusText = `✓ Admin Verified`;
                            if (detection.distance) {
                                statusText += ` (confidence: ${(1 - detection.distance).toFixed(2)})`;
                            }
                            break;
                            
                        case 'Unauthorized':
                            statusClass = 'face-unauthorized';
                            statusText = `⚠️ UNAUTHORIZED PERSON`;
                            if (detection.distance) {
                                statusText += ` (distance: ${detection.distance.toFixed(3)})`;
                            }
                            break;
                            
                        case 'No Face':
                            statusClass = 'face-none';
                            statusText = '👤 No face in view';
                            break;
                            
                        default:
                            statusClass = 'face-none';
                            statusText = detection.label;
                    }
                    
                    statusDiv.className = `face-status ${statusClass}`;
                    statusDiv.innerHTML = statusText;
                    
                    if (detection.timestamp) {
                        const time = detection.timestamp.split(' ')[1];
                        statusDiv.innerHTML += `<br><small>Last update: ${time}</small>`;
                    }
                })
                .catch(error => console.error('Error updating face detection:', error));
        }
        
        function refreshData() {
            // Refresh USB devices
            fetch('/api/usb-devices')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('usb-devices');
                    if (data.devices && data.devices.length > 0) {
                        container.innerHTML = data.devices.map(device => 
                            `<div class="list-item">${device.drive_letter} - ${device.volume_name} (${device.status})</div>`
                        ).join('');
                    } else {
                        container.innerHTML = '<div class="list-item">No USB devices detected</div>';
                    }
                })
                .catch(error => {
                    console.error('Error loading USB devices:', error);
                    document.getElementById('usb-devices').innerHTML = '<div class="list-item">Error loading devices</div>';
                });
            
            // Refresh suspicious processes
            fetch('/api/suspicious-processes')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('suspicious-processes');
                    if (data.processes && data.processes.length > 0) {
                        container.innerHTML = data.processes.map(proc => 
                            `<div class="list-item alert-high">PID ${proc.pid}: ${proc.name}</div>`
                        ).join('');
                    } else {
                        container.innerHTML = '<div class="list-item">No suspicious processes</div>';
                    }
                })
                .catch(error => {
                    console.error('Error loading suspicious processes:', error);
                    document.getElementById('suspicious-processes').innerHTML = '<div class="list-item">Error loading processes</div>';
                });
            
            // Refresh alerts
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('alerts');
                    if (data.alerts && data.alerts.length > 0) {
                        container.innerHTML = data.alerts.slice(-5).reverse().map(alert => 
                            `<div class="list-item alert-${alert.severity}">${alert.timestamp.split(' ')[1]} - ${alert.message}</div>`
                        ).join('');
                    } else {
                        container.innerHTML = '<div class="list-item">No alerts</div>';
                    }
                })
                .catch(error => {
                    console.error('Error loading alerts:', error);
                    document.getElementById('alerts').innerHTML = '<div class="list-item">Error loading alerts</div>';
                });
            
            // Refresh face detection status
            updateFaceDetection();
            
            // Refresh system stats
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('system-stats');
                    container.innerHTML = `
                        <div class="list-item">Total Alerts: ${data.total_alerts}</div>
                        <div class="list-item">USB Devices: ${data.usb_devices}</div>
                        <div class="list-item">Suspicious Processes: ${data.suspicious_processes}</div>
                        <div class="list-item">Log Entries: ${data.log_entries}</div>
                    `;
                })
                .catch(error => {
                    console.error('Error loading stats:', error);
                    document.getElementById('system-stats').innerHTML = '<div class="list-item">Error loading stats</div>';
                });
            
            // Refresh activity log
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('activity-log');
                    if (data.logs && data.logs.length > 0) {
                        container.innerHTML = data.logs.slice(-20).reverse().map(log => 
                            `<div class="list-item">${log.timestamp} - ${log.message}</div>`
                        ).join('');
                    } else {
                        container.innerHTML = '<div class="list-item">No log entries</div>';
                    }
                })
                .catch(error => {
                    console.error('Error loading logs:', error);
                    document.getElementById('activity-log').innerHTML = '<div class="list-item">Error loading logs</div>';
                });
            
            updateStatus();
            updateSystemInfo();
            updateSecurityStats();
            updateFileAttempts();
        }
        
        // Initial load and periodic refresh
        refreshData();
        setInterval(refreshData, 5000);
        setInterval(updateStatus, 2000);
        setInterval(updateSystemInfo, 3000);
        setInterval(updateFaceDetection, 1000);
        setInterval(updateSecurityStats, 2000);
        setInterval(updateFileAttempts, 1000);
    </script>
</body>
</html>
"""

# Flask routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def get_status():
    return jsonify({
        'usb_monitoring': monitor.usb_monitoring,
        'face_monitoring': monitor.face_monitoring,
        'admin_faces_loaded': len(monitor.admin_encodings)
    })

@app.route('/api/system-info')
def get_system_info():
    return jsonify({
        'admin_faces_loaded': len(monitor.admin_encodings),
        'face_threshold': monitor.face_threshold,
        'total_usb_devices': len(monitor.current_usb_devices),
        'total_alerts': len(monitor.alerts),
        'notifications_enabled': monitor.notification_settings['enabled'],
        'encrypted_file_exists': os.path.exists(monitor.encrypted_file_path)
    })

@app.route('/api/security-stats')
def get_security_stats():
    critical_alerts = len([a for a in monitor.alerts if a.get('severity') == 'critical'])
    return jsonify({
        'unauthorized_attempts': monitor.unauthorized_attempts,
        'last_admin_seen': monitor.last_admin_seen.strftime("%H:%M:%S") if monitor.last_admin_seen else None,
        'critical_alerts': critical_alerts
    })

@app.route('/api/file-attempts')
def get_file_attempts():
    return jsonify({
        'attempts': monitor.unauthorized_file_attempts,
        'max_attempts': monitor.max_file_attempts,
        'user_authorized': monitor.current_user_authorized,
        'shutdown_pending': monitor.is_shutting_down,
        'file_monitoring_active': monitor.file_monitoring_active
    })

@app.route('/api/file-attempts/reset', methods=['POST'])
def reset_file_attempts():
    if monitor.current_user_authorized:  # Only allow if admin is verified
        monitor.unauthorized_file_attempts = 0
        monitor.is_shutting_down = False
        monitor.log_message("File access attempts reset by admin")
        return jsonify({
            'success': True,
            'message': 'File access attempts reset successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Unauthorized - Admin verification required'
        }), 403

@app.route('/api/test-camera', methods=['POST'])
def test_camera_endpoint():
    camera_available = monitor.test_camera()
    return jsonify({
        'success': camera_available,
        'message': 'Camera is working properly' if camera_available else 'Camera not available or not working'
    })

@app.route('/api/usb/start', methods=['POST'])
def start_usb():
    success = monitor.start_usb_monitoring()
    return jsonify({
        'success': success,
        'message': 'USB monitoring started' if success else 'USB monitoring already running'
    })

@app.route('/api/usb/stop', methods=['POST'])
def stop_usb():
    success = monitor.stop_usb_monitoring()
    return jsonify({
        'success': success,
        'message': 'USB monitoring stopped' if success else 'USB monitoring not running'
    })

@app.route('/api/face/start', methods=['POST'])
def start_face():
    success = monitor.start_face_monitoring()
    return jsonify({
        'success': success,
        'message': 'Face monitoring started' if success else 'Failed to start face monitoring (check camera/encodings)'
    })

@app.route('/api/face/stop', methods=['POST'])
def stop_face():
    success = monitor.stop_face_monitoring()
    return jsonify({
        'success': success,
        'message': 'Face monitoring stopped' if success else 'Face monitoring not running'
    })

@app.route('/api/scan', methods=['POST'])
def manual_scan():
    result = monitor.manual_scan()
    return jsonify(result)

@app.route('/api/usb-devices')
def get_usb_devices():
    return jsonify({'devices': monitor.current_usb_devices})

@app.route('/api/suspicious-processes')
def get_suspicious_processes():
    return jsonify({'processes': monitor.suspicious_processes})

@app.route('/api/alerts')
def get_alerts():
    return jsonify({'alerts': monitor.alerts})

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_alerts': len(monitor.alerts),
        'usb_devices': len(monitor.current_usb_devices),
        'suspicious_processes': len(monitor.suspicious_processes),
        'log_entries': len(monitor.activity_log)
    })

@app.route('/api/logs')
def get_logs():
    return jsonify({'logs': monitor.activity_log})

@app.route('/api/face/detection')
def get_face_detection():
    return jsonify({
        'current_detection': monitor.last_face_detection,
        'monitoring_active': monitor.face_monitoring,
        'encodings_loaded': len(monitor.admin_encodings),
        'threshold': monitor.face_threshold
    })

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    data = request.get_json()
    alert_type = data.get('type') if data else None
    
    if alert_type:
        original_count = len(monitor.alerts)
        monitor.alerts = [alert for alert in monitor.alerts if alert['type'] != alert_type]
        cleared = original_count - len(monitor.alerts)
        monitor.log_message(f"Cleared {cleared} {alert_type} alerts")
    else:
        cleared = len(monitor.alerts)
        monitor.alerts = []
        monitor.log_message(f"Cleared all {cleared} alerts")
    
    return jsonify({
        'success': True,
        'cleared': cleared,
        'remaining': len(monitor.alerts)
    })

@app.route('/api/notifications/toggle', methods=['POST'])
def toggle_notifications():
    data = request.get_json()
    enabled = data.get('enabled', True)
    monitor.notification_settings['enabled'] = enabled
    monitor.log_message(f"Notifications {'enabled' if enabled else 'disabled'}")
    return jsonify({
        'success': True,
        'enabled': monitor.notification_settings['enabled']
    })

@app.route('/api/test-notification', methods=['POST'])
def test_notification():
    success = monitor.send_notification(
        title="Test Notification",
        message="This is a test notification from Security Monitor",
        urgency='normal',
        test=True
    )
    return jsonify({
        'success': success,
        'message': 'Notification test completed'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("INTEGRATED SECURITY MONITOR WITH FILE PROTECTION")
    print("=" * 60)
    print("Starting security monitoring system...")
    print(f"Loaded {len(monitor.admin_encodings)} admin face encodings")
    print(f"Monitoring encrypted file: {monitor.encrypted_file_path}")
    print(f"File exists: {os.path.exists(monitor.encrypted_file_path)}")
    print(f"Max unauthorized attempts before shutdown: {monitor.max_file_attempts}")
    print(f"Notifications: {'Enabled' if monitor.notification_settings['enabled'] else 'Disabled'}")
    print(f"Auto-start Face Recognition: {'Enabled' if monitor.notification_settings['auto_start_face_monitor'] else 'Disabled'}")
    print("\nAccess the web interface at:")
    print("  http://localhost:5000")
    print("  http://127.0.0.1:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    
    # Camera troubleshooting tips
    print("\nCAMERA TROUBLESHOOTING:")
    print("1. Make sure no other application is using the camera")
    print("2. Check if camera drivers are installed")
    print("3. Try closing Skype, Teams, or other video apps")
    print("4. Check Windows Camera app to verify camera works")
    print("5. Run as Administrator if camera permission issues")
    print("=" * 60)
    
    # Install required packages reminder
    print("\nMake sure these packages are installed:")
    print("pip install flask flask-cors psutil opencv-python face-recognition numpy joblib pywin32 plyer pillow pyautogui watchdog")
    print("=" * 60)
    
    app.run(debug=False, host='0.0.0.0', port=5000)
