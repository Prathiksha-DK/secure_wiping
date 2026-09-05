#!/usr/bin/env python3
"""
Server Startup Script
Starts both the main server (port 8586) and API server (port 5403)
"""

import os
import sys
import time
import subprocess
import signal
from multiprocessing import Process

def start_main_server():
    """Start the main server on port 8586"""
    print("[*] Starting Main Server (port 8586)...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([sys.executable, os.path.join(script_dir, "main_server.py")])

def start_api_server():
    """Start the API server on port 5403"""
    print("[*] Starting API Server (port 5403)...")
    # Wait a bit for main server to start
    time.sleep(3)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([sys.executable, os.path.join(script_dir, "api_server.py")])

def signal_handler(signum, frame):
    """Handle shutdown of both servers"""
    print("\n[-] Shutting down both servers...")
    sys.exit(0)

if __name__ == '__main__':
    print("=" * 70)
    print("Starting Dual Server Architecture")
    print("Main Server (Socket.IO): Port 8586 - For client connections")  
    print("API Server (REST): Port 5403 - For querying connected users")
    print("=" * 70)
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start both servers in separate processes
        main_process = Process(target=start_main_server)
        api_process = Process(target=start_api_server)
        
        main_process.start()
        api_process.start()
        
        print("\n[+] Both servers started!")
        print("Usage:")
        print("   • Clients connect to: http://127.0.0.1:8586")
        print("   • Query users via: http://127.0.0.1:5403/getConnectedUsers")
        print("   • Press Ctrl+C to stop both servers")
        
        # Wait for both processes
        main_process.join()
        api_process.join()
        
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        print(f"[!] Error starting servers: {e}")
        signal_handler(signal.SIGTERM, None)
