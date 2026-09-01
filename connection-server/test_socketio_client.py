#!/usr/bin/env python3
"""
Socket.IO test client to verify device communication
"""
import socketio
import time
import json

# Create a Socket.IO client
sio = socketio.Client()

@sio.event
def connect():
    print("🔌 Connected to server!")
    
    # Send device data after connection
    time.sleep(1)
    
    test_devices = [
        {
            "name": "Test NVMe Drive",
            "type": "SSD",
            "size": "500 GB", 
            "health": "Healthy (100%)"
        }
    ]
    
    print("📤 Sending device data...")
    
    # Try different event names your client might use
    event_names = [
        'setDevices',
        'deviceList', 
        'devices',
        'sendDevices',
        'worker_devices',
        'device_data'
    ]
    
    for event_name in event_names:
        print(f"🔄 Trying event: {event_name}")
        sio.emit(event_name, {"devices": test_devices}, callback=handle_ack)
        time.sleep(1)

def handle_ack(response):
    print(f"✅ Received acknowledgment: {response}")

@sio.event
def disconnect():
    print("🔌 Disconnected from server!")

@sio.event  
def devicesUpdated(data):
    print(f"📱 Devices updated: {data}")

@sio.event
def error(data):
    print(f"❌ Error received: {data}")

def main():
    try:
        print("🚀 Connecting to Socket.IO server...")
        sio.connect('http://192.168.137.191:8586')
        
        # Keep connection alive
        print("⏳ Keeping connection alive for 30 seconds...")
        time.sleep(30)
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
    finally:
        if sio.connected:
            sio.disconnect()

if __name__ == "__main__":
    main()
