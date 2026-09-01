#!/usr/bin/env python3
"""
Test Client for Flask Connection Server
Demonstrates how to connect to the Flask server using Socket.IO
"""

import sys
import time
import json
import signal
import threading
from datetime import datetime

import socketio

# Configuration - Connect to main server for Socket.IO
SERVER_URL = 'http://192.168.137.191:8586'
USERNAME = sys.argv[1] if len(sys.argv) > 1 else f'TestUser{int(time.time())}'

print(f'🔌 Connecting to server: {SERVER_URL}')
print(f'👤 Username: {USERNAME}')

# Create Socket.IO client
sio = socketio.Client()

# Global variables
user_id = None
connected = False

# Event handlers
@sio.on('connect')
def on_connect():
    global connected
    connected = True
    print('✅ Connected to server!')
    
    # Send username to server after a short delay
    def set_username():
        time.sleep(0.5)
        if connected:
            sio.emit('setUsername', {'username': USERNAME})
    
    # Start username setting in a separate thread
    threading.Thread(target=set_username, daemon=True).start()

@sio.on('disconnect')
def on_disconnect():
    global connected
    connected = False
    print('🔌 Disconnected from server')

@sio.on('welcome')
def on_welcome(data):
    global user_id
    user_id = data.get('userId')
    assigned_username = data.get('assignedUsername')
    
    print(f'🎉 Welcome! Assigned ID: {user_id}')
    print(f'🏷️ Default username: {assigned_username}')

@sio.on('usernameUpdated')
def on_username_updated(data):
    username = data.get('username')
    print(f'✅ Username updated to: {username}')

@sio.on('pong')
def on_pong(data):
    print('💓 Received pong from server')

@sio.on('error')
def on_error(data):
    print(f'❌ Server error: {data}')

@sio.on('message')
def on_message(data):
    print(f'📨 Received message: {data}')

# Ping function for connection health
def ping_server():
    """Send periodic pings to server"""
    while connected:
        try:
            if connected:
                sio.emit('ping')
                time.sleep(30)  # Ping every 30 seconds
            else:
                break
        except Exception as e:
            print(f'❌ Error sending ping: {e}')
            break

# Graceful shutdown handler
def signal_handler(signum, frame):
    global connected
    print('\n🛑 Shutting down client...')
    connected = False
    
    try:
        if sio.connected:
            sio.disconnect()
    except:
        pass
    
    print('✅ Client shut down gracefully')
    sys.exit(0)

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    global connected
    
    print('\n📝 Instructions:')
    print('- This client will automatically connect and set a username')
    print('- Press Ctrl+C to disconnect')
    print('- Check the /getConnectedUsers endpoint while this is running')
    print(f'- Usage: python test_client.py [username]')
    print('\n⏳ Attempting connection...')
    
    try:
        # Connect to server
        sio.connect(SERVER_URL)
        
        # Start ping thread
        ping_thread = threading.Thread(target=ping_server, daemon=True)
        ping_thread.start()
        
        # Keep the client running
        while connected:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                signal_handler(signal.SIGINT, None)
                
    except socketio.exceptions.ConnectionError as e:
        print(f'❌ Failed to connect to server: {e}')
        print('💡 Make sure the Flask server is running on http://127.0.0.1:8586')
        sys.exit(1)
    except Exception as e:
        print(f'❌ Unexpected error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
