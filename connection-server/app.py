#!/usr/bin/env python3
"""
Flask Connection Server
A Python Flask backend server that manages client connections and provides 
a REST API endpoint to retrieve connected users information.
"""

import os
import signal
import sys
import uuid
from datetime import datetime
from typing import Dict, Any
import logging

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit, disconnect
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)

# SocketIO configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    async_mode='eventlet'
)

# Port configuration
PORT = 8586

# Store for connected users
connected_users: Dict[str, Dict[str, Any]] = {}

def get_client_ip():
    """Helper function to get client IP address"""
    # Try to get the real IP address from various headers
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        # If behind a proxy
        ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        # If behind nginx
        ip = request.environ['HTTP_X_REAL_IP']
    elif request.environ.get('REMOTE_ADDR'):
        # Direct connection
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = '127.0.0.1'
    
    # Clean IPv6 mapped IPv4 addresses
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    
    return ip

def generate_username():
    """Generate a default username for new users"""
    return f"Worker{len(connected_users) + 1}"

# REST API Endpoints

@app.route('/getConnectedUsers', methods=['GET'])
def get_connected_users():
    """
    Main endpoint: GET /getConnectedUsers
    Returns a list of currently connected users
    """
    try:
        users = []
        for user_id, user_info in connected_users.items():
            users.append({
                'id': user_info['id'],
                'username': user_info['username'],
                'ipAddress': user_info['ipAddress'],
                'connectedSince': user_info['connectedSince'],
                'devices': user_info.get('devices', [])
            })
        
        response = {'users': users}
        logger.info(f"GET /getConnectedUsers - Returned {len(users)} users")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in /getConnectedUsers: {e}")
        return jsonify({'error': 'Internal server error while retrieving connected users'}), 500

@app.route('/status', methods=['GET'])
def get_status():
    """Server status endpoint"""
    try:
        uptime = datetime.now().timestamp() - app.config.get('START_TIME', datetime.now().timestamp())
        
        status_info = {
            'status': 'running',
            'port': PORT,
            'connectedUsers': len(connected_users),
            'uptime': uptime,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        return jsonify(status_info), 200
    except Exception as e:
        logger.error(f"Error in /status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Device API endpoint - returns server device information"""
    try:
        # Sample server device data - in real implementation, this would query actual system devices
        # This matches the format expected by the client
        server_devices = [
            {
                'name': 'KINGSTON OM8SFP4512P-AH',
                'type': 'SSD',
                'size': '476.9 GB',
                'health': 'Healthy',
                'id': 'device_001'
            },
            {
                'name': 'NVMe Micron_2450_MTFDKBA512TFK',
                'type': 'SSD', 
                'size': '476.9 GB',
                'health': 'Healthy (100%)',
                'id': 'device_002'
            }
        ]
        
        logger.info(f"GET /api/devices - Returned {len(server_devices)} server devices")
        return jsonify({'devices': server_devices, 'count': len(server_devices)}), 200
        
    except Exception as e:
        logger.error(f"Error in /api/devices: {e}")
        return jsonify({'error': 'Internal server error while retrieving devices'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': f'Route {request.method} {request.path} not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'Internal server error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

# WebSocket Event Handlers

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connections"""
    try:
        user_id = str(uuid.uuid4())
        ip_address = get_client_ip()
        connected_since = datetime.utcnow().isoformat() + 'Z'
        username = generate_username()
        
        # Store user connection info
        user_info = {
            'id': user_id,
            'username': username,
            'ipAddress': ip_address,
            'connectedSince': connected_since,
            'session_id': request.sid,
            'devices': []  # Initialize empty device list
        }
        
        connected_users[user_id] = user_info
        
        logger.info(f"🔌 New client connected: {user_id} from {ip_address}")
        logger.info(f"📊 Total connected users: {len(connected_users)}")
        logger.info(f"🆔 Session ID: {request.sid}")
        
        # Send welcome message to client
        emit('welcome', {
            'type': 'welcome',
            'message': 'Connected successfully',
            'userId': user_id,
            'assignedUsername': username
        })
        
    except Exception as e:
        logger.error(f"❌ Error handling connection: {e}")
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnections"""
    try:
        # Find and remove user by session ID
        user_to_remove = None
        for user_id, user_info in connected_users.items():
            if user_info.get('session_id') == request.sid:
                user_to_remove = user_id
                break
        
        if user_to_remove:
            del connected_users[user_to_remove]
            logger.info(f"Client disconnected: {user_to_remove}")
            logger.info(f"Total connected users: {len(connected_users)}")
        
    except Exception as e:
        logger.error(f"Error handling disconnection: {e}")

@socketio.on('setUsername')
def handle_set_username(data):
    """Handle username updates"""
    try:
        if not isinstance(data, dict) or 'username' not in data:
            emit('error', {'error': 'Invalid username data'})
            return
        
        new_username = data['username']
        if not new_username or not isinstance(new_username, str):
            emit('error', {'error': 'Username must be a non-empty string'})
            return
        
        # Find user by session ID
        user_to_update = None
        for user_id, user_info in connected_users.items():
            if user_info.get('session_id') == request.sid:
                user_to_update = user_id
                break
        
        if user_to_update:
            connected_users[user_to_update]['username'] = new_username
            logger.info(f"User {user_to_update} updated username to: {new_username}")
            
            # Acknowledge username change
            emit('usernameUpdated', {
                'type': 'usernameUpdated',
                'username': new_username
            })
        else:
            emit('error', {'error': 'User not found'})
            
    except Exception as e:
        logger.error(f"Error updating username: {e}")
        emit('error', {'error': 'Failed to update username'})

@socketio.on('setDevices')
def handle_set_devices(data, callback=None):
    """Handle device list updates from clients"""
    try:
        logger.info(f"📥 Received setDevices request from session {request.sid}")
        logger.info(f"📝 Data received: {data}")
        logger.info(f"🔄 Callback provided: {callback is not None}")
        
        if not isinstance(data, dict) or 'devices' not in data:
            error_msg = {'status': 'error', 'message': 'Invalid device data'}
            if callback:
                callback(error_msg)
            else:
                emit('error', error_msg)
            return
        
        devices = data['devices']
        if not isinstance(devices, list):
            error_msg = {'status': 'error', 'message': 'Devices must be a list'}
            if callback:
                callback(error_msg)
            else:
                emit('error', error_msg)
            return
        
        # Find user by session ID
        user_to_update = None
        for user_id, user_info in connected_users.items():
            if user_info.get('session_id') == request.sid:
                user_to_update = user_id
                break
        
        if user_to_update:
            connected_users[user_to_update]['devices'] = devices
            device_count = len(devices)
            logger.info(f"User {user_to_update} updated device list: {device_count} devices")
            for i, device in enumerate(devices, 1):
                logger.info(f"  {i}. {device.get('name', 'Unknown')} - {device.get('type', 'Unknown')} - {device.get('size', 'Unknown')}")
            
            # Send acknowledgment
            response = {
                'status': 'success',
                'message': 'Device list updated successfully',
                'deviceCount': device_count,
                'devices': devices
            }
            
            if callback:
                callback(response)
            else:
                emit('devicesUpdated', response)
        else:
            error_msg = {'status': 'error', 'message': 'User not found'}
            if callback:
                callback(error_msg)
            else:
                emit('error', error_msg)
            
    except Exception as e:
        logger.error(f"Error updating device list: {e}")
        error_msg = {'status': 'error', 'message': 'Failed to update device list'}
        if callback:
            callback(error_msg)
        else:
            emit('error', error_msg)

@socketio.on('ping')
def handle_ping():
    """Handle ping requests for connection health"""
    try:
        emit('pong', {'type': 'pong'})
    except Exception as e:
        logger.error(f"Error handling ping: {e}")

@socketio.on('deviceList')
def handle_device_list(data, callback=None):
    """Handle device list events (alternative event name)"""
    logger.info(f"Received deviceList event: {data}")
    return handle_set_devices(data, callback)

@socketio.on('sendDevices')
def handle_send_devices(data, callback=None):
    """Handle sendDevices events (alternative event name)"""
    logger.info(f"📤 Received sendDevices event: {data}")
    return handle_set_devices(data, callback)

@socketio.on('devices')
def handle_devices(data, callback=None):
    """Handle devices events"""
    logger.info(f"📱 Received devices event: {data}")
    return handle_set_devices(data, callback)

@socketio.on('device_data')
def handle_device_data(data, callback=None):
    """Handle device_data events"""
    logger.info(f"💾 Received device_data event: {data}")
    return handle_set_devices(data, callback)

@socketio.on('worker_devices')
def handle_worker_devices(data, callback=None):
    """Handle worker_devices events"""
    logger.info(f"👷 Received worker_devices event: {data}")
    return handle_set_devices(data, callback)

# Catch-all event handler to debug unknown events
@socketio.on_error_default
def default_error_handler(e):
    logger.error(f"❌ Socket.IO error: {e}")
    
# This will catch all events that don't have specific handlers
@socketio.event
def catch_all_event(event, *args):
    """Catch all unknown events for debugging"""
    logger.info(f"🔍 Unknown event received: '{event}' with args: {args}")
    if len(args) > 0:
        data = args[0]
        callback = args[1] if len(args) > 1 and callable(args[1]) else None
        
        # Try to handle it as a device event if it contains device data
        if isinstance(data, dict) and 'devices' in data:
            logger.info(f"🔄 Attempting to handle as device event")
            return handle_set_devices(data, callback)
    
    # Return acknowledgment for any unknown event
    return {'status': 'received', 'event': event, 'message': 'Event received but not handled'}

@socketio.on('message')
def handle_message(data):
    """Handle generic messages"""
    try:
        logger.info(f"Received message: {data}")
        
        if isinstance(data, dict):
            msg_type = data.get('type')
            
            if msg_type == 'setUsername' and 'username' in data:
                handle_set_username(data)
            elif msg_type == 'setDevices' and 'devices' in data:
                handle_set_devices(data)
            elif msg_type == 'deviceList' and 'devices' in data:
                handle_set_devices(data)
            elif msg_type == 'ping':
                handle_ping()
            else:
                # Echo back unknown message types
                emit('message', {
                    'type': 'echo',
                    'originalMessage': data,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
        
    except Exception as e:
        logger.error(f"Error handling message: {e}")
        emit('error', {'error': 'Failed to process message'})

def signal_handler(signum, frame):
    """Handle graceful shutdown"""
    logger.info('\n🛑 Shutting down server...')
    
    # Disconnect all clients
    for user_id in list(connected_users.keys()):
        try:
            user_info = connected_users[user_id]
            socketio.disconnect(user_info.get('session_id'))
        except:
            pass
    
    connected_users.clear()
    logger.info('✅ Server shut down gracefully')
    sys.exit(0)

if __name__ == '__main__':
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Store start time for uptime calculation
    app.config['START_TIME'] = datetime.now().timestamp()
    
    # Print startup information
    print('=' * 50)
    print('🚀 Connection Server started successfully!')
    print(f'📡 HTTP Server: http://192.168.137.54:{PORT}')
    print(f'🔌 Socket.IO Server: http://192.168.137.54:{PORT}')
    print(f'📊 Main endpoint: http://192.168.137.54:{PORT}/getConnectedUsers')
    print('=' * 50)
    print('Waiting for client connections...')
    
    try:
        # Start the Flask-SocketIO server
        socketio.run(
            app,
            host='192.168.137.222',
            port=PORT,
            debug=False,
            use_reloader=False
        )
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
