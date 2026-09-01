#!/usr/bin/env python3
"""
Main Connection Server - Port 8586
Handles client Socket.IO connections and stores user data.
Provides internal API for the separate API server to query user data.
"""

import os
import signal
import sys
import uuid
from datetime import datetime
from typing import Dict, Any
import logging
import json

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
app.config['SECRET_KEY'] = 'main-server-secret-key'
CORS(app)

# SocketIO configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    async_mode='threading'
)

# Port configuration
PORT = 8586
HOST = '127.0.0.1'
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

# Internal API Endpoints (for API server to query)

@app.route('/internal/users', methods=['GET'])
def get_internal_users():
    """
    Internal endpoint for API server to get connected users
    This endpoint is called by the separate API server on port 5403
    """
    try:
        users = []
        for user_id, user_info in connected_users.items():
            users.append({
                'id': user_info['id'],
                'username': user_info['username'],
                'ipAddress': user_info['ipAddress'],
                'connectedSince': user_info['connectedSince']
            })
        
        logger.info(f"Internal API: Returned {len(users)} users to API server")
        return jsonify({'users': users}), 200
        
    except Exception as e:
        logger.error(f"Error in internal API: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/internal/status', methods=['GET'])
def get_internal_status():
    """Internal status endpoint for API server"""
    try:
        uptime = datetime.now().timestamp() - app.config.get('START_TIME', datetime.now().timestamp())
        
        status_info = {
            'status': 'running',
            'server_type': 'main_connection_server',
            'port': PORT,
            'host': HOST,
            'connectedUsers': len(connected_users),
            'uptime': uptime,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        return jsonify(status_info), 200
    except Exception as e:
        logger.error(f"Error in internal status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Socket.IO Event Handlers

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
            'session_id': request.sid
        }
        
        connected_users[user_id] = user_info
        
        logger.info(f"New client connected: {user_id} from {ip_address}")
        logger.info(f"Total connected users: {len(connected_users)}")
        
        # Send welcome message to client
        emit('welcome', {
            'type': 'welcome',
            'message': 'Connected successfully to main server',
            'userId': user_id,
            'assignedUsername': username,
            'server': 'main_connection_server',
            'port': PORT
        })
        
    except Exception as e:
        logger.error(f"Error handling connection: {e}")
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

@socketio.on('ping')
def handle_ping():
    """Handle ping requests for connection health"""
    try:
        emit('pong', {'type': 'pong', 'server': 'main_connection_server'})
    except Exception as e:
        logger.error(f"Error handling ping: {e}")

@socketio.on('message')
def handle_message(data):
    """Handle generic messages"""
    try:
        logger.info(f"Received message: {data}")
        
        if isinstance(data, dict):
            msg_type = data.get('type')
            
            if msg_type == 'setUsername' and 'username' in data:
                handle_set_username(data)
            elif msg_type == 'ping':
                handle_ping()
            else:
                # Echo back unknown message types
                emit('message', {
                    'type': 'echo',
                    'originalMessage': data,
                    'server': 'main_connection_server',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
        
    except Exception as e:
        logger.error(f"Error handling message: {e}")
        emit('error', {'error': 'Failed to process message'})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': f'Route {request.method} {request.path} not found on main server'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'Internal server error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

def signal_handler(signum, frame):
    """Handle graceful shutdown"""
    logger.info('\n[-] Shutting down main server...')
    
    # Disconnect all clients
    for user_id in list(connected_users.keys()):
        try:
            user_info = connected_users[user_id]
            socketio.disconnect(user_info.get('session_id'))
        except:
            pass
    
    connected_users.clear()
    logger.info('[+] Main server shut down gracefully')
    sys.exit(0)

if __name__ == '__main__':
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Store start time for uptime calculation
    app.config['START_TIME'] = datetime.now().timestamp()
    
    # Print startup information
    print('=' * 60)
    print('Main Connection Server started successfully!')
    print(f'Purpose: Handle client Socket.IO connections')
    print(f'Socket.IO Server: http://{HOST}:{PORT}')
    print(f'Internal API: http://{HOST}:{PORT}/internal/users')
    print(f'Clients connect here for real-time communication')
    print('=' * 60)
    print('Waiting for client connections...')
    
    try:
        # Start the Flask-SocketIO server
        socketio.run(
            app,
            host=HOST,
            port=PORT,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Failed to start main server: {e}")
        sys.exit(1)
