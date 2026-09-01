#!/usr/bin/env python3
"""
API Server - Port 5403
Provides REST API endpoints to query connected users from the main server.
This server communicates with the main server on port 8586 to get user data.
"""

import os
import signal
import sys
import requests
from datetime import datetime
import logging
import json
from typing import Dict, Any

from flask import Flask, jsonify, request
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'api-server-secret-key'
CORS(app)

# Port and host configuration
PORT = 5403
HOST = '127.0.0.1'
MAIN_SERVER_URL = f'http://{HOST}:8586'

def query_main_server(endpoint):
    """Helper function to query the main server"""
    try:
        url = f"{MAIN_SERVER_URL}/internal/{endpoint}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            return response.json(), 200
        else:
            logger.error(f"Main server returned status {response.status_code}")
            return {'error': f'Main server error: {response.status_code}'}, response.status_code
            
    except requests.exceptions.ConnectionError:
        logger.error("Could not connect to main server")
        return {'error': 'Main server is not reachable. Please ensure it is running on port 8586.'}, 503
    except requests.exceptions.Timeout:
        logger.error("Request to main server timed out")
        return {'error': 'Main server request timed out'}, 504
    except Exception as e:
        logger.error(f"Error querying main server: {e}")
        return {'error': 'Failed to communicate with main server'}, 500

# REST API Endpoints

@app.route('/getConnectedUsers', methods=['GET'])
def get_connected_users():
    """
    Main endpoint: GET /getConnectedUsers
    Queries the main server and returns the list of connected users
    """
    try:
        logger.info("Received request for connected users")
        
        # Query the main server
        data, status_code = query_main_server('users')
        
        if status_code == 200:
            logger.info(f"Successfully retrieved {len(data.get('users', []))} users from main server")
            return jsonify(data), 200
        else:
            logger.error(f"Failed to get users from main server: {data}")
            return jsonify(data), status_code
            
    except Exception as e:
        logger.error(f"Error in /getConnectedUsers: {e}")
        return jsonify({'error': 'Internal server error while retrieving connected users'}), 500

@app.route('/status', methods=['GET'])
def get_status():
    """API server status endpoint"""
    try:
        uptime = datetime.now().timestamp() - app.config.get('START_TIME', datetime.now().timestamp())
        
        # Try to get main server status
        main_server_status, main_status_code = query_main_server('status')
        
        status_info = {
            'status': 'running',
            'server_type': 'api_server',
            'port': PORT,
            'host': HOST,
            'uptime': uptime,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'main_server': {
                'url': MAIN_SERVER_URL,
                'status': 'reachable' if main_status_code == 200 else 'unreachable',
                'details': main_server_status if main_status_code == 200 else None
            }
        }
        
        return jsonify(status_info), 200
    except Exception as e:
        logger.error(f"Error in /status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Basic health check
        health_status = {'status': 'healthy', 'server_type': 'api_server'}
        
        # Check if main server is reachable
        try:
            response = requests.get(f"{MAIN_SERVER_URL}/internal/status", timeout=3)
            if response.status_code == 200:
                health_status['main_server_connection'] = 'ok'
            else:
                health_status['main_server_connection'] = 'error'
                health_status['status'] = 'degraded'
        except:
            health_status['main_server_connection'] = 'unreachable'
            health_status['status'] = 'degraded'
        
        return jsonify(health_status), 200
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return jsonify({'error': 'Health check failed'}), 500

@app.route('/info', methods=['GET'])
def get_info():
    """Information endpoint about this API server"""
    return jsonify({
        'server_type': 'api_server',
        'purpose': 'Query connected users from main server',
        'port': PORT,
        'host': HOST,
        'main_server_url': MAIN_SERVER_URL,
        'endpoints': {
            'get_users': '/getConnectedUsers',
            'status': '/status',
            'health': '/health',
            'info': '/info'
        },
        'usage': {
            'description': 'Use this server to get connected user information',
            'main_endpoint': f'http://{HOST}:{PORT}/getConnectedUsers',
            'connects_to': f'Main server on {MAIN_SERVER_URL}'
        }
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': f'Route {request.method} {request.path} not found on API server',
        'available_endpoints': ['/getConnectedUsers', '/status', '/health', '/info']
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'Internal server error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

def signal_handler(signum, frame):
    """Handle graceful shutdown"""
    logger.info('\n[-] Shutting down API server...')
    logger.info('[+] API server shut down gracefully')
    sys.exit(0)

if __name__ == '__main__':
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Store start time for uptime calculation
    app.config['START_TIME'] = datetime.now().timestamp()
    
    # Print startup information
    print('=' * 60)
    print('API Server started successfully!')
    print(f'Purpose: Provide REST API for connected users')
    print(f'HTTP Server: http://{HOST}:{PORT}')
    print(f'Main endpoint: http://{HOST}:{PORT}/getConnectedUsers')
    print(f'Connects to main server: {MAIN_SERVER_URL}')
    print('=' * 60)
    print('Ready to serve API requests...')
    
    try:
        # Check if main server is reachable on startup
        try:
            response = requests.get(f"{MAIN_SERVER_URL}/internal/status", timeout=3)
            if response.status_code == 200:
                print(f'[+] Successfully connected to main server on {MAIN_SERVER_URL}')
            else:
                print(f'[!] Warning: Main server responded with status {response.status_code}')
        except:
            print(f'[!] Warning: Could not reach main server on {MAIN_SERVER_URL}')
            print('   Make sure the main server is running on port 8586')
        
        # Start the Flask server
        app.run(
            host=HOST,
            port=PORT,
            debug=False,
            use_reloader=False
        )
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        sys.exit(1)
