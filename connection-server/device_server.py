#!/usr/bin/env python3
"""
Device API Server - Runs on port 9758
Provides device information for clients that expect it on this port
"""
from flask import Flask, jsonify
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Device API endpoint - returns server device information"""
    try:
        # Sample server device data matching your client's expected format
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
        
        response = {
            'devices': server_devices, 
            'count': len(server_devices),
            'status': 'success'
        }
        
        logger.info(f"📱 GET /api/devices - Returned {len(server_devices)} devices")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"❌ Error in /api/devices: {e}")
        return jsonify({'error': 'Internal server error while retrieving devices'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'device-api'}), 200

if __name__ == '__main__':
    print("=" * 70)
    print("🔧 Device API Server starting...")
    print("📡 Listening on: http://192.168.137.191:9758")
    print("📊 Device endpoint: http://192.168.137.191:9758/api/devices")
    print("=" * 70)
    
    try:
        app.run(
            host='192.168.137.191',
            port=9758,
            debug=False
        )
    except Exception as e:
        logger.error(f"❌ Failed to start device server: {e}")
