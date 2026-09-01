# Dual Server Architecture

## Overview
This system consists of two separate servers working together:

1. **Main Server (Port 8586)**: Handles client Socket.IO connections
2. **API Server (Port 5403)**: Provides REST API to query connected users

## Architecture Diagram
```
Clients → Main Server (8586) ← API Server (5403) ← API Requests
          [Socket.IO]           [Internal HTTP]      [REST API]
          [User Storage]
```

## Server Details

### 🎯 Main Server (Port 8586)
- **Purpose**: Handle client connections via Socket.IO
- **URL**: `http://192.168.137.191:8586`
- **File**: `main_server.py`
- **Features**:
  - Real-time client connections
  - User data storage (in-memory)
  - Auto-assigned usernames (Worker1, Worker2, etc.)
  - Socket.IO events (welcome, setUsername, ping/pong)
  - Internal API for data sharing

### 🔗 API Server (Port 5403)  
- **Purpose**: Provide REST API to query connected users
- **URL**: `http://192.168.137.191:5403`
- **File**: `api_server.py`
- **Features**:
  - REST API endpoints
  - Queries main server for user data
  - Status and health monitoring
  - CORS enabled for web clients

## Key Endpoints

### API Server (5403) - Public Endpoints
- `GET /getConnectedUsers` - **Main endpoint** to get connected users
- `GET /status` - Server status and main server connectivity
- `GET /health` - Health check
- `GET /info` - Server information

### Main Server (8586) - Internal API
- `GET /internal/users` - Used by API server to get user data
- `GET /internal/status` - Internal status for API server

## Usage

### Starting Both Servers
```bash
# Option 1: Use the startup script
python start_servers.py

# Option 2: Start manually (in separate terminals)
python main_server.py    # Terminal 1
python api_server.py     # Terminal 2
```

### Client Connections
Clients should connect to the **Main Server** for Socket.IO:
```javascript
// JavaScript client
const socket = io('http://192.168.137.191:8586');
```

```python
# Python client  
import socketio
sio = socketio.Client()
sio.connect('http://192.168.137.191:8586')
```

### Getting Connected Users
Query the **API Server** for user information:
```bash
# cURL
curl http://192.168.137.191:5403/getConnectedUsers

# PowerShell
Invoke-RestMethod -Uri "http://192.168.137.191:5403/getConnectedUsers"
```

```python
# Python
import requests
response = requests.get('http://192.168.137.191:5403/getConnectedUsers')
users = response.json()
```

## Response Format
```json
{
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "Worker1",
      "ipAddress": "192.168.1.100", 
      "connectedSince": "2024-08-01T10:00:00Z"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "username": "Alice",
      "ipAddress": "192.168.1.101",
      "connectedSince": "2024-08-01T10:05:00Z" 
    }
  ]
}
```

## Testing

### Test Client Connection
```bash
python test_client.py "MyUsername"
```

### Test API Endpoints
```bash
# Test main endpoint
curl http://192.168.137.191:5403/getConnectedUsers

# Test server status
curl http://192.168.137.191:5403/status

# Test health
curl http://192.168.137.191:5403/health

# Get server info
curl http://192.168.137.191:5403/info
```

## Flow Diagram
```
1. Client connects to Main Server (8586) via Socket.IO
2. Main Server assigns UUID, username, stores user data
3. API request comes to API Server (5403)
4. API Server queries Main Server's internal endpoint
5. Main Server returns user data
6. API Server responds with user list
```

## Benefits of This Architecture
- **Separation of Concerns**: Connection handling vs API serving
- **Scalability**: Each server can be scaled independently  
- **Reliability**: If API server goes down, client connections remain
- **Security**: Internal communication between servers
- **Flexibility**: Easy to add more API servers or change API logic

## Network Ports Summary
- **8586**: Main server - Client connections (Socket.IO)
- **5403**: API server - REST API queries (HTTP)

## Dependencies
Same as before:
```bash
pip install flask flask-socketio flask-cors python-socketio eventlet requests
```

## Files Created
- `main_server.py` - Main Socket.IO server
- `api_server.py` - REST API server  
- `start_servers.py` - Startup script for both servers
- `test_client.py` - Test client (connects to 8586)
- `DUAL_SERVER_README.md` - This documentation
