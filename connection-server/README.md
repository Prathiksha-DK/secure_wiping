# Connection Server

A Python Flask backend server that manages client connections and provides a REST API endpoint to retrieve connected users information.

## Features

- **Socket.IO Server**: Handles client connections with real-time communication using Flask-SocketIO
- **REST API**: Provides `/getConnectedUsers` endpoint as specified
- **User Management**: Tracks connected users with unique IDs, usernames, IP addresses, and connection timestamps
- **Health Monitoring**: Additional endpoints for server status and health checks
- **Graceful Shutdown**: Proper cleanup of connections and resources
- **Cross-Origin Support**: CORS enabled for web client connections

## Installation

1. Navigate to the connection-server directory:
```bash
cd E:\SecureWiping\connection-server
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Running the Server

### Development mode:
```bash
python app.py
```

### Using Flask's development server:
```bash
flask --app app run --port 8586 --host localhost
```

The server will start on port **8586** as specified.

## API Endpoints

### Main Endpoint

#### GET `/getConnectedUsers`
- **Purpose**: Retrieve a list of users currently connected to the server
- **Port**: 8586
- **Full URL**: `http://localhost:8586/getConnectedUsers`
- **Method**: GET
- **Body**: None required

**Success Response (200 OK):**
```json
{
  "users": [
    {
      "id": "unique-user-id-1",
      "username": "Worker1",
      "ipAddress": "192.168.1.101",
      "connectedSince": "2024-08-01T10:00:00Z"
    },
    {
      "id": "unique-user-id-2",
      "username": "Worker2",
      "ipAddress": "192.168.1.102",
      "connectedSince": "2024-08-01T10:05:00Z"
    }
  ]
}
```

**Error Response (500):**
```json
{
  "error": "Internal server error while retrieving connected users"
}
```

### Additional Endpoints

#### GET `/status`
Returns server status and statistics.

#### GET `/health`
Simple health check endpoint.

## Socket.IO Connection

Clients can connect to the Socket.IO server at `http://localhost:8586` to establish a persistent connection.

### Socket.IO Events

#### Client to Server:
- `setUsername`: Update the user's display name
- `ping`: Health check ping
- `message`: Generic message handling

#### Server to Client:
- `welcome`: Initial connection confirmation with user ID
- `usernameUpdated`: Username change confirmation
- `pong`: Response to ping
- `error`: Error messages
- `message`: Generic message responses

### Example Socket.IO Messages:

**Set Username:**
```python
sio.emit('setUsername', {'username': 'MyCustomName'})
```

**Ping:**
```python
sio.emit('ping')
```

## Testing the Server

### Test Client
A Python test client is provided to simulate connections:

```bash
python test_client.py [optional-username]
```

Examples:
```bash
python test_client.py "Alice"
python test_client.py "Bob"
python test_client.py  # Uses auto-generated username
```

### Manual Testing with curl

Test the main endpoint:
```bash
curl http://localhost:8586/getConnectedUsers
```

Test server status:
```bash
curl http://localhost:8586/status
```

Test health check:
```bash
curl http://localhost:8586/health
```

## Server Output

When running, you'll see output like:
```
==================================================
🚀 Connection Server started successfully!
📡 HTTP Server: http://localhost:8586
🔌 WebSocket Server: ws://localhost:8586
📊 Main endpoint: http://localhost:8586/getConnectedUsers
==================================================
Waiting for client connections...
```

## User Connection Flow

1. Client connects via Socket.IO to `http://localhost:8586`
2. Server assigns unique ID and default username (`Worker1`, `Worker2`, etc.)
3. Server sends `welcome` event with user ID and assigned username
4. Server stores user info with IP address and connection timestamp
5. Client can optionally update username via `setUsername` event
6. User info is available via `/getConnectedUsers` endpoint
7. On disconnect, user is automatically removed from connected users list

## Error Handling

- Invalid routes return 404 with error message
- Server errors return 500 with error message
- WebSocket errors are logged and connections cleaned up
- Graceful shutdown on SIGINT/SIGTERM

## Dependencies

- **Flask**: Python web framework for REST API endpoints
- **Flask-SocketIO**: Socket.IO integration for Flask
- **Flask-CORS**: Cross-origin resource sharing support
- **python-socketio**: Socket.IO server implementation
- **eventlet**: Async networking library for Socket.IO
- **websocket-client**: WebSocket client library (for test client)
- **uuid**: Unique ID generation

## Architecture

- **HTTP Server**: Flask framework for REST API endpoints
- **Socket.IO Server**: Flask-SocketIO for real-time client connections
- **In-Memory Storage**: Dictionary-based storage for connected users (can be extended to use database)
- **IP Address Detection**: Handles both IPv4 and IPv6 addresses with proper cleanup
- **Event-Driven**: Asynchronous event handling using eventlet
