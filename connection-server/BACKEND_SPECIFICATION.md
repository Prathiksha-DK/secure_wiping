# Backend Server Specification for Client Connection Management

## Overview
You need to create a backend server that manages client connections and provides a REST API endpoint to retrieve connected user information. The server should support both HTTP REST API and real-time WebSocket/Socket.IO connections.

## Server Requirements

### Network Configuration
- **Host/IP Address**: `192.168.137.191`
- **Port**: `8586`
- **Protocol**: HTTP with Socket.IO support
- **CORS**: Enable cross-origin requests from any origin

### Core Functionality
1. **Client Connection Management**: Track connected clients with real-time WebSocket/Socket.IO connections
2. **User Data Storage**: Store user information in memory (can be extended to database)
3. **REST API Endpoints**: Provide HTTP endpoints for querying connected users
4. **Real-time Communication**: Handle Socket.IO events for client interaction

## API Endpoints

### 1. Main Endpoint: GET /getConnectedUsers
- **URL**: `http://192.168.137.191:8586/getConnectedUsers`
- **Method**: GET
- **Purpose**: Retrieve list of currently connected users
- **Request Body**: None (simple GET request)

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

### 2. Status Endpoint: GET /status
- **URL**: `http://192.168.137.191:8586/status`
- **Purpose**: Server health and statistics

**Response:**
```json
{
  "status": "running",
  "port": 8586,
  "connectedUsers": 2,
  "uptime": 123.45,
  "timestamp": "2024-08-01T10:00:00Z"
}
```

### 3. Health Check: GET /health
- **URL**: `http://192.168.137.191:8586/health`
- **Response**: `{"status": "healthy"}`

## WebSocket/Socket.IO Events

### Client Connection URL
- **Socket.IO URL**: `http://192.168.137.191:8586`

### Server-to-Client Events
1. **welcome**: Sent when client connects
   ```json
   {
     "type": "welcome",
     "message": "Connected successfully",
     "userId": "unique-user-id",
     "assignedUsername": "Worker1"
   }
   ```

2. **usernameUpdated**: Confirms username change
   ```json
   {
     "type": "usernameUpdated", 
     "username": "NewUsername"
   }
   ```

3. **pong**: Response to ping (health check)
   ```json
   {"type": "pong"}
   ```

4. **error**: Error messages
   ```json
   {"error": "Error description"}
   ```

### Client-to-Server Events
1. **setUsername**: Update username
   ```json
   {"username": "NewUsername"}
   ```

2. **ping**: Health check ping
   ```json
   {"type": "ping"}
   ```

## User Data Structure
Each connected user should be stored with:
```json
{
  "id": "unique-uuid-v4",
  "username": "Worker1", // Default: Worker1, Worker2, etc.
  "ipAddress": "client-ip-address",
  "connectedSince": "ISO-8601-timestamp",
  "session_id": "socket-session-id"
}
```

## Connection Flow
1. Client connects via Socket.IO to `http://192.168.137.191:8586`
2. Server generates unique UUID for user
3. Server assigns default username (`Worker1`, `Worker2`, etc.)
4. Server detects client IP address
5. Server stores connection timestamp in ISO 8601 format
6. Server sends `welcome` event with user details
7. Client can optionally update username via `setUsername` event  
8. User information is immediately available via `/getConnectedUsers` endpoint
9. On disconnect, user is automatically removed from active users list

## Technical Implementation Notes

### IP Address Detection
- Check `HTTP_X_FORWARDED_FOR` header (proxy)
- Check `HTTP_X_REAL_IP` header (nginx)
- Fall back to `REMOTE_ADDR`
- Clean IPv6-mapped IPv4 addresses (remove `::ffff:` prefix)

### Username Generation
- Default usernames: `Worker1`, `Worker2`, `Worker3`, etc.
- Based on current number of connected users + 1

### Error Handling
- 404 for undefined routes
- 500 for internal server errors
- WebSocket connection errors should be logged and cleaned up
- Graceful shutdown on SIGINT/SIGTERM

### Data Storage
- Use in-memory storage (dictionary/map/hash table)
- Key: User UUID
- Value: User information object
- Automatically clean up on disconnect

## Framework Recommendations

### Python (Recommended)
- **Flask** + **Flask-SocketIO** + **eventlet**
- Dependencies: `flask`, `flask-socketio`, `flask-cors`, `python-socketio`, `eventlet`

### Node.js Alternative  
- **Express** + **Socket.IO**
- Dependencies: `express`, `socket.io`, `cors`, `uuid`

### Other Languages
- **Go**: Gin + Socket.IO equivalent
- **Java**: Spring Boot + WebSocket
- **C#**: ASP.NET Core + SignalR

## Testing
Create a test client that:
1. Connects to Socket.IO server
2. Sets a custom username
3. Sends periodic pings
4. Handles all server events
5. Allows testing the `/getConnectedUsers` endpoint

## Security Considerations
- Enable CORS for web clients
- Input validation for username updates
- Rate limiting (optional)
- Connection limits (optional)

## Example URLs for Testing
- Main endpoint: `http://192.168.137.191:8586/getConnectedUsers`
- Status: `http://192.168.137.191:8586/status`
- Health: `http://192.168.137.191:8586/health`
- Socket.IO: `http://192.168.137.191:8586`

## Expected Behavior
- Server binds to `192.168.137.191:8586`
- Accepts connections from any client on the network
- Tracks real-time user connections
- Provides instant user list via REST API
- Handles multiple simultaneous connections
- Automatically manages connection lifecycle
