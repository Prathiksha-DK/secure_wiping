# AI Backend Implementation Instructions

## Quick Summary
Create a backend server that manages client connections and provides a REST API to retrieve connected user information.

## Server Configuration
- **IP Address**: `192.168.137.191`
- **Port**: `8586`  
- **Protocol**: HTTP + Socket.IO
- **CORS**: Enable all origins

## Required Endpoint
**GET /getConnectedUsers**
- URL: `http://192.168.137.191:8586/getConnectedUsers`
- Returns JSON with array of connected users

**Response Format:**
```json
{
  "users": [
    {
      "id": "unique-uuid-v4",
      "username": "Worker1", 
      "ipAddress": "client-ip",
      "connectedSince": "2024-08-01T10:00:00Z"
    }
  ]
}
```

## Socket.IO Implementation
- Connection URL: `http://192.168.137.191:8586`
- Auto-assign usernames: Worker1, Worker2, Worker3...
- Track: UUID, username, IP, connection timestamp
- Events: welcome, setUsername, ping/pong, disconnect
- Store users in memory, remove on disconnect

## User Flow
1. Client connects via Socket.IO → Server assigns UUID + Worker# username
2. Server stores user data (id, username, IP, timestamp)  
3. /getConnectedUsers returns current user list
4. Client can update username via setUsername event
5. Auto-cleanup on disconnect

## Additional Endpoints (Optional)
- GET /status - Server statistics
- GET /health - Health check

## Tech Stack Suggestions
- **Python**: Flask + Flask-SocketIO + eventlet
- **Node.js**: Express + Socket.IO
- **Go**: Gin + WebSocket library
- **Any language with HTTP server + WebSocket/Socket.IO support

## Key Points
- Bind to IP `192.168.137.191` port `8586`
- Real-time connection tracking
- JSON API responses
- Cross-origin requests enabled
- In-memory user storage
- UUID generation for unique user IDs

This creates a network-accessible server that other devices can connect to for real-time user management.
