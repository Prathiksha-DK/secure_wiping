# Server Connection Information

## Server Details
- **Host**: `192.168.137.191` (network accessible)
- **Port**: `8586`
- **Protocol**: HTTP with Socket.IO

## Client Connection URLs

### For HTTP REST API:
- **Base URL**: `http://192.168.137.191:8586`
- **Main Endpoint**: `http://192.168.137.191:8586/getConnectedUsers`
- **Status Endpoint**: `http://192.168.137.191:8586/status`
- **Health Check**: `http://192.168.137.191:8586/health`

### For Socket.IO WebSocket Connections:
- **Socket.IO URL**: `http://192.168.137.191:8586`

## Quick Test Commands

### Test the main endpoint:
```bash
curl http://192.168.137.191:8586/getConnectedUsers
```

### Test with PowerShell:
```powershell
Invoke-RestMethod -Uri "http://192.168.137.191:8586/getConnectedUsers" -Method GET
```

### Test with Python:
```python
import requests
response = requests.get('http://192.168.137.191:8586/getConnectedUsers')
print(response.json())
```

## Starting the Server
```bash
python app.py
```

## Expected Response Format
```json
{
  "users": [
    {
      "id": "unique-user-id-1",
      "username": "Worker1",
      "ipAddress": "192.168.137.191",
      "connectedSince": "2024-08-01T10:00:00Z"
    }
  ]
}
```

## Server Status
✅ Server is currently running on port 8586
✅ All endpoints are responding correctly
✅ Ready to accept client connections
