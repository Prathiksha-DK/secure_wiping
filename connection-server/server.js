const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Port configuration
const PORT = 8586;

// Middleware
app.use(cors());
app.use(express.json());

// Store for connected users
const connectedUsers = new Map();

// Helper function to get client IP address
function getClientIpAddress(req, ws) {
    // For WebSocket connections
    if (ws) {
        return ws._socket.remoteAddress || 
               ws._socket.connection?.remoteAddress || 
               '127.0.0.1';
    }
    
    // For HTTP requests
    return req.ip || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
           '127.0.0.1';
}

// Helper function to clean IPv6 mapped IPv4 addresses
function cleanIpAddress(ip) {
    if (ip && ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip || '127.0.0.1';
}

// WebSocket connection handling
wss.on('connection', (ws, req) => {
    const userId = uuidv4();
    const ipAddress = cleanIpAddress(getClientIpAddress(req, ws));
    const connectedSince = new Date().toISOString();
    
    // Store user connection info
    const userInfo = {
        id: userId,
        username: `Worker${connectedUsers.size + 1}`, // Default username
        ipAddress: ipAddress,
        connectedSince: connectedSince,
        websocket: ws
    };
    
    connectedUsers.set(userId, userInfo);
    
    console.log(`New client connected: ${userId} from ${ipAddress}`);
    console.log(`Total connected users: ${connectedUsers.size}`);
    
    // Send welcome message to client
    ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected successfully',
        userId: userId,
        assignedUsername: userInfo.username
    }));
    
    // Handle incoming messages
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // Handle username update
            if (data.type === 'setUsername' && data.username) {
                const user = connectedUsers.get(userId);
                if (user) {
                    user.username = data.username;
                    connectedUsers.set(userId, user);
                    console.log(`User ${userId} updated username to: ${data.username}`);
                    
                    // Acknowledge username change
                    ws.send(JSON.stringify({
                        type: 'usernameUpdated',
                        username: data.username
                    }));
                }
            }
            
            // Handle ping/pong for connection health
            if (data.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
            }
            
        } catch (error) {
            console.error('Error parsing message:', error);
        }
    });
    
    // Handle client disconnect
    ws.on('close', () => {
        connectedUsers.delete(userId);
        console.log(`Client disconnected: ${userId}`);
        console.log(`Total connected users: ${connectedUsers.size}`);
    });
    
    // Handle connection errors
    ws.on('error', (error) => {
        console.error(`WebSocket error for user ${userId}:`, error);
        connectedUsers.delete(userId);
    });
});

// REST API Endpoints

// GET /getConnectedUsers - Main endpoint as specified
app.get('/getConnectedUsers', (req, res) => {
    try {
        const users = Array.from(connectedUsers.values()).map(user => ({
            id: user.id,
            username: user.username,
            ipAddress: user.ipAddress,
            connectedSince: user.connectedSince
        }));
        
        res.status(200).json({
            users: users
        });
        
        console.log(`GET /getConnectedUsers - Returned ${users.length} users`);
    } catch (error) {
        console.error('Error in /getConnectedUsers:', error);
        res.status(500).json({
            error: 'Internal server error while retrieving connected users'
        });
    }
});

// Additional helpful endpoints

// GET /status - Server status
app.get('/status', (req, res) => {
    res.status(200).json({
        status: 'running',
        port: PORT,
        connectedUsers: connectedUsers.size,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// GET /health - Health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy'
    });
});

// Handle 404 for undefined routes
app.use('*', (req, res) => {
    res.status(404).json({
        error: `Route ${req.method} ${req.originalUrl} not found`
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error'
    });
});

// Start the server
server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log(`🚀 Connection Server started successfully!`);
    console.log(`📡 HTTP Server: http://localhost:${PORT}`);
    console.log(`🔌 WebSocket Server: ws://localhost:${PORT}`);
    console.log(`📊 Main endpoint: http://localhost:${PORT}/getConnectedUsers`);
    console.log('='.repeat(50));
    console.log('Waiting for client connections...');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server...');
    
    // Close all WebSocket connections
    wss.clients.forEach((ws) => {
        ws.close();
    });
    
    server.close(() => {
        console.log('✅ Server shut down gracefully');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server shut down gracefully');
        process.exit(0);
    });
});
