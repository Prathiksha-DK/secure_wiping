const WebSocket = require('ws');

// Configuration
const SERVER_URL = 'ws://192.168.137.191:8586';
const USERNAME = process.argv[2] || `TestUser${Date.now()}`;

console.log(`🔌 Connecting to server: ${SERVER_URL}`);
console.log(`👤 Username: ${USERNAME}`);

// Create WebSocket connection
const ws = new WebSocket(SERVER_URL);

let userId = null;
let pingInterval = null;

ws.on('open', () => {
    console.log('✅ Connected to server!');
    
    // Send username to server
    setTimeout(() => {
        ws.send(JSON.stringify({
            type: 'setUsername',
            username: USERNAME
        }));
    }, 500);
    
    // Send sample device list after connecting
    setTimeout(() => {
        const sampleDevices = [
            {
                name: 'C: (Primary Drive)',
                type: 'SSD',
                size: '256GB',
                status: 'ready'
            },
            {
                name: 'D: (Data Drive)',
                type: 'HDD',
                size: '1TB',
                status: 'ready'
            },
            {
                name: 'USB Flash Drive',
                type: 'USB',
                size: '32GB',
                status: 'busy'
            }
        ];
        
        ws.send(JSON.stringify({
            type: 'setDevices',
            devices: sampleDevices
        }));
        
        console.log(`📱 Sent ${sampleDevices.length} sample devices to server`);
    }, 1500);
    
    // Start ping/pong for connection health
    pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
        }
    }, 30000); // Ping every 30 seconds
});

ws.on('message', (data) => {
    try {
        const message = JSON.parse(data);
        
        switch (message.type) {
            case 'welcome':
                userId = message.userId;
                console.log(`🎉 Welcome! Assigned ID: ${userId}`);
                console.log(`🏷️ Default username: ${message.assignedUsername}`);
                break;
                
            case 'usernameUpdated':
                console.log(`✅ Username updated to: ${message.username}`);
                break;
                
            case 'devicesUpdated':
                console.log(`📱 Device list updated: ${message.deviceCount} devices`);
                break;
                
            case 'pong':
                console.log('💓 Received pong from server');
                break;
                
            default:
                console.log('📨 Received message:', message);
        }
    } catch (error) {
        console.error('❌ Error parsing message:', error);
    }
});

ws.on('close', (code, reason) => {
    console.log(`🔌 Connection closed. Code: ${code}, Reason: ${reason}`);
    if (pingInterval) {
        clearInterval(pingInterval);
    }
});

ws.on('error', (error) => {
    console.error('❌ WebSocket error:', error.message);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down client...');
    if (pingInterval) {
        clearInterval(pingInterval);
    }
    if (ws.readyState === WebSocket.OPEN) {
        ws.close();
    }
    setTimeout(() => process.exit(0), 1000);
});

console.log('\n📝 Instructions:');
console.log('- This client will automatically connect and set a username');
console.log('- Press Ctrl+C to disconnect');
console.log('- Check the /getConnectedUsers endpoint while this is running');
console.log(`- Usage: node test-client.js [username]`);
console.log('\n⏳ Attempting connection...');
