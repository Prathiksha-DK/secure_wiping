
'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from './ui/card';
import { ScrollArea } from './ui/scroll-area';
import { Loader2, ServerOff, User, Wifi, Clock, RefreshCw, Monitor, HardDrive } from 'lucide-react';
import { Button } from './ui/button';
import { formatDistanceToNow } from 'date-fns';

type Device = {
  name: string;
  type: string;
  size?: string;
  status?: string;
  health?: string;
  id?: string;
};

type ConnectedUser = {
  id: string;
  username: string;
  ipAddress: string;
  connectedSince: string;
  devices: Device[];
};

type FetchState = 'loading' | 'success' | 'error';

const mockUsers: ConnectedUser[] = [
  {
    id: 'user-1',
    username: 'Worker-01',
    ipAddress: '192.168.1.101',
    connectedSince: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    devices: [
      {
        id: 'dev-1-1',
        name: 'Primary Workstation SSD',
        type: 'SSD',
        size: '1TB',
        health: 'Healthy',
        status: 'ready'
      },
      {
        id: 'dev-1-2',
        name: 'Client Project Drive',
        type: 'USB Drive',
        size: '256GB',
        health: 'Warning',
        status: 'busy'
      }
    ]
  },
  {
    id: 'user-2',
    username: 'FieldAgent-Alpha',
    ipAddress: '10.8.0.5',
    connectedSince: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    devices: [
      {
        id: 'dev-2-1',
        name: 'Android Tablet',
        type: 'Android Storage',
        size: '128GB',
        health: 'Healthy',
        status: 'ready'
      }
    ]
  },
    {
    id: 'user-3',
    username: 'Data-Center-Ops',
    ipAddress: '172.16.5.23',
    connectedSince: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    devices: [
       {
        id: 'dev-3-1',
        name: 'RAID Array 5',
        type: 'HDD',
        size: '16TB',
        health: 'Critical',
        status: 'error'
      },
      {
        id: 'dev-3-2',
        name: 'Backup Server Drive',
        type: 'HDD',
        size: '32TB',
        health: 'Healthy',
        status: 'ready'
      }
    ]
  },
    {
    id: 'user-4',
    username: 'Remote-Worker-Ben',
    ipAddress: '203.0.113.88',
    connectedSince: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    devices: []
  }
];


export default function ConnectedUsers() {
  const [users, setUsers] = useState<ConnectedUser[]>([]);
  const [status, setStatus] = useState<FetchState>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchConnectedUsers = () => {
    setStatus('loading');
    // Simulate network delay
    setTimeout(() => {
        setUsers(mockUsers);
        setStatus('success');
        setLastUpdated(new Date());
    }, 500);
  };

  useEffect(() => {
    fetchConnectedUsers();
    // Keep refresh functionality, but it will just re-set the mock data
    const interval = setInterval(fetchConnectedUsers, 30000); 

    return () => clearInterval(interval);
  }, []);

  const renderContent = () => {
    if (status === 'loading') {
      return (
        <div className="flex flex-col items-center justify-center h-full">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <p className="mt-4 text-muted-foreground">Fetching connected users...</p>
        </div>
      );
    }
    
    if (users.length === 0) {
        return (
             <div className="flex flex-col items-center justify-center h-full">
                <User className="h-10 w-10 text-muted-foreground" />
                <p className="mt-4 text-center text-muted-foreground">No users are currently connected.</p>
             </div>
        )
    }

    return (
      <ScrollArea className="h-full">
        <div className="space-y-4 pr-6">
          {users.map((user) => (
            <div key={user.id} className="p-4 bg-muted/50 rounded-lg border">
              <div className="flex items-start gap-4">
                <div className="p-2 bg-primary/10 rounded-full">
                  <User className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-grow">
                  <p className="font-semibold">{user.username}</p>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                    <span className='flex items-center gap-1.5'><Wifi size={12}/>{user.ipAddress}</span>
                    <span className='flex items-center gap-1.5'><Clock size={12}/>{formatDistanceToNow(new Date(user.connectedSince), { addSuffix: true })}</span>
                  </div>
                  
                  {/* Device List */}
                  {user.devices && user.devices.length > 0 && (
                    <div className="mt-3">
                      <div className="flex items-center gap-2 mb-2">
                        <HardDrive className="h-3 w-3 text-muted-foreground" />
                        <span className="text-xs font-medium text-muted-foreground">
                          {user.devices.length} Device{user.devices.length !== 1 ? 's' : ''}
                        </span>
                      </div>
                      <div className="grid gap-1">
                        {user.devices.map((device, index) => (
                          <div key={index} className="flex items-center gap-2 p-2 bg-background/50 rounded text-xs">
                            <Monitor className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                            <div className="flex-grow min-w-0">
                              <div className="font-medium truncate">{device.name}</div>
                              <div className="text-muted-foreground flex items-center gap-3 flex-wrap">
                                <span>Type: {device.type}</span>
                                {device.size && <span>Size: {device.size}</span>}
                                {device.health && (
                                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                                    device.health.toLowerCase().includes('healthy') ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400' :
                                    device.health.toLowerCase().includes('warning') ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400' :
                                    device.health.toLowerCase().includes('critical') ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400' :
                                    'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'
                                  }`}>
                                    {device.health}
                                  </span>
                                )}
                                {device.status && (
                                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                                    device.status === 'ready' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400' :
                                    device.status === 'busy' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400' :
                                     device.status === 'error' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400' :
                                    'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'
                                  }`}>
                                    {device.status}
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {(!user.devices || user.devices.length === 0) && (
                    <div className="mt-3 text-xs text-muted-foreground italic">
                      No devices reported
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    );
  };

  return (
    <Card className="flex flex-col h-full">
      <CardHeader>
        <div className="flex items-center justify-between">
            <div>
                <CardTitle>Connected Users</CardTitle>
                <CardDescription>
                Live view of server connections.
                </CardDescription>
            </div>
            <Button variant="ghost" size="icon" onClick={fetchConnectedUsers} disabled={status === 'loading'}>
                <RefreshCw className={`h-4 w-4 ${status === 'loading' ? 'animate-spin' : ''}`} />
            </Button>
        </div>
      </CardHeader>
      <CardContent className="flex-grow overflow-hidden">
        {renderContent()}
      </CardContent>
    </Card>
  );
}
