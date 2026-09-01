import Link from 'next/link';
import {
  HardDrive,
  Smartphone,
  Usb,
  Database,
  Shield,
  Activity,
  FileClock,
  PlusCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

const deviceIcons: { [key: string]: React.ElementType } = {
  SSD: HardDrive,
  HDD: Database,
  'USB Drive': Usb,
  'Android Storage': Smartphone,
};
export const dynamic = "force-dynamic";

type Device = {
  name: string;
  type: string;
  size: string;
  health: number;
  healthStatus: string;
  color: string;
};

async function getDevices(): Promise<Device[]> {
  try {
    const res = await fetch('http://localhost:9758/api/devices', { cache: 'no-store' });
    if (!res.ok) {
      console.error('Failed to fetch devices');
      return [];
    }
    const devices = await res.json();
    return devices.map((d: any) => ({...d, color: d.health > 80 ? 'bg-green-500' : d.health > 50 ? 'bg-yellow-500' : 'bg-red-500'}));
  } catch (error) {
    console.error('Error fetching devices:', error);
    return [];
  }
}


export default async function DashboardPage() {
  const devices = await getDevices();
  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your connected devices.
          </p>
        </div>
        <Button>
          <PlusCircle className="mr-2 h-4 w-4" /> Add Device
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 mt-6">
        {devices.map((device) => {
          const Icon = deviceIcons[device.type] || HardDrive;
          return (
            <Card key={device.name} className="flex flex-col">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Icon className="h-5 w-5 text-muted-foreground" />
                      {device.name}
                    </CardTitle>
                    <CardDescription>
                      {device.type} - {device.size}
                    </CardDescription>
                  </div>
                  <Badge variant="outline">{device.healthStatus}</Badge>
                </div>
              </CardHeader>
              <CardContent className="flex-grow">
                <div className="text-sm text-muted-foreground">Device Health</div>
                <div className="flex items-center gap-2 mt-1">
                  <Progress value={device.health} aria-label={`${device.health}% health`} />
                  <span className="font-semibold">{device.health}%</span>
                </div>
              </CardContent>
              <CardFooter className="flex justify-between gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link href={`/history?device=${device.name}`}>
                    <FileClock className="mr-2 h-4 w-4" /> Logs
                  </Link>
                </Button>
                <Button size="sm" asChild>
                  <Link href={`/wipe?device=${device.name}`}>
                    <Shield className="mr-2 h-4 w-4" /> Wipe
                  </Link>
                </Button>
              </CardFooter>
            </Card>
          );
        })}
      </div>
    </>
  );
}
