'use client';

import React from 'react';
import { BookOpen, ChevronDown, ChevronUp, Shield } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';

const API_BASE = 'http://localhost:9758/api';

type AuditEvent = {
  id: string;
  timestamp: string;
  event_type: string;
  device_id?: string;
  actor?: string;
  result?: string;
  details?: Record<string, unknown>;
};

const EVENT_TYPE_STYLES: Record<string, string> = {
  DEVICE_DETECTED: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  SANITIZATION_STARTED: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
  SANITIZATION_COMPLETED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  CERTIFICATE_GENERATED: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  DECISION_MADE: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  REUSE_APPROVED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  DISPOSAL_REQUIRED: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  HANDOVER_CREATED: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  DISPOSAL_CONFIRMED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  VERIFICATION_COMPLETED: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
};

const ALL_EVENT_TYPES = Object.keys(EVENT_TYPE_STYLES);

function getResultBadge(result?: string) {
  if (!result) return null;
  if (result === 'SUCCESS' || result === 'PASS' || result === 'OK') {
    return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">{result}</Badge>;
  }
  if (result === 'WARN' || result === 'WARNING') {
    return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">{result}</Badge>;
  }
  if (result === 'FAIL' || result === 'ERROR') {
    return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">{result}</Badge>;
  }
  return <Badge variant="outline">{result}</Badge>;
}

function ExpandableDetails({ details }: { details?: Record<string, unknown> }) {
  const [open, setOpen] = React.useState(false);
  if (!details || Object.keys(details).length === 0) return <span className="text-muted-foreground text-xs">—</span>;
  return (
    <div>
      <Button variant="ghost" size="sm" className="h-6 text-xs px-2" onClick={() => setOpen((o) => !o)}>
        {open ? <ChevronUp className="h-3 w-3 mr-1" /> : <ChevronDown className="h-3 w-3 mr-1" />}
        {open ? 'Hide' : 'Show'}
      </Button>
      {open && (
        <pre className="mt-1 text-[10px] bg-muted p-2 rounded overflow-x-auto max-w-[320px]">
          {JSON.stringify(details, null, 2)}
        </pre>
      )}
    </div>
  );
}

export default function AuditTrailPage() {
  const [events, setEvents] = React.useState<AuditEvent[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [typeFilter, setTypeFilter] = React.useState('ALL');

  React.useEffect(() => {
    async function fetchEvents() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`${API_BASE}/compliance/audit-events`);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const data = await res.json();
        setEvents(Array.isArray(data) ? data : (data.events ?? []));
      } catch (err: any) {
        setError(err.message ?? 'Failed to load audit events.');
        setEvents([]);
      } finally {
        setLoading(false);
      }
    }
    fetchEvents();
  }, []);

  const filtered = events.filter(
    (e) => typeFilter === 'ALL' || e.event_type === typeFilter
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-3">
        <BookOpen className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Audit Trail</h1>
          <p className="text-muted-foreground">Append-only audit log of all lifecycle events.</p>
        </div>
      </div>

      <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-950/30 dark:border-blue-800">
        <Shield className="h-4 w-4 text-blue-600 dark:text-blue-400" />
        <AlertDescription className="text-blue-700 dark:text-blue-400 text-sm">
          Audit events are append-only and integrity-hashed. No event can be modified or deleted after creation.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
            <div>
              <CardTitle className="text-base">Lifecycle Events</CardTitle>
              <CardDescription>
                {loading ? 'Loading…' : `${filtered.length} event${filtered.length !== 1 ? 's' : ''}`}
              </CardDescription>
            </div>
            <div className="ml-auto">
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[220px]">
                  <SelectValue placeholder="Filter by event type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">All Event Types</SelectItem>
                  {ALL_EVENT_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.replace(/_/g, ' ')}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Event ID</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>Event Type</TableHead>
                <TableHead>Device ID</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                    Loading audit events…
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-10 text-red-500">
                    {error}
                  </TableCell>
                </TableRow>
              ) : filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                    {typeFilter !== 'ALL'
                      ? `No events of type ${typeFilter}.`
                      : 'No audit events yet. Events will appear as the platform processes devices.'}
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-mono text-xs">
                      {event.id.substring(0, 12)}…
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Badge className={EVENT_TYPE_STYLES[event.event_type] ?? 'bg-gray-100 text-gray-700'}>
                        {event.event_type.replace(/_/g, ' ')}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {event.device_id ? event.device_id.substring(0, 16) + '…' : '—'}
                    </TableCell>
                    <TableCell className="text-xs">{event.actor ?? '—'}</TableCell>
                    <TableCell>{getResultBadge(event.result)}</TableCell>
                    <TableCell>
                      <ExpandableDetails details={event.details} />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
