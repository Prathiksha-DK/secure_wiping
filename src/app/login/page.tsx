
'use client';

import {useState, useTransition, useEffect} from 'react';
import {useFormState, useFormStatus} from 'react-dom';
import Link from 'next/link';
import {LogIn, ShieldCheck, Building2, UserSquare, MapPin, Info, Loader2 } from 'lucide-react';
import {Button} from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {Input} from '@/components/ui/input';
import {Label} from '@/components/ui/label';
import {login, getMasterUserDetails} from '@/app/actions';
import {Alert, AlertDescription, AlertTitle} from '@/components/ui/alert';
import { cn } from '@/lib/utils';

function SubmitButton() {
  const {pending} = useFormStatus();

  return (
    <Button className="w-full" type="submit" disabled={pending}>
      {pending ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin" /><span>Logging in...</span></>) : 'Login'}
      {!pending && <LogIn className="ml-2 h-4 w-4" />}
    </Button>
  );
}

export default function LoginPage() {
  const [state, formAction] = useFormState(login, undefined);
  const [username, setUsername] = useState('');
  const [details, setDetails] = useState({ companyName: '', position: '', address: '', personalInfo: '' });
  const [isFetchingDetails, startFetchingDetails] = useTransition();

  const isMasterUser = username === 'Madhan';

  useEffect(() => {
    if (isMasterUser) {
      startFetchingDetails(async () => {
        const result = await getMasterUserDetails(username);
        if (result.status === 'found' && result.data) {
          setDetails(result.data);
        } else {
          // Clear fields if not found or on error
          setDetails({ companyName: '', position: '', address: '', personalInfo: '' });
        }
      });
    }
  }, [isMasterUser, username]);

  const handleDetailsChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setDetails(prev => ({ ...prev, [e.target.name]: e.target.value }));
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-muted/40 py-12">
      <div className="w-full max-w-md mx-4">
        <Card>
          <CardHeader className="text-center">
            <ShieldCheck className="mx-auto h-12 w-12 text-primary" />
            <CardTitle className="mt-4 text-2xl">SecureWipe</CardTitle>
            <CardDescription>Enter your credentials to access the tool.</CardDescription>
          </CardHeader>
          <CardContent>
            <form action={formAction} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  name="username"
                  placeholder="e.g., Madhan"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" name="password" type="password" required />
              </div>

              {isMasterUser && (
                  <div className="space-y-4 border-t pt-4">
                      <p className="text-sm text-muted-foreground text-center">Master user detected. Please provide additional details.</p>
                       {isFetchingDetails ? (
                          <div className="flex items-center justify-center p-4">
                              <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                              <span>Loading details...</span>
                          </div>
                       ) : (
                          <>
                              <div className="space-y-2">
                                  <Label htmlFor="companyName" className='flex items-center gap-2'><Building2 size={14}/> Company Name</Label>
                                  <Input id="companyName" name="companyName" placeholder="e.g., Stark Industries" required value={details.companyName} onChange={handleDetailsChange} />
                              </div>
                              <div className="space-y-2">
                                  <Label htmlFor="position" className='flex items-center gap-2'><UserSquare size={14}/> Position</Label>
                                  <Input id="position" name="position" placeholder="e.g., CEO" required value={details.position} onChange={handleDetailsChange} />
                              </div>
                              <div className="space-y-2">
                                  <Label htmlFor="address" className='flex items-center gap-2'><MapPin size={14}/> Address</Label>
                                  <Input id="address" name="address" placeholder="e.g., 10880 Malibu Point, CA" required value={details.address} onChange={handleDetailsChange} />
                              </div>
                              <div className="space-y-2">
                                  <Label htmlFor="personalInfo" className='flex items-center gap-2'><Info size={14}/> Personal Info</Label>
                                  <textarea
                                      id="personalInfo"
                                      name="personalInfo"
                                      placeholder="A short bio..."
                                      required
                                      value={details.personalInfo}
                                      onChange={handleDetailsChange}
                                      className={cn(
                                        "flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-base ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
                                      )}
                                    />
                              </div>
                          </>
                       )}
                  </div>
              )}

              {state?.error && (
                <Alert variant="destructive">
                  <AlertTitle>Login Failed</AlertTitle>
                  <AlertDescription>{state.error}</AlertDescription>
                </Alert>
              )}
              <SubmitButton />
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
