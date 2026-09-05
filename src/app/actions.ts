'use server';

import { z } from 'zod';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

const API_BASE = process.env.API_BASE || 'http://127.0.0.1:9758';

export async function suggestWipeMethodAction(prevState: any, formData: FormData) {
  const schema = z.object({
    dataType: z.string(),
    securityLevel: z.string(),
  });

  const validatedFields = schema.safeParse({
    dataType: formData.get('dataType'),
    securityLevel: formData.get('securityLevel'),
  });

  if (!validatedFields.success) {
    return { error: 'Invalid input' };
  }

  try {
    const { suggestWipeMethod } = await import('@/ai/flows/suggest-wipe-method');
    const result = await suggestWipeMethod(validatedFields.data as any);
    return result;
  } catch (error) {
    console.error(error);
    return { error: 'An error occurred while getting the suggestion.' };
  }
}

export async function generateBlastReportAction(input: any): Promise<{ status: 'success'; report: any } | { status: 'error'; error: string }> {
  try {
    const { generateBlastReport } = await import('@/ai/flows/generate-blast-report');
    const result = await generateBlastReport(input);
    return { status: 'success' as const, report: result };
  } catch (error) {
    console.error(error);
    return {
      status: 'error' as const,
      error: 'An error occurred while generating the blast report.',
    };
  }
}

export async function getMasterUserDetails(username: string) {
  if (username !== 'Madhan') {
    return { status: 'not_master' };
  }
  try {
    const response = await fetch(`${API_BASE}/api/get-login-details`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });

    if (!response.ok) {
      return { status: 'error', message: 'Could not connect to the user details service.' };
    }

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Failed to connect to getLoginDetails endpoint:', error);
    return { status: 'error', message: 'Could not connect to the user details service.' };
  }
}

export async function login(prevState: any, formData: FormData) {
  const schema = z.object({
    username: z.string(),
    password: z.string(),
    role: z.string().optional(),
  });
  const data = schema.parse(Object.fromEntries(formData));

  try {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: data.username,
        password: data.password,
      }),
    });

    const result = await response.json();

    if (!response.ok || result.status !== 'success') {
      // Fallback for demo usernames if offline
      if (data.username === 'citizen_user' && data.password === 'Individual@2026') {
        return await _completeLogin({ username: data.username, role: 'individual', token: 'demo-indiv' });
      } else if (data.username === 'gov_officer' && data.password === 'GovAdmin@2026') {
        return await _completeLogin({ username: data.username, role: 'government', token: 'demo-gov' });
      } else if (data.username === 'forensic_analyst' && data.password === 'Forensic@2026') {
        return await _completeLogin({ username: data.username, role: 'forensic', token: 'demo-forensic' });
      }
      return {
        error: result.message || 'Invalid username or password.',
      };
    }

    return await _completeLogin(result.session);
  } catch (error) {
    console.error('Login network error:', error);
    // Offline demo fallback
    if (data.username === 'citizen_user' && data.password === 'Individual@2026') {
      return await _completeLogin({ username: data.username, role: 'individual', token: 'demo-indiv' });
    } else if (data.username === 'gov_officer' && data.password === 'GovAdmin@2026') {
      return await _completeLogin({ username: data.username, role: 'government', token: 'demo-gov' });
    } else if (data.username === 'forensic_analyst' && data.password === 'Forensic@2026') {
      return await _completeLogin({ username: data.username, role: 'forensic', token: 'demo-forensic' });
    }
    return {
      error: 'Could not connect to the authentication server (Port 9758). Please ensure backend is running.',
    };
  }
}

async function _completeLogin(sessionData: { username: string; role: string; token: string; [k: string]: any }) {
  const cookieStore = await cookies();
  cookieStore.set('session', JSON.stringify(sessionData), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
  });
  cookieStore.set('session_token', sessionData.token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
  });
  cookieStore.set('userRole', sessionData.role, {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
  });

  if (sessionData.role === 'government') {
    redirect('/government/dashboard');
  } else if (sessionData.role === 'forensic') {
    redirect('/forensic/dashboard');
  } else {
    redirect('/individual/dashboard');
  }
}

export async function logout() {
  const cookieStore = await cookies();
  cookieStore.delete('session');
  cookieStore.delete('session_token');
  cookieStore.delete('userRole');
  redirect('/login');
}
