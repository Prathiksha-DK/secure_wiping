
'use server';

import {z} from 'zod';
import {cookies} from 'next/headers';
import {redirect} from 'next/navigation';

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
    return {
      error: 'Invalid input',
    };
  }

  try {
    const {suggestWipeMethod} = await import('@/ai/flows/suggest-wipe-method');
    const result = await suggestWipeMethod(validatedFields.data as any);
    return result;
  } catch (error) {
    console.error(error);
    return {
      error: 'An error occurred while getting the suggestion.',
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
    username: z.string().min(1, 'Username is required'),
    password: z.string().min(1, 'Password is required'),
    companyName: z.string().optional(),
    position: z.string().optional(),
    address: z.string().optional(),
    personalInfo: z.string().optional(),
  });
  const data = schema.parse(Object.fromEntries(formData));

  try {
    const authRes = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: data.username,
        password: data.password,
      }),
    });

    const result = await authRes.json();
    if (!authRes.ok || result.status !== 'success') {
      return {
        error: result.message || 'Invalid username or password.',
      };
    }

    const user = result.user;
    const role = (user.role === 'ADMINISTRATOR' ? 'master' : 'worker');

    const cookieStore = await cookies();
    cookieStore.set('session', JSON.stringify({ username: user.username, role, token: user.token }), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: '/',
    });
    cookieStore.set('session_token', user.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 7,
      path: '/',
    });
    cookieStore.set('userRole', role, {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: '/',
    });

    if (role === 'master') {
      redirect('/master/dashboard');
    } else {
      redirect('/worker/dashboard');
    }
  } catch (error: any) {
    if (error?.digest?.startsWith('NEXT_REDIRECT')) {
      throw error;
    }
    console.error('Login action error:', error);
    return {
      error: error.message || 'Authentication service error. Ensure the backend is running.',
    };
  }
}

export async function logout() {
  try {
    await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' }).catch(() => null);
  } catch {}
  const cookieStore = await cookies();
  cookieStore.delete('session');
  cookieStore.delete('session_token');
  cookieStore.delete('userRole');
  redirect('/login');
}
