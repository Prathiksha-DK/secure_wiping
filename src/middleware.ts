import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('session') || request.cookies.get('session_token');
  const userRoleCookie = request.cookies.get('userRole');
  const { pathname } = request.nextUrl;

  // Allow direct access to system/API assets
  if (
    pathname.startsWith('/api') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon.ico')
  ) {
    return NextResponse.next();
  }

  // ALWAYS allow /login and public registration to render directly
  if (
    pathname === '/login' ||
    pathname === '/hunter/register' ||
    pathname.startsWith('/hunter/register') ||
    pathname === '/register'
  ) {
    return NextResponse.next();
  }

  // If there's no session and the user is not on a public page, redirect to /login
  if (
    !sessionCookie &&
    pathname !== '/login' &&
    !pathname.startsWith('/hunter/register') &&
    !pathname.startsWith('/register')
  ) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Parse session role
  if (sessionCookie) {
    try {
      let role = 'individual';
      try {
        const parsed = JSON.parse(sessionCookie.value);
        role = parsed.role || 'individual';
      } catch {
        if (userRoleCookie?.value) {
          role = userRoleCookie.value;
        }
      }

      // If user is on root (/), redirect to their role dashboard
      if (pathname === '/') {
        if (role === 'government') {
          return NextResponse.redirect(new URL('/government/dashboard', request.url));
        } else if (role === 'forensic') {
          return NextResponse.redirect(new URL('/forensic/dashboard', request.url));
        } else if (role === 'hunter') {
          return NextResponse.redirect(new URL('/hunter/dashboard', request.url));
        } else if (role === 'master') {
          return NextResponse.redirect(new URL('/master/dashboard', request.url));
        } else if (role === 'worker') {
          return NextResponse.redirect(new URL('/worker/dashboard', request.url));
        } else {
          return NextResponse.redirect(new URL('/individual/dashboard', request.url));
        }
      }

      // Helper for fallback dashboard
      const getRoleDashboard = (r: string) => {
        if (r === 'hunter') return '/hunter/dashboard';
        if (r === 'forensic') return '/forensic/dashboard';
        if (r === 'government') return '/government/dashboard';
        if (r === 'master') return '/master/dashboard';
        if (r === 'worker') return '/worker/dashboard';
        return '/individual/dashboard';
      };

      // Enforce role boundaries
      if (pathname.startsWith('/hunter') && !pathname.startsWith('/hunter/register') && role !== 'hunter') {
        return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
      }
      if (pathname.startsWith('/government') && role !== 'government') {
        return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
      }
      if (pathname.startsWith('/forensic') && role !== 'forensic') {
        return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
      }
      if (
        pathname.startsWith('/individual') &&
        role !== 'individual' &&
        role !== 'master' &&
        role !== 'worker'
      ) {
        return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
      }
      if (pathname.startsWith('/master') && role !== 'master') {
        return NextResponse.redirect(new URL('/worker/dashboard', request.url));
      }
      if (pathname.startsWith('/worker') && role !== 'worker') {
        return NextResponse.redirect(new URL('/master/dashboard', request.url));
      }
    } catch {
      const response = NextResponse.redirect(new URL('/login', request.url));
      response.cookies.delete('session');
      response.cookies.delete('session_token');
      response.cookies.delete('userRole');
      return response;
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
