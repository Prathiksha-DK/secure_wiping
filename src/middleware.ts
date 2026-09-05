import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('session') || request.cookies.get('session_token');
  const { pathname } = request.nextUrl;

  // Allow direct access to public resources and api routes
  if (
    pathname.startsWith('/api') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon.ico')
  ) {
    return NextResponse.next();
  }

  // If there's no session and the user is not on the login page, redirect to login
  if (!sessionCookie && pathname !== '/login') {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  if (sessionCookie) {
    try {
      let role = 'individual';
      try {
        const parsed = JSON.parse(sessionCookie.value);
        role = parsed.role || 'individual';
      } catch {
        // Fallback: check userRole cookie
        const userRoleCookie = request.cookies.get('userRole');
        if (userRoleCookie) {
          role = userRoleCookie.value;
        }
      }

      // If user is on the root landing page (/), redirect to their role dashboard
      if (pathname === '/') {
        if (role === 'government') {
          return NextResponse.redirect(new URL('/government/dashboard', request.url));
        } else if (role === 'forensic') {
          return NextResponse.redirect(new URL('/forensic/dashboard', request.url));
        } else {
          return NextResponse.redirect(new URL('/individual/dashboard', request.url));
        }
      }

      // Enforce role boundaries
      if (pathname.startsWith('/government') && role !== 'government') {
        return NextResponse.redirect(new URL(role === 'forensic' ? '/forensic/dashboard' : '/individual/dashboard', request.url));
      }
      if (pathname.startsWith('/forensic') && role !== 'forensic') {
        return NextResponse.redirect(new URL(role === 'government' ? '/government/dashboard' : '/individual/dashboard', request.url));
      }
      if (pathname.startsWith('/individual') && role !== 'individual') {
        return NextResponse.redirect(new URL(role === 'government' ? '/government/dashboard' : '/forensic/dashboard', request.url));
      }
    } catch {
      const response = NextResponse.redirect(new URL('/login', request.url));
      response.cookies.delete('session');
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
