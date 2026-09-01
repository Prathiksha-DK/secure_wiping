
import {NextResponse} from 'next/server';
import type {NextRequest} from 'next/server';

export function middleware(request: NextRequest) {
  const session = request.cookies.get('session');
  const {pathname} = request.nextUrl;

  // Allow direct access to dashboards for testing
  if (pathname.startsWith('/master/dashboard') || pathname.startsWith('/worker/dashboard')) {
      return NextResponse.next();
  }

  // If there's no session and the user is not on the login page, redirect to login
  if (!session && pathname !== '/login') {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // If there's a session
  if (session) {
    try {
      const sessionData = JSON.parse(session.value);
      const {role} = sessionData;

      // If user is on login page, redirect to their dashboard
      if (pathname === '/login') {
        if (role === 'master') {
          return NextResponse.redirect(new URL('/master/dashboard', request.url));
        }
        if (role === 'worker') {
          return NextResponse.redirect(new URL('/worker/dashboard', request.url));
        }
      }

      // Role-based access control
      if (pathname.startsWith('/master') && role !== 'master') {
        return NextResponse.redirect(new URL('/worker/dashboard', request.url));
      }
      if (pathname.startsWith('/worker') && role !== 'worker') {
        return NextResponse.redirect(new URL('/master/dashboard', request.url));
      }

    } catch (error) {
        // If cookie is malformed, clear it and redirect to login
        const response = NextResponse.redirect(new URL('/login', request.url));
        response.cookies.delete('session');
        return response;
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
