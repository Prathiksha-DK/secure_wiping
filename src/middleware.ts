
import {NextResponse} from 'next/server';
import type {NextRequest} from 'next/server';

// Public & Main Application routes accessible directly
const PUBLIC_ROUTES = [
  '/',
  '/login',
  '/how-it-works',
  '/why-securewipe',
  '/marketplace',
  '/verify',
  '/about',
  '/faq',
  '/dashboard',
  '/admin',
  '/wipe',
  '/inspector',
  '/swarm',
  '/faris',
  '/history',
  '/lifecycle',
  '/iso-mode'
];

export function middleware(request: NextRequest) {
  const session = request.cookies.get('session');
  const { pathname } = request.nextUrl;
  const host = request.headers.get('host') || '';
  const isPort3001 = host.includes(':3001') || request.nextUrl.port === '3001';

  // If accessed on Port 3001 (Main Application Engine), route root to /login or role dashboard
  if (isPort3001 && pathname === '/') {
    if (session) {
      try {
        const sessionData = JSON.parse(session.value);
        if (sessionData.role === 'master') {
          return NextResponse.redirect(new URL('/master/dashboard', request.url));
        }
        return NextResponse.redirect(new URL('/worker/dashboard', request.url));
      } catch {}
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Allow direct access to public routes
  const isPublic = PUBLIC_ROUTES.some(route => pathname === route || (route !== '/' && pathname.startsWith(route)));
  if (isPublic) {
    return NextResponse.next();
  }

  // Allow legacy internal dashboards
  if (pathname.startsWith('/master/dashboard') || pathname.startsWith('/worker/dashboard')) {
    return NextResponse.next();
  }

  // If there's no session and the user is not on a public page, redirect to login
  if (!session) {
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
