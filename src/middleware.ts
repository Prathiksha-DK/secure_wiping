import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Public routes accessible without authentication
const PUBLIC_ROUTES = [
  '/',
  '/login',
  '/how-it-works',
  '/why-securewipe',
  '/marketplace',
  '/verify',
  '/about',
  '/faq',
  '/iso-mode',
];

export function middleware(request: NextRequest) {
  const sessionCookie = request.cookies.get('session') || request.cookies.get('session_token');
  const userRoleCookie = request.cookies.get('userRole');
  const { pathname } = request.nextUrl;
  const host = request.headers.get('host') || '';
  const isPort3001 = host.includes(':3001') || request.nextUrl.port === '3001';

  // Allow direct access to system/API assets
  if (
    pathname.startsWith('/api') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon.ico')
  ) {
    return NextResponse.next();
  }

  // Parse session role
  let role = 'individual';
  let isAuthenticated = false;

  if (sessionCookie) {
    try {
      const parsed = JSON.parse(sessionCookie.value);
      role = parsed.role || 'individual';
      isAuthenticated = true;
    } catch {
      if (userRoleCookie?.value) {
        role = userRoleCookie.value;
        isAuthenticated = true;
      } else if (sessionCookie.value) {
        isAuthenticated = true;
      }
    }
  }

  // Helper for role dashboard URL
  const getRoleDashboard = (r: string) => {
    switch (r) {
      case 'government':
        return '/government/dashboard';
      case 'forensic':
        return '/forensic/dashboard';
      case 'master':
        return '/master/dashboard';
      case 'worker':
        return '/worker/dashboard';
      case 'individual':
      default:
        return '/individual/dashboard';
    }
  };

  // If accessed on Port 3001 (Main Application Engine) or root landing while authenticated
  if (isPort3001 && pathname === '/') {
    if (isAuthenticated) {
      return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // If authenticated user is on /login, redirect to their role dashboard
  if (pathname === '/login' && isAuthenticated) {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }

  // Allow direct access to public marketing/informational routes
  const isPublic = PUBLIC_ROUTES.some(
    (route) => pathname === route || (route !== '/' && pathname.startsWith(route))
  );
  if (isPublic) {
    return NextResponse.next();
  }

  // If not authenticated and not on a public page, redirect to login
  if (!isAuthenticated) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Role-Based Access Control (RBAC) Enforcement
  if (pathname.startsWith('/government') && role !== 'government') {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }
  if (pathname.startsWith('/forensic') && role !== 'forensic') {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }
  if (pathname.startsWith('/individual') && role !== 'individual' && role !== 'master' && role !== 'worker') {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }
  if (pathname.startsWith('/master') && role !== 'master') {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }
  if (pathname.startsWith('/worker') && role !== 'worker') {
    return NextResponse.redirect(new URL(getRoleDashboard(role), request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
