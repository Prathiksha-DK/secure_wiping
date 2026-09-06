'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useFormState, useFormStatus } from 'react-dom';
import {
  ShieldCheck,
  Building2,
  User,
  Search,
  LogIn,
  KeyRound,
  Lock,
  ArrowRight,
  Loader2,
  CheckCircle2,
  Info,
  LogOut,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { login, logout } from '@/app/actions';

function SubmitButton() {
  const { pending } = useFormStatus();

  return (
    <Button
      className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold py-3 h-11 rounded-xl shadow-lg shadow-cyan-950/50 transition-all flex items-center justify-center gap-2 text-sm hover:scale-[1.01]"
      type="submit"
      disabled={pending}
    >
      {pending ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin text-white" />
          <span>Authenticating Session...</span>
        </>
      ) : (
        <>
          <LogIn className="h-4 w-4" />
          <span>Authenticate & Access Command</span>
        </>
      )}
    </Button>
  );
}

export default function LoginPage() {
  const [state, formAction] = useFormState(login, undefined);
  const [username, setUsername] = useState('citizen_user');
  const [password, setPassword] = useState('Individual@2026');
  const [selectedRole, setSelectedRole] = useState<'individual' | 'government' | 'forensic' | 'hunter'>('individual');
  const [activeSession, setActiveSession] = useState<{ username: string; role: string } | null>(null);

  useEffect(() => {
    // Check if there is an active session in cookies
    try {
      const match = document.cookie.match(/(?:^|; )session=([^;]*)/);
      if (match) {
        const parsed = JSON.parse(decodeURIComponent(match[1]));
        if (parsed.username && parsed.role) {
          setActiveSession(parsed);
        }
      }
    } catch {
      // Ignore parse error
    }
  }, []);

  const setDemoCredentials = (role: 'individual' | 'government' | 'forensic' | 'hunter', variant: string = 'approved') => {
    setSelectedRole(role);
    if (role === 'individual') {
      setUsername('citizen_user');
      setPassword('Individual@2026');
    } else if (role === 'government') {
      setUsername('gov_officer');
      setPassword('GovAdmin@2026');
    } else if (role === 'forensic') {
      setUsername('forensic_analyst');
      setPassword('Forensic@2026');
    } else if (role === 'hunter') {
      if (variant === 'pending') {
        setUsername('pending_hunter');
        setPassword('Hunter@2026');
      } else if (variant === 'rejected') {
        setUsername('rejected_hunter');
        setPassword('Hunter@2026');
      } else {
        setUsername('hunter_agent');
        setPassword('Hunter@2026');
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#060A12] flex flex-col justify-center items-center p-4 relative overflow-hidden text-slate-100">
      {/* Ambient background glow & subtle radial light */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-cyan-500/10 via-blue-600/5 to-transparent blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg z-10 space-y-6">
        {/* Header Branding */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 text-xs tracking-wider uppercase font-mono shadow-sm">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <span>NTRO Enterprise Defense & Forensic Facility</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            SecureWipe Platform
          </h1>
          <p className="text-sm text-slate-400 max-w-md mx-auto font-normal leading-relaxed">
            Integrated Data Sanitization, Closed-Loop Forensic Recovery Verification & Tamper-Evident SHA-256 Ledger
          </p>
        </div>

        {/* Active Session Notification (if already logged in) */}
        {activeSession && (
          <div className="p-4 rounded-2xl border border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 to-[#0B1322] shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping shrink-0" />
              <div>
                <div className="text-xs font-semibold text-white">
                  Active Session: <span className="text-emerald-300 font-mono">{activeSession.username}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                  Role: {activeSession.role}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 self-end sm:self-auto">
              <Link
                href={
                  activeSession.role === 'government'
                    ? '/government/dashboard'
                    : activeSession.role === 'forensic'
                    ? '/forensic/dashboard'
                    : activeSession.role === 'hunter'
                    ? '/hunter/dashboard'
                    : '/individual/dashboard'
                }
              >
                <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs h-8 px-3 rounded-lg font-medium">
                  Go to Dashboard <ArrowRight className="h-3 w-3 ml-1" />
                </Button>
              </Link>
              <Button
                size="sm"
                variant="outline"
                onClick={() => logout()}
                className="border-slate-700 bg-slate-900 text-slate-300 hover:text-white text-xs h-8 px-2.5 rounded-lg"
                title="Sign out current session"
              >
                <LogOut className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        )}

        {/* Top Mode Selector: Sign In vs Register as Hunter */}
        <div className="grid grid-cols-2 gap-2 bg-[#070C16] p-1.5 rounded-2xl border border-slate-800 shadow-xl">
          <div className="py-2.5 px-4 rounded-xl text-xs font-bold transition-all bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950/50 flex items-center justify-center gap-2 cursor-default">
            <LogIn className="h-4 w-4" />
            <span>Sign In</span>
          </div>
          <Link
            href="/hunter/register"
            className="py-2.5 px-4 rounded-xl text-xs font-bold transition-all text-purple-300 hover:text-white hover:bg-purple-900/30 border border-purple-500/20 hover:border-purple-500/50 flex items-center justify-center gap-2 group"
          >
            <ShieldCheck className="h-4 w-4 text-purple-400 group-hover:scale-110 transition-transform" />
            <span>Hunter Registration →</span>
          </Link>
        </div>

        {/* Role Quick Selection / Demo Pills */}
        <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-3 shadow-xl backdrop-blur-md space-y-2">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider px-2 pt-1 flex items-center justify-between font-semibold">
            <span>Select Active Persona:</span>
            <span className="text-cyan-400 text-[10px] font-semibold">1-Click Quick Fill</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <button
              type="button"
              onClick={() => setDemoCredentials('individual')}
              className={`p-2.5 rounded-xl border text-left transition-all flex flex-col gap-1 ${
                selectedRole === 'individual'
                  ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-200 shadow-md shadow-cyan-950/50 ring-1 ring-cyan-500/30'
                  : 'border-slate-800 bg-[#070C16] text-slate-400 hover:border-slate-700 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-1.5 font-semibold text-xs text-white">
                <User className="h-3.5 w-3.5 text-cyan-400" />
                <span>Individual</span>
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">Personal User</span>
            </button>

            <button
              type="button"
              onClick={() => setDemoCredentials('government')}
              className={`p-2.5 rounded-xl border text-left transition-all flex flex-col gap-1 ${
                selectedRole === 'government'
                  ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-200 shadow-md shadow-emerald-950/50 ring-1 ring-emerald-500/30'
                  : 'border-slate-800 bg-[#070C16] text-slate-400 hover:border-slate-700 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-1.5 font-semibold text-xs text-white">
                <Building2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Gov / Org</span>
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">LAN Fleet</span>
            </button>

            <button
              type="button"
              onClick={() => setDemoCredentials('forensic')}
              className={`p-2.5 rounded-xl border text-left transition-all flex flex-col gap-1 ${
                selectedRole === 'forensic'
                  ? 'border-amber-500/60 bg-amber-500/15 text-amber-200 shadow-md shadow-amber-950/50 ring-1 ring-amber-500/30'
                  : 'border-slate-800 bg-[#070C16] text-slate-400 hover:border-slate-700 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-1.5 font-semibold text-xs text-white">
                <Search className="h-3.5 w-3.5 text-amber-400" />
                <span>Forensic</span>
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">Deep Carver</span>
            </button>

            <button
              type="button"
              onClick={() => setDemoCredentials('hunter')}
              className={`p-2.5 rounded-xl border text-left transition-all flex flex-col gap-1 ${
                selectedRole === 'hunter'
                  ? 'border-purple-500/60 bg-purple-500/15 text-purple-200 shadow-md shadow-purple-950/50 ring-1 ring-purple-500/30'
                  : 'border-slate-800 bg-[#070C16] text-slate-400 hover:border-slate-700 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-1.5 font-semibold text-xs text-white">
                <ShieldCheck className="h-3.5 w-3.5 text-purple-400" />
                <span>Hunter</span>
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">ISO Triage</span>
            </button>
          </div>

          {/* Special test buttons when Hunter role is active */}
          {selectedRole === 'hunter' && (
            <div className="pt-2 border-t border-slate-800/80 mt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
              <span className="text-[10px] font-mono text-slate-400">Hunter Test States:</span>
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => setDemoCredentials('hunter', 'approved')}
                  className="px-2 py-1 rounded-md text-[10px] font-mono bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/25 transition-all"
                  title="Test login for approved hunter"
                >
                  ✓ Approved
                </button>
                <button
                  type="button"
                  onClick={() => setDemoCredentials('hunter', 'pending')}
                  className="px-2 py-1 rounded-md text-[10px] font-mono bg-amber-500/15 border border-amber-500/30 text-amber-300 hover:bg-amber-500/25 transition-all"
                  title="Test login rejection for pending approval"
                >
                  ⏳ Pending
                </button>
                <button
                  type="button"
                  onClick={() => setDemoCredentials('hunter', 'rejected')}
                  className="px-2 py-1 rounded-md text-[10px] font-mono bg-rose-500/15 border border-rose-500/30 text-rose-300 hover:bg-rose-500/25 transition-all"
                  title="Test login rejection for rejected applicant"
                >
                  ✗ Rejected
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Authentication Card */}
        <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden">
          <div className="p-6 pb-4 border-b border-slate-800/80 bg-[#090F1D] flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Lock className="h-4 w-4 text-cyan-400" />
                <span>Secure Authentication</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Passwords verified via PBKDF2-HMAC-SHA256 (100,000 iterations).
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-300 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 font-semibold">
              {selectedRole.toUpperCase()}
            </span>
          </div>

          <div className="p-6 space-y-4">
            {state?.error && (
              <div className="p-3.5 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 text-xs flex items-center gap-2.5">
                <Info className="h-4 w-4 text-rose-400 shrink-0" />
                <span>{state.error}</span>
              </div>
            )}

            <form action={formAction} className="space-y-4">
              <input type="hidden" name="role" value={selectedRole} />

              <div className="space-y-1.5">
                <Label htmlFor="username" className="text-xs font-semibold text-slate-200">
                  Username
                </Label>
                <div className="relative">
                  <Input
                    id="username"
                    name="username"
                    placeholder="Enter username"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="bg-[#060A12] border-slate-700/80 text-white placeholder:text-slate-500 text-xs pl-10 h-10 rounded-xl focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  />
                  <User className="h-4 w-4 text-slate-500 absolute left-3.5 top-3" />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-xs font-semibold text-slate-200">
                  Password
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="••••••••••••"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="bg-[#060A12] border-slate-700/80 text-white placeholder:text-slate-500 text-xs pl-10 h-10 rounded-xl focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  />
                  <KeyRound className="h-4 w-4 text-slate-500 absolute left-3.5 top-3" />
                </div>
              </div>

              <div className="pt-2">
                <SubmitButton />
              </div>

              <div className="pt-3 text-center border-t border-slate-800/70">
                <p className="text-xs text-slate-400">
                  New threat & forensic analyst?{' '}
                  <Link
                    href="/hunter/register"
                    className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 decoration-cyan-500/50 hover:decoration-cyan-300 transition-colors"
                  >
                    Apply for Hunter Clearance →
                  </Link>
                </p>
              </div>
            </form>
          </div>

          <div className="px-6 py-4 border-t border-slate-800/80 bg-[#090F1D] flex flex-wrap items-center justify-center gap-4 text-[11px] text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              SHA-256 Audit Chain
            </span>
            <span>•</span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
              Session Encrypted
            </span>
            <span>•</span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-blue-400" />
              Role-Enforced
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
