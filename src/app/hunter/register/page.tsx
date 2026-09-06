'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldCheck,
  User,
  Mail,
  Phone,
  CreditCard,
  FileCheck2,
  Award,
  Calendar,
  Lock,
  KeyRound,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Info,
  ShieldAlert,
  ArrowLeft,
  Building,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

export default function HunterRegisterPage() {
  const router = useRouter();

  // Form State
  const [formData, setFormData] = useState({
    // Personal / Identity
    name: '',
    email: '',
    mobile: '',
    aadhaar: '',
    pan: '',
    // Professional / Certification
    cert_name: '',
    cert_id: '',
    issuing_org: '',
    cert_expiry: '',
    professional_details: '',
    // Account
    username: '',
    password: '',
    confirm_password: '',
  });

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successData, setSuccessData] = useState<{
    application_id: string;
    username: string;
    message: string;
  } | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value }));
    setErrorMsg(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    // Basic Validation
    if (!formData.name.trim()) return setErrorMsg('Full Legal Name is required.');
    if (!formData.email.trim() || !formData.email.includes('@')) return setErrorMsg('A valid email address is required.');
    if (!formData.mobile.trim()) return setErrorMsg('Mobile phone number is required.');
    if (!formData.aadhaar.trim()) return setErrorMsg('Aadhaar number or identification detail is required.');
    if (!formData.pan.trim()) return setErrorMsg('PAN number is required for forensic clearance validation.');
    if (!formData.cert_name.trim() || !formData.cert_id.trim() || !formData.issuing_org.trim()) {
      return setErrorMsg('Global Certification details (Name, Credential ID, and Issuing Organization) are required.');
    }
    if (!formData.username.trim()) return setErrorMsg('Desired account username is required.');
    if (formData.password.length < 8) return setErrorMsg('Password must be at least 8 characters long.');
    if (formData.password !== formData.confirm_password) return setErrorMsg('Passwords do not match.');

    setLoading(true);

    try {
      const res = await fetch('http://localhost:9758/api/hunter/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await res.json();

      if (!res.ok || data.status !== 'success') {
        throw new Error(data.message || 'Registration failed. Please review your information.');
      }

      setSuccessData({
        application_id: data.application_id,
        username: formData.username,
        message: data.message,
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'Unable to connect to backend registration endpoint.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060A12] text-slate-100 flex flex-col justify-center items-center p-4 sm:p-6 lg:p-8 relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[450px] bg-gradient-to-b from-purple-600/10 via-cyan-600/5 to-transparent blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-900/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-3xl z-10 space-y-6">
        {/* Back Link & Navigation */}
        <div className="flex items-center justify-between">
          <Link
            href="/login"
            className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Return to Login Portal</span>
          </Link>
          <span className="text-[11px] font-mono uppercase tracking-widest text-purple-400/80 bg-purple-500/10 border border-purple-500/20 px-3 py-1 rounded-full">
            Specialized Role Application
          </span>
        </div>

        {/* Header Branding */}
        <div className="space-y-2 text-center">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-300 text-xs tracking-wider uppercase font-mono shadow-sm">
            <ShieldAlert className="h-4 w-4 text-purple-400" />
            <span>NTRO Threat & Forensic Hunter Intake</span>
          </div>
          <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white">
            Hunter Registration & Clearance
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto font-normal leading-relaxed">
            Apply for external triage access to authorized Forensic ISO Images, memory artifacts, and deep recovery verification.
          </p>
        </div>

        {/* Mandatory Clearance Notice */}
        <div className="p-4 rounded-2xl border border-amber-500/40 bg-gradient-to-r from-amber-950/30 to-[#0D1527] shadow-lg flex items-start gap-3.5">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 space-y-1">
            <div className="font-semibold text-amber-300 flex items-center gap-2">
              <span>Forensic Investigator Clearance Protocol Enforced</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                STATUS: PENDING_APPROVAL
              </span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Submitting this registration does <strong className="text-slate-200">NOT</strong> immediately grant system access.
              Your identity credentials and global certification will be reviewed and verified by an authorized{' '}
              <strong className="text-amber-200">Forensic Investigator</strong> before login eligibility is activated.
            </p>
          </div>
        </div>

        {/* Success Confirmation State */}
        {successData ? (
          <div className="bg-[#0D1527] border border-emerald-500/50 rounded-2xl p-8 shadow-2xl space-y-6 text-center animate-in fade-in-50">
            <div className="h-16 w-16 bg-emerald-500/15 border border-emerald-500/30 rounded-2xl flex items-center justify-center mx-auto text-emerald-400 shadow-lg shadow-emerald-950/40">
              <CheckCircle2 className="h-9 w-9" />
            </div>

            <div className="space-y-2">
              <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                APPLICATION SUBMITTED SUCCESSFULLY
              </span>
              <h2 className="text-2xl font-bold text-white">Registration Awaiting Clearance</h2>
              <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                {successData.message}
              </p>
            </div>

            <div className="bg-[#070C16] border border-slate-800 rounded-xl p-4 max-w-md mx-auto text-left space-y-2 font-mono text-xs">
              <div className="flex justify-between items-center text-slate-400">
                <span>Application Reference:</span>
                <span className="text-white font-bold">{successData.application_id}</span>
              </div>
              <div className="flex justify-between items-center text-slate-400">
                <span>Username Registered:</span>
                <span className="text-cyan-300">{successData.username}</span>
              </div>
              <div className="flex justify-between items-center text-slate-400">
                <span>Initial Account Status:</span>
                <span className="text-amber-400 font-semibold">PENDING_FORENSIC_APPROVAL</span>
              </div>
              <div className="flex justify-between items-center text-slate-400">
                <span>Audit Ledger Hash:</span>
                <span className="text-slate-500 text-[10px] truncate max-w-[160px]">SHA-256 RECORDED</span>
              </div>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/login" className="w-full sm:w-auto">
                <Button className="w-full sm:w-auto bg-cyan-600 hover:bg-cyan-500 text-white text-xs h-10 px-6 rounded-xl font-semibold shadow-lg shadow-cyan-950/50 flex items-center justify-center gap-2">
                  <span>Return to Login Portal</span>
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>
          </div>
        ) : (
          /* Registration Form */
          <form onSubmit={handleSubmit} className="space-y-6">
            {errorMsg && (
              <div className="p-3.5 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-200 text-xs flex items-center gap-2.5">
                <Info className="h-4 w-4 text-rose-400 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Section 1: Personal & Identity Information */}
            <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800/80">
                <div className="h-7 w-7 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                  <User className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">1. Personal & Identity Verification</h2>
                  <p className="text-[11px] text-slate-400">Government identification details for forensic chain-of-custody</p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="name" className="text-xs font-medium text-slate-200">
                    Full Legal Name <span className="text-rose-400">*</span>
                  </Label>
                  <Input
                    id="name"
                    name="name"
                    placeholder="e.g. Vikramaditya Sen"
                    value={formData.name}
                    onChange={handleChange}
                    required
                    className="bg-[#060A12] border-slate-800 text-white text-xs h-10 rounded-xl focus:border-cyan-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="email" className="text-xs font-medium text-slate-200">
                    Official / Primary Email <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="email"
                      name="email"
                      type="email"
                      placeholder="hunter@organization.in"
                      value={formData.email}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-cyan-500"
                    />
                    <Mail className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="mobile" className="text-xs font-medium text-slate-200">
                    Mobile Phone Number <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="mobile"
                      name="mobile"
                      placeholder="+91-9876543210"
                      value={formData.mobile}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-cyan-500"
                    />
                    <Phone className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="aadhaar" className="text-xs font-medium text-slate-200">
                    Aadhaar Number / Details <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="aadhaar"
                      name="aadhaar"
                      placeholder="XXXX-XXXX-XXXX"
                      value={formData.aadhaar}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-cyan-500 font-mono"
                    />
                    <CreditCard className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                  <p className="text-[10px] text-slate-500">Masked during dashboard review (last 4 digits inspected).</p>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="pan" className="text-xs font-medium text-slate-200">
                    PAN Card Details <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="pan"
                      name="pan"
                      placeholder="ABCDE1234F"
                      value={formData.pan}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-cyan-500 font-mono uppercase"
                    />
                    <CreditCard className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                  <p className="text-[10px] text-slate-500">Directly matched with tax authority registry.</p>
                </div>
              </div>
            </div>

            {/* Section 2: Professional & Global Certification Information */}
            <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800/80">
                <div className="h-7 w-7 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                  <Award className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">2. Global Certification & Professional Background</h2>
                  <p className="text-[11px] text-slate-400">Accredited cybersecurity & digital forensics credentials</p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="cert_name" className="text-xs font-medium text-slate-200">
                    Certification Name <span className="text-rose-400">*</span>
                  </Label>
                  <Input
                    id="cert_name"
                    name="cert_name"
                    placeholder="e.g. GIAC Certified Forensic Analyst (GCFA)"
                    value={formData.cert_name}
                    onChange={handleChange}
                    required
                    className="bg-[#060A12] border-slate-800 text-white text-xs h-10 rounded-xl focus:border-purple-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="cert_id" className="text-xs font-medium text-slate-200">
                    Certification Number / Credential ID <span className="text-rose-400">*</span>
                  </Label>
                  <Input
                    id="cert_id"
                    name="cert_id"
                    placeholder="e.g. GCFA-IND-884920"
                    value={formData.cert_id}
                    onChange={handleChange}
                    required
                    className="bg-[#060A12] border-slate-800 text-white text-xs h-10 rounded-xl focus:border-purple-500 font-mono"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="issuing_org" className="text-xs font-medium text-slate-200">
                    Issuing Organization <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="issuing_org"
                      name="issuing_org"
                      placeholder="e.g. SANS Institute / EC-Council / (ISC)²"
                      value={formData.issuing_org}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-purple-500"
                    />
                    <Building className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="cert_expiry" className="text-xs font-medium text-slate-200">
                    Validity / Expiry Date (if applicable)
                  </Label>
                  <div className="relative">
                    <Input
                      id="cert_expiry"
                      name="cert_expiry"
                      type="date"
                      value={formData.cert_expiry}
                      onChange={handleChange}
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-purple-500"
                    />
                    <Calendar className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="professional_details" className="text-xs font-medium text-slate-200">
                    Relevant Professional Details & Investigation Scope
                  </Label>
                  <Textarea
                    id="professional_details"
                    name="professional_details"
                    placeholder="Briefly describe your digital forensics experience, file system carving expertise, reverse engineering experience, or prior DFIR engagements..."
                    value={formData.professional_details}
                    onChange={handleChange}
                    rows={3}
                    className="bg-[#060A12] border-slate-800 text-white text-xs rounded-xl focus:border-purple-500 resize-none"
                  />
                </div>
              </div>
            </div>

            {/* Section 3: Account Information */}
            <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800/80">
                <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Lock className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">3. Account Credentials</h2>
                  <p className="text-[11px] text-slate-400">Login username and password for the Hunter Portal</p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="username" className="text-xs font-medium text-slate-200">
                    Username <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="username"
                      name="username"
                      placeholder="hunter_agent"
                      value={formData.username}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-emerald-500 font-mono"
                    />
                    <User className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="password" className="text-xs font-medium text-slate-200">
                    Password <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      name="password"
                      type="password"
                      placeholder="••••••••••••"
                      value={formData.password}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-emerald-500"
                    />
                    <KeyRound className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="confirm_password" className="text-xs font-medium text-slate-200">
                    Confirm Password <span className="text-rose-400">*</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="confirm_password"
                      name="confirm_password"
                      type="password"
                      placeholder="••••••••••••"
                      value={formData.confirm_password}
                      onChange={handleChange}
                      required
                      className="bg-[#060A12] border-slate-800 text-white text-xs pl-9 h-10 rounded-xl focus:border-emerald-500"
                    />
                    <KeyRound className="h-4 w-4 text-slate-500 absolute left-3 top-3" />
                  </div>
                </div>
              </div>
            </div>

            {/* Submission Action */}
            <div className="pt-2 space-y-3">
              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-semibold py-3.5 h-12 rounded-xl shadow-xl shadow-purple-950/50 transition-all flex items-center justify-center gap-2 text-sm hover:scale-[1.01]"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin text-white" />
                    <span>Submitting Hunter Application for Review...</span>
                  </>
                ) : (
                  <>
                    <FileCheck2 className="h-4 w-4" />
                    <span>Submit Registration for Forensic Approval</span>
                  </>
                )}
              </Button>

              <p className="text-[11px] text-center text-slate-500 font-mono">
                By submitting, you certify that all submitted identity records and global certifications are authentic and subject to statutory audit under the NTRO Security Framework.
              </p>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
