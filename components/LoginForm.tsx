'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { signIn, signUp } from '@/lib/auth-client';
import { Button } from './ui/button';
import { Input } from './ui/input';

export function LoginForm() {
  const router = useRouter();
  const [mode, setMode] = useState<'sign-in' | 'sign-up'>('sign-in');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const fd = new FormData(e.currentTarget);
    const email = String(fd.get('email') ?? '').trim();
    const password = String(fd.get('password') ?? '');
    const name = String(fd.get('name') ?? '').trim();

    try {
      if (mode === 'sign-up') {
        const { error } = await signUp.email({
          email,
          password,
          name: name || email.split('@')[0],
        });
        if (error) {
          setError(error.message ?? 'Sign-up failed');
          setLoading(false);
          return;
        }
      } else {
        const { error } = await signIn.email({ email, password });
        if (error) {
          setError(error.message ?? 'Invalid email or password');
          setLoading(false);
          return;
        }
      }
      router.refresh();
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          {mode === 'sign-in' ? 'Welcome back' : 'Create your account'}
        </h1>
        <p className="text-sm text-muted-foreground">
          {mode === 'sign-in'
            ? 'Sign in to upload SBOMs and view your vulnerability analyses.'
            : 'Sign up to start analyzing your software bill of materials.'}
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-3">
        {mode === 'sign-up' && (
          <div className="space-y-1.5">
            <label htmlFor="name" className="text-xs font-medium text-muted-foreground">Name</label>
            <Input id="name" name="name" type="text" placeholder="Your name" autoComplete="name" />
          </div>
        )}
        <div className="space-y-1.5">
          <label htmlFor="email" className="text-xs font-medium text-muted-foreground">Email</label>
          <Input id="email" name="email" type="email" placeholder="you@example.com" autoComplete="email" required />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="password" className="text-xs font-medium text-muted-foreground">Password</label>
          <Input id="password" name="password" type="password" placeholder={mode === 'sign-up' ? 'At least 8 characters' : '••••••••'} autoComplete={mode === 'sign-up' ? 'new-password' : 'current-password'} minLength={8} required />
        </div>
        {error && <p className="text-xs text-critical">{error}</p>}
        <Button type="submit" size="lg" className="w-full" disabled={loading}>
          {loading && <Loader2 size={14} className="spin" />}
          {mode === 'sign-in' ? 'Sign in' : 'Create account'}
        </Button>
      </form>

      <div className="relative text-center text-xs text-muted-foreground after:absolute after:inset-0 after:top-1/2 after:z-0 after:flex after:items-center after:border-t after:border-border">
        <span className="relative z-10 bg-background px-2">
          {mode === 'sign-in' ? 'New here?' : 'Already have an account?'}
        </span>
      </div>

      <Button
        type="button"
        variant="outline"
        className="w-full"
        onClick={() => { setError(null); setMode(mode === 'sign-in' ? 'sign-up' : 'sign-in'); }}
      >
        {mode === 'sign-in' ? 'Create an account' : 'Sign in instead'}
      </Button>

      <p className="text-center text-xs text-muted-foreground">
        Self-hosted authentication. Your password is hashed with Argon2id and stored in your own database — no third-party identity provider.
      </p>
    </div>
  );
}
