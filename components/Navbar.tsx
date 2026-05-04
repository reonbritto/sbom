'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldCheck } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';
import { Button } from './ui/button';
import { signOut, useSession } from '@/lib/auth-client';

export function Navbar() {
  const router = useRouter();
  const { data: session, isPending } = useSession();
  const signedIn = !!session?.user && !isPending;

  async function handleSignOut() {
    await signOut();
    router.refresh();
  }

  return (
    <nav className="sticky top-0 z-40 border-b border-border bg-card/80 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center justify-between px-6">
        <div className="flex items-center gap-2">
          <ShieldCheck size={20} className="text-primary" />
          <Link href="/" className="font-semibold">SBOM Vulnerability Analyzer</Link>
        </div>
        <div className="flex items-center gap-1">
          {signedIn && (
            <>
              <Button asChild variant="ghost" size="sm"><Link href="/">Dashboard</Link></Button>
              <Button asChild variant="ghost" size="sm"><Link href="/upload">Upload</Link></Button>
              <Button asChild variant="ghost" size="sm"><a href="/api/docs">API Docs</a></Button>
            </>
          )}
          <ThemeToggle />
          {signedIn && (
            <div className="flex items-center gap-2 ml-2">
              <span className="text-xs text-muted-foreground hidden md:inline">{session?.user.email ?? session?.user.name}</span>
              <Button variant="outline" size="sm" onClick={handleSignOut}>Logout</Button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
