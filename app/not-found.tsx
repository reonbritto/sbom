import Link from 'next/link';
import { Button } from '@/components/ui/button';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center text-center gap-4 py-24">
      <h1 className="text-5xl font-bold tracking-tight">404</h1>
      <p className="text-muted-foreground">That resource could not be found.</p>
      <Button asChild><Link href="/">Back to dashboard</Link></Button>
    </div>
  );
}
