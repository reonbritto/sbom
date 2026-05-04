import { redirect } from 'next/navigation';
import { getSessionUser } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { SbomUploader } from '@/components/SbomUploader';
import { DemoButton } from '@/components/DemoButton';

export const dynamic = 'force-dynamic';

export default async function UploadPage() {
  const user = await getSessionUser();
  if (!user) redirect('/');

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Upload an SBOM</h1>
        <p className="text-sm text-muted-foreground mt-2">
          Upload a CycloneDX or SPDX JSON file. We&apos;ll parse the components, query OSV.dev for known vulnerabilities,
          enrich with EPSS exploit scores, OpenSSF Scorecard metadata, CISA KEV flags, and surface every CVE that affects your dependencies.
        </p>
      </div>
      <SbomUploader />
      <Card>
        <CardContent className="p-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <strong>Don&apos;t have an SBOM handy?</strong>
            <div className="text-xs text-muted-foreground mt-1">
              Load a curated demo with Log4Shell, prototype-pollution lodash, typosquats, and clean packages — every feature visible at a glance.
            </div>
          </div>
          <DemoButton label="Load demo" variant="default" />
        </CardContent>
      </Card>
    </div>
  );
}
