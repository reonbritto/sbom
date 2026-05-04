export function Footer() {
  return (
    <footer className="mx-auto max-w-[1400px] px-6 py-8 text-xs text-muted-foreground">
      Vulnerability data from{' '}
      <a className="text-primary hover:underline" href="https://osv.dev" target="_blank" rel="noreferrer">osv.dev</a>,
      {' '}exploit scoring from{' '}
      <a className="text-primary hover:underline" href="https://www.first.org/epss" target="_blank" rel="noreferrer">FIRST EPSS</a>,
      {' '}package reputation from{' '}
      <a className="text-primary hover:underline" href="https://deps.dev" target="_blank" rel="noreferrer">deps.dev</a>,
      {' '}KEV from{' '}
      <a className="text-primary hover:underline" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer">CISA</a>.
    </footer>
  );
}
