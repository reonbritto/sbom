import './globals.css';
import { Navbar } from '@/components/Navbar';
import { Footer } from '@/components/Footer';
import { ThemeScript } from '@/components/ThemeScript';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'SBOM Vulnerability Analyzer',
  description: 'Upload an SBOM and track every vulnerability affecting its components.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <Navbar />
        <main className="mx-auto max-w-[1400px] px-6 py-8">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
