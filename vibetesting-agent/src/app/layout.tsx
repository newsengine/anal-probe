import type { Metadata } from 'next';
import { headers } from 'next/headers';
import { IBM_Plex_Sans, JetBrains_Mono } from 'next/font/google';
import { AgentSetupBar, SiteFooter } from '@/components/agent-setup-links';
import './globals.css';

const sans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
});

const mono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '700', '800'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'VibeTesting Agent — security scans for vibe-coded apps',
  description:
    'Black-box security for AI-built software. Free lite scan on the homepage. Hosted plans: Casual Coding $25 · Business Prototyping $100 · Mission Critical $250. Ownership verification required. Open-source scanner included.',
  metadataBase: new URL('https://vibetestingagent.com'),
  alternates: {
    canonical: 'https://vibetestingagent.com',
  },
  openGraph: {
    title: 'VibeTesting Agent',
    description: 'Ship with vibe. Scan before customers—bad guys—do.',
    url: 'https://vibetestingagent.com',
    siteName: 'VibeTesting Agent',
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'VibeTesting Agent',
  applicationCategory: 'SecurityApplication',
  operatingSystem: 'Web',
  url: 'https://vibetestingagent.com',
  description:
    'Black-box security scanning for vibe-coded apps. Free lite scan; paid continuous full scans after ownership verification.',
  offers: {
    '@type': 'AggregateOffer',
    lowPrice: '0',
    highPrice: '250',
    priceCurrency: 'USD',
  },
  provider: {
    '@type': 'Organization',
    name: 'Newsengine',
    url: 'https://vibetestingagent.com',
  },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? undefined;

  return (
    <html lang="en">
      <body className={`${sans.variable} ${mono.variable} antialiased flex min-h-screen flex-col`}>
        <script
          type="application/ld+json"
          nonce={nonce}
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <AgentSetupBar />
        <div className="flex flex-1 flex-col">{children}</div>
        <SiteFooter />
      </body>
    </html>
  );
}
