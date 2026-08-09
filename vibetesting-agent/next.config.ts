import type { NextConfig } from 'next';
import path from 'node:path';

const nextConfig: NextConfig = {
  // better-sqlite3 is Node-only (local dev); Workers use D1
  serverExternalPackages: ['better-sqlite3'],
  turbopack: {
    root: path.join(__dirname),
  },
  // Security headers live in src/middleware.ts (single source — avoids duplicate header values)
};

export default nextConfig;

// Enable Cloudflare bindings during `next dev` when OpenNext is installed
import { initOpenNextCloudflareForDev } from '@opennextjs/cloudflare';
initOpenNextCloudflareForDev();
