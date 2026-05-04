/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    serverActions: { bodySizeLimit: '12mb' },
  },
  serverExternalPackages: ['ioredis', '@prisma/client', 'prom-client'],
};

export default nextConfig;
