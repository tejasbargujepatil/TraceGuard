/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['sanity', '@sanity/ui', '@sanity/icons', '@sanity/vision'],
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'cdn.sanity.io',
      },
    ],
  },
};

export default nextConfig;
