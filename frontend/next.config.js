/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // Allow API calls to backend
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: process.env.NEXT_PUBLIC_API_URL 
          ? `${process.env.NEXT_PUBLIC_API_URL}/:path*`
          : 'http://backend:8000/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
