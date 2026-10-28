import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard calls /api/*, which is proxied to the FastAPI backend.
export default defineConfig({
  plugins: [react()],
  // three.js lives in its own lazy-loaded chunk (src/three/), fetched only when a 3D view shows.
  build: { chunkSizeWarningLimit: 900 },
  test: { environment: 'jsdom', include: ['src/**/*.test.{js,jsx}'], setupFiles: ['src/test-setup.js'] },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.SENTINEL_API ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
