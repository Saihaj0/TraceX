import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The API server runs on 127.0.0.1:8000 (FastAPI). During development Vite
// proxies /api so the frontend and backend share an origin.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});