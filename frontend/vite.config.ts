import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    target: 'es2022',
    // Inline assets would require relaxing the CSP (data: URIs) — keep everything as files.
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
        },
      },
    },
  },
  server: {
    port: 5173,
    // Local development against the dockerised stack (gateway on https://localhost).
    proxy: {
      '/api': { target: 'https://localhost', changeOrigin: false, secure: false },
    },
  },
});
