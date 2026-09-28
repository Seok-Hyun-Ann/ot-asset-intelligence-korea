import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';

// 폐쇄망 요구(NFR-OFF-001): 번들이 자기완결이어야 한다.
// 외부 CDN 을 참조하지 않고 전부 번들에 넣는다.
export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: {
    outDir: '../web/dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    rollupOptions: {output: {manualChunks: {vendor: ['react', 'react-dom', 'cytoscape']}}},
  },
  server: {proxy: {'/api': 'http://127.0.0.1:8000'}},
});
