import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import fs from 'fs';

function copyManifestPlugin() {
  return {
    name: 'copy-manifest',
    closeBundle() {
      const manifestSrc = resolve(__dirname, 'manifest.json');
      const manifestDist = resolve(__dirname, 'dist', 'manifest.json');
      if (fs.existsSync(manifestSrc)) {
        fs.copyFileSync(manifestSrc, manifestDist);
      }
      // Also copy icons directory if it exists
      const iconsSrc = resolve(__dirname, 'icons');
      const iconsDist = resolve(__dirname, 'dist', 'icons');
      if (fs.existsSync(iconsSrc)) {
        fs.cpSync(iconsSrc, iconsDist, { recursive: true });
      }
    },
  };
}

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: process.env.NODE_ENV !== 'production',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        options: resolve(__dirname, 'options.html'),
        warning: resolve(__dirname, 'warning.html'),
        'service-worker': resolve(__dirname, 'src/background/service-worker.ts'),
        'link-guard': resolve(__dirname, 'src/content/link-guard.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'service-worker') {
            return 'service-worker.js';
          }
          if (chunkInfo.name === 'link-guard') {
            return 'link-guard.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
  plugins: [copyManifestPlugin()],
  test: {
    environment: 'node',
    globals: true,
  },
});

