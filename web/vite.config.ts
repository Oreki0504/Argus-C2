import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    ...(mode === 'mock'
      ? [
          {
            name: 'argus-development-worker',
            configureServer(server: import('vite').ViteDevServer) {
              server.middlewares.use('/mockServiceWorker.js', (_req, res) => {
                const require = createRequire(import.meta.url)
                res.setHeader('Content-Type', 'application/javascript')
                res.setHeader('Cache-Control', 'no-store')
                res.end(
                  readFileSync(
                    join(dirname(require.resolve('msw/package.json')), 'lib/mockServiceWorker.js'),
                  ),
                )
              })
            },
          },
        ]
      : []),
  ],
  // Do not proxy Fleet credentials or relax TLS/Origin checks. Live development
  // needs a same-origin HTTPS Console integration (see docs/web-design.md).
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  publicDir: false,
}))
