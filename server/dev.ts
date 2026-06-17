/**
 * Standalone Express dev server — runs on port 3001
 * Vite dev server (port 8080) proxies all /api/* calls here.
 *
 * WHY separate servers?
 * Vite's built-in middleware pipeline has its own body size cap that
 * intercepts multipart requests BEFORE Express ever sees them.
 * Running Express on its own port completely bypasses that limit,
 * allowing uploads up to 15 GB.
 *
 * Start with:  npx tsx server/dev.ts
 */

import { createServer } from "./index.ts";

const app  = createServer();
const PORT = process.env.EXPRESS_PORT ?? 3001;

app.listen(PORT, () => {
  console.log(`\n🚀 ATL Express API server running on http://localhost:${PORT}`);
  console.log(`   Vite frontend:  http://localhost:8080`);
  console.log(`   ML Engine:      http://localhost:5001\n`);
});
