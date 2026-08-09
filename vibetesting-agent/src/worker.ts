/**
 * Optional background worker — polls for queued scans.
 * Default API path processes scans inline; use this when SCAN_INLINE=0.
 *
 *   npm run worker
 */
import { eq } from 'drizzle-orm';
import { getDb, schema } from './lib/db';
import { processScan } from './lib/scans';

const POLL_MS = Number(process.env.WORKER_POLL_MS || 2000);

async function tick() {
  const db = await getDb();
  const queued = await db
    .select()
    .from(schema.scans)
    .where(eq(schema.scans.status, 'queued'))
    .limit(5);

  for (const scan of queued) {
    console.log(`[worker] processing ${scan.id} ${scan.url}`);
    await processScan(scan.id);
  }
}

console.log('[worker] VibeTesting Agent scan worker started');
for (;;) {
  try {
    await tick();
  } catch (err) {
    console.error('[worker] error', err);
  }
  await new Promise((r) => setTimeout(r, POLL_MS));
}
