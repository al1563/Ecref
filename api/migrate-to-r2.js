// /api/migrate-to-r2  — one-shot bulk migration of repo-tracked PDFs +
// page JPGs to Cloudflare R2.
//
// The function fetches each file from its own deployment (same-origin
// HTTPS) and PUTs it to R2 under the same path. Deterministic keys, so
// re-running is idempotent.
//
// Usage:
//   curl -X POST "https://ecref-git-reference-tab-XXX.vercel.app/api/migrate-to-r2?batch=pdfs" \
//     -H "Authorization: Bearer YOUR_EDITOR_PASSWORD"
//
// Batches: pdfs | abx | mgh-1 | mgh-2 | mgh-3 | uw
// (MGH is split into thirds so each batch fits in the 60s function timeout)
//
// DELETE THIS FILE AFTER MIGRATION COMPLETES.

import { uploadImage, isR2Configured } from '../lib/r2.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

const range = (n, prefix, pad = 3) =>
    Array.from({ length: n }, (_, i) => `${prefix}${String(i + 1).padStart(pad, '0')}.jpg`);

// MGH chopped to 270 pages; UWORLD to 163; abx-guide to 1.
const BATCHES = {
    pdfs:  [
        'docs/MGH-2526-handbook.pdf',
        'docs/UWORLD_boards_flow_sheet_tables.pdf',
        'docs/nu-introductory-guide-to-antibiotics.pdf',
        'docs/abx_venn.png',
    ],
    abx:   ['docs/abx-guide-pages/page-1.jpg'],
    'mgh-1': range(90,  'docs/mgh-pages/page-'),                 // 001-090
    'mgh-2': Array.from({length: 90}, (_, i) => `docs/mgh-pages/page-${String(i+91).padStart(3,'0')}.jpg`),  // 091-180
    'mgh-3': Array.from({length: 90}, (_, i) => `docs/mgh-pages/page-${String(i+181).padStart(3,'0')}.jpg`), // 181-270
    'uw':    range(163, 'docs/uw-flowsheets-pages/page-'),
};

const MIME = {
    pdf:  'application/pdf',
    jpg:  'image/jpeg',
    jpeg: 'image/jpeg',
    png:  'image/png',
};

// Vercel function config — give it time + parallelize within batch
export const config = { maxDuration: 60 };
const CONCURRENCY = 8;

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'POST only' });
    }
    if (!isR2Configured()) {
        return res.status(503).json({ error: 'R2 not configured on this deployment' });
    }
    const auth = checkAuth(req);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    const batch = (req.query.batch || 'pdfs').toString();
    const paths = BATCHES[batch];
    if (!paths) {
        return res.status(400).json({ error: `unknown batch: ${batch}`, available: Object.keys(BATCHES) });
    }

    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const base = `${proto}://${host}`;

    const results = [];
    let cursor = 0;

    async function worker() {
        while (cursor < paths.length) {
            const idx = cursor++;
            const p = paths[idx];
            try {
                const r = await fetch(`${base}/${p}`);
                if (!r.ok) throw new Error(`fetch ${p}: HTTP ${r.status}`);
                const buf = Buffer.from(await r.arrayBuffer());
                const ext = (p.split('.').pop() || '').toLowerCase();
                const ctype = MIME[ext] || 'application/octet-stream';
                const url = await uploadImage({ key: p, contentBuffer: buf, contentType: ctype });
                results.push({ path: p, url, bytes: buf.length });
            } catch (e) {
                results.push({ path: p, error: e.message });
            }
        }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, worker));

    const ok = results.filter(r => !r.error).length;
    const failed = results.filter(r => r.error);
    return res.status(200).json({
        batch,
        attempted: paths.length,
        succeeded: ok,
        failed: failed.length,
        publicUrlPrefix: process.env.R2_PUBLIC_URL,
        failures: failed.slice(0, 20),  // cap for response size
    });
}
