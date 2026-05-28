// /api/mksap-content/seed  — bulk write the MKSAP topic store.
// Body: { index?: [...], bodies?: { id: "<html>", ... } }
// Either or both keys may be present. Allows batched seeding from the
// client so the request stays under Vercel's body-size limit.
// Auth: Bearer MKSAP_PASSWORD.

import { setMksapIndex, setMksapBody, isKvConfigured } from '../../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../../lib/auth.js';

export const config = {
    api: { bodyParser: { sizeLimit: '8mb' } },
};

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'POST only' });
    }
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }
    const auth = checkAuth(req, 'MKSAP_PASSWORD');
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    const { index, bodies } = req.body || {};
    let indexCount = 0, bodyCount = 0;

    try {
        if (Array.isArray(index)) {
            await setMksapIndex(index);
            indexCount = index.length;
        }
        if (bodies && typeof bodies === 'object') {
            // Set each body separately — each value comfortably under the
            // Upstash per-command limit.
            for (const [id, html] of Object.entries(bodies)) {
                if (!id || typeof html !== 'string') continue;
                await setMksapBody(id, html);
                bodyCount++;
            }
        }
        return res.status(200).json({ ok: true, indexCount, bodyCount });
    } catch (e) {
        console.error('api/mksap-content/seed error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
