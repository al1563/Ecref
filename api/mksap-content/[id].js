// /api/mksap-content/[id]  — returns the full HTML body for one MKSAP topic.
// Auth: Bearer MKSAP_PASSWORD.

import { getMksapBody, isKvConfigured } from '../../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../../lib/auth.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        res.setHeader('Allow', 'GET');
        return res.status(405).json({ error: 'GET only' });
    }
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }
    const auth = checkAuth(req, 'MKSAP_PASSWORD');
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'missing id' });

    try {
        const body = await getMksapBody(id);
        if (body === null) return res.status(404).json({ error: 'topic not found' });
        // Bodies are immutable after seed — cache aggressively on the CDN edge.
        res.setHeader('Cache-Control', 'private, max-age=300, s-maxage=300, stale-while-revalidate=86400');
        return res.status(200).json({ id, body });
    } catch (e) {
        console.error(`api/mksap-content/${id} error:`, e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
