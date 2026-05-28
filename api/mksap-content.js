// /api/mksap-content  — returns the MKSAP topic index.
// Each entry: { id, title, subspecialty, subspecialtyName, chapter, keyPoints }
// Auth: Bearer MKSAP_PASSWORD (same gate as the legacy mksap notes section).

import { getMksapIndex, isKvConfigured } from '../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

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

    try {
        const index = await getMksapIndex();
        res.setHeader('Cache-Control', 'private, max-age=0, s-maxage=10, must-revalidate');
        return res.status(200).json({ index });
    } catch (e) {
        console.error('api/mksap-content error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
