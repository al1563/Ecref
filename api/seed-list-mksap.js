// /api/seed-list-mksap  — bulk-set a list section gated by MKSAP_PASSWORD.
// Body: { section: "board-review", items: [...] }
// Auth: Bearer MKSAP_PASSWORD
//
// Sibling to /api/seed-list (EDITOR_PASSWORD) — kept separate so the two
// auth scopes don't have to share an endpoint.

import { setList, isKvConfigured } from '../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';
import { rejectIfBase64 } from '../lib/guard.js';

const ALLOWED = new Set(['board-review', 'abim-objectives']);

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

    const { section, items } = req.body || {};
    if (!section || !ALLOWED.has(section)) {
        return res.status(400).json({ error: 'section required; allowed: ' + [...ALLOWED].join(', ') });
    }
    if (!Array.isArray(items)) {
        return res.status(400).json({ error: 'items must be an array' });
    }
    if (rejectIfBase64(items, res)) return;

    try {
        await setList(section, items);
        return res.status(200).json({ ok: true, section, count: items.length });
    } catch (e) {
        console.error('api/seed-list-mksap error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
