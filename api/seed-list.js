// /api/seed-list  — bulk-set a list section (replaces existing contents).
// Body: { section: "dot-phrases", items: [...] }
// Auth: Bearer EDITOR_PASSWORD

import { setList, isKvConfigured } from '../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

const ALLOWED = new Set([
    'ebm', 'uw', 'abx-extras', 'uci-antibiogram',
    'uw-toc-overrides', 'usmle-toc-overrides', 'dot-phrases',
    // mksap intentionally NOT here — different auth model
]);

export const config = {
    api: { bodyParser: { sizeLimit: '4mb' } },
};

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'POST only' });
    }
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }
    const auth = checkAuth(req);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    const { section, items } = req.body || {};
    if (!section || !ALLOWED.has(section)) {
        return res.status(400).json({ error: 'section required; allowed: ' + [...ALLOWED].join(', ') });
    }
    if (!Array.isArray(items)) {
        return res.status(400).json({ error: 'items must be an array' });
    }

    try {
        await setList(section, items);
        return res.status(200).json({ ok: true, section, count: items.length });
    } catch (e) {
        console.error('api/seed-list error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
