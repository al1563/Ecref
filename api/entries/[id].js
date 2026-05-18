// /api/entries/[id]  — single-entry endpoint
//   PUT    → update entry by id (auth required)
//   DELETE → remove entry by id (auth required)

import { updateEntry, deleteEntry, isKvConfigured } from '../../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../../lib/auth.js';

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }
    const auth = checkAuth(req);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'missing id' });

    try {
        if (req.method === 'PUT') {
            const patch = req.body || {};
            const updated = await updateEntry(id, patch);
            if (!updated) return res.status(404).json({ error: 'Entry not found' });
            return res.status(200).json({ entry: updated });
        }

        if (req.method === 'DELETE') {
            const ok = await deleteEntry(id);
            if (!ok) return res.status(404).json({ error: 'Entry not found' });
            return res.status(200).json({ ok: true });
        }

        res.setHeader('Allow', 'PUT, DELETE');
        return res.status(405).json({ error: 'Method not allowed' });
    } catch (e) {
        console.error('api/entries/[id] error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
