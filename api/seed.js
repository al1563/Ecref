// /api/seed  — one-time / occasional bulk import
//   POST { database: [...] }  → replace entire KV contents with this array
//
// Use to import reference_data.json on first KV setup, or to restore from a
// backup. Always requires auth.

import { setAllEntries, isKvConfigured } from '../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';
import { rejectIfBase64 } from '../lib/guard.js';

export const config = {
    api: { bodyParser: { sizeLimit: '8mb' } },
};

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'Method not allowed' });
    }
    const auth = checkAuth(req);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    try {
        const { database } = req.body || {};
        if (!Array.isArray(database)) {
            return res.status(400).json({ error: 'request body must be { database: [...] }' });
        }
        if (rejectIfBase64(database, res)) return;
        await setAllEntries(database);
        return res.status(200).json({ count: database.length });
    } catch (e) {
        console.error('api/seed error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
