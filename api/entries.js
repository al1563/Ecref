// /api/entries  — collection-level endpoint
//   GET    → list all KB entries
//   POST   → add a new entry (auth required)

import { getAllEntries, addEntry, isKvConfigured } from '../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }

    try {
        if (req.method === 'GET') {
            const entries = await getAllEntries();
            // Cache-control: brief CDN cache, must-revalidate so edits show up fast
            res.setHeader('Cache-Control', 'public, max-age=0, s-maxage=10, must-revalidate');
            return res.status(200).json({ database: entries });
        }

        if (req.method === 'POST') {
            const auth = checkAuth(req);
            if (!auth.ok) return sendUnauthorized(res, auth.reason);
            const entry = req.body;
            if (!entry || !entry.id) {
                return res.status(400).json({ error: 'entry.id is required' });
            }
            const saved = await addEntry(entry);
            return res.status(201).json({ entry: saved });
        }

        res.setHeader('Allow', 'GET, POST');
        return res.status(405).json({ error: 'Method not allowed' });
    } catch (e) {
        console.error('api/entries error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
