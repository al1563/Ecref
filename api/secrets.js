// /api/secrets — KV-backed override for script.js's baked SECRETS object.
// Lets the in-browser change-password UI persist new ciphertexts without
// requiring a redeploy.
//
//   GET  /api/secrets  -> { secrets: {...} | null }   (public; ciphertext only)
//   PUT  /api/secrets  -> { ok: true }                (auth required)
//      Body: { secrets: { clinicalDocUrl: {ct, iv, salt}, patientsSheetUrl: {...} } }
//
// The values are AES-GCM ciphertexts that can only be decrypted with the
// matching password, so exposing them publicly is fine (same model as
// shipping them in script.js).

import { Redis } from '@upstash/redis';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';
import { isKvConfigured } from '../lib/kv.js';

const KEY = 'ecref:secrets';

function client() {
    return Redis.fromEnv();
}

function isValidSecret(s) {
    return s && typeof s.ct === 'string' && typeof s.iv === 'string' && typeof s.salt === 'string';
}

function sanitizeSecrets(input) {
    if (!input || typeof input !== 'object') return null;
    const out = {};
    for (const [k, v] of Object.entries(input)) {
        if (isValidSecret(v)) out[k] = { ct: v.ct, iv: v.iv, salt: v.salt };
    }
    return out;
}

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }

    try {
        if (req.method === 'GET') {
            const raw = await client().get(KEY);
            const parsed = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : null;
            res.setHeader('Cache-Control', 'public, max-age=0, s-maxage=10, must-revalidate');
            return res.status(200).json({ secrets: parsed });
        }

        if (req.method === 'PUT') {
            const auth = checkAuth(req);
            if (!auth.ok) return sendUnauthorized(res, auth.reason);

            const cleaned = sanitizeSecrets(req.body?.secrets);
            if (!cleaned || Object.keys(cleaned).length === 0) {
                return res.status(400).json({ error: 'secrets object required (each entry needs ct/iv/salt)' });
            }
            // Merge with existing — partial updates are fine
            const raw = await client().get(KEY);
            const existing = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : {};
            const merged = { ...existing, ...cleaned };
            await client().set(KEY, JSON.stringify(merged));
            return res.status(200).json({ ok: true, keys: Object.keys(merged) });
        }

        res.setHeader('Allow', 'GET, PUT');
        return res.status(405).json({ error: 'Method not allowed' });
    } catch (e) {
        console.error('api/secrets error:', e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
