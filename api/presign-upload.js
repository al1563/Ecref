// /api/presign-upload — returns a presigned R2 PUT URL for direct browser upload.
//
// Vercel's serverless functions cap request bodies at 4.5 MB. For larger
// images, the client requests a presigned URL here (tiny request) and then
// PUTs the file bytes straight to R2 (no Vercel hop). R2 has a 5 TB per-
// object limit so this scales effectively without bound.
//
// Body: { filename: "foo.png", contentType: "image/png" }
// Auth: Bearer EDITOR_PASSWORD
// Response: { uploadUrl: "<signed-r2-url>", publicUrl: "<r2-public-url>" }
//
// NB: R2 bucket must allow PUT from this site's origin via CORS. The user
// applies that one-time via Cloudflare dashboard: R2 → bucket → Settings →
// CORS Policy.

import { presignPut, isR2Configured } from '../lib/r2.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

function slugify(text, maxlen = 40) {
    return (text || 'img')
        .toLowerCase()
        .replace(/\.[^.]+$/, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, maxlen) || 'img';
}

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'Method not allowed' });
    }
    if (!isR2Configured()) {
        return res.status(503).json({ error: 'R2 not configured on this deployment' });
    }
    const auth = checkAuth(req);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    try {
        const { filename, contentType } = req.body || {};
        if (!filename || !contentType) {
            return res.status(400).json({ error: 'filename and contentType required' });
        }
        if (!contentType.startsWith('image/')) {
            return res.status(400).json({ error: 'Only image content types allowed' });
        }
        const ext = (filename.split('.').pop() || 'bin').toLowerCase();
        const key = `images/${slugify(filename)}-${Date.now()}.${ext}`;
        const { uploadUrl, publicUrl } = await presignPut({ key, contentType });
        return res.status(200).json({ uploadUrl, publicUrl, key });
    } catch (e) {
        console.error('api/presign-upload error:', e);
        return res.status(500).json({ error: e.message || 'Presign failed' });
    }
}
