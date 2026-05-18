// /api/upload-image  — uploads image to Cloudflare R2, returns public URL.
// Body: { filename: "foo.png", contentB64: "...", contentType: "image/png" }
// Auth: Bearer EDITOR_PASSWORD

import { uploadImage, isR2Configured } from '../lib/r2.js';
import { checkAuth, sendUnauthorized } from '../lib/auth.js';

// Vercel function config — bump body size since images can be > default 1 MB
export const config = {
    api: {
        bodyParser: { sizeLimit: '8mb' },
    },
};

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
        const { filename, contentB64, contentType } = req.body || {};
        if (!filename || !contentB64 || !contentType) {
            return res.status(400).json({ error: 'filename, contentB64, contentType required' });
        }
        if (!contentType.startsWith('image/')) {
            return res.status(400).json({ error: 'Only image content types allowed' });
        }
        const buf = Buffer.from(contentB64, 'base64');
        if (buf.length > 8 * 1024 * 1024) {
            return res.status(413).json({ error: 'Image too large (8 MB max)' });
        }
        const ext = (filename.split('.').pop() || 'bin').toLowerCase();
        const key = `images/${slugify(filename)}-${Date.now()}.${ext}`;
        const url = await uploadImage({ key, contentBuffer: buf, contentType });
        return res.status(201).json({ url, key });
    } catch (e) {
        console.error('api/upload-image error:', e);
        return res.status(500).json({ error: e.message || 'Upload failed' });
    }
}
