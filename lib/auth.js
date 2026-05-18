// Bearer-token auth for editor write operations.
// Compares the incoming token against process.env.EDITOR_PASSWORD with a
// constant-time comparison to defeat timing attacks.

import crypto from 'crypto';

export function checkAuth(req) {
    const expected = process.env.EDITOR_PASSWORD;
    if (!expected) return { ok: false, reason: 'EDITOR_PASSWORD not set on server' };

    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return { ok: false, reason: 'missing bearer token' };
    const token = header.slice(7);

    try {
        const a = Buffer.from(token, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        if (a.length !== b.length) return { ok: false, reason: 'wrong password' };
        if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'wrong password' };
        return { ok: true };
    } catch (e) {
        return { ok: false, reason: 'bad token format' };
    }
}

// Helper: send a 401 response with reason. Always returns null so callers
// can `return sendUnauthorized(res, reason)` to short-circuit.
export function sendUnauthorized(res, reason) {
    res.status(401).json({ error: 'Unauthorized', reason });
    return null;
}
