// /api/health  — diagnostic for KV + R2 + auth configuration.
// Public (no auth) so you can hit it from a browser to debug setup.
// Returns env var presence as boolean — never the values themselves.

import { isKvConfigured } from '../lib/kv.js';
import { isR2Configured } from '../lib/r2.js';

export default async function handler(req, res) {
    const present = name => !!process.env[name];
    res.status(200).json({
        kv: {
            configured: isKvConfigured(),
            vars: {
                KV_REST_API_URL: present('KV_REST_API_URL'),
                KV_REST_API_TOKEN: present('KV_REST_API_TOKEN'),
                UPSTASH_REDIS_REST_URL: present('UPSTASH_REDIS_REST_URL'),
                UPSTASH_REDIS_REST_TOKEN: present('UPSTASH_REDIS_REST_TOKEN'),
            },
        },
        r2: {
            configured: isR2Configured(),
            vars: {
                R2_ACCOUNT_ID: present('R2_ACCOUNT_ID'),
                R2_ACCESS_KEY_ID: present('R2_ACCESS_KEY_ID'),
                R2_SECRET_ACCESS_KEY: present('R2_SECRET_ACCESS_KEY'),
                R2_BUCKET: present('R2_BUCKET'),
                R2_PUBLIC_URL: present('R2_PUBLIC_URL'),
            },
        },
        auth: {
            EDITOR_PASSWORD: present('EDITOR_PASSWORD'),
            MKSAP_PASSWORD: present('MKSAP_PASSWORD'),
        },
    });
}
