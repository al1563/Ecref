// /api/list/[section]  — collection-level for Reference tab lists
//   GET    → list all items
//   POST   → add a new item (auth required)
//
// Sections:
//   ebm, uw, abx-extras  → public read, EDITOR_PASSWORD for write
//   mksap                → MKSAP_PASSWORD required for both read & write

import { getList, addListItem, isKvConfigured } from '../../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../../lib/auth.js';
import { rejectIfBase64 } from '../../lib/guard.js';

const SECTIONS = {
    'ebm':                { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'uw':                 { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'abx-extras':         { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'uci-antibiogram':    { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'uw-toc-overrides':   { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'usmle-toc-overrides':{ writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'dot-phrases':        { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'core-im':            { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'cps-illness':        { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'cps-schemas':        { writeAuth: 'EDITOR_PASSWORD', publicRead: true  },
    'board-review':       { writeAuth: 'MKSAP_PASSWORD',  publicRead: false },
    'abim-objectives':    { writeAuth: 'MKSAP_PASSWORD',  publicRead: false },
    'mksap':              { writeAuth: 'MKSAP_PASSWORD',  publicRead: false },
};

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }

    const { section } = req.query;
    const cfg = SECTIONS[section];
    if (!cfg) return res.status(404).json({ error: `unknown section: ${section}` });

    try {
        if (req.method === 'GET') {
            if (!cfg.publicRead) {
                const auth = checkAuth(req, cfg.writeAuth);
                if (!auth.ok) return sendUnauthorized(res, auth.reason);
            }
            const items = await getList(section);
            res.setHeader('Cache-Control', 'public, max-age=0, s-maxage=10, must-revalidate');
            return res.status(200).json({ items });
        }

        if (req.method === 'POST') {
            const auth = checkAuth(req, cfg.writeAuth);
            if (!auth.ok) return sendUnauthorized(res, auth.reason);
            const item = req.body;
            if (!item || !item.id) return res.status(400).json({ error: 'item.id is required' });
            if (rejectIfBase64(item, res)) return;
            const saved = await addListItem(section, item);
            return res.status(201).json({ item: saved });
        }

        res.setHeader('Allow', 'GET, POST');
        return res.status(405).json({ error: 'Method not allowed' });
    } catch (e) {
        console.error(`api/list/${section} error:`, e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
