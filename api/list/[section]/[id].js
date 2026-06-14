// /api/list/[section]/[id]  — single-item endpoint for Reference tab lists
//   PUT    → update item (auth required)
//   DELETE → remove item (auth required)

import { updateListItem, deleteListItem, isKvConfigured } from '../../../lib/kv.js';
import { checkAuth, sendUnauthorized } from '../../../lib/auth.js';
import { rejectIfBase64 } from '../../../lib/guard.js';

const SECTIONS = {
    'ebm':                { writeAuth: 'EDITOR_PASSWORD' },
    'uw':                 { writeAuth: 'EDITOR_PASSWORD' },
    'abx-extras':         { writeAuth: 'EDITOR_PASSWORD' },
    'uci-antibiogram':    { writeAuth: 'EDITOR_PASSWORD' },
    'uw-toc-overrides':   { writeAuth: 'EDITOR_PASSWORD' },
    'usmle-toc-overrides':{ writeAuth: 'EDITOR_PASSWORD' },
    'dot-phrases':        { writeAuth: 'EDITOR_PASSWORD' },
    'core-im':            { writeAuth: 'EDITOR_PASSWORD' },
    'cps-illness':        { writeAuth: 'EDITOR_PASSWORD' },
    'cps-schemas':        { writeAuth: 'EDITOR_PASSWORD' },
    'board-review':       { writeAuth: 'MKSAP_PASSWORD'  },
    'abim-objectives':    { writeAuth: 'MKSAP_PASSWORD'  },
    'mksap':              { writeAuth: 'MKSAP_PASSWORD'  },
};

export default async function handler(req, res) {
    if (!isKvConfigured()) {
        return res.status(503).json({ error: 'KV not configured on this deployment' });
    }

    const { section, id } = req.query;
    const cfg = SECTIONS[section];
    if (!cfg) return res.status(404).json({ error: `unknown section: ${section}` });
    if (!id) return res.status(400).json({ error: 'missing id' });

    const auth = checkAuth(req, cfg.writeAuth);
    if (!auth.ok) return sendUnauthorized(res, auth.reason);

    try {
        if (req.method === 'PUT') {
            const patch = req.body || {};
            if (rejectIfBase64(patch, res)) return;
            const updated = await updateListItem(section, id, patch);
            if (!updated) return res.status(404).json({ error: 'Item not found' });
            return res.status(200).json({ item: updated });
        }

        if (req.method === 'DELETE') {
            const ok = await deleteListItem(section, id);
            if (!ok) return res.status(404).json({ error: 'Item not found' });
            return res.status(200).json({ ok: true });
        }

        res.setHeader('Allow', 'PUT, DELETE');
        return res.status(405).json({ error: 'Method not allowed' });
    } catch (e) {
        console.error(`api/list/${section}/${id} error:`, e);
        return res.status(500).json({ error: e.message || 'Server error' });
    }
}
