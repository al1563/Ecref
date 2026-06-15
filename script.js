// =========================================================================
// Medical Reference — application script
// =========================================================================

// Encrypted URLs. Regenerate with tools/encrypt-urls.html when rotating the
// password or updating the Google Sheet/Doc.
// AES-GCM(256) ciphertext + iv + salt, base64-encoded. PBKDF2-SHA256, 200k iter.
const SECRETS = {
  "clinicalDocUrl": {
    "ct": "19vVXKkOWJBThT+9jeluG8IMzwQ5JmJRlVQ+58J9ZJqE5VEWlMJ6bqq4WQgfV8MDVmO4+yXnX5IKADgDaerkG8AHp7lZdwoQwdw93jGVS0vAuryFUg+EoM60gICX5Yx8rhoy9XkRqacZhK5uD8ZHtg==",
    "iv": "Hcflkazrvu2JJX29",
    "salt": "CBk7wJtAsMdS3rmbE1EDLw=="
  },
  "patientsSheetUrl": {
    "ct": "RnmvlZw+bQ3pQDjTbwBqX08Eb2TaFIg49LljU/OJJmNqu0aJ5q5CpLr7uRSSlkTEBwnAU/vVN3jNYcATmfAGw5OMjcm+jo7TiHc8V31eCCWOduC8hUGGQfLdjHMQQeSFRwGIlckJo43SgQTyxfiOjf/fCNw=",
    "iv": "1Yr9FGeE1TzNGBnC",
    "salt": "g7GMdxWiS0LyVellK2qDPQ=="
  },
  "mksapSentinel": {
    "ct": "O/9y43+jn/28v8M255IQI/Mj9kvyi3W2xQ6+6JfD",
    "iv": "smy8H6a8eFiell/j",
    "salt": "/xfXFIfaF/cpC1f5l/3QXA=="
  }
};
const MKSAP_SENTINEL_PLAINTEXT = 'MKSAP_UNLOCKED';
const PBKDF2_ITER = 200000;

// =========================================================================
// Boot
// =========================================================================

$(document).ready(function () {
    const bust = `?v=${Date.now()}`;
    loadEntries(bust)
        .then(entries => {
            initKB(entries);
            $('#loading').hide();
        })
        .then(() => initDotphrases(bust))
        .then(() => initHandbook(bust))
        .catch(err => {
            console.error('Error loading data:', err);
            $('#loading').html('<div class="alert alert-danger">Error loading reference data. Please refresh the page.</div>');
        });

    // Tab switching
    $('.tab-button').on('click', function () {
        const section = $(this).data('section');
        $('.tab-button').removeClass('active');
        $(this).addClass('active');
        $('.data-section').removeClass('active');
        $(`#${section}-section`).addClass('active');
    });

    // Pull KV-stored SECRETS overrides BEFORE wiring gates so the very
    // first unlock attempt uses the latest ciphertext. Promise-style — we
    // don't block other init work on it.
    loadSecretsFromKV();

    // Secure gates — URLs decrypt only when the right password is entered.
    // Each gate has its own password now (Clinical Reasoning uses
    // ElaineCool, Patients uses ElaineHW). Both can be rotated from the UI
    // via the change-password button next to the lock button.
    setupSecureGate({
        secretKey: 'clinicalDocUrl',
        label: 'Clinical Reasoning',
        submitBtn: '#submit-password',
        passwordInput: '#doc-password',
        errorMsg: '#password-error',
        gate: '#password-gate',
        container: '#document-container',
        iframe: '#google-doc-frame',
        lockBtn: '#lock-document',
        changePwBtn: '#cr-change-password',
    });

    setupSecureGate({
        secretKey: 'patientsSheetUrl',
        label: 'Patients',
        submitBtn: '#patients-submit',
        passwordInput: '#patients-password',
        errorMsg: '#patients-error',
        gate: '#patients-gate',
        container: '#patients-container',
        iframe: '#patients-frame',
        lockBtn: '#patients-lock',
        changePwBtn: '#patients-change-password',
        unconfiguredMsg: 'Patient log not configured yet. Run tools/encrypt-urls.html to set up.',
    });

    // Wire the change-password modal submit button (one shared modal for
    // both gates; opens with context set by openChangePasswordModal).
    document.getElementById('changePwSubmit')?.addEventListener('click', submitChangePassword);

    // Image modal handlers
    $('.close-modal').on('click', () => $('#imageModal').hide());
    $('#imageModal').on('click', function (e) {
        if (e.target.id === 'imageModal') $('#imageModal').hide();
    });

    // Editor (add/edit/delete entries via GitHub API)
    initEditor();

    // Reference tab (Antibiotics + ConanLi + EBM + UW + MKSAP)
    initReference();

    // "Paste markdown" modal — shared by both KB and Reference editors
    initPasteMarkdownModal();
});

// =========================================================================
// Secure gate — Web Crypto (PBKDF2 + AES-GCM) decrypts URL on correct password
// =========================================================================

function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bufToB64(buf) {
    let s = '';
    new Uint8Array(buf).forEach(b => s += String.fromCharCode(b));
    return btoa(s);
}

async function deriveAesKey(password, saltBuf) {
    const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITER, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

async function decryptSecret(password, secret) {
    if (!secret) throw new Error('UNCONFIGURED');
    const key = await deriveAesKey(password, b64ToBuf(secret.salt));
    const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBuf(secret.iv) },
        key,
        b64ToBuf(secret.ct)
    );
    return new TextDecoder().decode(plaintextBuf);
}

// PBKDF2 -> AES-GCM key for encryption (mirrors deriveAesKey, but with the
// encrypt usage permission)
async function deriveAesKeyForEncrypt(password, saltBuf) {
    const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITER, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
}

async function encryptSecret(password, plaintext) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveAesKeyForEncrypt(password, salt);
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    return { ct: bufToB64(ct), iv: bufToB64(iv), salt: bufToB64(salt) };
}

// On boot, try to fetch SECRETS overrides from KV. Falls back silently to
// the baked SECRETS if KV is unreachable or empty. Resolves before the
// gates are wired so the UI always sees the latest values.
async function loadSecretsFromKV() {
    try {
        const r = await fetch('/api/secrets', { cache: 'no-store' });
        if (!r.ok) return;
        const { secrets } = await r.json();
        if (!secrets || typeof secrets !== 'object') return;
        for (const [k, v] of Object.entries(secrets)) {
            if (v && v.ct && v.iv && v.salt) SECRETS[k] = v;
        }
    } catch (e) { /* offline or KV down — keep baked */ }
}

function setupSecureGate(opts) {
    // Look up the secret lazily so KV-loaded overrides take effect
    const getSecret = () => SECRETS[opts.secretKey];
    let currentPassword = null;   // remembered while unlocked, for change-password flow
    let currentPlaintext = null;  // ditto

    const submit = async () => {
        const $err = $(opts.errorMsg);
        const $pw = $(opts.passwordInput);
        const $submit = $(opts.submitBtn);
        const password = $pw.val();
        $err.hide();
        const secret = getSecret();
        if (!secret) {
            $err.text(opts.unconfiguredMsg || 'This gate is not configured yet.').show();
            return;
        }
        $submit.prop('disabled', true);
        try {
            const url = await decryptSecret(password, secret);
            currentPassword = password;
            currentPlaintext = url;
            $(opts.gate).hide();
            $(opts.container).show();
            $(opts.iframe).attr('src', url);
            $pw.val('');
        } catch (e) {
            // AES-GCM auth-tag mismatch on wrong password throws — treat all errors as wrong password
            $err.text('Incorrect password. Please try again.').show();
            $pw.val('').focus();
        } finally {
            $submit.prop('disabled', false);
        }
    };
    $(opts.submitBtn).on('click', submit);
    $(opts.passwordInput).on('keypress', function (e) {
        if (e.which === 13) submit();
    });
    $(opts.lockBtn).on('click', function () {
        currentPassword = null;
        currentPlaintext = null;
        $(opts.container).hide();
        $(opts.gate).show();
        $(opts.iframe).attr('src', '');
        $(opts.passwordInput).val('');
    });

    // Wire the "change password" button (next to the lock button in the
    // unlocked container). Each gate uses its own button id.
    if (opts.changePwBtn) {
        $(opts.changePwBtn).on('click', () => {
            if (!currentPassword || !currentPlaintext) return;
            openChangePasswordModal({
                secretKey: opts.secretKey,
                currentPassword,
                plaintext: currentPlaintext,
                label: opts.label || opts.secretKey,
                onSuccess: (newPassword) => { currentPassword = newPassword; },
            });
        });
    }
}

// ----- In-UI password rotation ------------------------------------------
// Decrypts the secret with the current password (proves the user knows it),
// re-encrypts with the new password, PUTs to /api/secrets (so all browsers
// see the change immediately on next page load), and updates the in-memory
// SECRETS object so the current session continues to work.

let _changePwCtx = null;
let _changePwModal = null;

function openChangePasswordModal(ctx) {
    _changePwCtx = ctx;
    if (!_changePwModal) {
        _changePwModal = new bootstrap.Modal(document.getElementById('changePasswordModal'));
    }
    document.getElementById('changePwLabel').textContent = `Change password — ${ctx.label}`;
    document.getElementById('changePwCurrent').value = '';
    document.getElementById('changePwNew').value = '';
    document.getElementById('changePwConfirm').value = '';
    document.getElementById('changePwError').style.display = 'none';
    _changePwModal.show();
}

async function submitChangePassword() {
    const ctx = _changePwCtx;
    if (!ctx) return;
    const errEl = document.getElementById('changePwError');
    const showErr = msg => { errEl.textContent = msg; errEl.style.display = 'block'; };
    errEl.style.display = 'none';

    const current = document.getElementById('changePwCurrent').value;
    const np = document.getElementById('changePwNew').value;
    const cf = document.getElementById('changePwConfirm').value;
    if (current !== ctx.currentPassword) { showErr('Current password is wrong.'); return; }
    if (!np || np.length < 8) { showErr('New password must be 8+ characters.'); return; }
    if (np !== cf) { showErr('New password and confirmation do not match.'); return; }
    if (!EDITOR_STATE.apiPassword) {
        showErr('Editor not unlocked. Open the Knowledge Base tab and unlock the editor first.');
        return;
    }

    const btn = document.getElementById('changePwSubmit');
    btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Updating...';
    try {
        const fresh = await encryptSecret(np, ctx.plaintext);
        const r = await fetch('/api/secrets', {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${EDITOR_STATE.apiPassword}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ secrets: { [ctx.secretKey]: fresh } }),
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        // Update in-memory so the current session stays usable
        SECRETS[ctx.secretKey] = fresh;
        if (ctx.onSuccess) ctx.onSuccess(np);
        toast('Password updated.', 'success');
        _changePwModal.hide();
    } catch (e) {
        showErr(`Update failed: ${e.message}`);
    } finally {
        btn.disabled = false; btn.innerHTML = '<i class="fas fa-key me-1"></i>Update password';
    }
}

// =========================================================================
// Shared helpers — image modal, escaping, formatting
// =========================================================================

function openImageModal(imageUrl) {
    $('#modalImage').attr('src', imageUrl);
    $('#imageModal').show();
}

// Page-image URL template: substitute {n}, {n:03d}, {n:04d} with `n`.
// Used by handbook + pdf-toc renderers. Supports any zero-padded width.
function fillPageTemplate(tmpl, n) {
    return String(tmpl).replace(/\{n(?::(\d+)d)?\}/g, (_, w) => {
        const width = w ? parseInt(w, 10) : 0;
        return String(n).padStart(width, '0');
    });
}

function escapeHtml(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatCellContent(text) {
    const escaped = escapeHtml(text);
    const withLinks = escaped.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    return withLinks.replace(/\n/g, '<br>');
}

// Richer text renderer: detects bullet/numbered lists and paragraphs.
// Used in KB card bodies for clinical notes & templates.
function renderRichText(text) {
    if (!text) return '';
    // Split into blocks separated by blank line(s)
    const blocks = text.split(/\n{2,}/);
    return blocks.map(renderRichBlock).filter(Boolean).join('');
}

function renderRichBlock(block) {
    const lines = block.split('\n');
    if (!lines.length) return '';
    // ATX heading: `# Title` ... `###### Title` (single-line block only)
    if (lines.length === 1) {
        const m = lines[0].match(/^\s*(#{1,6})\s+(.+?)\s*#*\s*$/);
        if (m) {
            // Map `#` → h2, `##` → h3, ... cap at h6. (Avoid h1 — too big in cards.)
            const level = Math.min(m[1].length + 1, 6);
            return `<h${level}>${formatInline(m[2])}</h${level}>`;
        }
    }
    // Blockquote: every non-blank line starts with "> "
    const isQuote = lines.every(l => !l.trim() || /^\s*>\s?/.test(l));
    if (isQuote && lines.some(l => /^\s*>\s?/.test(l))) {
        const inner = lines
            .filter(l => l.trim())
            .map(l => formatInline(l.replace(/^\s*>\s?/, '')))
            .join('<br>');
        return `<blockquote>${inner}</blockquote>`;
    }
    // Bullet list: every non-blank line starts with "- " or "* "
    const isBullet = lines.every(l => !l.trim() || /^\s*[-*]\s+/.test(l));
    // Numbered list: every non-blank line starts with "N." or "N)"
    const isNumbered = lines.every(l => !l.trim() || /^\s*\d+[.)]\s+/.test(l));

    if (isBullet && lines.some(l => /^\s*[-*]\s+/.test(l))) {
        const items = lines.filter(l => l.trim()).map(l => {
            const inner = l.replace(/^\s*[-*]\s+/, '');
            return `<li>${formatInline(inner)}</li>`;
        });
        return `<ul class="kb-list-block">${items.join('')}</ul>`;
    }
    if (isNumbered && lines.some(l => /^\s*\d+[.)]\s+/.test(l))) {
        const items = lines.filter(l => l.trim()).map(l => {
            const inner = l.replace(/^\s*\d+[.)]\s+/, '');
            return `<li>${formatInline(inner)}</li>`;
        });
        return `<ol class="kb-list-block">${items.join('')}</ol>`;
    }
    // Plain paragraph: keep single newlines as <br>
    return `<p class="kb-para">${lines.map(formatInline).join('<br>')}</p>`;
}

// Inline-only formatting: escape, link URLs, bold (**), italic (*), `code`.
function formatInline(text) {
    let out = escapeHtml(text);
    // URLs
    out = out.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    // Bold first so the bold delimiters get consumed before italic runs.
    out = out.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
    // Italic: *text* — guard against matching part of remaining ** sequences.
    out = out.replace(/(^|[^*\w])\*([^*\n]+?)\*(?!\w|\*)/g, '$1<em>$2</em>');
    // Inline code: `code`
    out = out.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    return out;
}

function markdownTableToHtml(markdown) {
    const lines = markdown
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line.length > 0);
    if (lines.length < 2) return null;
    const headerLine = lines[0];
    const separatorLine = lines[1];
    const isTable = headerLine.startsWith('|') && headerLine.endsWith('|') &&
        /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?$/.test(separatorLine);
    if (!isTable) return null;
    const splitRow = (row) => row
        .replace(/^\|/, '').replace(/\|$/, '')
        .split('|').map(cell => cell.trim());
    const headers = splitRow(headerLine);
    const bodyRows = lines.slice(2).map(splitRow);
    let html = '<div class="table-responsive"><table class="table table-bordered table-sm markdown-table">';
    html += '<thead><tr>' + headers.map(h => `<th>${formatCellContent(h)}</th>`).join('') + '</tr></thead>';
    html += '<tbody>';
    bodyRows.forEach(row => {
        html += '<tr>' + row.map(cell => `<td>${formatCellContent(cell)}</td>`).join('') + '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
}

function renderCellContent(data) {
    if (!data) return '';
    // If the content was authored in the Quill editor it's already HTML.
    // Sanitize and render directly so bold/italic/lists/colors survive.
    if (looksLikeHtml(data)) return sanitizeHtml(data);
    const tableHtml = markdownTableToHtml(data);
    if (tableHtml) return tableHtml;
    return renderRichText(data);
}

function copyTextToClipboard(text, btn) {
    const setCopied = () => {
        if (!btn) return;
        const orig = btn.textContent;
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = orig;
        }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(setCopied).catch(() => fallbackCopy(text, setCopied));
    } else {
        fallbackCopy(text, setCopied);
    }
}

function fallbackCopy(text, onDone) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); onDone(); } catch (e) { alert('Copy failed'); }
    document.body.removeChild(ta);
}

// =========================================================================
// Knowledge Base — sidebar + cards, favorites, recents, scoped search
// =========================================================================

const KB_STATE = {
    entries: [],
    query: '',
    scope: 'all',
    sort: 'updatedAt-desc',
    category: null,
    activeTags: [],
    expanded: new Set(),
    favorites: new Set(),
    recents: [],
};

const KB_STORAGE = {
    favorites: 'ecref.kb.favorites',
    recents: 'ecref.kb.recents',
};

function loadKBPrefs() {
    try {
        KB_STATE.favorites = new Set(JSON.parse(localStorage.getItem(KB_STORAGE.favorites) || '[]'));
        KB_STATE.recents = JSON.parse(localStorage.getItem(KB_STORAGE.recents) || '[]').filter(Boolean);
    } catch (e) {
        KB_STATE.favorites = new Set();
        KB_STATE.recents = [];
    }
}

function saveKBPrefs() {
    localStorage.setItem(KB_STORAGE.favorites, JSON.stringify([...KB_STATE.favorites]));
    localStorage.setItem(KB_STORAGE.recents, JSON.stringify(KB_STATE.recents));
}

function toggleFavorite(id) {
    if (KB_STATE.favorites.has(id)) KB_STATE.favorites.delete(id);
    else KB_STATE.favorites.add(id);
    saveKBPrefs();
    renderKB();
}

function pushRecent(id) {
    KB_STATE.recents = [id, ...KB_STATE.recents.filter(x => x !== id)].slice(0, 10);
    saveKBPrefs();
}

function getTitle(entry) {
    for (const line of (entry.data || '').split('\n')) {
        const t = line.trim().replace(/^#+\s*/, '');
        if (t) return t;
    }
    return '(untitled)';
}

function applyFilters() {
    const q = KB_STATE.query.trim().toLowerCase();
    const filtered = KB_STATE.entries.filter(e => {
        if (KB_STATE.category && e.category !== KB_STATE.category) return false;
        if (KB_STATE.activeTags.length) {
            const tags = (e.tags || []).map(t => t.toLowerCase());
            if (!KB_STATE.activeTags.every(t => tags.includes(t.toLowerCase()))) return false;
        }
        if (q) {
            const title = getTitle(e).toLowerCase();
            const body = ((e.data || '') + ' ' + (e.template || '') + ' ' + (e.tags || []).join(' ')).toLowerCase();
            if (KB_STATE.scope === 'title') {
                if (!title.includes(q)) return false;
            } else if (KB_STATE.scope === 'body') {
                if (!body.includes(q)) return false;
            } else {
                if (!title.includes(q) && !body.includes(q)) return false;
            }
        }
        return true;
    });
    return sortEntries(filtered, KB_STATE.sort);
}

function sortEntries(list, mode) {
    const sorted = [...list];
    switch (mode) {
        case 'updatedAt-desc':
            sorted.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
            break;
        case 'createdAt-desc':
            sorted.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
            break;
        case 'title-asc':
            sorted.sort((a, b) => getTitle(a).toLowerCase().localeCompare(getTitle(b).toLowerCase()));
            break;
        case 'title-desc':
            sorted.sort((a, b) => getTitle(b).toLowerCase().localeCompare(getTitle(a).toLowerCase()));
            break;
    }
    return sorted;
}

// Human-readable relative time, e.g. "5 min ago", "2 days ago", "May 1, 2026"
function relativeTime(iso) {
    if (!iso) return '';
    const then = new Date(iso);
    if (isNaN(then.getTime())) return '';
    const diffMs = Date.now() - then.getTime();
    const sec = Math.round(diffMs / 1000);
    if (sec < 60) return 'just now';
    const min = Math.round(sec / 60);
    if (min < 60) return `${min} min ago`;
    const hr = Math.round(min / 60);
    if (hr < 24) return `${hr} hr ago`;
    const day = Math.round(hr / 24);
    if (day < 30) return `${day} day${day === 1 ? '' : 's'} ago`;
    // Older than ~a month — show absolute date
    return then.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function categoryClass(cat) {
    return 'cat-' + (cat || 'Other').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function renderImageMarkup(imgs) {
    if (!imgs || !imgs.trim()) return '';
    const urls = imgs.split(',').map(u => u.trim()).filter(Boolean);
    if (!urls.length) return '';
    let html = '<div class="image-container">';
    urls.forEach(url => {
        if (/\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(url)) {
            const caption = url.startsWith('images/cpsolvers/')
                ? '<div class="img-attr">Schema: Clinical Problem Solvers</div>'
                : '';
            const safeUrl = url.replace(/'/g, "\\'");
            html += `<div class="img-wrap"><img src="${escapeHtml(url)}" class="reference-image" alt="Reference image" onclick="openImageModal('${safeUrl}')" title="Click to enlarge">${caption}</div>`;
        } else if (url.startsWith('http')) {
            html += `<a href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(url)}</a><br>`;
        } else {
            html += `<span class="img-note">${escapeHtml(url)}</span><br>`;
        }
    });
    html += '</div>';
    return html;
}

function renderLinksSection(links) {
    if (!links || !links.length) return '';
    let html = '<div class="kb-links"><h6><i class="fas fa-link me-1"></i>External resources</h6><ul>';
    links.forEach(link => {
        if (!link || !link.url) return;
        html += `<li><a href="${escapeHtml(link.url)}" target="_blank" rel="noopener">${escapeHtml(link.label || link.url)}</a></li>`;
    });
    html += '</ul></div>';
    return html;
}

function renderCard(entry) {
    const title = getTitle(entry);
    const isExpanded = KB_STATE.expanded.has(entry.id);
    const isFav = KB_STATE.favorites.has(entry.id);
    const cat = entry.category || 'Other';
    const tags = entry.tags || [];

    const tagChipsHtml = tags.map(t =>
        `<button class="tag-chip" data-tag="${escapeHtml(t)}" type="button">${escapeHtml(t)}</button>`
    ).join('');

    let bodyHtml = '';
    if (isExpanded) {
        const dataHtml = renderCellContent(entry.data);
        const templateHtml = renderCellContent(entry.template);
        const imgsHtml = renderImageMarkup(entry.imgs);
        const linksHtml = renderLinksSection(entry.links);

        bodyHtml = '<div class="kb-card-body">';
        if (dataHtml) {
            bodyHtml += `<div class="kb-section"><div class="kb-section-head"><h6>Reference</h6><button class="btn btn-sm btn-outline-primary kb-copy-btn" data-copy-target="data-${escapeHtml(entry.id)}" type="button">Copy</button></div><div class="kb-section-content" id="data-${escapeHtml(entry.id)}">${dataHtml}</div></div>`;
        }
        if (templateHtml) {
            bodyHtml += `<div class="kb-section"><div class="kb-section-head"><h6>Template</h6><button class="btn btn-sm btn-outline-primary kb-copy-btn" data-copy-target="tpl-${escapeHtml(entry.id)}" type="button">Copy</button></div><div class="kb-section-content" id="tpl-${escapeHtml(entry.id)}">${templateHtml}</div></div>`;
        }
        if (imgsHtml) {
            bodyHtml += `<div class="kb-section"><div class="kb-section-head"><h6>Images</h6></div>${imgsHtml}</div>`;
        }
        if (linksHtml) bodyHtml += linksHtml;
        if (EDITOR_STATE.configured) {
            bodyHtml += `<div class="kb-edit-row"><button class="btn btn-sm btn-outline-secondary kb-edit-btn" data-edit-id="${escapeHtml(entry.id)}" type="button"><i class="fas fa-pen me-1"></i>Edit</button></div>`;
        }
        bodyHtml += '</div>';
    }

    const updatedLabel = entry.updatedAt ? relativeTime(entry.updatedAt) : '';
    const updatedAbs = entry.updatedAt ? new Date(entry.updatedAt).toLocaleString() : '';
    const updatedHtml = updatedLabel
        ? `<span class="kb-card-date" title="Last updated ${escapeHtml(updatedAbs)}">· ${escapeHtml(updatedLabel)}</span>`
        : '';

    return `
<div class="kb-card${isExpanded ? ' expanded' : ''}" data-id="${escapeHtml(entry.id)}">
  <div class="kb-card-header" data-toggle-id="${escapeHtml(entry.id)}">
    <button class="kb-fav${isFav ? ' on' : ''}" data-fav-id="${escapeHtml(entry.id)}" type="button" aria-label="Toggle favorite" title="${isFav ? 'Unfavorite' : 'Favorite'}">
      <i class="${isFav ? 'fas' : 'far'} fa-star"></i>
    </button>
    <div class="kb-card-title-wrap">
      <div class="kb-card-title">${escapeHtml(title)}</div>
      <div class="kb-card-meta">
        <span class="kb-category-badge ${categoryClass(cat)}">${escapeHtml(cat)}</span>
        ${tagChipsHtml}
        ${updatedHtml}
      </div>
    </div>
    <i class="fas fa-chevron-${isExpanded ? 'up' : 'down'} kb-chevron"></i>
  </div>
  ${bodyHtml}
</div>`;
}

function renderSidebar() {
    const favEntries = [...KB_STATE.favorites]
        .map(id => KB_STATE.entries.find(e => e.id === id))
        .filter(Boolean);
    const favHtml = favEntries.length
        ? favEntries.map(e => `<li><a href="#" data-jump-id="${escapeHtml(e.id)}">${escapeHtml(getTitle(e).slice(0, 50))}</a></li>`).join('')
        : '<li class="kb-empty-list">No favorites yet</li>';
    document.getElementById('kbFavorites').innerHTML = favHtml;

    const recEntries = KB_STATE.recents
        .map(id => KB_STATE.entries.find(e => e.id === id))
        .filter(Boolean);
    const recHtml = recEntries.length
        ? recEntries.map(e => `<li><a href="#" data-jump-id="${escapeHtml(e.id)}">${escapeHtml(getTitle(e).slice(0, 50))}</a></li>`).join('')
        : '<li class="kb-empty-list">No recent views</li>';
    document.getElementById('kbRecents').innerHTML = recHtml;

    const counts = {};
    KB_STATE.entries.forEach(e => {
        const c = e.category || 'Other';
        counts[c] = (counts[c] || 0) + 1;
    });
    const sortedCats = Object.keys(counts).sort((a, b) => {
        if (a === 'Other') return 1;
        if (b === 'Other') return -1;
        return a.localeCompare(b);
    });
    let catHtml = `<li><a href="#" data-cat="" class="${!KB_STATE.category ? 'active' : ''}">All (${KB_STATE.entries.length})</a></li>`;
    sortedCats.forEach(c => {
        catHtml += `<li><a href="#" data-cat="${escapeHtml(c)}" class="${KB_STATE.category === c ? 'active' : ''}"><span class="kb-cat-dot ${categoryClass(c)}"></span>${escapeHtml(c)} <span class="kb-cat-count">${counts[c]}</span></a></li>`;
    });
    document.getElementById('kbCategories').innerHTML = catHtml;
}

function renderActiveFilters() {
    const chips = [];
    if (KB_STATE.category) {
        chips.push(`<span class="filter-chip">Category: ${escapeHtml(KB_STATE.category)} <button data-clear-cat type="button" aria-label="Clear category">&times;</button></span>`);
    }
    KB_STATE.activeTags.forEach(t => {
        chips.push(`<span class="filter-chip">Tag: ${escapeHtml(t)} <button data-clear-tag="${escapeHtml(t)}" type="button" aria-label="Clear tag">&times;</button></span>`);
    });
    if (KB_STATE.query) {
        chips.push(`<span class="filter-chip">"${escapeHtml(KB_STATE.query)}" <button data-clear-query type="button" aria-label="Clear search">&times;</button></span>`);
    }
    document.getElementById('kbActiveFilters').innerHTML = chips.length ? chips.join(' ') : '';
}

function renderKB() {
    renderSidebar();
    renderActiveFilters();
    const filtered = applyFilters();
    document.getElementById('kbCount').textContent = `Showing ${filtered.length} of ${KB_STATE.entries.length}`;
    document.getElementById('kbCards').innerHTML = filtered.map(renderCard).join('');
    document.getElementById('kbEmpty').style.display = filtered.length ? 'none' : 'block';
}

function jumpToCard(id) {
    $('.tab-button[data-section="database"]').click();
    if (!KB_STATE.expanded.has(id)) {
        KB_STATE.expanded.add(id);
        pushRecent(id);
        renderKB();
    }
    setTimeout(() => {
        const el = document.querySelector(`.kb-card[data-id="${CSS.escape(id)}"]`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

function initKB(entries) {
    KB_STATE.entries = entries;
    loadKBPrefs();

    document.getElementById('kbSearch').addEventListener('input', e => {
        KB_STATE.query = e.target.value;
        renderKB();
    });

    document.querySelectorAll('input[name="kbScope"]').forEach(r => {
        r.addEventListener('change', e => {
            KB_STATE.scope = e.target.value;
            renderKB();
        });
    });

    const sortEl = document.getElementById('kbSort');
    if (sortEl) {
        sortEl.value = KB_STATE.sort;
        sortEl.addEventListener('change', e => {
            KB_STATE.sort = e.target.value;
            renderKB();
        });
    }

    document.getElementById('kbSidebarToggle')?.addEventListener('click', () => {
        document.getElementById('kbSidebar').classList.toggle('open');
    });

    document.getElementById('database-section').addEventListener('click', e => {
        // Edit button (inside expanded card)
        const editBtn = e.target.closest('.kb-edit-btn');
        if (editBtn) {
            e.stopPropagation();
            openEntryEditor(editBtn.dataset.editId);
            return;
        }
        // Star toggle (must check before card header)
        const favBtn = e.target.closest('[data-fav-id]');
        if (favBtn) {
            e.stopPropagation();
            toggleFavorite(favBtn.dataset.favId);
            return;
        }
        // Copy button inside card
        const copyBtn = e.target.closest('.kb-copy-btn');
        if (copyBtn) {
            e.stopPropagation();
            const targetId = copyBtn.dataset.copyTarget;
            const el = document.getElementById(targetId);
            if (el) copyTextToClipboard(el.innerText, copyBtn);
            return;
        }
        // Tag chip
        const tagBtn = e.target.closest('.tag-chip');
        if (tagBtn) {
            e.stopPropagation();
            const tag = tagBtn.dataset.tag;
            if (!KB_STATE.activeTags.includes(tag)) KB_STATE.activeTags.push(tag);
            renderKB();
            return;
        }
        // Card header toggle
        const header = e.target.closest('[data-toggle-id]');
        if (header) {
            const id = header.dataset.toggleId;
            if (KB_STATE.expanded.has(id)) {
                KB_STATE.expanded.delete(id);
            } else {
                KB_STATE.expanded.add(id);
                pushRecent(id);
            }
            renderKB();
            return;
        }
        // Sidebar category click
        const catLink = e.target.closest('[data-cat]');
        if (catLink) {
            e.preventDefault();
            KB_STATE.category = catLink.dataset.cat || null;
            renderKB();
            return;
        }
        // Sidebar jump link
        const jumpLink = e.target.closest('[data-jump-id]');
        if (jumpLink) {
            e.preventDefault();
            jumpToCard(jumpLink.dataset.jumpId);
            return;
        }
        // Active filter clears
        if (e.target.closest('[data-clear-cat]')) {
            KB_STATE.category = null;
            renderKB();
            return;
        }
        const clearTag = e.target.closest('[data-clear-tag]');
        if (clearTag) {
            const t = clearTag.dataset.clearTag;
            KB_STATE.activeTags = KB_STATE.activeTags.filter(x => x !== t);
            renderKB();
            return;
        }
        if (e.target.closest('[data-clear-query]')) {
            KB_STATE.query = '';
            document.getElementById('kbSearch').value = '';
            renderKB();
            return;
        }
    });

    renderKB();
}

// =========================================================================
// Dot Phrases — KB-style sidebar + card grid, editable, KV-backed.
// =========================================================================
// Data model (one record per phrase):
//   { id, name, content, category, tags[], createdAt, updatedAt }
// Source of truth: KV section `dot-phrases`. Falls back to dotphrases.txt
// (static seed) on read failure so the tab still works during cold-starts.

const DP_STATE = {
    phrases: [],
    query: '',
    scope: 'all',
    sort: 'title-asc',
    category: null,         // single-select category filter
    activeTags: new Set(),
    favorites: new Set(),
    recents: [],
    expanded: new Set(),    // collapsed-by-default; toggle to expand
    modal: null,
    editing: null,          // phrase being edited (or null for add)
    editingTags: [],
};
const DP_STORAGE = {
    favorites: 'ecref.dp.favorites',
    recents:   'ecref.dp.recents',
};
const DP_CATEGORIES = [
    'Note Template', 'Communication', 'Procedure',
    'Cardiac', 'Pulmonary', 'GI', 'Renal', 'ID', 'Neuro',
    'Heme/Onc', 'Endo', 'Derm', 'Tox', 'MSK', 'Psych', 'OB/GYN', 'Other',
];

async function initDotphrases(bust) {
    // Load preferences (favorites, recents)
    try {
        const f = JSON.parse(localStorage.getItem(DP_STORAGE.favorites) || '[]');
        DP_STATE.favorites = new Set(Array.isArray(f) ? f : []);
        const r = JSON.parse(localStorage.getItem(DP_STORAGE.recents) || '[]');
        DP_STATE.recents = Array.isArray(r) ? r.slice(0, 12) : [];
    } catch (e) { /* corrupt JSON — ignore */ }

    // Fetch from KV; fall back to static dotphrases.txt
    let phrases = [];
    try {
        const r = await fetch('/api/list/dot-phrases', { cache: 'no-store' });
        if (r.ok) {
            const j = await r.json();
            phrases = j.items || [];
        }
    } catch (e) { /* swallow */ }
    if (phrases.length === 0) {
        try {
            const r = await fetch('dotphrases.txt' + (bust || ''), { cache: 'no-store' });
            if (r.ok) {
                const text = await r.text();
                phrases = parseDotphrasesText(text);
            }
        } catch (e) { /* nothing to fall back to */ }
    }
    DP_STATE.phrases = phrases;

    DP_STATE.modal = new bootstrap.Modal(document.getElementById('dotphraseModal'));
    wireDotphrasesUI();
    renderDP();
}

function parseDotphrasesText(text) {
    // Static-fallback parser; same format as the old dotphrases.txt.
    // Returns records compatible with the KV schema so the renderer doesn't
    // care which source the data came from.
    const out = [];
    let name = null;
    let buf = [];
    for (const line of text.split('\n')) {
        const m = line.match(/^DOTPHRASE\s+(.+?)\s*$/);
        if (m) {
            if (name !== null) out.push(_makeDP(name, buf.join('\n').trim()));
            name = m[1].trim();
            buf = [];
        } else if (name !== null) {
            buf.push(line);
        }
    }
    if (name !== null) out.push(_makeDP(name, buf.join('\n').trim()));
    return out;
}
function _makeDP(name, content) {
    return {
        id: (name || 'phrase').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60),
        name, content, category: 'Other', tags: [],
        createdAt: null, updatedAt: null,
    };
}

function saveDPPrefs() {
    try {
        localStorage.setItem(DP_STORAGE.favorites, JSON.stringify([...DP_STATE.favorites]));
        localStorage.setItem(DP_STORAGE.recents, JSON.stringify(DP_STATE.recents.slice(0, 12)));
    } catch (e) { /* quota / disabled — ignore */ }
}

function toggleDPFavorite(id) {
    if (DP_STATE.favorites.has(id)) DP_STATE.favorites.delete(id);
    else DP_STATE.favorites.add(id);
    saveDPPrefs();
}

function pushDPRecent(id) {
    DP_STATE.recents = [id, ...DP_STATE.recents.filter(r => r !== id)].slice(0, 12);
    saveDPPrefs();
}

function applyDPFilters() {
    const q = DP_STATE.query.trim().toLowerCase();
    const tagSet = DP_STATE.activeTags;
    const cat = DP_STATE.category;
    return DP_STATE.phrases.filter(p => {
        if (cat && p.category !== cat) return false;
        if (tagSet.size && !(p.tags || []).some(t => tagSet.has(t))) return false;
        if (!q) return true;
        const name = (p.name || '').toLowerCase();
        const body = (p.content || '').toLowerCase();
        if (DP_STATE.scope === 'title') return name.includes(q);
        if (DP_STATE.scope === 'body')  return body.includes(q);
        return name.includes(q) || body.includes(q)
            || (p.tags || []).some(t => t.toLowerCase().includes(q));
    });
}

function sortDPPhrases(list, mode) {
    const cmp = {
        'title-asc':       (a, b) => (a.name || '').localeCompare(b.name || ''),
        'title-desc':      (a, b) => (b.name || '').localeCompare(a.name || ''),
        'updatedAt-desc':  (a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''),
        'createdAt-desc':  (a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''),
    }[mode] || ((a, b) => 0);
    return list.slice().sort(cmp);
}

function renderDPCard(phrase) {
    const isFav = DP_STATE.favorites.has(phrase.id);
    const isExpanded = DP_STATE.expanded.has(phrase.id);
    const catClass = categoryClass(phrase.category);
    const tagsHtml = (phrase.tags || []).map(t =>
        `<button type="button" class="tag-chip" data-tag="${escapeHtml(t)}">${escapeHtml(t)}</button>`
    ).join('');
    const updated = phrase.updatedAt ? relativeTime(phrase.updatedAt) : '';
    const canEdit = editorReadyHtml();
    return `<article class="kb-card${isExpanded ? ' expanded' : ''}" data-dp-id="${escapeHtml(phrase.id)}">
        <header class="kb-card-head" data-dp-toggle="${escapeHtml(phrase.id)}">
            <button type="button" class="kb-fav${isFav ? ' on' : ''}" data-dp-fav="${escapeHtml(phrase.id)}" aria-label="${isFav ? 'Unfavorite' : 'Favorite'}">
                <i class="${isFav ? 'fas' : 'far'} fa-star"></i>
            </button>
            <div class="kb-card-titles">
                <h5 class="kb-card-title"><i class="fas fa-file-medical me-2 text-muted"></i>${escapeHtml(phrase.name || '(no name)')}</h5>
                <div class="kb-card-meta">
                    <span class="kb-cat-badge ${catClass}">${escapeHtml(phrase.category || 'Other')}</span>
                    ${tagsHtml}
                    ${updated ? `<span class="kb-card-time"><i class="far fa-clock me-1"></i>${escapeHtml(updated)}</span>` : ''}
                </div>
            </div>
            <button type="button" class="kb-copy" data-dp-copy="${escapeHtml(phrase.id)}" title="Copy phrase">
                <i class="far fa-copy"></i>
            </button>
            <button type="button" class="kb-expand" aria-label="Expand" data-dp-toggle="${escapeHtml(phrase.id)}">
                <i class="fas fa-chevron-${isExpanded ? 'up' : 'down'}"></i>
            </button>
        </header>
        ${isExpanded ? `<div class="kb-card-body">
            <pre class="dp-content">${escapeHtml(phrase.content || '')}</pre>
            <div class="kb-card-actions">
                <button type="button" class="btn btn-sm btn-primary" data-dp-copy="${escapeHtml(phrase.id)}">
                    <i class="far fa-copy me-1"></i>Copy phrase
                </button>
                ${canEdit ? `<button type="button" class="btn btn-sm btn-outline-secondary" data-dp-edit="${escapeHtml(phrase.id)}">
                    <i class="fas fa-edit me-1"></i>Edit
                </button>` : ''}
            </div>
        </div>` : ''}
    </article>`;
}

function renderDPSidebar() {
    const counts = {};
    for (const p of DP_STATE.phrases) {
        const c = p.category || 'Other';
        counts[c] = (counts[c] || 0) + 1;
    }
    const cats = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

    document.getElementById('dpCategories').innerHTML = cats.map(([c, n]) => `
        <li><a href="#" class="kb-cat-link${DP_STATE.category === c ? ' active' : ''}" data-dp-cat="${escapeHtml(c)}">
            <span class="kb-cat-dot ${categoryClass(c)}"></span>
            <span class="kb-cat-name">${escapeHtml(c)}</span>
            <span class="kb-cat-count">${n}</span>
        </a></li>`).join('');

    const byId = new Map(DP_STATE.phrases.map(p => [p.id, p]));
    const favs = [...DP_STATE.favorites].map(id => byId.get(id)).filter(Boolean).slice(0, 12);
    document.getElementById('dpFavorites').innerHTML = favs.length
        ? favs.map(p => `<li><a href="#" data-dp-jump="${escapeHtml(p.id)}">${escapeHtml(p.name)}</a></li>`).join('')
        : '<li class="kb-empty-mini">No favorites yet.</li>';

    const recents = DP_STATE.recents.map(id => byId.get(id)).filter(Boolean).slice(0, 8);
    document.getElementById('dpRecents').innerHTML = recents.length
        ? recents.map(p => `<li><a href="#" data-dp-jump="${escapeHtml(p.id)}">${escapeHtml(p.name)}</a></li>`).join('')
        : '<li class="kb-empty-mini">No recents yet.</li>';
}

function renderDPActiveFilters() {
    const chips = [];
    if (DP_STATE.category) {
        chips.push(`<span class="filter-chip">${escapeHtml(DP_STATE.category)}
            <button type="button" data-dp-cat-clear>&times;</button></span>`);
    }
    for (const t of DP_STATE.activeTags) {
        chips.push(`<span class="filter-chip">#${escapeHtml(t)}
            <button type="button" data-dp-tag-clear="${escapeHtml(t)}">&times;</button></span>`);
    }
    document.getElementById('dpActiveFilters').innerHTML = chips.join('');
}

function renderDP() {
    const filtered = sortDPPhrases(applyDPFilters(), DP_STATE.sort);
    const cards = document.getElementById('dpCards');
    const count = document.getElementById('dpCount');
    const empty = document.getElementById('dpEmpty');

    count.textContent = `${filtered.length} of ${DP_STATE.phrases.length} dot phrase${filtered.length === 1 ? '' : 's'}`;
    if (!filtered.length) {
        cards.innerHTML = '';
        empty.style.display = 'block';
    } else {
        empty.style.display = 'none';
        cards.innerHTML = filtered.map(renderDPCard).join('');
    }
    renderDPSidebar();
    renderDPActiveFilters();
}

function jumpToDPCard(id) {
    DP_STATE.expanded.add(id);
    pushDPRecent(id);
    renderDP();
    setTimeout(() => {
        const el = document.querySelector(`[data-dp-id="${CSS.escape(id)}"]`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
}

function wireDotphrasesUI() {
    // Search
    document.getElementById('dpSearch').addEventListener('input', e => {
        DP_STATE.query = e.target.value;
        renderDP();
    });
    // Scope radios
    document.querySelectorAll('input[name="dpScope"]').forEach(el => {
        el.addEventListener('change', () => {
            DP_STATE.scope = document.querySelector('input[name="dpScope"]:checked').value;
            renderDP();
        });
    });
    // Sort
    document.getElementById('dpSort').addEventListener('change', e => {
        DP_STATE.sort = e.target.value;
        renderDP();
    });
    // Add
    document.getElementById('dpAddBtn').addEventListener('click', () => requireEditor(() => openDPEditor(null)));
    // Sidebar toggle
    document.getElementById('dpSidebarToggle').addEventListener('click', () => {
        document.getElementById('dpSidebar').classList.toggle('open');
    });

    // Delegated clicks on the card grid
    document.getElementById('dpCards').addEventListener('click', e => {
        const fav = e.target.closest('[data-dp-fav]');
        if (fav) { e.stopPropagation(); toggleDPFavorite(fav.dataset.dpFav); renderDP(); return; }

        const copyBtn = e.target.closest('[data-dp-copy]');
        if (copyBtn) {
            e.stopPropagation();
            const p = DP_STATE.phrases.find(x => x.id === copyBtn.dataset.dpCopy);
            if (p) {
                copyTextToClipboard(p.content, copyBtn);
                pushDPRecent(p.id);
            }
            return;
        }

        const editBtn = e.target.closest('[data-dp-edit]');
        if (editBtn) {
            e.stopPropagation();
            requireEditor(() => {
                const p = DP_STATE.phrases.find(x => x.id === editBtn.dataset.dpEdit);
                if (p) openDPEditor(p);
            });
            return;
        }

        const toggle = e.target.closest('[data-dp-toggle]');
        if (toggle) {
            const id = toggle.dataset.dpToggle;
            if (DP_STATE.expanded.has(id)) DP_STATE.expanded.delete(id);
            else { DP_STATE.expanded.add(id); pushDPRecent(id); }
            renderDP();
            return;
        }

        const tag = e.target.closest('[data-tag]');
        if (tag) {
            DP_STATE.activeTags.add(tag.dataset.tag);
            renderDP();
            return;
        }
    });

    // Sidebar click handlers
    document.getElementById('dpCategories').addEventListener('click', e => {
        const link = e.target.closest('[data-dp-cat]');
        if (!link) return;
        e.preventDefault();
        const cat = link.dataset.dpCat;
        DP_STATE.category = (DP_STATE.category === cat) ? null : cat;
        renderDP();
    });
    document.getElementById('dpSidebar').addEventListener('click', e => {
        const jump = e.target.closest('[data-dp-jump]');
        if (jump) { e.preventDefault(); jumpToDPCard(jump.dataset.dpJump); }
    });
    document.getElementById('dpActiveFilters').addEventListener('click', e => {
        if (e.target.closest('[data-dp-cat-clear]')) { DP_STATE.category = null; renderDP(); return; }
        const tagClear = e.target.closest('[data-dp-tag-clear]');
        if (tagClear) { DP_STATE.activeTags.delete(tagClear.dataset.dpTagClear); renderDP(); }
    });

    // Editor modal wiring
    wireDPEditor();
}

// ----- Dot phrase editor modal -----

function wireDPEditor() {
    const tagInput = document.getElementById('dpTagInput');
    tagInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const v = tagInput.value.trim();
            if (v && !DP_STATE.editingTags.includes(v)) {
                DP_STATE.editingTags.push(v);
                renderDPEditTags();
            }
            tagInput.value = '';
        }
    });
    document.getElementById('dpTagsBox').addEventListener('click', e => {
        const rm = e.target.closest('[data-rm-tag]');
        if (rm) {
            DP_STATE.editingTags = DP_STATE.editingTags.filter(t => t !== rm.dataset.rmTag);
            renderDPEditTags();
        }
    });
    document.getElementById('dpSaveBtn').addEventListener('click', saveDPFromEditor);
    document.getElementById('dpDeleteBtn').addEventListener('click', () => {
        if (DP_STATE.editing && confirm(`Delete "${DP_STATE.editing.name}"?`)) deleteDP(DP_STATE.editing.id);
    });
}

function renderDPEditTags() {
    document.getElementById('dpTagsBox').innerHTML = DP_STATE.editingTags.map(t =>
        `<span class="editor-tag-chip">${escapeHtml(t)} <button type="button" data-rm-tag="${escapeHtml(t)}" aria-label="Remove tag">&times;</button></span>`
    ).join('');
}

function openDPEditor(phrase) {
    DP_STATE.editing = phrase;
    DP_STATE.editingTags = (phrase?.tags || []).slice();

    document.getElementById('dotphraseModalLabel').textContent = phrase ? `Edit — ${phrase.name}` : 'Add dot phrase';
    document.getElementById('dpName').value = phrase?.name || '';
    document.getElementById('dpCategory').value = phrase?.category || 'Note Template';
    document.getElementById('dpContent').value = phrase?.content || '';
    document.getElementById('dpDeleteBtn').style.display = phrase ? 'inline-block' : 'none';
    renderDPEditTags();

    DP_STATE.modal.show();
}

async function saveDPFromEditor() {
    const password = EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }
    const name = document.getElementById('dpName').value.trim();
    const content = document.getElementById('dpContent').value;
    if (!name)    { toast('Name is required.', 'error'); return; }
    if (!content.trim()) { toast('Content is required.', 'error'); return; }

    const existing = DP_STATE.editing;
    const now = new Date().toISOString();
    const id = existing?.id || (name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) + '-' + Date.now().toString(36));
    const record = {
        id,
        name,
        content,
        category: document.getElementById('dpCategory').value,
        tags: DP_STATE.editingTags.slice(),
        createdAt: existing?.createdAt || now,
        updatedAt: now,
    };

    const btn = document.getElementById('dpSaveBtn');
    btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Saving...';
    try {
        const url = existing
            ? `/api/list/dot-phrases/${encodeURIComponent(id)}`
            : '/api/list/dot-phrases';
        const r = await fetch(url, {
            method: existing ? 'PUT' : 'POST',
            headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(record),
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        // Optimistic in-memory update
        if (existing) {
            DP_STATE.phrases = DP_STATE.phrases.map(p => p.id === id ? record : p);
        } else {
            DP_STATE.phrases.push(record);
        }
        toast(existing ? 'Updated.' : 'Added.', 'success');
        DP_STATE.modal.hide();
        renderDP();
    } catch (e) {
        toast(`Save failed: ${e.message}`, 'error', { duration: 5000 });
    } finally {
        btn.disabled = false; btn.innerHTML = '<i class="fas fa-save me-1"></i>Save';
    }
}

async function deleteDP(id) {
    const password = EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }
    try {
        const r = await fetch(`/api/list/dot-phrases/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${password}` },
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        DP_STATE.phrases = DP_STATE.phrases.filter(p => p.id !== id);
        DP_STATE.favorites.delete(id);
        DP_STATE.recents = DP_STATE.recents.filter(r => r !== id);
        DP_STATE.expanded.delete(id);
        saveDPPrefs();
        toast('Deleted.', 'success');
        DP_STATE.modal.hide();
        renderDP();
    } catch (e) {
        toast(`Delete failed: ${e.message}`, 'error', { duration: 5000 });
    }
}

// =========================================================================
// In-browser editor — commits to GitHub via API for zero-friction adds/edits
// =========================================================================

const EDITOR_STORAGE = {
    pat: 'ecref.editor.pat',         // encrypted PAT blob (localStorage, GitHub mode)
    repo: 'ecref.editor.repo',       // {owner, repo} JSON if user overrides auto-detect
    apiPassword: 'ecref.editor.apipw', // plain editor password (sessionStorage, API mode)
};

const EDITOR_STATE = {
    mode: 'github',            // 'api' (Vercel KV) | 'github' (PAT-based)
    configured: false,         // GitHub mode: is an encrypted PAT in localStorage?
    pat: null,                 // GitHub mode: decrypted PAT (memory only)
    apiPassword: null,         // API mode: editor password (memory only)
    owner: null,
    repo: null,
    tags: [],                  // tags being edited in the modal
    links: [],                 // links being edited
    images: [],                // image paths currently attached
    pendingUploads: [],        // {filename, contentB64} not yet committed
    editingId: null,           // null = add new, else id of entry being edited
    setupModal: null,
    unlockModal: null,
    entryModal: null,
    pendingActionAfterUnlock: null,
};

// Loads entries with mode auto-detection. Sets EDITOR_STATE.mode + .configured
// as side effects so renderKB picks them up immediately.
async function loadEntries(bust) {
    let entries;
    // Try the API first — works on Vercel deployments with KV configured.
    try {
        const r = await fetch('/api/entries', { cache: 'no-store' });
        if (r.ok) {
            const data = await r.json();
            EDITOR_STATE.mode = 'api';
            entries = data.database || [];
        }
    } catch (e) {
        // Network error, no /api on this host, etc. — fall through.
    }
    if (entries === undefined) {
        EDITOR_STATE.mode = 'github';
        const r = await fetch('reference_data.json' + (bust || ''), { cache: 'no-store' });
        const data = await r.json();
        entries = data.database || [];
    }
    // API mode is always "configured" (just need password). GitHub mode depends on PAT.
    EDITOR_STATE.configured = EDITOR_STATE.mode === 'api'
        || !!localStorage.getItem(EDITOR_STORAGE.pat);
    return entries;
}

// Detect owner/repo from GitHub Pages URL or stored override
function detectRepo() {
    const stored = localStorage.getItem(EDITOR_STORAGE.repo);
    if (stored) {
        try {
            const parsed = JSON.parse(stored);
            if (parsed.owner && parsed.repo) return parsed;
        } catch (e) { /* fall through */ }
    }
    const host = window.location.hostname;
    const path = window.location.pathname;
    // Pattern: <user>.github.io/<repo>/...
    const ghMatch = host.match(/^([^.]+)\.github\.io$/);
    if (ghMatch) {
        const owner = ghMatch[1];
        const pathParts = path.split('/').filter(Boolean);
        // If user pages (owner.github.io/) the repo is owner.github.io itself
        const repo = pathParts.length > 0 ? pathParts[0] : `${owner}.github.io`;
        return { owner, repo };
    }
    // Custom domain or local dev — no auto-detect
    return { owner: null, repo: null };
}

function initEditor() {
    const { owner, repo } = detectRepo();
    EDITOR_STATE.owner = owner;
    EDITOR_STATE.repo = repo;
    // In API mode, "configured" is always true (just need to enter password).
    // In GitHub mode, it depends on whether an encrypted PAT exists.
    EDITOR_STATE.configured = EDITOR_STATE.mode === 'api'
        || !!localStorage.getItem(EDITOR_STORAGE.pat);

    // Restore API password from sessionStorage if we set it earlier this tab session.
    if (EDITOR_STATE.mode === 'api') {
        try {
            const stored = sessionStorage.getItem(EDITOR_STORAGE.apiPassword);
            if (stored) EDITOR_STATE.apiPassword = stored;
        } catch (e) { /* private mode etc. — ignore */ }
    }

    // Bootstrap modal instances
    if (window.bootstrap) {
        EDITOR_STATE.setupModal = new bootstrap.Modal(document.getElementById('setupModal'));
        EDITOR_STATE.unlockModal = new bootstrap.Modal(document.getElementById('unlockModal'));
        EDITOR_STATE.entryModal = new bootstrap.Modal(document.getElementById('entryModal'));
    }

    // Pre-fill the repo name in setup screen 1
    const repoNameEl = document.getElementById('setupRepoName');
    if (repoNameEl) {
        repoNameEl.textContent = repo ? `${owner}/${repo}` : 'your Ecref repo';
    }

    wireSetupWizard();
    wireUnlockModal();
    wireEntryEditor();

    // Toolbar buttons
    document.getElementById('kbAddBtn')?.addEventListener('click', () => {
        requireEditor(() => openEntryEditor(null));
    });
    document.getElementById('kbEditorMenu')?.addEventListener('click', () => {
        if (EDITOR_STATE.mode === 'api') {
            // API mode: offer to clear the cached password (forces re-prompt)
            if (EDITOR_STATE.apiPassword) {
                if (confirm('Clear the editor password? You will be prompted again on next edit.')) {
                    EDITOR_STATE.apiPassword = null;
                    try { sessionStorage.removeItem(EDITOR_STORAGE.apiPassword); } catch (e) { /* ignore */ }
                    toast('Editor password cleared.', 'info');
                }
            } else {
                toast('API mode: password is set in Vercel env var EDITOR_PASSWORD. Click Add Entry to enter it.', 'info', { duration: 5000 });
            }
            return;
        }
        openSetupWizard();
    });

    // Re-render KB now that we know the editor mode (affects Edit button visibility)
    if (typeof renderKB === 'function' && KB_STATE.entries.length) renderKB();
}

// =========================================================================
// PAT encryption + storage
// =========================================================================

async function encryptPat(pat, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(pat)
    );
    return { ct: bufToB64(ct), iv: bufToB64(iv), salt: bufToB64(salt) };
}

async function decryptPat(secret, password) {
    const key = await deriveAesKey(password, b64ToBuf(secret.salt));
    const buf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBuf(secret.iv) },
        key,
        b64ToBuf(secret.ct)
    );
    return new TextDecoder().decode(buf);
}

function loadEncryptedPat() {
    const raw = localStorage.getItem(EDITOR_STORAGE.pat);
    return raw ? JSON.parse(raw) : null;
}

function storeEncryptedPat(secret) {
    localStorage.setItem(EDITOR_STORAGE.pat, JSON.stringify(secret));
    EDITOR_STATE.configured = true;
}

function clearStoredPat() {
    localStorage.removeItem(EDITOR_STORAGE.pat);
    EDITOR_STATE.pat = null;
    EDITOR_STATE.configured = false;
    renderKB();
}

// =========================================================================
// GitHub API client
// =========================================================================

const GH_API = 'https://api.github.com';

function ghHeaders() {
    if (!EDITOR_STATE.pat) throw new Error('Editor not unlocked');
    return {
        'Authorization': `Bearer ${EDITOR_STATE.pat}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    };
}

async function ghTestAuth(pat) {
    const r = await fetch(`${GH_API}/repos/${EDITOR_STATE.owner}/${EDITOR_STATE.repo}`, {
        headers: {
            'Authorization': `Bearer ${pat}`,
            'Accept': 'application/vnd.github+json',
        }
    });
    if (r.status === 401) throw new Error('Token rejected — check that you copied it correctly.');
    if (r.status === 403) throw new Error('Token lacks the right permissions — needs Contents: Read and write.');
    if (r.status === 404) throw new Error(`Repo ${EDITOR_STATE.owner}/${EDITOR_STATE.repo} not found or token can't see it.`);
    if (!r.ok) throw new Error(`GitHub returned HTTP ${r.status}`);
    return r.json();
}

async function ghGetFile(path) {
    const url = `${GH_API}/repos/${EDITOR_STATE.owner}/${EDITOR_STATE.repo}/contents/${encodeURIComponent(path)}`;
    const r = await fetch(url, { headers: ghHeaders() });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub GET ${path}: HTTP ${r.status}`);
    const data = await r.json();
    return { sha: data.sha, contentB64: data.content };
}

async function ghPutFile(path, contentB64, sha, message) {
    const url = `${GH_API}/repos/${EDITOR_STATE.owner}/${EDITOR_STATE.repo}/contents/${encodeURIComponent(path)}`;
    const body = { message, content: contentB64 };
    if (sha) body.sha = sha;
    const r = await fetch(url, {
        method: 'PUT',
        headers: { ...ghHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.message || `GitHub PUT ${path}: HTTP ${r.status}`);
    }
    return r.json();
}

// UTF-8 safe base64 (btoa chokes on multibyte; we need this for JSON commits)
function utf8ToB64(str) {
    const bytes = new TextEncoder().encode(str);
    let s = '';
    bytes.forEach(b => s += String.fromCharCode(b));
    return btoa(s);
}

function b64ToUtf8(b64) {
    const binary = atob(b64.replace(/\s/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
}

// =========================================================================
// Setup wizard
// =========================================================================

function wireSetupWizard() {
    document.querySelectorAll('[data-setup-next]').forEach(btn => {
        btn.addEventListener('click', () => showSetupStep(btn.dataset.setupNext));
    });
    document.querySelectorAll('[data-setup-prev]').forEach(btn => {
        btn.addEventListener('click', () => showSetupStep(btn.dataset.setupPrev));
    });
    document.getElementById('setupTestBtn')?.addEventListener('click', completeSetup);
}

function showSetupStep(n) {
    ['1', '2', '3', '4'].forEach(s => {
        const el = document.getElementById('setupStep' + s);
        if (el) el.style.display = s === n ? 'block' : 'none';
    });
}

function openSetupWizard() {
    // Reset state
    document.getElementById('setupPatInput').value = '';
    document.getElementById('setupPasswordInput').value = '';
    document.getElementById('setupPasswordConfirm').value = '';
    document.getElementById('setupPwError').style.display = 'none';
    showSetupStep('1');
    EDITOR_STATE.setupModal?.show();
}

async function completeSetup() {
    const pat = document.getElementById('setupPatInput').value.trim();
    const pw = document.getElementById('setupPasswordInput').value;
    const pwConfirm = document.getElementById('setupPasswordConfirm').value;
    const err = document.getElementById('setupPwError');
    err.style.display = 'none';

    if (!pat) {
        document.getElementById('setupPatInput').focus();
        showSetupStep('2');
        toast('Paste your GitHub access token first.', 'error');
        return;
    }
    if (pw.length < 8) {
        err.textContent = 'Password must be at least 8 characters.';
        err.style.display = 'block';
        return;
    }
    if (pw !== pwConfirm) {
        err.textContent = 'Passwords do not match.';
        err.style.display = 'block';
        return;
    }

    showSetupStep('4');
    const titleEl = document.getElementById('setupResultTitle');
    const bodyEl = document.getElementById('setupResultBody');
    const doneRow = document.getElementById('setupDoneRow');
    const retryRow = document.getElementById('setupRetryRow');
    titleEl.textContent = 'Testing your token...';
    bodyEl.innerHTML = '<i class="fas fa-spinner fa-spin fa-2x text-primary"></i>';
    doneRow.style.display = 'none';
    retryRow.style.display = 'none';

    if (!EDITOR_STATE.owner || !EDITOR_STATE.repo) {
        titleEl.textContent = 'Cannot detect your repo';
        bodyEl.innerHTML = '<p>This site does not appear to be hosted on GitHub Pages. Local preview cannot save to GitHub. Deploy first, then try again from the live URL.</p>';
        retryRow.style.display = 'flex';
        return;
    }

    EDITOR_STATE.pat = pat;
    try {
        const repoInfo = await ghTestAuth(pat);
        const secret = await encryptPat(pat, pw);
        storeEncryptedPat(secret);
        titleEl.innerHTML = '<i class="fas fa-check-circle text-success me-2"></i>All set!';
        bodyEl.innerHTML = `<p>Editor is ready. You can now add and edit entries in <strong>${escapeHtml(repoInfo.full_name)}</strong>.</p><p class="text-muted small">Tip: keep using the same password as your other gates — easier to remember.</p>`;
        doneRow.style.display = 'flex';
        renderKB();  // re-render so Edit buttons appear
    } catch (e) {
        EDITOR_STATE.pat = null;
        titleEl.innerHTML = '<i class="fas fa-times-circle text-danger me-2"></i>Setup failed';
        bodyEl.innerHTML = `<p>${escapeHtml(e.message)}</p><p class="text-muted small">Common fixes: regenerate the token with <code>Contents: Read and write</code> permission, or check that you selected the right repository.</p>`;
        retryRow.style.display = 'flex';
    }
}

// =========================================================================
// Unlock modal
// =========================================================================

function wireUnlockModal() {
    document.getElementById('unlockSubmit')?.addEventListener('click', unlockPatFromModal);
    document.getElementById('unlockPasswordInput')?.addEventListener('keypress', e => {
        if (e.which === 13) unlockPatFromModal();
    });
}

async function unlockPatFromModal() {
    const pw = document.getElementById('unlockPasswordInput').value;
    const err = document.getElementById('unlockError');
    err.style.display = 'none';

    if (EDITOR_STATE.mode === 'api') {
        // Verify the password by attempting a no-op authenticated request.
        // We use DELETE on a known-missing id; expect 404 (auth OK) or 401 (bad pw).
        try {
            const r = await fetch('/api/entries/__auth_probe__', {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${pw}` },
            });
            if (r.status === 401) {
                err.textContent = 'Wrong password.';
                err.style.display = 'block';
                return;
            }
            // Any other status (404, 200) means auth was accepted
            EDITOR_STATE.apiPassword = pw;
            try { sessionStorage.setItem(EDITOR_STORAGE.apiPassword, pw); } catch (e) { /* ignore */ }
            document.getElementById('unlockPasswordInput').value = '';
            EDITOR_STATE.unlockModal?.hide();
            const next = EDITOR_STATE.pendingActionAfterUnlock;
            EDITOR_STATE.pendingActionAfterUnlock = null;
            if (next) next();
        } catch (e) {
            err.textContent = 'Could not reach the API. Try again.';
            err.style.display = 'block';
        }
        return;
    }

    // GitHub mode: decrypt the PAT with the password
    const secret = loadEncryptedPat();
    if (!secret) {
        EDITOR_STATE.unlockModal?.hide();
        openSetupWizard();
        return;
    }
    try {
        EDITOR_STATE.pat = await decryptPat(secret, pw);
        document.getElementById('unlockPasswordInput').value = '';
        EDITOR_STATE.unlockModal?.hide();
        const next = EDITOR_STATE.pendingActionAfterUnlock;
        EDITOR_STATE.pendingActionAfterUnlock = null;
        if (next) next();
    } catch (e) {
        err.textContent = 'Wrong password.';
        err.style.display = 'block';
    }
}

// Run callback once editor is unlocked. Branches by mode.
function requireEditor(cb) {
    if (EDITOR_STATE.mode === 'api') {
        if (EDITOR_STATE.apiPassword) { cb(); return; }
        EDITOR_STATE.pendingActionAfterUnlock = cb;
        promptApiPassword();
        return;
    }
    // GitHub mode (default / legacy)
    if (EDITOR_STATE.pat) { cb(); return; }
    if (EDITOR_STATE.configured) {
        EDITOR_STATE.pendingActionAfterUnlock = cb;
        document.getElementById('unlockError').style.display = 'none';
        document.getElementById('unlockPasswordInput').value = '';
        EDITOR_STATE.unlockModal?.show();
        setTimeout(() => document.getElementById('unlockPasswordInput').focus(), 250);
    } else {
        EDITOR_STATE.pendingActionAfterUnlock = cb;
        openSetupWizard();
    }
}

// API mode: open the unlock modal repurposed as a "enter editor password" prompt.
function promptApiPassword() {
    const titleEl = document.querySelector('#unlockModal .modal-title');
    const bodyText = document.querySelector('#unlockModal .modal-body p');
    if (titleEl) titleEl.innerHTML = '<i class="fas fa-key me-2"></i>Editor password';
    if (bodyText) bodyText.textContent = 'Enter the editor password (set in Vercel as EDITOR_PASSWORD).';
    document.getElementById('unlockError').style.display = 'none';
    document.getElementById('unlockPasswordInput').value = '';
    EDITOR_STATE.unlockModal?.show();
    setTimeout(() => document.getElementById('unlockPasswordInput').focus(), 250);
}

// =========================================================================
// Entry editor modal
// =========================================================================

function wireEntryEditor() {
    document.getElementById('entrySaveBtn')?.addEventListener('click', saveEntry);
    document.getElementById('entryDeleteBtn')?.addEventListener('click', confirmDeleteEntry);

    // Quill needs the container to have its final width before it builds
    // the toolbar, otherwise the formatting bar gets miscomputed (especially
    // for the second editor, which renders in cramped layout). Apply the
    // pending bodies AFTER the modal is fully shown.
    const entryModalEl = document.getElementById('entryModal');
    entryModalEl?.addEventListener('shown.bs.modal', () => {
        const pending = EDITOR_STATE._pendingBodies;
        if (pending) {
            setKbBody('data', pending.data);
            setKbBody('template', pending.template);
            EDITOR_STATE._pendingBodies = null;
        }
        // Defensive: if the Quills were created in a previous open while
        // the modal was smaller, force a layout refresh now.
        try { _kbQuill.data && _kbQuill.data.update('user'); } catch (_) {}
        try { _kbQuill.template && _kbQuill.template.update('user'); } catch (_) {}
    });

    // Tag chip input
    const tagInput = document.getElementById('entryTagInput');
    tagInput?.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault();
            const val = tagInput.value.trim().replace(/,$/, '').trim();
            if (val && !EDITOR_STATE.tags.includes(val)) {
                EDITOR_STATE.tags.push(val);
                renderEditorTags();
            }
            tagInput.value = '';
        } else if (e.key === 'Backspace' && !tagInput.value && EDITOR_STATE.tags.length) {
            EDITOR_STATE.tags.pop();
            renderEditorTags();
        }
    });
    document.getElementById('entryTagsBox')?.addEventListener('click', e => {
        const rm = e.target.closest('[data-rm-tag]');
        if (rm) {
            EDITOR_STATE.tags = EDITOR_STATE.tags.filter(t => t !== rm.dataset.rmTag);
            renderEditorTags();
        }
    });

    // Add link row
    document.getElementById('entryAddLinkBtn')?.addEventListener('click', () => {
        EDITOR_STATE.links.push({ label: '', url: '' });
        renderEditorLinks();
    });
    document.getElementById('entryLinksList')?.addEventListener('click', e => {
        const rm = e.target.closest('[data-rm-link]');
        if (rm) {
            EDITOR_STATE.links.splice(parseInt(rm.dataset.rmLink, 10), 1);
            renderEditorLinks();
        }
    });
    document.getElementById('entryLinksList')?.addEventListener('input', e => {
        const labelInput = e.target.closest('[data-link-label]');
        if (labelInput) EDITOR_STATE.links[parseInt(labelInput.dataset.linkLabel, 10)].label = labelInput.value;
        const urlInput = e.target.closest('[data-link-url]');
        if (urlInput) EDITOR_STATE.links[parseInt(urlInput.dataset.linkUrl, 10)].url = urlInput.value;
    });

    // Image picker + drag-drop
    const drop = document.getElementById('entryImageDrop');
    const fileInput = document.getElementById('entryImageFile');
    document.getElementById('entryImagePickBtn')?.addEventListener('click', () => fileInput.click());
    fileInput?.addEventListener('change', e => handleImageFiles(e.target.files));
    drop?.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('dragover'); });
    drop?.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop?.addEventListener('drop', e => {
        e.preventDefault();
        drop.classList.remove('dragover');
        handleImageFiles(e.dataTransfer.files);
    });
    document.getElementById('entryImagesList')?.addEventListener('click', e => {
        const rm = e.target.closest('[data-rm-img]');
        if (rm) {
            EDITOR_STATE.images = EDITOR_STATE.images.filter(p => p !== rm.dataset.rmImg);
            EDITOR_STATE.pendingUploads = EDITOR_STATE.pendingUploads.filter(u => u.path !== rm.dataset.rmImg);
            renderEditorImages();
        }
    });
}

// ----- KB entry Quill instances (data + template) -----------------------
// Initialized lazily the first time the entry modal opens. Each Quill
// shares the same SANITIZE_CONFIG as the Reference editor.
const _kbQuill = { data: null, template: null };

function getKbQuill(which) {
    if (_kbQuill[which] || typeof Quill === 'undefined') return _kbQuill[which];
    registerQuillExtensions();
    const id = which === 'data' ? '#entryData' : '#entryTemplate';
    _kbQuill[which] = new Quill(id, {
        theme: 'snow',
        placeholder: which === 'data'
            ? 'Clinical details, differential, key findings... paste from UpToDate/MKSAP to keep formatting. Use the "Paste markdown" button for raw markdown text.'
            : 'Workup, orders, assessment template... rich text supported. Use the "Paste markdown" button for raw markdown text.',
        modules: {
            toolbar: [
                [{ header: [1, 2, 3, 4, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ list: 'ordered' }, { list: 'bullet' }],
                ['blockquote', 'code-block'],
                ['link'],
                [{ color: [] }, { background: [] }],
                ['clean'],
            ],
            clipboard: {
                matchers: quillClipboardMatchers(),
            },
        },
    });
    attachImagePasteInterceptor(_kbQuill[which]);
    return _kbQuill[which];
}

function setKbBody(which, body) {
    const q = getKbQuill(which);
    if (!q) {
        const el = document.getElementById(which === 'data' ? 'entryData' : 'entryTemplate');
        if (el) el.textContent = body || '';
        return;
    }
    loadBodyIntoQuill(q, body);
}

function getKbBody(which) {
    const q = getKbQuill(which);
    if (!q) {
        const el = document.getElementById(which === 'data' ? 'entryData' : 'entryTemplate');
        return el ? el.textContent : '';
    }
    const raw = (q.getSemanticHTML && q.getSemanticHTML()) || q.root.innerHTML;
    if (/^\s*(<p>(<br>)?<\/p>\s*)+$/i.test(raw)) return '';
    return sanitizeHtml(raw);
}

function openEntryEditor(id) {
    requireEditor(() => {
        EDITOR_STATE.editingId = id;
        EDITOR_STATE.pendingUploads = [];
        const isEdit = !!id;
        document.getElementById('entryModalLabel').textContent = isEdit ? 'Edit entry' : 'Add entry';
        document.getElementById('entryDeleteBtn').style.display = isEdit ? 'inline-block' : 'none';

        let pendingData = '';
        let pendingTemplate = '';
        if (isEdit) {
            const entry = KB_STATE.entries.find(e => e.id === id);
            if (!entry) {
                toast('Entry not found.', 'error');
                return;
            }
            document.getElementById('entryTitle').value = getTitle(entry);
            document.getElementById('entryCategory').value = entry.category || 'Other';
            EDITOR_STATE.tags = [...(entry.tags || [])];
            EDITOR_STATE.links = (entry.links || []).map(l => ({ ...l }));
            EDITOR_STATE.images = (entry.imgs || '').split(',').map(s => s.trim()).filter(Boolean);
            // Strip title from data (we re-add it on save). For HTML bodies the
            // saved format is "title\n<html>..." — same split logic works.
            const dataLines = (entry.data || '').split('\n');
            const titleLine = dataLines.findIndex(l => l.trim().replace(/^#+\s*/, ''));
            const bodyLines = titleLine >= 0 ? dataLines.slice(titleLine + 1) : dataLines;
            pendingData = bodyLines.join('\n').replace(/^\n+/, '');
            pendingTemplate = entry.template || '';
        } else {
            document.getElementById('entryTitle').value = '';
            document.getElementById('entryCategory').value = KB_STATE.category || 'Other';
            EDITOR_STATE.tags = [];
            EDITOR_STATE.links = [];
            EDITOR_STATE.images = [];
        }
        document.getElementById('entryTagInput').value = '';
        renderEditorTags();
        renderEditorLinks();
        renderEditorImages();

        // Defer Quill construction + body load until after the modal is
        // actually visible. If we do this while the modal is display:none,
        // Quill measures the container at 0 width and the toolbar lays out
        // wrong — the second editor in particular ends up with no room for
        // the formatting bar.
        EDITOR_STATE._pendingBodies = { data: pendingData, template: pendingTemplate };
        EDITOR_STATE.entryModal?.show();
    });
}

function renderEditorTags() {
    const box = document.getElementById('entryTagsBox');
    if (!EDITOR_STATE.tags.length) {
        box.innerHTML = '<span class="text-muted small">No tags yet.</span>';
        return;
    }
    box.innerHTML = EDITOR_STATE.tags.map(t =>
        `<span class="editor-tag-chip">${escapeHtml(t)} <button type="button" data-rm-tag="${escapeHtml(t)}" aria-label="Remove tag">&times;</button></span>`
    ).join(' ');
}

function renderEditorLinks() {
    const list = document.getElementById('entryLinksList');
    if (!EDITOR_STATE.links.length) {
        list.innerHTML = '<div class="text-muted small mb-2">No links yet.</div>';
        return;
    }
    list.innerHTML = EDITOR_STATE.links.map((l, i) => `
        <div class="editor-link-row">
            <input type="text" class="form-control form-control-sm" placeholder="Label (e.g. CPSolvers: chest pain)" data-link-label="${i}" value="${escapeHtml(l.label || '')}">
            <input type="text" class="form-control form-control-sm" placeholder="https://..." data-link-url="${i}" value="${escapeHtml(l.url || '')}">
            <button type="button" class="btn btn-sm btn-outline-danger" data-rm-link="${i}" aria-label="Remove link">&times;</button>
        </div>
    `).join('');
}

function renderEditorImages() {
    const list = document.getElementById('entryImagesList');
    if (!EDITOR_STATE.images.length) {
        list.innerHTML = '';
        return;
    }
    list.innerHTML = EDITOR_STATE.images.map(p => {
        const isUploading = p.startsWith('uploading:');
        const isImg = /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(p);
        const isPending = EDITOR_STATE.pendingUploads.some(u => u.path === p);
        let thumb;
        if (isUploading) {
            thumb = '<div class="img-uploading"><i class="fas fa-spinner fa-spin"></i></div>';
        } else if (isImg) {
            thumb = `<img src="${escapeHtml(p)}" alt="">`;
        } else {
            thumb = `<span class="img-note">${escapeHtml(p)}</span>`;
        }
        const label = isUploading ? p.slice('uploading:'.length) : p;
        let badge = '';
        if (isUploading) badge = '<span class="badge bg-info text-dark">Uploading…</span>';
        else if (isPending) badge = '<span class="badge bg-warning text-dark">Will upload on save</span>';
        return `<div class="editor-image-chip${isPending || isUploading ? ' pending' : ''}">
            ${thumb}
            <div class="editor-image-meta">
                <small>${escapeHtml(label)}</small>
                ${badge}
            </div>
            <button type="button" class="btn btn-sm btn-outline-danger" data-rm-img="${escapeHtml(p)}" aria-label="Remove image"${isUploading ? ' disabled' : ''}>&times;</button>
        </div>`;
    }).join('');
}

// Vercel's platform request-body limit is 4.5 MB. Base64 inflates by ~33%,
// so the practical raw-file ceiling for the JSON /api/upload-image path is
// ~3.3 MB. For larger files we fall back to:
//   1) client-side compression (re-encode to JPEG, cap dimension)
//   2) if still too big, a presigned PUT straight to R2 (bypasses Vercel)
const MAX_INLINE_UPLOAD_BYTES = 3_300_000;
const COMPRESS_MAX_DIM = 1920;          // 1920px on the long edge — plenty for clinical images
const COMPRESS_JPEG_QUALITY = 0.85;

function isUnsupportedImageType(file) {
    const name = (file.name || '').toLowerCase();
    const type = (file.type || '').toLowerCase();
    return type === 'image/heic' || type === 'image/heif'
        || name.endsWith('.heic') || name.endsWith('.heif');
}

function imageUploadPrecheck(file) {
    if (isUnsupportedImageType(file)) {
        return 'HEIC/HEIF isn’t supported in most browsers (Chrome/Firefox can’t display it). '
             + 'Convert to JPEG or PNG first: Preview → File → Export As → JPEG, '
             + 'or right-click the file in Finder → Quick Actions → Convert Image.';
    }
    return null;
}

// Re-encode an image to JPEG via canvas, capping the long edge at maxDim.
// Returns a new File or the original if compression didn't help (or failed).
async function compressImageIfNeeded(file) {
    if (file.size <= MAX_INLINE_UPLOAD_BYTES) return file;
    if (!file.type.startsWith('image/')) return file;
    try {
        const bitmap = await createImageBitmap(file);
        const scale = Math.min(1, COMPRESS_MAX_DIM / Math.max(bitmap.width, bitmap.height));
        const w = Math.round(bitmap.width * scale);
        const h = Math.round(bitmap.height * scale);
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        const ctx = canvas.getContext('2d');
        // White backdrop so transparent PNGs don't go black when re-encoded as JPEG.
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, w, h);
        ctx.drawImage(bitmap, 0, 0, w, h);
        bitmap.close && bitmap.close();
        const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', COMPRESS_JPEG_QUALITY));
        if (!blob || blob.size >= file.size) return file;   // compression made it bigger — keep original
        const baseName = (file.name || 'image').replace(/\.[^.]+$/, '');
        return new File([blob], `${baseName}.jpg`, { type: 'image/jpeg', lastModified: Date.now() });
    } catch (e) {
        console.warn('compressImageIfNeeded failed; uploading original', e);
        return file;
    }
}

// Smart upload: pick the right pipeline for the file size.
//   ≤ 3.3 MB raw            → POST /api/upload-image (single round-trip)
//   3.3 MB – ~10 MB         → compress to JPEG, re-check size, then either path
//   still > 3.3 MB          → presigned PUT direct to R2 (bypasses Vercel)
// Returns the public URL of the uploaded image.
async function uploadImageSmart(originalFile, password) {
    let file = originalFile;
    if (file.size > MAX_INLINE_UPLOAD_BYTES) {
        file = await compressImageIfNeeded(file);
    }
    if (file.size <= MAX_INLINE_UPLOAD_BYTES) {
        return await uploadImageInline(file, password);
    }
    return await uploadImageViaPresign(file, password);
}

async function uploadImageInline(file, password) {
    const b64 = await fileToB64(file);
    const r = await fetch('/api/upload-image', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, contentB64: b64, contentType: file.type }),
    });
    if (r.status === 503) throw new Error('R2 not configured on the server');
    if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${r.status}`);
    }
    return (await r.json()).url;
}

async function uploadImageViaPresign(file, password) {
    // 1) Ask our function for a presigned URL.
    const presignRes = await fetch('/api/presign-upload', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, contentType: file.type }),
    });
    if (presignRes.status === 503) throw new Error('R2 not configured on the server');
    if (!presignRes.ok) {
        const j = await presignRes.json().catch(() => ({}));
        throw new Error(j.error || `presign HTTP ${presignRes.status}`);
    }
    const { uploadUrl, publicUrl } = await presignRes.json();
    // 2) PUT bytes straight to R2. The browser must be allowed via the
    // bucket's CORS config (one-time setup; see README).
    const putRes = await fetch(uploadUrl, {
        method: 'PUT',
        headers: { 'Content-Type': file.type },
        body: file,
    });
    if (!putRes.ok) {
        throw new Error(`R2 PUT failed (HTTP ${putRes.status}). If this says CORS or 403, the R2 bucket needs CORS allowing PUT from this origin.`);
    }
    return publicUrl;
}

async function handleImageFiles(files) {
    for (const file of files) {
        if (!file.type.startsWith('image/') && !/\.(heic|heif)$/i.test(file.name || '')) continue;

        const reason = imageUploadPrecheck(file);
        if (reason) {
            toast(reason, 'error', { duration: 10000 });
            continue;
        }

        // API mode: smart-upload (compress + presigned PUT for big files).
        if (EDITOR_STATE.mode === 'api' && EDITOR_STATE.apiPassword) {
            const placeholderPath = `uploading:${file.name}-${Date.now()}`;
            EDITOR_STATE.images.push(placeholderPath);
            renderEditorImages();
            let progressToast;
            if (file.size > MAX_INLINE_UPLOAD_BYTES) {
                progressToast = toast(`Compressing & uploading ${file.name} (${(file.size/1024/1024).toFixed(1)} MB)...`, 'info', { duration: 0 });
            }
            try {
                const url = await uploadImageSmart(file, EDITOR_STATE.apiPassword);
                EDITOR_STATE.images = EDITOR_STATE.images.map(p => p === placeholderPath ? url : p);
                renderEditorImages();
            } catch (e) {
                EDITOR_STATE.images = EDITOR_STATE.images.filter(p => p !== placeholderPath);
                renderEditorImages();
                if (String(e.message).includes('R2 not configured')) {
                    toast('R2 not configured on the server. Image queued for GitHub commit instead.', 'error', { duration: 8000 });
                    await queueImageForGithub(file);
                } else {
                    toast(`Image upload failed: ${e.message}`, 'error', { duration: 6000 });
                }
            } finally {
                if (progressToast && typeof progressToast.hide === 'function') progressToast.hide();
            }
        } else {
            // GitHub mode (or API mode with no R2): queue for the GitHub commit at save
            await queueImageForGithub(file);
        }
    }
}

async function queueImageForGithub(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    const baseSlug = (file.name.replace(/\.[^.]+$/, '') || 'img')
        .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
    const path = `images/${baseSlug}-${Date.now()}.${ext}`;
    const b64 = await fileToB64(file);
    EDITOR_STATE.pendingUploads.push({ path, contentB64: b64 });
    EDITOR_STATE.images.push(path);
    renderEditorImages();
}

function fileToB64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result.split(',', 2)[1]);  // strip data: prefix
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
    });
}

function slugifyTitle(title) {
    return title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'entry';
}

// Build entry from the modal form
function buildEntryFromForm() {
    const title = document.getElementById('entryTitle').value.trim();
    if (!title) throw new Error('Title is required.');
    // Reject save while uploads are still in flight
    if (EDITOR_STATE.images.some(p => p.startsWith('uploading:'))) {
        throw new Error('Wait for image uploads to finish before saving.');
    }
    const dataBody = getKbBody('data');
    const template = getKbBody('template');
    const category = document.getElementById('entryCategory').value || 'Other';
    const cleanLinks = EDITOR_STATE.links.filter(l => l.label?.trim() || l.url?.trim());
    const data = dataBody ? `${title}\n${dataBody}` : title;
    const now = new Date().toISOString();
    const existing = EDITOR_STATE.editingId
        ? KB_STATE.entries.find(e => e.id === EDITOR_STATE.editingId)
        : null;
    return {
        id: EDITOR_STATE.editingId || ensureUniqueId(slugifyTitle(title)),
        data,
        template,
        imgs: EDITOR_STATE.images.join(', '),
        category,
        tags: [...EDITOR_STATE.tags],
        links: cleanLinks,
        createdAt: existing?.createdAt || now,
        updatedAt: now,
    };
}

function ensureUniqueId(base) {
    const taken = new Set(KB_STATE.entries.map(e => e.id));
    if (!taken.has(base)) return base;
    let n = 2;
    while (taken.has(`${base}-${n}`)) n++;
    return `${base}-${n}`;
}

async function saveEntry() {
    let entry;
    try { entry = buildEntryFromForm(); }
    catch (e) { toast(e.message, 'error'); return; }

    const isEdit = !!EDITOR_STATE.editingId;
    const previousEntries = [...KB_STATE.entries];

    // Optimistic local update — feels instant
    if (isEdit) {
        KB_STATE.entries = KB_STATE.entries.map(e => e.id === entry.id ? entry : e);
    } else {
        KB_STATE.entries.push(entry);
        KB_STATE.expanded.add(entry.id);
        pushRecent(entry.id);
    }
    renderKB();
    EDITOR_STATE.entryModal?.hide();
    const savingToast = toast(`Saving "${getTitle(entry)}"...`, 'info', { duration: 0 });

    try {
        if (EDITOR_STATE.mode === 'api') {
            // Image uploads still go through GitHub (KV stores JSON only). If the
            // user has a PAT configured, use it; otherwise warn that images won't
            // be uploaded but the entry will still save with image paths only.
            if (EDITOR_STATE.pendingUploads.length) {
                if (EDITOR_STATE.pat) {
                    for (const upload of EDITOR_STATE.pendingUploads) {
                        await ghPutFile(upload.path, upload.contentB64, null, `Add image ${upload.path}`);
                    }
                } else {
                    toast('Image uploads skipped (need GitHub PAT for images). Entry saved without new images.', 'info', { duration: 5000 });
                    // Strip pending-upload paths from the entry
                    const pendingPaths = new Set(EDITOR_STATE.pendingUploads.map(u => u.path));
                    entry.imgs = entry.imgs.split(',').map(s => s.trim()).filter(p => p && !pendingPaths.has(p)).join(', ');
                }
                EDITOR_STATE.pendingUploads = [];
            }
            const url = isEdit ? `/api/entries/${encodeURIComponent(entry.id)}` : '/api/entries';
            const method = isEdit ? 'PUT' : 'POST';
            const r = await fetch(url, {
                method,
                headers: {
                    'Authorization': `Bearer ${EDITOR_STATE.apiPassword}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(entry),
            });
            if (r.status === 401) {
                EDITOR_STATE.apiPassword = null;
                try { sessionStorage.removeItem(EDITOR_STORAGE.apiPassword); } catch (e) { /* ignore */ }
                throw new Error('Editor password rejected. Click save again to re-enter.');
            }
            if (!r.ok) {
                const j = await r.json().catch(() => ({}));
                throw new Error(j.error || `API error: ${r.status}`);
            }
            dismissToast(savingToast);
            toast('Saved! Live immediately.', 'success');
        } else {
            // GitHub mode — commits to reference_data.json in the repo
            for (const upload of EDITOR_STATE.pendingUploads) {
                await ghPutFile(upload.path, upload.contentB64, null, `Add image ${upload.path}`);
            }
            EDITOR_STATE.pendingUploads = [];

            const file = await ghGetFile('reference_data.json');
            if (!file) throw new Error('reference_data.json not found in repo.');
            const existing = JSON.parse(b64ToUtf8(file.contentB64));
            if (isEdit) {
                existing.database = existing.database.map(e => e.id === entry.id ? entry : e);
            } else {
                existing.database.push(entry);
            }
            const newContent = JSON.stringify(existing, null, 2);
            await ghPutFile('reference_data.json', utf8ToB64(newContent), file.sha,
                isEdit ? `Update entry: ${getTitle(entry)}` : `Add entry: ${getTitle(entry)}`);
            dismissToast(savingToast);
            toast('Saved! Live on GitHub Pages in ~60 seconds.', 'success');
        }
    } catch (err) {
        // Revert optimistic update
        KB_STATE.entries = previousEntries;
        renderKB();
        dismissToast(savingToast);
        toast(`Save failed: ${err.message}`, 'error', { duration: 6000 });
    }
}

function confirmDeleteEntry() {
    if (!EDITOR_STATE.editingId) return;
    const entry = KB_STATE.entries.find(e => e.id === EDITOR_STATE.editingId);
    if (!entry) return;
    if (!confirm(`Delete "${getTitle(entry)}" from the knowledge base? This commits to GitHub.`)) return;
    deleteEntry(entry);
}

async function deleteEntry(entry) {
    const previousEntries = [...KB_STATE.entries];
    KB_STATE.entries = KB_STATE.entries.filter(e => e.id !== entry.id);
    KB_STATE.favorites.delete(entry.id);
    KB_STATE.expanded.delete(entry.id);
    KB_STATE.recents = KB_STATE.recents.filter(id => id !== entry.id);
    saveKBPrefs();
    renderKB();
    EDITOR_STATE.entryModal?.hide();
    const savingToast = toast(`Deleting "${getTitle(entry)}"...`, 'info', { duration: 0 });

    try {
        if (EDITOR_STATE.mode === 'api') {
            const r = await fetch(`/api/entries/${encodeURIComponent(entry.id)}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${EDITOR_STATE.apiPassword}` },
            });
            if (r.status === 401) {
                EDITOR_STATE.apiPassword = null;
                try { sessionStorage.removeItem(EDITOR_STORAGE.apiPassword); } catch (e) { /* ignore */ }
                throw new Error('Editor password rejected.');
            }
            if (!r.ok && r.status !== 404) {
                const j = await r.json().catch(() => ({}));
                throw new Error(j.error || `API error: ${r.status}`);
            }
            dismissToast(savingToast);
            toast('Deleted. Live immediately.', 'success');
        } else {
            const file = await ghGetFile('reference_data.json');
            if (!file) throw new Error('reference_data.json not found.');
            const existing = JSON.parse(b64ToUtf8(file.contentB64));
            existing.database = existing.database.filter(e => e.id !== entry.id);
            const newContent = JSON.stringify(existing, null, 2);
            await ghPutFile('reference_data.json', utf8ToB64(newContent), file.sha, `Delete entry: ${getTitle(entry)}`);
            dismissToast(savingToast);
            toast('Deleted. Live on GitHub Pages in ~60 seconds.', 'success');
        }
    } catch (err) {
        KB_STATE.entries = previousEntries;
        renderKB();
        dismissToast(savingToast);
        toast(`Delete failed: ${err.message}`, 'error', { duration: 6000 });
    }
}

// =========================================================================
// Toasts
// =========================================================================

let toastCounter = 0;
function toast(message, kind = 'info', opts = {}) {
    const id = ++toastCounter;
    const container = document.getElementById('toastContainer');
    if (!container) { console.log(`[${kind}]`, message); return id; }
    const icon = kind === 'success' ? 'fa-check-circle' : kind === 'error' ? 'fa-times-circle' : 'fa-info-circle';
    const el = document.createElement('div');
    el.className = `toast-msg toast-${kind}`;
    el.dataset.toastId = id;
    el.innerHTML = `<i class="fas ${icon} me-2"></i><span class="toast-text">${escapeHtml(message)}</span><button class="toast-close" aria-label="Dismiss">&times;</button>`;
    el.querySelector('.toast-close').addEventListener('click', () => el.remove());
    container.appendChild(el);
    const duration = opts.duration !== undefined ? opts.duration : 3500;
    if (duration > 0) setTimeout(() => el.remove(), duration);
    return id;
}

function dismissToast(id) {
    const el = document.querySelector(`[data-toast-id="${id}"]`);
    if (el) el.remove();
}

// =========================================================================
// MGH Handbook — TOC tab driven by mgh-toc.json
// =========================================================================

const HANDBOOK_STATE = { toc: null, query: '', activeEntry: null };

function initHandbook(bust) {
    fetch('mgh-toc.json' + (bust || ''), { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(toc => {
            if (!toc) {
                document.getElementById('handbookContent').innerHTML =
                    '<div class="alert alert-warning">Could not load <code>mgh-toc.json</code>.</div>';
                return;
            }
            HANDBOOK_STATE.toc = toc;
            document.getElementById('handbookSubtitle').textContent = toc.subtitle || '';
            renderHandbook();
        })
        .catch(() => {
            document.getElementById('handbookContent').innerHTML =
                '<div class="alert alert-info">No handbook configured yet. Drop your PDF at <code>docs/mgh-handbook.pdf</code> and edit <code>mgh-toc.json</code> with the page numbers.</div>';
        });

    document.getElementById('handbookSearch')?.addEventListener('input', e => {
        HANDBOOK_STATE.query = e.target.value;
        renderHandbook();
    });

    // Delegated click on TOC entries — render page images inline
    document.getElementById('handbookContent')?.addEventListener('click', e => {
        const link = e.target.closest('[data-entry-id]');
        if (!link) return;
        e.preventDefault();
        const entryId = link.dataset.entryId;
        const [si, ei] = entryId.split('-').map(Number);
        const sec = HANDBOOK_STATE.toc?.sections?.[si];
        const entry = sec?.entries?.[ei];
        if (entry) loadHandbookEntry(entry, entryId);
    });
}

function loadHandbookEntry(entry, entryId) {
    HANDBOOK_STATE.activeEntry = entryId;
    const viewer = document.getElementById('handbookViewer');
    const placeholder = document.getElementById('handbookViewerPlaceholder');
    const titleEl = document.getElementById('handbookViewerTitle');
    const actions = document.getElementById('handbookViewerActions');
    const pagesLabel = document.getElementById('handbookViewerPages');
    const openPdf = document.getElementById('handbookOpenPdf');
    const toc = HANDBOOK_STATE.toc;

    const start = Number(entry.page) || 1;
    const end = Number(entry.pageEnd) || start;
    const tmpl = toc?.pageImagePath || 'docs/mgh-pages/page-{n:03d}.jpg';
    const pdfPath = toc?.pdfPath || 'docs/MGH-2526-handbook.pdf';

    // Build the image stack
    let html = '';
    for (let n = start; n <= end; n++) {
        const src = fillPageTemplate(tmpl, n);
        const eager = (n === start) ? 'eager' : 'lazy';
        html += `<figure class="handbook-page">
            <img src="${escapeHtml(src)}" alt="Page ${n}" loading="${eager}" decoding="async">
            <figcaption>p.${n}</figcaption>
        </figure>`;
    }
    viewer.innerHTML = html;
    viewer.scrollTop = 0;
    viewer.style.display = 'block';
    if (placeholder) placeholder.style.display = 'none';

    titleEl.textContent = entry.title || '';
    titleEl.classList.remove('text-muted');
    actions.style.display = 'flex';
    pagesLabel.textContent = (start === end) ? `p.${start}` : `p.${start}–${end}`;
    openPdf.href = `${pdfPath}#page=${start}`;

    // Highlight active entry in TOC
    document.querySelectorAll('.handbook-entry.active').forEach(el => el.classList.remove('active'));
    const el = document.querySelector(`[data-entry-id="${CSS.escape(entryId)}"]`);
    if (el) el.classList.add('active');
}

function renderHandbook() {
    const toc = HANDBOOK_STATE.toc;
    if (!toc) return;
    const q = HANDBOOK_STATE.query.trim().toLowerCase();
    const pdfPath = toc.pdfPath || 'docs/mgh-handbook.pdf';
    const sections = (toc.sections || []).map(sec => {
        const entries = (sec.entries || []).filter(e => {
            if (!q) return true;
            return (e.title || '').toLowerCase().includes(q)
                || (sec.title || '').toLowerCase().includes(q);
        });
        return { ...sec, entries };
    }).filter(sec => sec.entries.length > 0);

    if (!sections.length) {
        document.getElementById('handbookContent').innerHTML = '';
        document.getElementById('handbookEmpty').style.display = 'block';
        return;
    }
    document.getElementById('handbookEmpty').style.display = 'none';

    const html = sections.map((sec, si) => `
        <div class="handbook-section">
            <h6 class="handbook-section-title">${escapeHtml(sec.title || '')}</h6>
            <ul class="handbook-entries">
                ${sec.entries.map((e, ei) => {
                    const page = Number(e.page) || 1;
                    const href = e.file
                        ? escapeHtml(e.file)
                        : `${escapeHtml(pdfPath)}#page=${page}`;
                    const entryId = `${si}-${ei}`;
                    const isActive = HANDBOOK_STATE.activeEntry === entryId;
                    return `<li>
                        <a href="${href}"
                           class="handbook-entry${isActive ? ' active' : ''}"
                           data-entry-href="${href}"
                           data-entry-title="${escapeHtml(e.title || '')}"
                           data-entry-id="${entryId}">
                            <span class="handbook-entry-title">${escapeHtml(e.title || '')}</span>
                            <span class="handbook-entry-page">p.${page}</span>
                        </a>
                    </li>`;
                }).join('')}
            </ul>
        </div>
    `).join('');
    document.getElementById('handbookContent').innerHTML = html;
}

// =========================================================================
// Reference tab — Antibiotics + ConanLi + EBM + UW + MKSAP
// =========================================================================

// Tree of TOC nodes. A node with an `items` array is a collapsible group.
// Otherwise it's an item; its `type` controls how the right pane renders it.
const REFERENCE_TOC = [
    { id: 'g-antibiotics', title: 'Antibiotics', icon: 'fa-pills', items: [
        { id: 'abx-guide',       title: 'Antibiotics guide',     icon: 'fa-file-image', type: 'poster',
          src: 'https://pub-2601b1bf40df47c5a0936edc7be74155.r2.dev/docs/abx-guide-pages/page-1.jpg',
          caption: 'Northwestern Introductory Guide to Antibiotics',
          pdf: 'https://pub-2601b1bf40df47c5a0936edc7be74155.r2.dev/docs/nu-introductory-guide-to-antibiotics.pdf' },
        { id: 'bugdrugdx',       title: 'BugDrugDx',             icon: 'fa-bug',        type: 'embed',
          url: 'https://bugdrugdx.com/',
          description: 'Cross-reference antibiotics, bugs, and infection types.' },
        { id: 'abx-venn',        title: 'Abx Venn diagram',      icon: 'fa-circle-dot', type: 'poster',
          src: 'https://pub-2601b1bf40df47c5a0936edc7be74155.r2.dev/docs/abx_venn.png',
          caption: 'Antibiotic spectrum overlap.' },
        { id: 'uci-antibiogram', title: 'UCI Antibiogram',       icon: 'fa-microscope', type: 'antibiogram',
          section: 'uci-antibiogram',
          caption: 'Latest UCI Medical Center antibiogram. Upload a new image/PDF to replace.' },
        { id: 'abx-extras',      title: 'Antibiotics — extras',  icon: 'fa-folder-plus',type: 'list',
          section: 'abx-extras',
          subtitle: 'Reference images, dosing tables, links you want to keep handy.' },
    ]},
    { id: 'conanli', title: 'ConanLi UMD', icon: 'fa-user-md', type: 'external',
      url: 'https://conanliumd.com/en-usd',
      reason: 'site blocks embedding (X-Frame-Options)' },
    { id: 'ebm', title: 'EBM articles', icon: 'fa-flask', type: 'list',
      section: 'ebm', dailyPick: true,
      subtitle: 'Landmark trials and evidence-based reference articles. One pick surfaces daily.' },
    { id: 'core-im', title: 'CoreIM podcast', icon: 'fa-podcast', type: 'list',
      section: 'core-im', dailyPick: true,
      subtitle: 'Core IM podcast archive — 5 Pearls, Hoofbeats, Bytes, At The Bedside. One surfaces daily.' },
    { id: 'g-cpsolvers', title: 'CPSolvers', icon: 'fa-brain', items: [
        { id: 'cps-schemas', title: 'Diagnostic Schemas', icon: 'fa-sitemap', type: 'list',
          section: 'cps-schemas', dailyPick: true,
          subtitle: 'Clinical Problem Solvers diagnostic frameworks. Image embedded; click to view source.' },
        { id: 'cps-illness', title: 'Illness Scripts', icon: 'fa-stethoscope', type: 'list',
          section: 'cps-illness', dailyPick: true,
          subtitle: 'Clinical Problem Solvers illness scripts. One surfaces daily.' },
    ]},
    { id: 'g-uworld', title: 'UWorld', icon: 'fa-graduation-cap', gated: 'mksap', items: [
        { id: 'uw-flowsheets', title: 'Flow Sheet Tables', icon: 'fa-table-list',
          type: 'pdf-toc',
          tocJson: 'uw-flowsheets-toc.json',
          overridesSection: 'uw-toc-overrides',
          subtitle: 'UWorld boards review tables and flowcharts (163 pages). Edit titles + categories with the pencil icon.' },
        { id: 'usmle-inner-circle', title: 'Inner Circle Notes', icon: 'fa-book',
          type: 'pdf-toc',
          tocJson: 'usmle-inner-circle-toc.json',
          overridesSection: 'usmle-toc-overrides',
          subtitle: 'USMLE Inner Circle Step 2/3 notes (1168 pages). One entry per chapter; long stacks load lazily.' },
        { id: 'board-review', title: 'Board Review Facts', icon: 'fa-clipboard-check',
          type: 'list',
          section: 'board-review', dailyPick: true,
          subtitle: 'High-yield boards review facts, grouped by subspecialty. One surfaces daily.' },
        { id: 'abim-objectives', title: 'ABIM Objectives', icon: 'fa-list-check',
          type: 'list',
          section: 'abim-objectives', dailyPick: 10,
          subtitle: 'ABIM educational objectives across all subspecialties. 10 surface daily by default.' },
    ]},
    { id: 'mksap', title: 'MKSAP Boards Basics', icon: 'fa-lock', type: 'mksap-content',
      dailyPick: true,
      subtitle: '' },
];

const REFERENCE_STATE = {
    activeId: null,
    query: '',
    lists: {},               // section name → array of items (cached)
    mksapUnlocked: false,
    mksapPassword: null,
    refModal: null,
    mksapUnlockModal: null,
    refItem: null,           // current item being edited in refItemModal
    refItemSection: null,    // which section that item belongs to
    refItemImage: null,      // staged image URL (after R2 upload)
    refItemTags: [],
};

const REFERENCE_STORAGE = {
    mksapPassword: 'ecref.mksap.pw',  // sessionStorage key
};

function refToc() { return document.getElementById('referenceToc'); }
function refViewer() { return document.getElementById('referenceViewer'); }
function refPlaceholder() { return document.getElementById('referenceViewerPlaceholder'); }
function refTitle() { return document.getElementById('referenceViewerTitle'); }
function refActions() { return document.getElementById('referenceViewerActions'); }

function initReference() {
    // Restore MKSAP password from sessionStorage if previously unlocked this tab
    try {
        const stored = sessionStorage.getItem(REFERENCE_STORAGE.mksapPassword);
        if (stored) {
            REFERENCE_STATE.mksapPassword = stored;
            REFERENCE_STATE.mksapUnlocked = true;
        }
    } catch (e) { /* sessionStorage disabled */ }

    REFERENCE_STATE.refModal = new bootstrap.Modal(document.getElementById('refItemModal'));
    REFERENCE_STATE.mksapUnlockModal = new bootstrap.Modal(document.getElementById('mksapUnlockModal'));

    renderReferenceToc();

    // Search
    document.getElementById('referenceSearch')?.addEventListener('input', e => {
        REFERENCE_STATE.query = e.target.value;
        renderReferenceToc();
    });

    // TOC delegated clicks
    refToc().addEventListener('click', e => {
        const groupTitle = e.target.closest('.reference-group-title');
        if (groupTitle) {
            groupTitle.parentElement.classList.toggle('collapsed');
            return;
        }
        const itemEl = e.target.closest('[data-ref-id]');
        if (itemEl) {
            e.preventDefault();
            loadReferenceItem(itemEl.dataset.refId);
        }
    });

    // refItem modal wiring
    wireRefItemModal();
    // MKSAP unlock modal wiring
    wireMksapUnlock();
    // PDF TOC override modal wiring
    document.getElementById('pdfTocOverrideSave')?.addEventListener('click', savePdfTocOverride);
    document.getElementById('pdfTocOverrideReset')?.addEventListener('click', () => {
        if (confirm('Revert this entry to its default title and category?')) deletePdfTocOverride();
    });

    // Delegated handler for the inline group-lock button (rendered by
    // groupLockBtnHtml inside the right-pane actions area).
    refActions().addEventListener('click', e => {
        const btn = e.target.closest('[data-group-lock]');
        if (!btn) return;
        REFERENCE_STATE.mksapUnlocked = false;
        REFERENCE_STATE.mksapPassword = null;
        try { sessionStorage.removeItem(REFERENCE_STORAGE.mksapPassword); } catch (e) {}
        toast('Locked.', 'info');
        if (REFERENCE_STATE.activeId) loadReferenceItem(REFERENCE_STATE.activeId);
    });
}

function refAllItems() {
    const out = [];
    for (const node of REFERENCE_TOC) {
        if (Array.isArray(node.items)) for (const ch of node.items) out.push(ch);
        else out.push(node);
    }
    return out;
}

function refFindById(id) {
    return refAllItems().find(i => i.id === id) || null;
}

function renderReferenceToc() {
    const q = REFERENCE_STATE.query.trim().toLowerCase();
    const matches = item => !q || (item.title || '').toLowerCase().includes(q);
    const html = REFERENCE_TOC.map(node => {
        if (Array.isArray(node.items)) {
            const childs = node.items.filter(matches);
            if (!childs.length) return '';
            return `<div class="reference-group">
                <div class="reference-group-title">
                    <i class="fas fa-chevron-down reference-chevron"></i>
                    <i class="fas ${escapeHtml(node.icon || 'fa-folder')} me-1"></i>
                    <span>${escapeHtml(node.title)}</span>
                </div>
                <ul class="reference-group-items">
                    ${childs.map(c => refTocItemHtml(c)).join('')}
                </ul>
            </div>`;
        }
        if (!matches(node)) return '';
        return `<ul class="reference-group-items" style="margin-left:0;">
            ${refTocItemHtml(node)}
        </ul>`;
    }).join('');
    refToc().innerHTML = html;
    // Restore active highlight
    if (REFERENCE_STATE.activeId) {
        const el = refToc().querySelector(`[data-ref-id="${CSS.escape(REFERENCE_STATE.activeId)}"]`);
        if (el) el.classList.add('active');
    }
}

function refTocItemHtml(item) {
    return `<li>
        <a href="#" class="reference-item" data-ref-id="${escapeHtml(item.id)}">
            <i class="fas ${escapeHtml(item.icon || 'fa-circle')}"></i>
            <span>${escapeHtml(item.title)}</span>
        </a>
    </li>`;
}

function refFindParentGroup(id) {
    for (const node of REFERENCE_TOC) {
        if (Array.isArray(node.items) && node.items.some(c => c.id === id)) return node;
    }
    return null;
}

function loadReferenceItem(id) {
    const node = refFindById(id);
    if (!node) return;
    REFERENCE_STATE.activeId = id;
    document.querySelectorAll('.reference-item.active').forEach(el => el.classList.remove('active'));
    const el = refToc().querySelector(`[data-ref-id="${CSS.escape(id)}"]`);
    if (el) el.classList.add('active');

    refTitle().textContent = node.title;
    refTitle().classList.remove('text-muted');
    refActions().innerHTML = '';
    refPlaceholder().style.display = 'none';

    const viewer = refViewer();
    viewer.style.display = 'block';
    viewer.classList.remove('fill');
    viewer.classList.remove('pdf-toc-host');
    viewer.scrollTop = 0;

    // If this item lives under a gated group, intercept and show the gate.
    const parent = refFindParentGroup(id);
    if (parent && parent.gated === 'mksap' && !REFERENCE_STATE.mksapUnlocked) {
        renderGroupGate(parent, node);
        return;
    }

    switch (node.type) {
        case 'poster':      return renderPoster(node);
        case 'embed':       return renderEmbed(node);
        case 'antibiogram': return renderAntibiogram(node);
        case 'external':    return renderExternal(node);
        case 'list':        return renderListSection(node);
        case 'mksap':         return renderMksapSection(node);
        case 'mksap-content':  return renderMksapContentSection(node);
        case 'pdf-toc':       return renderPdfToc(node);
        default:
            viewer.innerHTML = `<div class="alert alert-warning">Unknown reference type: ${escapeHtml(node.type || '')}</div>`;
    }
}

// ----- Static poster (single image) -----
function renderPoster(node) {
    const viewer = refViewer();
    viewer.innerHTML = `
        <div class="reference-poster">
            <img src="${escapeHtml(node.src)}" alt="${escapeHtml(node.title)}" loading="eager">
            ${node.caption ? `<figcaption>${escapeHtml(node.caption)}</figcaption>` : ''}
        </div>`;
    viewer.querySelector('img').addEventListener('click', e => openImageModal(e.target.src));
    if (node.pdf) {
        refActions().innerHTML = `<a href="${escapeHtml(node.pdf)}" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-file-pdf me-1"></i>PDF
        </a>`;
    }
}

// ----- Embedded iframe with graceful fallback if blocked -----
function renderEmbed(node) {
    const viewer = refViewer();
    viewer.classList.add('fill');
    viewer.innerHTML = `
        <iframe src="${escapeHtml(node.url)}" class="reference-embed-frame" allowfullscreen
                referrerpolicy="no-referrer-when-downgrade"></iframe>`;
    refActions().innerHTML = `<a href="${escapeHtml(node.url)}" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary">
        <i class="fas fa-external-link-alt me-1"></i>Open in new tab
    </a>`;
}

// HTML for an inline Lock button shown in the right-pane header when the
// active item lives under a gated group AND we're currently unlocked.
// Empty string otherwise. Click handling is delegated once (see initReference).
function groupLockBtnHtml(node) {
    const parent = refFindParentGroup(node?.id);
    if (!parent || parent.gated !== 'mksap' || !REFERENCE_STATE.mksapUnlocked) return '';
    return ` <button class="btn btn-sm btn-outline-secondary ms-2" data-group-lock="${escapeHtml(parent.id)}" title="Lock ${escapeHtml(parent.title)}">
        <i class="fas fa-lock me-1"></i>Lock
    </button>`;
}

// ----- Group gate (shown when a child of a gated group is clicked) -----
function renderGroupGate(group, originalNode) {
    const viewer = refViewer();
    viewer.innerHTML = `
        <div class="reference-mksap-gate">
            <i class="fas fa-lock"></i>
            <h5>${escapeHtml(group.title)} is locked</h5>
            <button class="btn btn-primary" id="groupGateUnlock">
                <i class="fas fa-unlock me-1"></i>Unlock
            </button>
        </div>`;
    document.getElementById('groupGateUnlock').addEventListener('click', () => {
        document.getElementById('mksapPasswordInput').value = '';
        document.getElementById('mksapUnlockError').style.display = 'none';
        REFERENCE_STATE.mksapUnlockModal.show();
    });
    refActions().innerHTML = '';
}

// ----- External-only (iframe blocked by remote site) -----
function renderExternal(node) {
    const viewer = refViewer();
    viewer.innerHTML = `
        <div class="reference-embed-blocked">
            <i class="fas fa-external-link-alt"></i>
            <h5>${escapeHtml(node.title)}</h5>
            <p class="text-muted small">This site doesn't allow embedding (${escapeHtml(node.reason || 'CSP / X-Frame-Options')}).</p>
            <a href="${escapeHtml(node.url)}" target="_blank" rel="noopener" class="btn btn-primary">
                <i class="fas fa-external-link-alt me-1"></i>Open ${escapeHtml(node.title)}
            </a>
        </div>`;
    refActions().innerHTML = `<a href="${escapeHtml(node.url)}" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary">
        <i class="fas fa-external-link-alt me-1"></i>Open in new tab
    </a>`;
}

// ----- UCI Antibiogram (single editable image slot) -----
async function renderAntibiogram(node) {
    const viewer = refViewer();
    viewer.innerHTML = `<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading...</div>`;
    const items = await fetchListSection(node.section);
    REFERENCE_STATE.lists[node.section] = items;

    if (!items.length) {
        viewer.innerHTML = `
            <div class="reference-empty-slot">
                <i class="fas fa-microscope"></i>
                <h5>No antibiogram uploaded yet</h5>
                <p class="text-muted">Click below to upload the latest UCI antibiogram. JPG, PNG, or PDF.</p>
                ${editorReadyHtml() ? `<button class="btn btn-primary" data-ref-add="${escapeHtml(node.section)}">
                    <i class="fas fa-upload me-1"></i>Upload antibiogram
                </button>` : `<p class="text-muted small">${unconfiguredEditorMsg()}</p>`}
            </div>`;
    } else {
        // Show most-recent first; render the latest big, list older below
        const sorted = items.slice().sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
        const latest = sorted[0];
        const older  = sorted.slice(1);
        const latestImages = (latest.images && latest.images.length) ? latest.images
                            : (latest.image ? [latest.image] : []);
        viewer.innerHTML = `
            <div class="reference-poster">
                ${latestImages.length
                    ? latestImages.map(u => `<img src="${escapeHtml(u)}" alt="${escapeHtml(latest.title)}" class="d-block mb-2">`).join('')
                    : (latest.url ? `<p><a href="${escapeHtml(latest.url)}" target="_blank" rel="noopener">${escapeHtml(latest.title)}</a></p>` : '')}
                <figcaption>${escapeHtml(latest.title)}${latestImages.length > 1 ? ` (${latestImages.length} pages)` : ''}${latest.createdAt ? ' — uploaded ' + escapeHtml(relativeTime(latest.createdAt)) : ''}</figcaption>
                ${latest.body ? `<div class="reference-list-item-body mt-3 text-start">${renderBody(latest.body)}</div>` : ''}
            </div>
            ${editorReadyHtml() ? `<div class="text-center mt-3">
                <button class="btn btn-sm btn-outline-primary" data-ref-edit="${escapeHtml(node.section)}/${escapeHtml(latest.id)}">
                    <i class="fas fa-edit me-1"></i>Edit
                </button>
                <button class="btn btn-sm btn-primary" data-ref-add="${escapeHtml(node.section)}">
                    <i class="fas fa-upload me-1"></i>Upload new version
                </button>
            </div>` : ''}
            ${older.length ? `<hr><h6 class="text-muted small mb-2">Older versions</h6>
                <div class="reference-list">${older.map(i => renderListItemHtml(i, node.section)).join('')}</div>` : ''}
        `;
        viewer.querySelectorAll('img').forEach(im => im.addEventListener('click', e => openImageModal(e.target.src)));
    }
    refActions().innerHTML = node.caption ? `<span class="text-muted small">${escapeHtml(node.caption)}</span>` : '';
    wireListActions(viewer, node.section);
}

// ----- Generic editable list (EBM, UW, abx-extras, core-im, board-review) -----
// Some sections (e.g. board-review) sit under an mksap-gated parent group and
// require the MKSAP password for both reads and writes. We detect that via the
// parent's `gated` flag.
async function renderListSection(node) {
    const viewer = refViewer();
    viewer.innerHTML = `<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading ${escapeHtml(node.title)}...</div>`;

    const parent = refFindParentGroup(node.id);
    const isMksapGated = parent && parent.gated === 'mksap';
    const fetchPw = isMksapGated ? REFERENCE_STATE.mksapPassword : null;

    let items;
    try {
        items = await fetchListSection(node.section, fetchPw);
    } catch (e) {
        viewer.innerHTML = `<div class="alert alert-warning">Couldn't load ${escapeHtml(node.title)}: ${escapeHtml(e.message)}</div>`;
        return;
    }
    REFERENCE_STATE.lists[node.section] = items;

    // Render with the current filter applied (defaults to empty)
    renderListSectionBody(node, items);
}

// Separated so the search box can re-render without re-fetching.
function renderListSectionBody(node, items) {
    const viewer = refViewer();
    const parent = refFindParentGroup(node.id);
    const isMksapGated = parent && parent.gated === 'mksap';

    // Sort newest first
    const sorted = items.slice().sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));

    // Apply per-section search filter (in-memory). Stored on REFERENCE_STATE.
    REFERENCE_STATE.listSearch = REFERENCE_STATE.listSearch || {};
    const q = (REFERENCE_STATE.listSearch[node.section] || '').trim().toLowerCase();
    const filtered = q
        ? sorted.filter(i => {
            const hay = [i.title, i.body, (i.tags || []).join(' '), i.category || '']
                .join(' ').toLowerCase();
            // strip basic HTML tags from body
            return hay.replace(/<[^>]+>/g, ' ').includes(q);
        })
        : sorted;

    const pickDefault = normalizeDailyPickFlag(node.dailyPick);
    const pickHtml = pickDefault && items.length && !q
        ? renderDailyPickHtml(items, node.title, node.section, pickDefault)
        : '';

    const canEdit = isMksapGated ? REFERENCE_STATE.mksapUnlocked : editorReadyHtml();

    const listHtml = filtered.length
        ? filtered.map(i => renderListItemHtml(i, node.section)).join('')
        : `<div class="reference-list-empty">
            <i class="fas fa-inbox fa-2x mb-2 d-block"></i>
            <p class="mb-0">${q ? 'No matches.' : `No items yet.${canEdit ? ' Click <strong>Add</strong> above to create one.' : ''}`}</p>
        </div>`;

    const showSearch = node.searchable !== false && items.length > 5;

    viewer.innerHTML = `
        <div class="reference-list-header">
            <div>
                <h5>${escapeHtml(node.title)}</h5>
                ${node.subtitle ? `<small class="text-muted">${escapeHtml(node.subtitle)}</small>` : ''}
            </div>
            <div>
                <span class="text-muted small me-2">${q ? `${filtered.length} of ${items.length}` : `${items.length} item${items.length === 1 ? '' : 's'}`}</span>
                ${canEdit ? `<button class="btn btn-sm btn-primary" data-ref-add="${escapeHtml(node.section)}">
                    <i class="fas fa-plus me-1"></i>Add
                </button>` : ''}
            </div>
        </div>
        ${showSearch ? `<div class="reference-list-search mb-3">
            <div class="input-group input-group-sm">
                <span class="input-group-text"><i class="fas fa-search"></i></span>
                <input type="search" class="form-control" id="refListSearch-${escapeHtml(node.section)}"
                       placeholder="Search ${escapeHtml(node.title.toLowerCase())}..."
                       value="${escapeHtml(REFERENCE_STATE.listSearch[node.section] || '')}">
            </div>
        </div>` : ''}
        ${pickHtml}
        <div class="reference-list">${listHtml}</div>
    `;

    if (!canEdit && !isMksapGated) {
        refActions().innerHTML = `<span class="text-muted small">${unconfiguredEditorMsg()}</span>`;
    } else {
        refActions().innerHTML = '';
    }

    if (showSearch) {
        const inp = document.getElementById(`refListSearch-${node.section}`);
        if (inp) {
            inp.addEventListener('input', e => {
                REFERENCE_STATE.listSearch[node.section] = e.target.value;
                renderListSectionBody(node, items);
                // Restore focus + caret to the search input after re-render
                const newInp = document.getElementById(`refListSearch-${node.section}`);
                if (newInp) {
                    newInp.focus();
                    const v = newInp.value;
                    newInp.value = ''; newInp.value = v;
                }
            });
        }
    }

    viewer.querySelectorAll('img').forEach(im => im.addEventListener('click', e => openImageModal(e.target.src)));
    wireListActions(viewer, node.section);
}

// ----- MKSAP section (gated by separate password) -----
async function renderMksapSection(node) {
    const viewer = refViewer();
    if (!REFERENCE_STATE.mksapUnlocked) {
        viewer.innerHTML = `
            <div class="reference-mksap-gate">
                <i class="fas fa-lock"></i>
                <h5>MKSAP Boards Basics</h5>
                <p class="text-muted">${escapeHtml(node.subtitle || 'Gated by a separate password.')}</p>
                <button class="btn btn-primary" id="mksapShowUnlock">
                    <i class="fas fa-unlock me-1"></i>Unlock
                </button>
            </div>`;
        document.getElementById('mksapShowUnlock').addEventListener('click', () => {
            document.getElementById('mksapPasswordInput').value = '';
            document.getElementById('mksapUnlockError').style.display = 'none';
            REFERENCE_STATE.mksapUnlockModal.show();
        });
        refActions().innerHTML = '';
        return;
    }

    // Unlocked: same rendering as a regular list, but auth-gated fetch
    viewer.innerHTML = `<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading MKSAP...</div>`;
    let items;
    try {
        items = await fetchListSection(node.section, REFERENCE_STATE.mksapPassword);
    } catch (e) {
        if (String(e.message).includes('401')) {
            // Password no longer valid (rotated server-side) — relock
            REFERENCE_STATE.mksapUnlocked = false;
            REFERENCE_STATE.mksapPassword = null;
            try { sessionStorage.removeItem(REFERENCE_STORAGE.mksapPassword); } catch (e) {}
            renderMksapSection(node);
            toast('MKSAP password no longer valid — please unlock again.', 'error');
            return;
        }
        viewer.innerHTML = `<div class="alert alert-warning">Couldn't load MKSAP: ${escapeHtml(e.message)}</div>`;
        return;
    }
    REFERENCE_STATE.lists[node.section] = items;

    const sorted = items.slice().sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    const pickDefault = normalizeDailyPickFlag(node.dailyPick);
    const pickHtml = pickDefault && items.length
        ? renderDailyPickHtml(items, node.title, node.section, pickDefault)
        : '';
    const listHtml = sorted.length
        ? sorted.map(i => renderListItemHtml(i, node.section)).join('')
        : `<div class="reference-list-empty">
            <i class="fas fa-inbox fa-2x mb-2 d-block"></i>
            <p class="mb-0">No MKSAP items yet. Click <strong>Add</strong> to create one.</p>
        </div>`;

    viewer.innerHTML = `
        <div class="reference-list-header">
            <div>
                <h5><i class="fas fa-unlock me-1 text-success"></i>${escapeHtml(node.title)}</h5>
                ${node.subtitle ? `<small class="text-muted">${escapeHtml(node.subtitle)}</small>` : ''}
            </div>
            <div>
                <span class="text-muted small me-2">${items.length} item${items.length === 1 ? '' : 's'}</span>
                <button class="btn btn-sm btn-primary" data-ref-add="${escapeHtml(node.section)}">
                    <i class="fas fa-plus me-1"></i>Add
                </button>
            </div>
        </div>
        ${pickHtml}
        <div class="reference-list">${listHtml}</div>
    `;
    refActions().innerHTML = `<button class="btn btn-sm btn-outline-secondary" id="mksapLockBtn">
        <i class="fas fa-lock me-1"></i>Lock
    </button>`;
    document.getElementById('mksapLockBtn').addEventListener('click', () => {
        REFERENCE_STATE.mksapUnlocked = false;
        REFERENCE_STATE.mksapPassword = null;
        try { sessionStorage.removeItem(REFERENCE_STORAGE.mksapPassword); } catch (e) {}
        renderMksapSection(node);
        toast('MKSAP locked.', 'info');
    });

    viewer.querySelectorAll('img').forEach(im => im.addEventListener('click', e => openImageModal(e.target.src)));
    wireListActions(viewer, node.section);
}

// ----- PDF TOC viewer (sub-TOC + page-image viewer inside right pane) -----
// Used for UWORLD flow sheets and any other PDF you want to surface inside
// Reference. The viewer fills the right pane with a two-column layout:
// sub-TOC on the left (240px, scrollable, searchable) and the page-image
// stack on the right.

const PDF_TOC_CACHE = {};   // path -> parsed JSON (base TOC)
const PDF_TOC_STATE = {};   // node.id -> { activePage, query, baseToc, merged, overrides, overridesSection }

// The override system: each pdf-toc node may declare `overridesSection` (a
// KV section name like 'uw-toc-overrides'). When set, the renderer fetches
// the override list, merges it onto the base TOC (override wins per page),
// and renders a pencil icon on each entry that the editor can use to
// rename/recategorize. Override records:
//   { id: 'p142', page: 142, title?: 'Wilson disease', section?: 'GI' }

async function renderPdfToc(node) {
    const viewer = refViewer();
    viewer.classList.add('pdf-toc-host');
    viewer.innerHTML = `<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading ${escapeHtml(node.title)}...</div>`;

    let baseToc;
    try {
        baseToc = PDF_TOC_CACHE[node.tocJson]
            ??= await fetch(node.tocJson, { cache: 'no-store' }).then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            });
    } catch (e) {
        viewer.innerHTML = `<div class="alert alert-warning">Couldn't load <code>${escapeHtml(node.tocJson)}</code>: ${escapeHtml(e.message)}</div>`;
        return;
    }

    let overrides = [];
    if (node.overridesSection) {
        try { overrides = await fetchListSection(node.overridesSection); }
        catch (e) { console.warn('Failed to load overrides:', e); }
    }

    const state = PDF_TOC_STATE[node.id] ||= { activePage: null, query: '' };
    state.baseToc = baseToc;
    state.overrides = overrides;
    state.overridesSection = node.overridesSection || null;
    state.merged = mergePdfTocOverrides(baseToc, overrides);

    const totalEntries = state.merged.sections.reduce((n, s) => n + s.entries.length, 0);
    const overrideCount = overrides.length;

    refActions().innerHTML = `<span class="text-muted small">${totalEntries} entries${overrideCount ? ` · ${overrideCount} edited` : ''}</span>
        <a href="${escapeHtml(baseToc.pdfPath)}" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary ms-2">
            <i class="fas fa-file-pdf me-1"></i>PDF
        </a>${groupLockBtnHtml(node)}`;

    viewer.innerHTML = `
        <div class="pdf-toc-layout">
            <aside class="pdf-toc-sidebar">
                <div class="pdf-toc-search-wrap">
                    <input type="search" class="form-control form-control-sm" id="pdfTocSearch" placeholder="Search ${escapeHtml(baseToc.title || 'entries')}...">
                </div>
                <div class="pdf-toc-list" id="pdfTocList"></div>
                <div class="pdf-toc-empty text-muted text-center py-3" id="pdfTocEmpty" style="display:none;">
                    <i class="fas fa-search me-2"></i>No matches.
                </div>
            </aside>
            <main class="pdf-toc-viewer" id="pdfTocViewer">
                <div class="pdf-toc-placeholder">
                    <i class="fas fa-arrow-left"></i>
                    <p>Pick an entry from the list to view its page.</p>
                </div>
            </main>
        </div>
    `;

    renderPdfTocSidebar(node, state);

    // Restore last active entry on revisit
    if (state.activePage) {
        const entry = findMergedEntryByPage(state.merged, state.activePage);
        if (entry) loadPdfTocEntry(node, entry);
    }

    document.getElementById('pdfTocSearch').addEventListener('input', e => {
        state.query = e.target.value;
        renderPdfTocSidebar(node, state);
    });

    document.getElementById('pdfTocList').addEventListener('click', e => {
        const editBtn = e.target.closest('[data-pdf-entry-edit]');
        if (editBtn) {
            e.preventDefault();
            const page = Number(editBtn.dataset.pdfEntryEdit);
            requireEditor(() => openPdfTocOverrideModal(node, page));
            return;
        }
        const link = e.target.closest('[data-pdf-entry-id]');
        if (!link) return;
        e.preventDefault();
        const page = Number(link.dataset.pdfEntryId);
        const entry = findMergedEntryByPage(state.merged, page);
        if (entry) loadPdfTocEntry(node, entry);
    });
}

// Merge override list onto base TOC. Override fields (when present) win.
// Sections retain their original order; brand-new categories appear at end.
function mergePdfTocOverrides(baseToc, overrides) {
    const ovByPage = {};
    for (const o of overrides || []) {
        if (o && o.page != null) ovByPage[o.page] = o;
    }

    const baseOrder = (baseToc.sections || []).map(s => s.title);
    const extraOrder = [];
    const buckets = new Map();
    for (const t of baseOrder) buckets.set(t, []);

    for (const sec of baseToc.sections || []) {
        for (const e of sec.entries || []) {
            const ov = ovByPage[e.page];
            const merged = {
                page: e.page,
                pageEnd: e.pageEnd,
                title: (ov && ov.title) || e.title,
                section: (ov && ov.section) || sec.title,
                _baseTitle: e.title,
                _baseSection: sec.title,
                _overridden: !!(ov && (ov.title || ov.section)),
            };
            if (!buckets.has(merged.section)) {
                buckets.set(merged.section, []);
                if (!baseOrder.includes(merged.section)) extraOrder.push(merged.section);
            }
            buckets.get(merged.section).push(merged);
        }
    }

    const orderedNames = [...baseOrder, ...extraOrder];
    const sections = orderedNames
        .filter(name => (buckets.get(name) || []).length > 0)
        .map(name => ({
            title: name,
            entries: buckets.get(name).slice().sort((a, b) => a.page - b.page),
        }));

    return { ...baseToc, sections };
}

function findMergedEntryByPage(merged, page) {
    for (const sec of merged.sections || []) {
        const e = sec.entries.find(x => x.page === page);
        if (e) return e;
    }
    return null;
}

function getMergedSectionNames(merged) {
    return (merged.sections || []).map(s => s.title);
}

function renderPdfTocSidebar(node, state) {
    const q = (state.query || '').trim().toLowerCase();
    const sections = (state.merged.sections || [])
        .map(sec => ({
            title: sec.title,
            entries: sec.entries.filter(e => !q
                || (e.title || '').toLowerCase().includes(q)
                || (sec.title || '').toLowerCase().includes(q)),
        }))
        .filter(sec => sec.entries.length > 0);

    const listEl = document.getElementById('pdfTocList');
    const emptyEl = document.getElementById('pdfTocEmpty');

    if (!sections.length) {
        listEl.innerHTML = '';
        emptyEl.style.display = 'block';
        return;
    }
    emptyEl.style.display = 'none';

    const canEdit = !!state.overridesSection && editorReadyHtml();

    listEl.innerHTML = sections.map(sec => `
        <div class="pdf-toc-section">
            <div class="pdf-toc-section-title">${escapeHtml(sec.title || '')}</div>
            <ul class="pdf-toc-entries">
                ${sec.entries.map(e => {
                    const page = Number(e.page) || 1;
                    const isActive = state.activePage === e.page;
                    const editBtn = canEdit
                        ? `<button class="pdf-toc-entry-edit" data-pdf-entry-edit="${page}" title="Rename / recategorize" aria-label="Edit">
                              <i class="fas fa-pencil-alt"></i>
                           </button>`
                        : '';
                    return `<li>
                        <div class="pdf-toc-entry-row${e._overridden ? ' overridden' : ''}">
                            <a href="#" class="pdf-toc-entry${isActive ? ' active' : ''}" data-pdf-entry-id="${page}">
                                <span class="pdf-toc-entry-title">${escapeHtml(e.title || '')}${e._overridden ? '<i class="fas fa-circle pdf-toc-entry-dot" title="Edited" aria-hidden="true"></i>' : ''}</span>
                                <span class="pdf-toc-entry-page">p.${page}</span>
                            </a>
                            ${editBtn}
                        </div>
                    </li>`;
                }).join('')}
            </ul>
        </div>
    `).join('');
}

function loadPdfTocEntry(node, entry) {
    const state = PDF_TOC_STATE[node.id];
    state.activePage = entry.page;

    const viewer = document.getElementById('pdfTocViewer');
    const start = Number(entry.page) || 1;
    const end = Number(entry.pageEnd) || start;
    const tmpl = state.baseToc.pageImagePath || 'docs/uw-flowsheets-pages/page-{n:03d}.jpg';

    let html = '';
    for (let n = start; n <= end; n++) {
        const src = fillPageTemplate(tmpl, n);
        const eager = (n === start) ? 'eager' : 'lazy';
        html += `<figure class="pdf-toc-page">
            <img src="${escapeHtml(src)}" alt="Page ${n}" loading="${eager}" decoding="async">
            <figcaption>p.${n}</figcaption>
        </figure>`;
    }
    viewer.innerHTML = html;
    viewer.scrollTop = 0;

    document.querySelectorAll('.pdf-toc-entry.active').forEach(el => el.classList.remove('active'));
    const el = document.querySelector(`[data-pdf-entry-id="${start}"]`);
    if (el) el.classList.add('active');

    const actions = refActions();
    const pages = (start === end) ? `p.${start}` : `p.${start}–${end}`;
    actions.innerHTML = `<span class="text-muted small me-2">${pages}</span>
        <a href="${escapeHtml(state.baseToc.pdfPath)}#page=${start}" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-file-pdf me-1"></i>PDF
        </a>${groupLockBtnHtml(node)}`;
}

// ----- PDF TOC override editor modal -----

function openPdfTocOverrideModal(node, page) {
    const state = PDF_TOC_STATE[node.id];
    if (!state || !state.overridesSection) {
        toast('Overrides not configured for this TOC.', 'error');
        return;
    }
    const entry = findMergedEntryByPage(state.merged, page);
    if (!entry) {
        toast(`Could not find entry for page ${page}.`, 'error');
        return;
    }
    const existingOverride = (state.overrides || []).find(o => o.page === page);

    // Stash context for the save handler
    REFERENCE_STATE.pdfTocEditCtx = { node, page, entry, existingOverride };

    // Populate the modal
    document.getElementById('pdfTocOverrideLabel').textContent =
        `Edit entry — page ${page}`;
    document.getElementById('pdfTocOverrideTitle').value = entry.title || '';
    document.getElementById('pdfTocOverrideBase').textContent =
        `Default: "${entry._baseTitle}" in ${entry._baseSection}`;

    const sel = document.getElementById('pdfTocOverrideSection');
    const sections = Array.from(new Set([
        ...getMergedSectionNames(state.merged),
        entry._baseSection,
    ])).filter(Boolean);
    sel.innerHTML = sections.map(s =>
        `<option value="${escapeHtml(s)}"${s === entry.section ? ' selected' : ''}>${escapeHtml(s)}</option>`
    ).join('');

    document.getElementById('pdfTocOverrideNewCat').value = '';
    document.getElementById('pdfTocOverrideReset').style.display = existingOverride ? 'inline-block' : 'none';

    if (!REFERENCE_STATE.pdfTocOverrideModal) {
        REFERENCE_STATE.pdfTocOverrideModal = new bootstrap.Modal(document.getElementById('pdfTocOverrideModal'));
    }
    REFERENCE_STATE.pdfTocOverrideModal.show();
}

async function savePdfTocOverride() {
    const ctx = REFERENCE_STATE.pdfTocEditCtx;
    if (!ctx) return;
    const { node, page, entry, existingOverride } = ctx;
    const state = PDF_TOC_STATE[node.id];

    const newTitle = document.getElementById('pdfTocOverrideTitle').value.trim();
    const newCat = document.getElementById('pdfTocOverrideNewCat').value.trim();
    const section = newCat || document.getElementById('pdfTocOverrideSection').value;

    if (!newTitle) { toast('Title is required.', 'error'); return; }

    // Only persist diff vs base — keeps storage tidy + makes "reset" trivial.
    const override = {
        id: `p${page}`,
        page,
        ...(newTitle !== entry._baseTitle ? { title: newTitle } : {}),
        ...(section !== entry._baseSection ? { section } : {}),
        updatedAt: new Date().toISOString(),
    };

    // If nothing differs from the base AND there's no existing override, just close.
    const onlyDefaults = !override.title && !override.section;
    if (onlyDefaults && !existingOverride) {
        REFERENCE_STATE.pdfTocOverrideModal.hide();
        return;
    }
    // If the user reverted everything to defaults, treat as delete.
    if (onlyDefaults && existingOverride) {
        await deletePdfTocOverride();
        return;
    }

    const password = EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }

    const btn = document.getElementById('pdfTocOverrideSave');
    btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Saving...';

    try {
        const url = `/api/list/${encodeURIComponent(state.overridesSection)}` +
            (existingOverride ? `/${encodeURIComponent(override.id)}` : '');
        const r = await fetch(url, {
            method: existingOverride ? 'PUT' : 'POST',
            headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(override),
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        toast(existingOverride ? 'Updated.' : 'Saved.', 'success');
        REFERENCE_STATE.pdfTocOverrideModal.hide();
        renderPdfToc(node);   // refresh
    } catch (e) {
        toast(`Save failed: ${e.message}`, 'error', { duration: 5000 });
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-save me-1"></i>Save';
    }
}

async function deletePdfTocOverride() {
    const ctx = REFERENCE_STATE.pdfTocEditCtx;
    if (!ctx || !ctx.existingOverride) return;
    const { node, existingOverride } = ctx;
    const state = PDF_TOC_STATE[node.id];
    const password = EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }

    try {
        const r = await fetch(`/api/list/${encodeURIComponent(state.overridesSection)}/${encodeURIComponent(existingOverride.id)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${password}` },
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        toast('Reverted to default.', 'success');
        REFERENCE_STATE.pdfTocOverrideModal.hide();
        renderPdfToc(node);
    } catch (e) {
        toast(`Reset failed: ${e.message}`, 'error', { duration: 5000 });
    }
}

// ----- Render a single list-item card -----
function urlDomain(url) {
    try { return new URL(url).hostname.replace(/^www\./, ''); }
    catch (e) { return ''; }
}

// Sections whose writes (and, for some, reads) are gated by MKSAP_PASSWORD
// rather than the regular EDITOR_PASSWORD.
function sectionUsesMksap(section) {
    return section === 'mksap' || section === 'board-review';
}

function renderListItemHtml(item, section) {
    const titleHtml = item.url
        ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener">${escapeHtml(item.title || '(no title)')}<i class="fas fa-external-link-alt reference-list-item-extlink" aria-hidden="true"></i></a>`
        : escapeHtml(item.title || '(no title)');
    const itemImages = (item.images && item.images.length) ? item.images : (item.image ? [item.image] : []);
    const imgHtml = itemImages.map(u => `<img src="${escapeHtml(u)}" alt="">`).join('');
    const tagsHtml = (item.tags || []).length
        ? (item.tags || []).map(t => `<span class="badge bg-light text-dark">${escapeHtml(t)}</span>`).join(' ')
        : '';
    const dateHtml = item.updatedAt || item.createdAt
        ? `<span><i class="far fa-clock me-1"></i>${escapeHtml(relativeTime(item.updatedAt || item.createdAt))}</span>`
        : '';
    // Visible source link — shows the domain so users see at a glance
    // where the link goes (2minutemedicine.com vs wikijournalclub.org).
    const sourceHtml = item.url
        ? `<a class="reference-list-item-source" href="${escapeHtml(item.url)}" target="_blank" rel="noopener" title="${escapeHtml(item.url)}">
            <i class="fas fa-link"></i>${escapeHtml(urlDomain(item.url) || item.url)}
           </a>`
        : '';
    return `<div class="reference-list-item" data-ref-item-id="${escapeHtml(item.id)}">
        <div class="reference-list-item-head">
            <div class="reference-list-item-title">${titleHtml}</div>
            ${editorReadyHtml() || sectionUsesMksap(section) ? `<div class="reference-list-item-actions">
                <button class="btn btn-outline-secondary" data-ref-edit="${escapeHtml(section)}/${escapeHtml(item.id)}" title="Edit"><i class="fas fa-edit"></i></button>
                <button class="btn btn-outline-danger" data-ref-delete="${escapeHtml(section)}/${escapeHtml(item.id)}" title="Delete"><i class="fas fa-trash"></i></button>
            </div>` : ''}
        </div>
        ${item.body ? `<div class="reference-list-item-body">${renderBody(item.body)}</div>` : ''}
        ${imgHtml}
        <div class="reference-list-item-meta">${sourceHtml}${tagsHtml}${dateHtml}</div>
    </div>`;
}

// Daily pick — supports either a single pick (`count === 1`, original behavior)
// or up to N picks rendered as a compact stacked list. Per-section count
// override lives in localStorage under `ecref.dailyPickCount.<section>`.
//
// The dropdown lets the user change the count or hide picks entirely; click
// any pick row to view the full item in a read-only modal.
const DAILY_PICK_OPTIONS = [0, 1, 5, 10];   // 0 = hidden
const DAILY_PICK_STORAGE = 'ecref.dailyPickCount';

function normalizeDailyPickFlag(flag) {
    // `dailyPick: true` → 1; `dailyPick: <n>` → n; falsy → 0.
    if (flag === true) return 1;
    const n = Number(flag);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function getDailyPickCount(section, defaultCount) {
    try {
        const raw = localStorage.getItem(`${DAILY_PICK_STORAGE}.${section}`);
        if (raw == null) return defaultCount;
        const n = parseInt(raw, 10);
        return Number.isFinite(n) && n >= 0 ? n : defaultCount;
    } catch (e) { return defaultCount; }
}

function setDailyPickCount(section, count) {
    try { localStorage.setItem(`${DAILY_PICK_STORAGE}.${section}`, String(count)); }
    catch (e) { /* localStorage disabled */ }
}

function renderDailyPickHtml(items, sectionTitle, section, defaultCount) {
    const count = getDailyPickCount(section, defaultCount);
    if (!count || !items.length) return '';
    const picks = picksOfTheDay(items, count);
    if (!picks.length) return '';
    const today = new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
    const dropdown = renderPickCountDropdown(section, count);
    const isMulti = picks.length > 1;
    const labelText = isMulti
        ? `Today's ${escapeHtml(sectionTitle)} picks · ${escapeHtml(today)}`
        : `Today's ${escapeHtml(sectionTitle)} pick · ${escapeHtml(today)}`;
    const header = `<div class="reference-pick-header">
        <div class="reference-pick-label"><i class="fas fa-star"></i>${labelText}</div>
        ${dropdown}
    </div>`;

    if (!isMulti) {
        const pick = picks[0];
        const titleHtml = pick.url
            ? `<a href="${escapeHtml(pick.url)}" target="_blank" rel="noopener">${escapeHtml(pick.title || '(no title)')}</a>`
            : `<a href="#" data-ref-view="${escapeHtml(section)}/${escapeHtml(pick.id)}">${escapeHtml(pick.title || '(no title)')}</a>`;
        return `<div class="reference-pick" data-pick-section="${escapeHtml(section)}">
            ${header}
            <div class="reference-pick-title">${titleHtml}</div>
            ${pick.body ? `<div class="reference-pick-body">${renderBody(pick.body)}</div>` : ''}
            ${((pick.images && pick.images.length) ? pick.images : (pick.image ? [pick.image] : [])).map(u => `<div class="reference-pick-body"><img src="${escapeHtml(u)}" alt=""></div>`).join('')}
        </div>`;
    }

    const rows = picks.map((p, i) => {
        const snippet = pickSnippet(p);
        const tag = (p.tags || [])[0] || '';
        return `<a href="#" class="reference-pick-row" data-ref-view="${escapeHtml(section)}/${escapeHtml(p.id)}">
            <span class="reference-pick-row-num">${i + 1}.</span>
            <span class="reference-pick-row-body">
                <span class="reference-pick-row-title">${escapeHtml(p.title || '(no title)')}</span>
                ${tag ? `<span class="reference-pick-row-tag">${escapeHtml(tag)}</span>` : ''}
                ${snippet ? `<span class="reference-pick-row-snippet">${escapeHtml(snippet)}</span>` : ''}
            </span>
        </a>`;
    }).join('');
    return `<div class="reference-pick reference-pick-multi" data-pick-section="${escapeHtml(section)}">
        ${header}
        <div class="reference-pick-rows">${rows}</div>
    </div>`;
}

function renderPickCountDropdown(section, current) {
    const opts = DAILY_PICK_OPTIONS.map(n => {
        const label = n === 0 ? 'Off' : String(n);
        const sel = n === current ? ' selected' : '';
        return `<option value="${n}"${sel}>${label}</option>`;
    }).join('');
    return `<select class="reference-pick-count" data-pick-count="${escapeHtml(section)}" title="How many picks to show per day">${opts}</select>`;
}

function pickSnippet(item) {
    const raw = (item.body || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    if (!raw) return '';
    return raw.length > 140 ? raw.slice(0, 137).trimEnd() + '…' : raw;
}

// Deterministic daily picks — same items all day, rotates at local midnight.
// `count === 1` returns a single-element array (back-compat for the original
// pickOfTheDay use case). Larger counts use a seeded Fisher-Yates shuffle so
// the same date + same items yields the same N picks with no dupes.
function picksOfTheDay(items, count) {
    if (!items.length || count <= 0) return [];
    const n = Math.min(count, items.length);
    const seed = dailyHashSeed();
    if (n === 1) {
        return [items[seed % items.length]];
    }
    const rng = mulberry32(seed);
    const idx = items.map((_, i) => i);
    for (let i = idx.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [idx[i], idx[j]] = [idx[j], idx[i]];
    }
    return idx.slice(0, n).map(i => items[i]);
}

function dailyHashSeed() {
    const today = new Date().toISOString().slice(0, 10);   // YYYY-MM-DD
    let h = 7;
    for (let i = 0; i < today.length; i++) h = ((h * 31) + today.charCodeAt(i)) >>> 0;
    return h;
}

function mulberry32(a) {
    return function() {
        a |= 0; a = a + 0x6D2B79F5 | 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

// Read-only viewer triggered by clicking a pick row.
function openRefItemView(section, id) {
    const item = (REFERENCE_STATE.lists[section] || []).find(i => i.id === id);
    if (!item) return;
    const modal = document.getElementById('refItemViewModal');
    if (!modal) return;
    document.getElementById('refItemViewLabel').textContent = item.title || '(no title)';
    const subtitleEl = document.getElementById('refItemViewSubtitle');
    const tags = (item.tags || []).filter(Boolean);
    const sourceHtml = item.url
        ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener" class="me-2"><i class="fas fa-link me-1"></i>${escapeHtml(urlDomain(item.url) || item.url)}</a>`
        : '';
    const tagsHtml = tags.map(t => `<span class="badge bg-light text-dark me-1">${escapeHtml(t)}</span>`).join('');
    subtitleEl.innerHTML = sourceHtml + tagsHtml;
    const bodyEl = document.getElementById('refItemViewBody');
    const itemImages = (item.images && item.images.length) ? item.images : (item.image ? [item.image] : []);
    const imgHtml = itemImages.map(u => `<img src="${escapeHtml(u)}" alt="" class="img-fluid mt-2">`).join('');
    bodyEl.innerHTML = (item.body ? sanitizeHtml(item.body) : '<p class="text-muted">No body.</p>') + imgHtml;
    bodyEl.querySelectorAll('img').forEach(im => im.addEventListener('click', e => openImageModal(e.target.src)));
    if (!REFERENCE_STATE.refItemViewModal) {
        REFERENCE_STATE.refItemViewModal = new bootstrap.Modal(modal);
    }
    REFERENCE_STATE.refItemViewModal.show();
}

// ----- Editor readiness gate -----
// Returns true when the API editor *can* be used. In API mode we always show
// edit buttons; clicking one triggers requireEditor() which lazily prompts
// for the password if it isn't already in this session.
function editorReadyHtml() {
    return EDITOR_STATE.mode === 'api';
}
function unconfiguredEditorMsg() {
    return 'Editing requires the Vercel/KV deployment.';
}

// The Reference sections reuse the existing global `requireEditor(cb)`
// helper (defined above) — same lazy-unlock flow as the KB. No separate
// password.

// ----- Fetch a list section -----
async function fetchListSection(section, bearer = null) {
    const headers = { 'Cache-Control': 'no-cache' };
    if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
    const r = await fetch(`/api/list/${encodeURIComponent(section)}`, { cache: 'no-store', headers });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    return j.items || [];
}

// ----- Wire delegated clicks on list items (add/edit/delete) -----
// Add/Edit/Delete on non-MKSAP sections lazy-unlock the editor via
// requireEditor(); MKSAP uses its own gate and is already unlocked by the
// time these buttons render.
function wireListActions(viewer, section) {
    const guard = sectionUsesMksap(section) ? (fn) => fn() : requireEditor;
    viewer.querySelectorAll('[data-ref-add]').forEach(el => {
        el.addEventListener('click', () => guard(() => openRefItemModal(el.dataset.refAdd, null)));
    });
    viewer.querySelectorAll('[data-ref-edit]').forEach(el => {
        const [sec, id] = el.dataset.refEdit.split('/');
        el.addEventListener('click', () => guard(() => {
            const item = (REFERENCE_STATE.lists[sec] || []).find(i => i.id === id);
            if (item) openRefItemModal(sec, item);
        }));
    });
    viewer.querySelectorAll('[data-ref-delete]').forEach(el => {
        const [sec, id] = el.dataset.refDelete.split('/');
        el.addEventListener('click', () => guard(() => deleteRefItem(sec, id)));
    });
    // Pick-row read-only view (no auth gate — these are items the user is
    // already entitled to see in the list below).
    viewer.querySelectorAll('[data-ref-view]').forEach(el => {
        el.addEventListener('click', e => {
            e.preventDefault();
            const [sec, id] = el.dataset.refView.split('/');
            openRefItemView(sec, id);
        });
    });
    // Daily-pick count dropdown — persist + re-render this section only.
    viewer.querySelectorAll('[data-pick-count]').forEach(sel => {
        sel.addEventListener('change', e => {
            const sec = e.target.dataset.pickCount;
            const n = parseInt(e.target.value, 10);
            setDailyPickCount(sec, Number.isFinite(n) ? n : 1);
            // Re-render the active section in place.
            if (REFERENCE_STATE.activeId) loadReferenceItem(REFERENCE_STATE.activeId);
        });
    });
}

// ----- Refresh active section after a mutation -----
function refreshActiveSection() {
    if (REFERENCE_STATE.activeId) loadReferenceItem(REFERENCE_STATE.activeId);
}

// =========================================================================
// Reference item editor modal
// =========================================================================

// ----- Rich-text body editor (Quill + DOMPurify) ---------------------
// Quill is loaded via CDN script tag. We init lazily the first time a
// body field is asked for, since the Quill bundle is ~200 KB and we'd
// rather not pay that cost if the user never opens the editor.

let _refItemQuill = null;

const SANITIZE_CONFIG = {
    ALLOWED_TAGS: ['p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                   'strong', 'b', 'em', 'i', 'u', 's', 'strike', 'mark', 'sub', 'sup',
                   'ul', 'ol', 'li',
                   'a', 'blockquote', 'pre', 'code',
                   'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
                   'img', 'hr', 'figure', 'figcaption'],
    // `style` is allowed so Quill's color/background spans survive
    // (Quill uses inline `style="color: rgb(...)"`). DOMPurify has a CSS
    // sanitizer that filters dangerous properties (expression, url(...js),
    // position:fixed, etc.), so this is safe for a personal site.
    ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'target', 'rel', 'colspan', 'rowspan',
                   'class', 'style', 'data-row', 'data-cell', 'width', 'height'],
    ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|data):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
    ADD_ATTR: ['target'],
};

// Heuristic: a string is treated as HTML if it contains a closing tag.
// (Plain text with stray `<50` won't false-positive.)
function looksLikeHtml(s) {
    return typeof s === 'string' && /<\/?[a-z][\s\S]*>/i.test(s);
}

function sanitizeHtml(html) {
    if (!html) return '';
    if (typeof DOMPurify === 'undefined') {
        // CDN not loaded — fall back to escaping for safety
        return escapeHtml(html);
    }
    let cleaned = DOMPurify.sanitize(html, SANITIZE_CONFIG);
    // Force external links to open in new tab + add rel for safety
    cleaned = cleaned.replace(/<a (?![^>]*\btarget=)/gi, '<a target="_blank" rel="noopener" ');
    return cleaned;
}

// Render the `body` field for display. Auto-detects HTML vs plain text
// so existing plain-text entries keep working without migration.
function renderBody(body) {
    if (!body) return '';
    if (looksLikeHtml(body)) return sanitizeHtml(body);
    return renderRichText(body);
}

// Cheap heuristic: does this string look like markdown (bold, lists, pipe
// tables, headings, blockquotes, horizontal rules)? Used when loading
// existing entries into Quill so the user sees formatted output instead
// of literal `**bold**`. NOT used at paste time anymore — paste uses the
// explicit "Paste markdown" button.
function looksLikeMarkdown(s) {
    if (!s) return false;
    return /(?:^|\n)\s*(?:\*\*[^*]|[-*]\s+|\d+[.)]\s+|#{1,6}\s+|>\s+|---+\s*$|\|.*\|)/.test(s);
}

// Convert markdown-ish body text to HTML.
//
// Classify each line by kind (heading, hr, ul, ol, quote, table, prose,
// blank), group consecutive same-kind lines into a "run", then emit each
// run as one block. This means content like "Can cause:\n- A\n- B" (no
// blank line) correctly splits into a <p> + a <ul>, instead of being
// flattened into a paragraph with literal `- A`.
function markdownBodyToHtml(text) {
    if (!text) return '';
    const lines = text.split('\n');
    const runs = [];        // [{ kind, lines }]
    let cur = null;

    const flush = () => { if (cur && cur.lines.length) runs.push(cur); cur = null; };

    for (const line of lines) {
        const kind = classifyMdLine(line);
        if (kind === 'blank') { flush(); continue; }
        // Headings and HRs are always single-line standalone blocks.
        if (kind === 'heading' || kind === 'hr') {
            flush();
            runs.push({ kind, lines: [line] });
            continue;
        }
        if (cur && cur.kind === kind) {
            cur.lines.push(line);
        } else {
            flush();
            cur = { kind, lines: [line] };
        }
    }
    flush();

    const out = [];
    for (const run of runs) {
        const html = renderMdRun(run);
        if (html) out.push(html);
    }
    return out.join('');
}

function classifyMdLine(line) {
    if (line.trim() === '') return 'blank';
    if (/^\s*#{1,6}\s+/.test(line)) return 'heading';
    if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) return 'hr';
    if (/^\s*\|.*\|\s*$/.test(line)) return 'table';
    if (/^\s*>\s?/.test(line)) return 'quote';
    if (/^\s*[-*+]\s+/.test(line)) return 'ul';
    if (/^\s*\d+[.)]\s+/.test(line)) return 'ol';
    return 'prose';
}

function renderMdRun({ kind, lines }) {
    switch (kind) {
        case 'heading': {
            const m = lines[0].match(/^\s*(#{1,6})\s+(.+?)\s*#*\s*$/);
            if (!m) return `<p>${formatInline(lines[0])}</p>`;
            const level = Math.min(m[1].length + 1, 6);  // h2..h6
            return `<h${level}>${formatInline(m[2])}</h${level}>`;
        }
        case 'hr':
            return '<hr>';
        case 'table':
            return markdownTableToHtml(lines.join('\n')) || '';
        case 'quote': {
            const inner = lines.map(l => formatInline(l.replace(/^\s*>\s?/, ''))).join('<br>');
            return `<blockquote>${inner}</blockquote>`;
        }
        case 'ul': {
            const items = lines.map(l => `<li>${formatInline(l.replace(/^\s*[-*+]\s+/, ''))}</li>`).join('');
            return `<ul>${items}</ul>`;
        }
        case 'ol': {
            const items = lines.map(l => `<li>${formatInline(l.replace(/^\s*\d+[.)]\s+/, ''))}</li>`).join('');
            return `<ol>${items}</ol>`;
        }
        case 'prose':
            return `<p>${lines.map(formatInline).join('<br>')}</p>`;
        default:
            return '';
    }
}

// Load a body string into a Quill instance. Routes HTML / markdown / plain
// text through the right path so the user always sees formatted output.
//
// CRITICAL: we MUST use `clipboard.dangerouslyPasteHTML` (not direct
// `innerHTML = ...`) so Quill's internal Delta model syncs with the
// visible DOM. Setting innerHTML alone paints the editor but leaves
// Quill's state empty; the next keystroke or `getSemanticHTML()` then
// silently drops the content.
function loadBodyIntoQuill(quill, body) {
    if (!quill) return;
    quill.setText('');
    if (!body) return;
    let html = '';
    if (looksLikeHtml(body)) html = sanitizeHtml(body);
    else if (looksLikeMarkdown(body)) html = sanitizeHtml(markdownBodyToHtml(body));
    else { quill.setText(body); return; }
    if (html) quill.clipboard.dangerouslyPasteHTML(0, html, 'silent');
}

// ----- Custom Quill blot: preserve pasted tables ----------------------
// Quill 2 core strips <table> on paste because its Delta format has no
// native table representation. We register a BlockEmbed that holds raw
// table HTML so tables pasted from MKSAP/UpToDate survive. Tables are
// rendered but not editable inside Quill — you can delete them but not
// edit cells. (Trade-off vs. pulling in a table-editor library that
// doesn't yet support Quill 2 cleanly.)
function registerQuillExtensions() {
    if (typeof Quill === 'undefined') return;
    if (Quill._ecrefRegistered) return;
    Quill._ecrefRegistered = true;

    const BlockEmbed = Quill.import('blots/block/embed');
    class TableHtmlBlot extends BlockEmbed {
        static create(value) {
            const node = super.create();
            node.innerHTML = String(value || '');
            node.setAttribute('contenteditable', 'false');
            return node;
        }
        static value(node) {
            const t = node.querySelector('table');
            return t ? t.outerHTML : node.innerHTML;
        }
    }
    TableHtmlBlot.blotName = 'table-html';
    TableHtmlBlot.tagName = 'div';
    TableHtmlBlot.className = 'ql-table-static';
    Quill.register(TableHtmlBlot, true);
}

// Shared clipboard matchers for both KB + Reference Quill instances.
// Captures <table> elements as table-html blots so paste preserves them.
function quillClipboardMatchers() {
    if (typeof Quill === 'undefined') return [];
    const Delta = Quill.import('delta');
    return [
        ['TABLE', (node) => new Delta().insert({ 'table-html': node.outerHTML })],
    ];
}

// ----- Image-paste interceptor (Step 2 of base64→R2 migration) -------------
// Pasting a screenshot or copying an <img> from another tab lets Quill
// inline the bytes as `data:image/...;base64,...`. A single screenshot can
// add 500 KB+ to the editor body. Multiple of these per entry pushed the
// Vercel KV `database` blob to the 10 MB per-request ceiling. This handler
// intercepts paste + drop events on each Quill, uploads images to R2,
// and inserts the returned URL instead of the bytes.
//
// Attached once per Quill instance (in getKbQuill / getRefItemQuill).
function attachImagePasteInterceptor(quill) {
    if (!quill || !quill.root) return;
    // Capture phase so we run before Quill's bubble-phase clipboard module.
    quill.root.addEventListener('paste', e => handleEditorImagePaste(quill, e, false), true);
    quill.root.addEventListener('drop',  e => handleEditorImagePaste(quill, e, true),  true);
}

async function handleEditorImagePaste(quill, event, isDrop) {
    const dt = isDrop ? event.dataTransfer : event.clipboardData;
    if (!dt) return;

    // Files from the clipboard / drop. Screenshots come through here.
    const files = [];
    for (const it of (dt.items || [])) {
        if (it.kind === 'file' && it.type && it.type.startsWith('image/')) {
            const f = it.getAsFile();
            if (f) files.push(f);
        }
    }
    if (!files.length && dt.files) {
        for (const f of dt.files) {
            if ((f.type && f.type.startsWith('image/')) || /\.(heic|heif)$/i.test(f.name || '')) {
                files.push(f);
            }
        }
    }

    // Reject HEIC/HEIF and oversize files before we even POST — Vercel
    // would 413 them anyway, and HEIC won't render in most browsers.
    const rejected = [];
    const accepted = [];
    for (const f of files) {
        const reason = imageUploadPrecheck(f);
        if (reason) rejected.push({ file: f, reason });
        else accepted.push(f);
    }
    for (const r of rejected) toast(r.reason, 'error', { duration: 10000 });

    // Inline data: URIs inside pasted HTML. Sites/Word/PDFs sometimes embed
    // bytes inside <img src="data:image/...;base64,...">.
    const html = (!isDrop && dt.getData) ? (dt.getData('text/html') || '') : '';
    const inlineBase64Re = /<img\b[^>]*\bsrc\s*=\s*["']data:image\//i;
    const hasInlineBase64 = inlineBase64Re.test(html);

    if (!accepted.length && !hasInlineBase64) {
        // Even an all-rejected set of files counts as an image-paste attempt
        // — swallow the event so Quill doesn't fall back to inlining anything.
        if (rejected.length) { event.preventDefault(); event.stopPropagation(); }
        return;
    }

    event.preventDefault();
    event.stopPropagation();

    const password = pickEditorPasswordFor(quill);
    if (!password) {
        toast('Editor not unlocked — image paste needs the editor password.', 'error');
        return;
    }

    let progress;
    try {
        if (accepted.length) {
            progress = toast(`Uploading pasted image${accepted.length > 1 ? 's' : ''}...`, 'info', { duration: 0 });
            const urls = [];
            for (const f of accepted) {
                try { urls.push(await uploadImageSmart(f, password)); }
                catch (e) {
                    toast(`Upload failed for ${f.name || 'pasted image'}: ${e.message}`, 'error', { duration: 6000 });
                }
            }
            for (const u of urls) insertImageAtCursor(quill, u);
        }
        if (hasInlineBase64) {
            if (!progress) progress = toast('Uploading pasted images...', 'info', { duration: 0 });
            const rewritten = await rewriteDataUrisInHtml(html, password);
            const safe = sanitizeHtml(rewritten);
            const range = quill.getSelection(true) || { index: quill.getLength(), length: 0 };
            if (range.length) quill.deleteText(range.index, range.length, 'user');
            quill.clipboard.dangerouslyPasteHTML(range.index, safe, 'user');
        }
    } catch (e) {
        toast('Image paste failed: ' + (e.message || e), 'error', { duration: 5000 });
    } finally {
        if (progress && typeof progress.hide === 'function') progress.hide();
    }
}

// Rewrite every <img src="data:image/...;base64,...">  in a chunk of HTML
// to a hotlinkable R2 URL. Routes through uploadImageSmart so big inline
// images also get compressed or sent via presigned PUT. Failures fall back
// to leaving the original src (caller will sanitize).
async function rewriteDataUrisInHtml(html, password) {
    const re = /(<img\b[^>]*\bsrc\s*=\s*["'])data:image\/([a-z0-9+.\-]+);base64,([^"']+)(["'])/gi;
    const matches = [...html.matchAll(re)];
    if (!matches.length) return html;
    const replacements = [];
    for (const m of matches) {
        const ext = m[2].toLowerCase();
        const b64 = m[3].replace(/\s+/g, '');
        try {
            const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const mime = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
            const file = new File([bytes],
                `pasted-html-${Date.now()}.${ext === 'jpeg' ? 'jpg' : ext}`,
                { type: mime });
            replacements.push(await uploadImageSmart(file, password));
        } catch (e) {
            console.warn('rewriteDataUrisInHtml: upload failed, leaving original', e);
            replacements.push(null);
        }
    }
    let i = 0;
    return html.replace(re, (full, pre, ext, b64, post) => {
        const url = replacements[i++];
        return url ? `${pre}${url}${post}` : full;
    });
}

function insertImageAtCursor(quill, url) {
    const range = quill.getSelection(true) || { index: quill.getLength(), length: 0 };
    if (range.length) quill.deleteText(range.index, range.length, 'user');
    quill.insertEmbed(range.index, 'image', url, 'user');
    quill.setSelection(range.index + 1, 0, 'user');
}

function pickEditorPasswordFor(quill) {
    // Reference item editor: section may be MKSAP-gated.
    if (typeof _refItemQuill !== 'undefined' && quill === _refItemQuill
        && REFERENCE_STATE && REFERENCE_STATE.refItemSection
        && typeof sectionUsesMksap === 'function'
        && sectionUsesMksap(REFERENCE_STATE.refItemSection)) {
        return REFERENCE_STATE.mksapPassword;
    }
    return EDITOR_STATE.apiPassword;
}

// Insert markdown (as user-supplied raw text) into a Quill instance.
// Converts markdown → HTML, sanitizes, and uses the clipboard module
// so Quill's Delta model stays in sync. Used by the "Paste markdown"
// modal — there is no automatic paste-time conversion anymore: a
// regular Ctrl+V paste of `# foo` stays literal.
function insertMarkdownIntoQuill(quill, markdownText) {
    if (!quill || !markdownText) return;
    const html = sanitizeHtml(markdownBodyToHtml(markdownText));
    if (!html) return;
    const range = quill.getSelection(true) || { index: quill.getLength(), length: 0 };
    if (range.length) quill.deleteText(range.index, range.length, 'user');
    quill.clipboard.dangerouslyPasteHTML(range.index, html, 'user');
    quill.setSelection(range.index + html.length, 0, 'user');
}

// "Paste markdown" modal — one shared modal, three target editors.
// The button's data-md-target tells us which Quill instance receives
// the converted HTML when the user hits Insert.
const PASTE_MD_STATE = { modal: null, targetId: null };

function getQuillById(id) {
    if (id === 'refItemBody') return getRefItemQuill();
    if (id === 'entryData')   return getKbQuill('data');
    if (id === 'entryTemplate') return getKbQuill('template');
    return null;
}

function initPasteMarkdownModal() {
    const modalEl = document.getElementById('pasteMarkdownModal');
    if (!modalEl) return;
    PASTE_MD_STATE.modal = new bootstrap.Modal(modalEl);

    // Delegated handler for every "Paste markdown" button on the page
    document.body.addEventListener('click', (e) => {
        const btn = e.target.closest('.md-paste-btn');
        if (!btn) return;
        PASTE_MD_STATE.targetId = btn.dataset.mdTarget;
        document.getElementById('pasteMarkdownInput').value = '';
        document.getElementById('pasteMarkdownPreview').innerHTML =
            '<span class="text-muted small">Preview appears here as you type.</span>';
        PASTE_MD_STATE.modal.show();
        // Defer focus so Bootstrap finishes its own focus dance first
        setTimeout(() => document.getElementById('pasteMarkdownInput')?.focus(), 100);
    });

    const inputEl = document.getElementById('pasteMarkdownInput');
    const previewEl = document.getElementById('pasteMarkdownPreview');
    inputEl?.addEventListener('input', () => {
        const text = inputEl.value;
        if (!text.trim()) {
            previewEl.innerHTML = '<span class="text-muted small">Preview appears here as you type.</span>';
            return;
        }
        previewEl.innerHTML = sanitizeHtml(markdownBodyToHtml(text))
            || '<span class="text-muted small">(nothing to render)</span>';
    });

    document.getElementById('pasteMarkdownInsert')?.addEventListener('click', () => {
        const text = inputEl.value;
        if (!text.trim()) { PASTE_MD_STATE.modal.hide(); return; }
        const quill = getQuillById(PASTE_MD_STATE.targetId);
        if (!quill) { toast('Editor not ready.', 'error'); return; }
        insertMarkdownIntoQuill(quill, text);
        PASTE_MD_STATE.modal.hide();
        toast('Markdown inserted.', 'success');
    });
}

function getRefItemQuill() {
    if (_refItemQuill || typeof Quill === 'undefined') return _refItemQuill;
    registerQuillExtensions();
    _refItemQuill = new Quill('#refItemBody', {
        theme: 'snow',
        placeholder: 'Notes, summary, key teaching points... paste from MKSAP/UpToDate to preserve formatting.',
        modules: {
            toolbar: [
                [{ header: [1, 2, 3, 4, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ list: 'ordered' }, { list: 'bullet' }],
                ['blockquote', 'code-block'],
                ['link', 'image'],
                [{ color: [] }, { background: [] }],
                ['clean'],
            ],
            clipboard: {
                matchers: quillClipboardMatchers(),
            },
        },
    });
    attachImagePasteInterceptor(_refItemQuill);
    return _refItemQuill;
}

function setRefItemBody(body) {
    const q = getRefItemQuill();
    if (!q) {
        // Fall back to a plain element if Quill failed to load
        const el = document.getElementById('refItemBody');
        if (el) el.textContent = body || '';
        return;
    }
    loadBodyIntoQuill(q, body);
}

function getRefItemBody() {
    const q = getRefItemQuill();
    if (!q) {
        const el = document.getElementById('refItemBody');
        return el ? el.textContent : '';
    }
    // Use semantic HTML when available (Quill 2.x) for tidier output
    const raw = (q.getSemanticHTML && q.getSemanticHTML()) || q.root.innerHTML;
    // Empty editor emits "<p><br></p>" — collapse to empty string
    if (/^\s*(<p>(<br>)?<\/p>\s*)+$/i.test(raw)) return '';
    return sanitizeHtml(raw);
}

function wireRefItemModal() {
    const tagInput = document.getElementById('refItemTagInput');
    tagInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const v = tagInput.value.trim();
            if (v && !REFERENCE_STATE.refItemTags.includes(v)) {
                REFERENCE_STATE.refItemTags.push(v);
                renderRefItemTags();
            }
            tagInput.value = '';
        }
    });
    document.getElementById('refItemTagsBox').addEventListener('click', e => {
        const rm = e.target.closest('[data-rm-tag]');
        if (rm) {
            REFERENCE_STATE.refItemTags = REFERENCE_STATE.refItemTags.filter(t => t !== rm.dataset.rmTag);
            renderRefItemTags();
        }
    });

    // Image picker — supports multi-select (and multi-file drop)
    document.getElementById('refItemImagePickBtn').addEventListener('click',
        () => document.getElementById('refItemImageFile').click());
    document.getElementById('refItemImageFile').addEventListener('change', e => {
        for (const f of e.target.files) uploadRefItemImage(f);
        e.target.value = '';  // allow re-selecting the same file
    });
    const drop = document.getElementById('refItemImageDrop');
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
    drop.addEventListener('drop', e => {
        e.preventDefault();
        drop.classList.remove('drag');
        for (const f of e.dataTransfer.files) uploadRefItemImage(f);
    });

    document.getElementById('refItemSaveBtn').addEventListener('click', saveRefItem);
    document.getElementById('refItemDeleteBtn').addEventListener('click', () => {
        if (REFERENCE_STATE.refItem && confirm(`Delete "${REFERENCE_STATE.refItem.title}"?`)) {
            deleteRefItem(REFERENCE_STATE.refItemSection, REFERENCE_STATE.refItem.id);
            REFERENCE_STATE.refModal.hide();
        }
    });
}

function renderRefItemTags() {
    const box = document.getElementById('refItemTagsBox');
    box.innerHTML = REFERENCE_STATE.refItemTags.map(t =>
        `<span class="editor-tag-chip">${escapeHtml(t)} <button type="button" data-rm-tag="${escapeHtml(t)}" aria-label="Remove tag">&times;</button></span>`
    ).join('');
}

function renderRefItemImagePreview() {
    const preview = document.getElementById('refItemImagePreview');
    const list = REFERENCE_STATE.refItemImages || [];
    if (!list.length) { preview.innerHTML = ''; return; }
    preview.innerHTML = list.map((url, i) => `
        <span class="ref-item-image-thumb">
            <img src="${escapeHtml(url)}" alt="">
            <button type="button" class="ref-item-image-remove" data-rm-img="${i}" aria-label="Remove image">&times;</button>
        </span>`).join('');
    preview.querySelectorAll('[data-rm-img]').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = Number(btn.dataset.rmImg);
            REFERENCE_STATE.refItemImages.splice(idx, 1);
            renderRefItemImagePreview();
        });
    });
}

function openRefItemModal(section, item) {
    REFERENCE_STATE.refItemSection = section;
    REFERENCE_STATE.refItem = item;
    // Multi-image: prefer `images` array; fall back to single `image` for old records
    REFERENCE_STATE.refItemImages = item?.images && item.images.length
        ? item.images.slice()
        : (item?.image ? [item.image] : []);
    REFERENCE_STATE.refItemTags = (item?.tags || []).slice();

    document.getElementById('refItemModalLabel').textContent =
        item ? `Edit — ${item.title || section}` : `Add to ${sectionPrettyName(section)}`;
    document.getElementById('refItemTitle').value = item?.title || '';
    document.getElementById('refItemUrl').value = item?.url || '';
    setRefItemBody(item?.body || '');
    document.getElementById('refItemDeleteBtn').style.display = item ? 'inline-block' : 'none';

    // Antibiogram + abx-extras + UW often have images; EBM mostly URLs. Show image either way.
    document.getElementById('refItemImageRow').style.display = '';
    document.getElementById('refItemUrlRow').style.display = '';

    renderRefItemTags();
    renderRefItemImagePreview();
    REFERENCE_STATE.refModal.show();
}

function sectionPrettyName(s) {
    return { ebm: 'EBM articles', uw: 'UW Learning Cards', 'abx-extras': 'Antibiotics extras',
             'uci-antibiogram': 'UCI Antibiogram', mksap: 'MKSAP Boards Basics',
             'core-im': 'CoreIM podcast', 'board-review': 'Board Review Facts',
             'abim-objectives': 'ABIM Objectives',
             'cps-illness': 'CPSolvers — Illness Scripts',
             'cps-schemas': 'CPSolvers — Diagnostic Schemas' }[s] || s;
}

async function uploadRefItemImage(file) {
    if (!file.type.startsWith('image/')) {
        toast('Only image files are supported here.', 'error');
        return;
    }
    if (!editorReadyHtml() && !sectionUsesMksap(REFERENCE_STATE.refItemSection)) {
        toast('Editor not unlocked.', 'error');
        return;
    }
    const password = sectionUsesMksap(REFERENCE_STATE.refItemSection)
        ? REFERENCE_STATE.mksapPassword
        : EDITOR_STATE.apiPassword;
    const placeholderToast = toast('Uploading image...', 'info', { duration: 0 });
    try {
        const b64 = await fileToB64(file);
        const r = await fetch('/api/upload-image', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: file.name, contentB64: b64, contentType: file.type }),
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        const { url } = await r.json();
        REFERENCE_STATE.refItemImages = (REFERENCE_STATE.refItemImages || []).concat(url);
        renderRefItemImagePreview();
        toast('Image uploaded.', 'success');
    } catch (e) {
        toast(`Upload failed: ${e.message}`, 'error', { duration: 5000 });
    } finally {
        dismissToast(placeholderToast);
    }
}

async function saveRefItem() {
    const section = REFERENCE_STATE.refItemSection;
    const existing = REFERENCE_STATE.refItem;
    const title = document.getElementById('refItemTitle').value.trim();
    if (!title) { toast('Title is required.', 'error'); return; }

    const password = sectionUsesMksap(section) ? REFERENCE_STATE.mksapPassword : EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }

    const now = new Date().toISOString();
    const id = existing?.id || (slugify(title) + '-' + Date.now().toString(36));
    const images = (REFERENCE_STATE.refItemImages || []).slice();
    const patch = {
        id,
        title,
        url: document.getElementById('refItemUrl').value.trim() || null,
        body: getRefItemBody(),
        images,                                         // canonical multi-image field
        image: images[0] || null,                       // back-compat: keep first as `image`
        tags: REFERENCE_STATE.refItemTags.slice(),
        updatedAt: now,
        createdAt: existing?.createdAt || now,
    };

    const btn = document.getElementById('refItemSaveBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Saving...';

    try {
        let r;
        if (existing) {
            r = await fetch(`/api/list/${encodeURIComponent(section)}/${encodeURIComponent(id)}`, {
                method: 'PUT',
                headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
                body: JSON.stringify(patch),
            });
        } else {
            r = await fetch(`/api/list/${encodeURIComponent(section)}`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${password}`, 'Content-Type': 'application/json' },
                body: JSON.stringify(patch),
            });
        }
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        toast(existing ? 'Updated.' : 'Added.', 'success');
        REFERENCE_STATE.refModal.hide();
        refreshActiveSection();
    } catch (e) {
        toast(`Save failed: ${e.message}`, 'error', { duration: 5000 });
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-save me-1"></i>Save';
    }
}

async function deleteRefItem(section, id) {
    const item = (REFERENCE_STATE.lists[section] || []).find(i => i.id === id);
    if (!item) return;
    if (!confirm(`Delete "${item.title}"?`)) return;
    const password = sectionUsesMksap(section) ? REFERENCE_STATE.mksapPassword : EDITOR_STATE.apiPassword;
    if (!password) { toast('Editor not unlocked.', 'error'); return; }
    try {
        const r = await fetch(`/api/list/${encodeURIComponent(section)}/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${password}` },
        });
        if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            throw new Error(j.error || `HTTP ${r.status}`);
        }
        toast('Deleted.', 'success');
        refreshActiveSection();
    } catch (e) {
        toast(`Delete failed: ${e.message}`, 'error', { duration: 5000 });
    }
}

function slugify(s) {
    return (s || 'item').toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 50);
}

// =========================================================================
// MKSAP unlock modal
// =========================================================================

function wireMksapUnlock() {
    const submit = document.getElementById('mksapUnlockSubmit');
    const input = document.getElementById('mksapPasswordInput');
    const err = document.getElementById('mksapUnlockError');

    const attempt = async () => {
        err.style.display = 'none';
        const pw = input.value;
        if (!pw) { err.textContent = 'Enter a password.'; err.style.display = 'block'; return; }
        try {
            if (!SECRETS.mksapSentinel) throw new Error('MKSAP not configured.');
            const plain = await decryptSecret(pw, SECRETS.mksapSentinel);
            if (plain !== MKSAP_SENTINEL_PLAINTEXT) throw new Error('Wrong password.');
            REFERENCE_STATE.mksapPassword = pw;
            REFERENCE_STATE.mksapUnlocked = true;
            try { sessionStorage.setItem(REFERENCE_STORAGE.mksapPassword, pw); } catch (e) {}
            REFERENCE_STATE.mksapUnlockModal.hide();
            toast('Unlocked.', 'success');
            // Refresh whatever's currently visible — handles both the MKSAP
            // section and any UWorld item that was gated behind this unlock.
            if (REFERENCE_STATE.activeId) loadReferenceItem(REFERENCE_STATE.activeId);
        } catch (e) {
            err.textContent = e.message === 'MKSAP not configured.'
                ? 'MKSAP not configured. Run tools/encrypt-urls.html to generate a sentinel.'
                : 'Wrong password.';
            err.style.display = 'block';
        }
    };
    submit.addEventListener('click', attempt);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') attempt(); });
}

// =========================================================================
// MKSAP Content viewer — sub-TOC by subspecialty + lazy body load
// =========================================================================

const MKSAP_CONTENT_STATE = {
    index: null,           // [{id, title, subspecialty, subspecialtyName, chapter, keyPoints}]
    activeId: null,
    query: '',
    bodyCache: {},         // id -> html
    showFullBody: false,   // toggled per topic; reset on each topic click
};

async function renderMksapContentSection(node) {
    const viewer = refViewer();
    viewer.classList.add('pdf-toc-host');

    // Gate first — same MKSAP unlock as before
    if (!REFERENCE_STATE.mksapUnlocked) {
        viewer.innerHTML = `
            <div class="reference-mksap-gate">
                <i class="fas fa-lock"></i>
                <h5>${escapeHtml(node.title)}</h5>
                <button class="btn btn-primary" id="mksapShowUnlock">
                    <i class="fas fa-unlock me-1"></i>Unlock
                </button>
            </div>`;
        document.getElementById('mksapShowUnlock').addEventListener('click', () => {
            document.getElementById('mksapPasswordInput').value = '';
            document.getElementById('mksapUnlockError').style.display = 'none';
            REFERENCE_STATE.mksapUnlockModal.show();
        });
        refActions().innerHTML = '';
        return;
    }

    viewer.innerHTML = `<div class="text-muted text-center py-4"><i class="fas fa-spinner fa-spin"></i> Loading MKSAP topics...</div>`;

    // Load index (cache it)
    if (!MKSAP_CONTENT_STATE.index) {
        try {
            const r = await fetch('/api/mksap-content', {
                cache: 'no-store',
                headers: { 'Authorization': `Bearer ${REFERENCE_STATE.mksapPassword}` },
            });
            if (!r.ok) {
                if (r.status === 401) {
                    REFERENCE_STATE.mksapUnlocked = false;
                    try { sessionStorage.removeItem(REFERENCE_STORAGE.mksapPassword); } catch (e) {}
                    return renderMksapContentSection(node);
                }
                throw new Error(`HTTP ${r.status}`);
            }
            const j = await r.json();
            MKSAP_CONTENT_STATE.index = j.index || [];
        } catch (e) {
            viewer.innerHTML = `<div class="alert alert-warning">Couldn't load MKSAP topics: ${escapeHtml(e.message)}.<br>
                If empty, visit /seed.html → "Seed MKSAP Topics" first.</div>`;
            return;
        }
    }

    const idx = MKSAP_CONTENT_STATE.index;
    if (!idx.length) {
        viewer.innerHTML = `<div class="alert alert-info">No MKSAP topics seeded yet. Visit
            <a href="/seed.html" target="_blank">/seed.html</a> and click "Seed MKSAP Topics".</div>`;
        return;
    }

    // Lock button + count in header
    refActions().innerHTML = `<span class="text-muted small me-2">${idx.length} topics</span>
        <button class="btn btn-sm btn-outline-secondary" id="mksapLockBtn">
            <i class="fas fa-lock me-1"></i>Lock
        </button>`;
    document.getElementById('mksapLockBtn').addEventListener('click', () => {
        REFERENCE_STATE.mksapUnlocked = false;
        REFERENCE_STATE.mksapPassword = null;
        try { sessionStorage.removeItem(REFERENCE_STORAGE.mksapPassword); } catch (e) {}
        renderMksapContentSection(node);
    });

    viewer.innerHTML = `
        <div class="pdf-toc-layout">
            <aside class="pdf-toc-sidebar">
                <div class="pdf-toc-search-wrap">
                    <input type="search" class="form-control form-control-sm" id="mksapContentSearch" placeholder="Search ${idx.length} topics...">
                </div>
                <div class="pdf-toc-list" id="mksapContentList"></div>
                <div class="pdf-toc-empty text-muted text-center py-3" id="mksapContentEmpty" style="display:none;">
                    <i class="fas fa-search me-2"></i>No matches.
                </div>
            </aside>
            <main class="pdf-toc-viewer mksap-content-viewer" id="mksapContentViewerPane">
                <div class="pdf-toc-placeholder" id="mksapContentPlaceholder">
                    <i class="fas fa-book-medical"></i>
                    <p>Pick a topic on the left to view its key points.</p>
                </div>
            </main>
        </div>`;

    renderMksapContentSidebar(node);

    // Show today's pick on first load (placeholder area).
    // MKSAP topic viewer always shows a single pick — the multi-pick UI is
    // only meaningful for sections whose items render as a list.
    if (node.dailyPick && !MKSAP_CONTENT_STATE.activeId) {
        const pick = picksOfTheDay(idx, 1)[0];
        if (pick) showMksapDailyPick(pick);
    }

    document.getElementById('mksapContentSearch').addEventListener('input', e => {
        MKSAP_CONTENT_STATE.query = e.target.value;
        renderMksapContentSidebar(node);
    });

    document.getElementById('mksapContentList').addEventListener('click', e => {
        const link = e.target.closest('[data-mksap-id]');
        if (!link) return;
        e.preventDefault();
        loadMksapTopic(link.dataset.mksapId);
    });

    if (MKSAP_CONTENT_STATE.activeId) {
        loadMksapTopic(MKSAP_CONTENT_STATE.activeId);
    }
}

function renderMksapContentSidebar(node) {
    const q = (MKSAP_CONTENT_STATE.query || '').trim().toLowerCase();
    const idx = MKSAP_CONTENT_STATE.index || [];

    // Group by subspecialtyName, preserving stable order
    const groups = new Map();
    for (const t of idx) {
        if (q && !(t.title || '').toLowerCase().includes(q)
              && !(t.subspecialtyName || '').toLowerCase().includes(q)) continue;
        const k = t.subspecialtyName || t.subspecialty || 'Other';
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(t);
    }
    // Sort each group by chapter number
    for (const list of groups.values()) {
        list.sort((a, b) => (a.chapter || 0) - (b.chapter || 0) || (a.title || '').localeCompare(b.title || ''));
    }

    const listEl = document.getElementById('mksapContentList');
    const emptyEl = document.getElementById('mksapContentEmpty');
    if (!groups.size) {
        listEl.innerHTML = '';
        emptyEl.style.display = 'block';
        return;
    }
    emptyEl.style.display = 'none';

    const sorted = [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    listEl.innerHTML = sorted.map(([sub, topics]) => `
        <div class="pdf-toc-section">
            <div class="pdf-toc-section-title">${escapeHtml(sub)}</div>
            <ul class="pdf-toc-entries">
                ${topics.map(t => {
                    const active = MKSAP_CONTENT_STATE.activeId === t.id;
                    return `<li>
                        <a href="#" class="pdf-toc-entry${active ? ' active' : ''}" data-mksap-id="${escapeHtml(t.id)}">
                            <span class="pdf-toc-entry-title">${escapeHtml(t.title)}</span>
                            <span class="pdf-toc-entry-page">ch.${t.chapter || '?'}</span>
                        </a>
                    </li>`;
                }).join('')}
            </ul>
        </div>
    `).join('');
}

function showMksapDailyPick(pick) {
    const pane = document.getElementById('mksapContentViewerPane');
    const today = new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
    pane.innerHTML = `
        <div class="mksap-topic">
            <div class="reference-pick mb-3">
                <div class="reference-pick-label">
                    <i class="fas fa-star"></i>Today's MKSAP pick · ${escapeHtml(today)}
                </div>
                <div class="reference-pick-title">
                    <a href="#" data-mksap-id="${escapeHtml(pick.id)}">${escapeHtml(pick.title)}</a>
                    <small class="text-muted ms-2">${escapeHtml(pick.subspecialtyName || '')} · ch.${pick.chapter || '?'}</small>
                </div>
                ${pick.keyPoints ? `<div class="mksap-keypoints-callout mt-2">${sanitizeHtml(pick.keyPoints)}</div>` : ''}
            </div>
            <p class="text-muted text-center">Pick a topic on the left for the full chapter.</p>
        </div>`;
    pane.querySelector('[data-mksap-id]')?.addEventListener('click', e => {
        e.preventDefault();
        loadMksapTopic(pick.id);
    });
}

async function loadMksapTopic(id) {
    const topic = (MKSAP_CONTENT_STATE.index || []).find(t => t.id === id);
    if (!topic) return;
    MKSAP_CONTENT_STATE.activeId = id;
    MKSAP_CONTENT_STATE.showFullBody = false;
    document.querySelectorAll('.pdf-toc-entry.active').forEach(el => el.classList.remove('active'));
    document.querySelector(`[data-mksap-id="${CSS.escape(id)}"]`)?.classList.add('active');

    const pane = document.getElementById('mksapContentViewerPane');
    pane.innerHTML = `
        <article class="mksap-topic">
            <header class="mksap-topic-head">
                <div class="mksap-topic-sub">${escapeHtml(topic.subspecialtyName || '')} · Chapter ${topic.chapter || '?'}</div>
                <h2 class="mksap-topic-title">${escapeHtml(topic.title)}</h2>
            </header>
            ${topic.keyPoints
                ? `<div class="mksap-keypoints-callout">
                       <div class="mksap-keypoints-label"><i class="fas fa-key me-1"></i>Key Points</div>
                       ${sanitizeHtml(topic.keyPoints)}
                   </div>`
                : '<div class="text-muted small">No key points extracted.</div>'}
            <div class="mksap-body-controls">
                <button class="btn btn-sm btn-outline-primary" id="mksapToggleBody">
                    <i class="fas fa-chevron-down me-1"></i>Show full content
                </button>
            </div>
            <div id="mksapBodyHost" class="mksap-body" style="display:none;"></div>
        </article>`;
    pane.scrollTop = 0;

    document.getElementById('mksapToggleBody').addEventListener('click', () => toggleMksapBody(id));
}

async function toggleMksapBody(id) {
    const btn = document.getElementById('mksapToggleBody');
    const host = document.getElementById('mksapBodyHost');
    if (!btn || !host) return;

    if (host.style.display === 'block') {
        host.style.display = 'none';
        btn.innerHTML = '<i class="fas fa-chevron-down me-1"></i>Show full content';
        return;
    }

    // Need to load the body
    let html = MKSAP_CONTENT_STATE.bodyCache[id];
    if (!html) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading...';
        try {
            const r = await fetch(`/api/mksap-content/${encodeURIComponent(id)}`, {
                cache: 'no-store',
                headers: { 'Authorization': `Bearer ${REFERENCE_STATE.mksapPassword}` },
            });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const j = await r.json();
            html = j.body || '';
            MKSAP_CONTENT_STATE.bodyCache[id] = html;
        } catch (e) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-chevron-down me-1"></i>Show full content';
            toast(`Body load failed: ${e.message}`, 'error');
            return;
        }
        btn.disabled = false;
    }

    host.innerHTML = sanitizeHtml(html);
    host.style.display = 'block';
    btn.innerHTML = '<i class="fas fa-chevron-up me-1"></i>Hide full content';
}
