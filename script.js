// =========================================================================
// Medical Reference — application script
// =========================================================================

// Encrypted URLs. Regenerate with tools/encrypt-urls.html when rotating the
// password or updating the Google Sheet/Doc.
// AES-GCM(256) ciphertext + iv + salt, base64-encoded. PBKDF2-SHA256, 200k iter.
const SECRETS = {
  "clinicalDocUrl": {
    "ct": "N8Vl1T8K4qz9XUCiIyqGR7ea6ONNb15cO79yfKzK4Ya6nyyZGEqTnQam8TDyGZwqWbi7WcjjQnd8SgGBdy7le1B5nKWNvlUe5QIVDXxtur/6WI/XBx6mbRCMLihqBpImd5yKWXikkJ5CnBTtN4AJSg==",
    "iv": "8Gmbx3N7t1c88wYB",
    "salt": "BzNNnuhOGajtk13s2pU5zA=="
  },
  "patientsSheetUrl": null
};
const PBKDF2_ITER = 200000;

let dotphrasesData = [];

// =========================================================================
// Boot
// =========================================================================

$(document).ready(function () {
    // Cache-bust on load so a fresh deploy is picked up immediately (avoids
    // GitHub Pages CDN serving stale JSON for up to 10 min after a commit).
    const bust = `?v=${Date.now()}`;
    fetch('reference_data.json' + bust, { cache: 'no-store' })
        .then(r => r.json())
        .then(data => {
            initKB(data.database || []);
            return fetch('dotphrases.txt' + bust, { cache: 'no-store' });
        })
        .then(r => r.text())
        .then(text => {
            parseDotphrases(text);
            $('#loading').hide();
        })
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

    // Secure gates — URLs decrypt only when correct password is entered.
    // Both gates share the same password (SECRETS were encrypted together).
    setupSecureGate({
        secretKey: 'clinicalDocUrl',
        submitBtn: '#submit-password',
        passwordInput: '#doc-password',
        errorMsg: '#password-error',
        gate: '#password-gate',
        container: '#document-container',
        iframe: '#google-doc-frame',
        lockBtn: '#lock-document',
    });

    setupSecureGate({
        secretKey: 'patientsSheetUrl',
        submitBtn: '#patients-submit',
        passwordInput: '#patients-password',
        errorMsg: '#patients-error',
        gate: '#patients-gate',
        container: '#patients-container',
        iframe: '#patients-frame',
        lockBtn: '#patients-lock',
        unconfiguredMsg: 'Patient log not configured yet. Run tools/encrypt-urls.html to set up.',
    });

    // Dotphrase search
    $('#dotphraseSearch').on('keyup', function () {
        const searchTerm = $(this).val().toLowerCase();
        $('.dotphrase-item').each(function () {
            const text = $(this).text().toLowerCase();
            $(this).toggle(text.includes(searchTerm));
        });
    });

    // Copy button for dotphrases
    $(document).on('click', '.copy-btn', function () {
        const btn = $(this);
        const text = btn.closest('.dotphrase-item').find('.dotphrase-content').text();
        copyTextToClipboard(text, btn[0]);
    });

    // Image modal handlers
    $('.close-modal').on('click', () => $('#imageModal').hide());
    $('#imageModal').on('click', function (e) {
        if (e.target.id === 'imageModal') $('#imageModal').hide();
    });

    // Editor (add/edit/delete entries via GitHub API)
    initEditor();
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

function setupSecureGate(opts) {
    const secret = SECRETS[opts.secretKey];
    const submit = async () => {
        const $err = $(opts.errorMsg);
        const $pw = $(opts.passwordInput);
        const $submit = $(opts.submitBtn);
        const password = $pw.val();
        $err.hide();
        if (!secret) {
            $err.text(opts.unconfiguredMsg || 'This gate is not configured yet.').show();
            return;
        }
        $submit.prop('disabled', true);
        try {
            const url = await decryptSecret(password, secret);
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
        $(opts.container).hide();
        $(opts.gate).show();
        $(opts.iframe).attr('src', '');
        $(opts.passwordInput).val('');
    });
}

// =========================================================================
// Shared helpers — image modal, escaping, formatting
// =========================================================================

function openImageModal(imageUrl) {
    $('#modalImage').attr('src', imageUrl);
    $('#imageModal').show();
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

// Inline-only formatting: escape, link URLs, bold (**), italic (*).
function formatInline(text) {
    let out = escapeHtml(text);
    // URLs
    out = out.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    // Bold: **text**
    out = out.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
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
// Dot phrases (unchanged)
// =========================================================================

function parseDotphrases(text) {
    const lines = text.split('\n');
    let currentPhrase = null;
    let content = [];
    lines.forEach(line => {
        if (line.startsWith('DOTPHRASE ')) {
            if (currentPhrase) {
                dotphrasesData.push({ title: currentPhrase, content: content.join('\n').trim() });
            }
            currentPhrase = line.replace('DOTPHRASE ', '').trim();
            content = [];
        } else if (currentPhrase) {
            content.push(line);
        }
    });
    if (currentPhrase) {
        dotphrasesData.push({ title: currentPhrase, content: content.join('\n').trim() });
    }
    renderDotphrases();
}

function renderDotphrases() {
    const container = $('#dotphrasesContent');
    container.empty();
    dotphrasesData.forEach(phrase => {
        const item = $('<div class="dotphrase-item mb-3"></div>');
        const title = $(`<div class="dotphrase-title d-flex justify-content-between align-items-center">
            <span><i class="fas fa-file-medical me-2"></i>${escapeHtml(phrase.title)}</span>
            <button class="btn btn-sm btn-primary copy-btn">Copy</button>
        </div>`);
        const content = $('<div class="dotphrase-content"></div>').text(phrase.content);
        item.append(title).append(content);
        container.append(item);
    });
}

// =========================================================================
// In-browser editor — commits to GitHub via API for zero-friction adds/edits
// =========================================================================

const EDITOR_STORAGE = {
    pat: 'ecref.editor.pat',         // encrypted PAT blob
    repo: 'ecref.editor.repo',       // {owner, repo} JSON if user overrides auto-detect
};

const EDITOR_STATE = {
    configured: false,         // is an encrypted PAT in localStorage?
    pat: null,                 // decrypted PAT (in memory only, this session)
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
    EDITOR_STATE.configured = !!localStorage.getItem(EDITOR_STORAGE.pat);

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
        openSetupWizard();
    });
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
        err.style.display = 'block';
    }
}

// Run callback once editor is unlocked. Shows wizard or unlock prompt as needed.
function requireEditor(cb) {
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

// =========================================================================
// Entry editor modal
// =========================================================================

function wireEntryEditor() {
    document.getElementById('entrySaveBtn')?.addEventListener('click', saveEntry);
    document.getElementById('entryDeleteBtn')?.addEventListener('click', confirmDeleteEntry);

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

function openEntryEditor(id) {
    requireEditor(() => {
        EDITOR_STATE.editingId = id;
        EDITOR_STATE.pendingUploads = [];
        const isEdit = !!id;
        document.getElementById('entryModalLabel').textContent = isEdit ? 'Edit entry' : 'Add entry';
        document.getElementById('entryDeleteBtn').style.display = isEdit ? 'inline-block' : 'none';

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
            // Strip title from data (we re-add it on save)
            const dataLines = (entry.data || '').split('\n');
            const titleLine = dataLines.findIndex(l => l.trim().replace(/^#+\s*/, ''));
            const bodyLines = titleLine >= 0 ? dataLines.slice(titleLine + 1) : dataLines;
            document.getElementById('entryData').value = bodyLines.join('\n').replace(/^\n+/, '');
            document.getElementById('entryTemplate').value = entry.template || '';
        } else {
            document.getElementById('entryTitle').value = '';
            document.getElementById('entryCategory').value = KB_STATE.category || 'Other';
            EDITOR_STATE.tags = [];
            EDITOR_STATE.links = [];
            EDITOR_STATE.images = [];
            document.getElementById('entryData').value = '';
            document.getElementById('entryTemplate').value = '';
        }
        document.getElementById('entryTagInput').value = '';
        renderEditorTags();
        renderEditorLinks();
        renderEditorImages();
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
        const isImg = /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(p);
        const isPending = EDITOR_STATE.pendingUploads.some(u => u.path === p);
        const thumb = isImg
            ? `<img src="${escapeHtml(p)}" alt="">`
            : `<span class="img-note">${escapeHtml(p)}</span>`;
        return `<div class="editor-image-chip${isPending ? ' pending' : ''}">
            ${thumb}
            <div class="editor-image-meta">
                <small>${escapeHtml(p)}</small>
                ${isPending ? '<span class="badge bg-warning text-dark">Will upload on save</span>' : ''}
            </div>
            <button type="button" class="btn btn-sm btn-outline-danger" data-rm-img="${escapeHtml(p)}" aria-label="Remove image">&times;</button>
        </div>`;
    }).join('');
}

async function handleImageFiles(files) {
    for (const file of files) {
        if (!file.type.startsWith('image/')) continue;
        const ext = file.name.split('.').pop().toLowerCase();
        const baseSlug = (file.name.replace(/\.[^.]+$/, '') || 'img')
            .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
        const path = `images/${baseSlug}-${Date.now()}.${ext}`;
        const b64 = await fileToB64(file);
        EDITOR_STATE.pendingUploads.push({ path, contentB64: b64 });
        EDITOR_STATE.images.push(path);
    }
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
    const dataBody = document.getElementById('entryData').value.trim();
    const template = document.getElementById('entryTemplate').value;
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
        // Upload any pending images first
        for (const upload of EDITOR_STATE.pendingUploads) {
            await ghPutFile(upload.path, upload.contentB64, null, `Add image ${upload.path}`);
        }
        EDITOR_STATE.pendingUploads = [];

        // Fetch fresh JSON for SHA + content
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
        const file = await ghGetFile('reference_data.json');
        if (!file) throw new Error('reference_data.json not found.');
        const existing = JSON.parse(b64ToUtf8(file.contentB64));
        existing.database = existing.database.filter(e => e.id !== entry.id);
        const newContent = JSON.stringify(existing, null, 2);
        await ghPutFile('reference_data.json', utf8ToB64(newContent), file.sha, `Delete entry: ${getTitle(entry)}`);
        dismissToast(savingToast);
        toast('Deleted. Live on GitHub Pages in ~60 seconds.', 'success');
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

const HANDBOOK_STATE = { toc: null, query: '' };

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

    const html = sections.map(sec => `
        <div class="handbook-section">
            <h6 class="handbook-section-title">${escapeHtml(sec.title || '')}</h6>
            <ul class="handbook-entries">
                ${sec.entries.map(e => {
                    const page = Number(e.page) || 1;
                    // Prefer chopped file if present; fall back to page anchor on full PDF
                    const href = e.file
                        ? escapeHtml(e.file)
                        : `${escapeHtml(pdfPath)}#page=${page}`;
                    return `<li>
                        <a href="${href}" target="_blank" rel="noopener" class="handbook-entry">
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
