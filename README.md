# Medical Reference Website

A clinical reference website for UCI Medical Center — quick guidelines, a searchable knowledge base, documentation templates (dot phrases), a password-gated Clinical Reasoning doc, and a password-gated patient log.

Author: Elaine Cheung

---

## Tabs

| Tab | What it is |
|---|---|
| **Quick Reference** | Admission workflow, triage criteria, telemetry guidelines |
| **Knowledge Base** | ~425 medical entries with categories, tags, favorites, recents, scoped search |
| **Dot Phrases** | Searchable, copy-to-clipboard documentation templates |
| **Clinical Reasoning** | Embedded Google Doc, gated by encrypted password (Web Crypto) |
| **Patients** | Embedded Google Sheet for de-identified patient log, same gate |
| **Handbook** | MGH Pocket Medicine TOC + inline page images |
| **Reference** | Antibiotic guides, ConanLi, EBM, UW Learning Objectives, MKSAP (separately gated) |

---

## Real-time editing via Vercel KV (recommended)

If the site is deployed on Vercel with KV configured, edits take effect **instantly** for everyone — no GitHub commit, no rebuild wait. The site auto-detects this and switches modes; on GitHub Pages it falls back to the GitHub-PAT flow described in the next section.

### Vercel KV one-time setup (~5 min)

1. **Create the KV store**
   - Vercel dashboard → your Ecref project → **Storage** tab → **Create Database** → pick **Upstash for Redis** (free tier covers this use case).
   - Vercel automatically adds the env vars (`KV_REST_API_URL`, `KV_REST_API_TOKEN`, etc.).

2. **Set the editor password**
   - Same dashboard → **Settings** → **Environment Variables**.
   - Add `EDITOR_PASSWORD` with the password you want to use for editing.
   - Add `MKSAP_PASSWORD` if you want to use the MKSAP section in the Reference tab (defaults to `ElaineWR`).
   - Apply to: Production, Preview, Development.

3. **Redeploy** (Settings → Deployments → … → Redeploy) so the new env vars take effect.

4. **Seed the KV with the current knowledge base**
   - Visit `https://your-vercel-url/seed.html`
   - Click **Check /api/entries** — should say "KV reachable" (or "503 KV not configured" if step 1 was skipped).
   - Enter your `EDITOR_PASSWORD` and click **Seed from reference_data.json**. Should say "✓ Seeded 442 entries."

5. **Done.** Go back to the main site, click **+ Add entry** — the unlock modal will prompt for your editor password (one-time per browser session). Hit save and the entry is live immediately.

The `/seed.html` page also has:
- **KV status check** — verify the API + KV are wired up
- **Backup** — download the current KV contents as a JSON file (commit to repo as a snapshot)

### What "real-time" means

| Action | Effect |
|---|---|
| You click Save in the editor | Entry appears in your KB instantly (optimistic UI) AND lands in KV |
| Someone else refreshes the site | They see your edit immediately (`/api/entries` reads KV directly) |
| You add an image to an entry | If you still have a GitHub PAT configured, the image uploads to the repo (triggers a Vercel rebuild). If not, the entry saves without the image. |

### Caveats

- **Images** are uploaded to Cloudflare R2 in real-time when R2 is configured (see next section). If R2 is not configured, image uploads fall back to GitHub commits (which trigger a Vercel rebuild). JSON-only edits never trigger rebuilds.
- **Backups**: KV is the source of truth in this mode. Periodically download the current state via `curl https://ecref.vercel.app/api/entries -o backup.json` and commit it to the repo as a snapshot.
- **github.io still shows the static `reference_data.json`** until you redirect it to Vercel — it will be stale post-KV-edits.
- **Vercel KV free tier**: 256 MB storage / 30k requests/day (Upstash free tier as of 2026). Plenty for personal use.

---

## Real-time image uploads via Cloudflare R2 (optional but recommended)

R2 is free up to 10 GB storage + 10M reads/month with **zero egress fees** (better than any S3-clone). Setting it up means image uploads become instant — no GitHub commit, no Vercel rebuild.

### One-time R2 setup (~10 min)

1. **Sign up for Cloudflare** if you don't have an account: <https://dash.cloudflare.com/sign-up>

2. **Create an R2 bucket**
   - Cloudflare dashboard → **R2** → **Create bucket**
   - Name: `ecref-images` (or whatever you want)
   - Location: Automatic
   - Click **Create bucket**

3. **Enable public access on the bucket**
   - Open the bucket → **Settings** → scroll to **Public Development URL** → **Allow Access**
   - Copy the resulting URL — looks like `https://pub-XXXXXXXXXXXXXXXXXXXXXXXX.r2.dev`. You'll need this.
   - (Optional: connect a custom domain like `images.ecref.com` for cleaner URLs)

4. **Create an R2 API token**
   - R2 dashboard → **Manage R2 API Tokens** → **Create API token**
   - Permission: **Object Read & Write**
   - Specify bucket: your `ecref-images` bucket
   - TTL: as long as you want (or "Forever" for personal use)
   - Click **Create API Token**
   - **Copy the Access Key ID and Secret Access Key now** — you can't see them again
   - Also note the **Account ID** at the top of the R2 dashboard

5. **Add env vars in Vercel**
   - Vercel dashboard → Ecref project → Settings → Environment Variables
   - Add five variables (Production + Preview + Development):
     - `R2_ACCOUNT_ID` = your Cloudflare account ID
     - `R2_ACCESS_KEY_ID` = the access key from step 4
     - `R2_SECRET_ACCESS_KEY` = the secret key from step 4
     - `R2_BUCKET` = `ecref-images`
     - `R2_PUBLIC_URL` = the `https://pub-XXX.r2.dev` URL from step 3 (no trailing slash)

6. **Redeploy** (Vercel auto-redeploys when env vars change; if not, do it manually).

7. **Test it**
   - Open the site → Add entry → drag an image into the editor → should see "Uploading…" briefly, then a thumbnail with a `pub-XXX.r2.dev` URL.
   - Save the entry. Image displays in the KB card.

### How R2 vs GitHub interact

| Mode | Image upload destination |
|---|---|
| KV + R2 configured | R2 (instant) |
| KV but no R2 | Falls back to GitHub commit (requires PAT) |
| GitHub-only mode (e.g., github.io) | GitHub commit (existing flow) |

### When images get expensive

R2 free tier covers far more than a personal site needs. You'd start paying when you exceed:
- **10 GB total storage** (≈ 20,000 medium PNG schemas) → $0.015/GB-month after
- **10M monthly reads** (≈ 333k page views with 30 images each) → $0.36 per million after
- **Egress: $0 always** — viral traffic doesn't bill you

Compare with Vercel Blob at this scale: roughly **10× more expensive** for storage and you'd pay $0.15/GB for egress.

---

## Editing the Knowledge Base from your browser (no coding required)

The site has a built-in editor that saves directly to GitHub. Once set up, you just click **+ Add entry** and fill out a form — the site commits to your repo for you, and GitHub Pages republishes within ~60 seconds.

### One-time setup (~3 minutes)

1. Visit the live site and open the **Knowledge Base** tab.
2. Click **+ Add entry** (or the gear ⚙ icon). The setup wizard opens.
3. Follow the on-screen steps. You'll need to:
   - Create a **fine-grained personal access token** at <https://github.com/settings/personal-access-tokens/new>
   - Repository access: **Only select repositories** → pick the Ecref repo
   - Repository permissions → **Contents: Read and write**
   - Click "Generate token," copy the token (starts with `github_pat_`)
   - Paste it into the wizard
   - Choose a password (use the same one as your other gates for convenience)
4. The wizard tests the token and stores it encrypted in your browser. Done.

### Adding / editing / deleting

- **+ Add entry** in the toolbar opens the editor.
- Expand any card → **Edit** button at the bottom right.
- The Edit modal has a **Delete** button (with a confirmation prompt).
- Images can be dragged into the form — they upload to `images/` in your repo on save.

### Behind the scenes

- Your token is encrypted at rest with your password (PBKDF2 → AES-GCM, same primitives as the URL gates) and stored in `localStorage`.
- The token is decrypted in memory only once per browser session, the first time you click Add/Edit.
- Saves use the GitHub Contents API: image uploads first, then a JSON update commit.
- Optimistic UI — the entry appears in your KB immediately; the commit happens in the background and a toast confirms once GitHub accepted it.

### When something goes wrong

- **"Token rejected"** — copy/paste error. Generate a new token and re-do setup (gear ⚙ button).
- **"Token lacks the right permissions"** — recreate the token with Contents: Read **and write**.
- **"Repo not found"** — the token doesn't include this repo in its scope. Recreate it and pick the right repo under "Only select repositories."
- **Setup fails with "cannot detect your repo"** — you're previewing locally. Deploy first, then run setup from the live GitHub Pages URL.
- **Token expired** — fine-grained tokens have an expiration (you picked it during setup). Just run setup again with a fresh token.
- **Lost your password** — click ⚙, click through to re-setup. This overwrites the encrypted token; you'll need to paste a new token too.

### If your token leaks

Revoke it immediately at <https://github.com/settings/tokens?type=beta>. Then run setup again with a fresh token. Old token = no longer works = no exposure beyond the moment it leaked.

### What the token CAN'T do

The fine-grained token is scoped to one repo with Contents permission only. It cannot delete the repo, change settings, access your other repos, or read your personal info. Worst case if leaked: someone could edit/add/delete files in this one repo.

---

## Updating the Knowledge Base by hand (`reference_data.json`)

If you'd rather edit the JSON directly (or the in-browser editor isn't available), each entry has this shape:

```json
{
  "id": "stable-kebab-case-slug",
  "data": "Title and clinical notes (first non-empty line becomes the card title)",
  "template": "Order set / treatment template",
  "imgs": "images/foo.png, https://example.com/bar.jpg",
  "category": "Cardiac",
  "tags": ["acs", "chest pain"],
  "links": [
    {"label": "CPSolvers schema: chest pain", "url": "https://clinicalproblemsolving.com/..."}
  ]
}
```

### Fields

- **`id`** — required, must be unique. Used as the stable key for favorites/recents. Use kebab-case (`acute-pancreatitis`).
- **`data`** — markdown-ish clinical content. First non-empty line is shown as the card title. Markdown tables (pipe-delimited) are auto-rendered.
- **`template`** — order set / assessment template. Has its own Copy button in the card.
- **`imgs`** — comma-separated. Local paths (`images/foo.png`) or external URLs. Image extensions are rendered as thumbnails with click-to-enlarge; non-image strings render as text/link.
  - **CPSolvers images:** put under `images/cpsolvers/<topic>.png` and the card will auto-caption them with attribution.
- **`category`** — one of: *Cardiac, Pulmonary, GI, Renal, ID, Neuro, Heme/Onc, Endo, Derm, Tox, MSK, Psych, OB/GYN, Other*.
- **`tags`** — array of free-text tags. Render as clickable chips on the card; clicking a chip adds it as a filter.
- **`links`** — array of `{label, url}` for an "External resources" section on the expanded card. Where CPSolvers / MDCalc / UpToDate deep links go.

### Adding a new entry

Append to `database` in `reference_data.json`:

```json
{
  "id": "pneumonia",
  "data": "pneumonia\n- Dx: CXR, CBC, blood culture, sputum culture",
  "template": "- CBC, CMP, blood cultures x2\n- CXR\n- CTX 1g IV q24h + azithro 500mg PO daily",
  "imgs": "",
  "category": "ID",
  "tags": ["sepsis", "abx"],
  "links": []
}
```

Don't forget the comma after the previous entry.

### Categorizing existing entries

Run a quick edit pass on `reference_data.json` — entries in the "Other" category and any obvious miscategorizations can be retagged by changing the `category` value. Tags can be expanded freely. The sidebar counts and category dots update automatically.

---

## Updating Dot Phrases (`dotphrases.txt`)

```
DOTPHRASE Phrase Name
@VARIABLE@-style content goes here.
Multiple lines allowed.
```

Blank line between phrases. Search bar filters by any text in the phrase.

---

## The password-gated tabs (Clinical Reasoning, Patients)

Both gates use real client-side encryption (PBKDF2 + AES-GCM via Web Crypto). The Google URLs are **never** present in plaintext in the deployed source — only ciphertext blobs in `script.js` under `const SECRETS`. Wrong password → decryption fails → no URL is ever revealed.

The two gates share one password (the SECRETS were encrypted together).

### Setting up / rotating the password / changing a URL

1. Open `tools/encrypt-urls.html` **locally** (double-click the file). It runs in your browser and never sends anything anywhere. This file is gitignored — never commit it.
2. Enter your new password (12+ characters recommended) and the two Google URLs.
3. Click **Encrypt**. Copy the generated `const SECRETS = { ... };` block.
4. Paste it into `script.js`, replacing the existing `SECRETS` constant near the top.
5. Commit `script.js`. The new ciphertext is what gets served from GitHub Pages.

### Security caveats — read this

- **Strength depends on password strength.** With a 12+ char password and 200,000 PBKDF2 iterations, brute-forcing is impractical. With a short or guessable password, it's not. Pick a good one.
- **Once unlocked in your browser**, the decrypted URL is loaded into the iframe — anyone shoulder-surfing can read it from there. That's unavoidable for any client-side gate.
- **The Google Sheet's own sharing setting still matters.** The encryption only hides the URL; if your sheet is set to "anyone with link can view/edit," anyone who learns the URL can access it. Use a long, hard-to-guess URL (Google's defaults are fine) and rotate it if leaked.
- **Do not store PHI** in the Patient sheet. Use de-identified initials, MRN-last-4, etc. — never names, DOB, full MRN, or other identifying detail. The site is not HIPAA-compliant infrastructure.

### Setting up the Patients tab for the first time

The bundled `SECRETS` ship with `patientsSheetUrl: null`, so the Patients gate shows "not configured yet" until you do this:

1. Create a Google Sheet with the columns you want (suggested: *Date | Initials | MRN-last4 | Age/Sex | Scenario | Status | Notes*).
2. Share it: "Anyone with the link — Editor."
3. Run `tools/encrypt-urls.html`, give it your password + both URLs, replace `SECRETS` in `script.js`, commit, push.

---

## The Reference tab

A nested table-of-contents tab that combines static antibiotic references with editable lists.

### Sections

| Section | Type | Editable? | Source |
|---|---|---|---|
| Antibiotics → Antibiotics guide | Static image | No | `docs/abx-guide-pages/page-1.jpg` (Northwestern guide) |
| Antibiotics → BugDrugDx | Embedded iframe | No | <https://bugdrugdx.com/> |
| Antibiotics → Abx Venn | Static image | No | `docs/abx_venn.png` |
| Antibiotics → UCI Antibiogram | Editable single image | Yes (EDITOR_PASSWORD) | KV section `uci-antibiogram` |
| Antibiotics → Antibiotics extras | Editable list (images / links) | Yes (EDITOR_PASSWORD) | KV section `abx-extras` |
| ConanLi UMD | External link card | No | <https://conanliumd.com/en-usd> (X-Frame-Options blocks embedding) |
| EBM articles | Editable list + daily pick | Yes (EDITOR_PASSWORD) | KV section `ebm` |
| UW Learning Objectives | Editable list | Yes (EDITOR_PASSWORD) | KV section `uw` |
| MKSAP Boards Basics | Editable list + daily pick | Yes (MKSAP_PASSWORD) | KV section `mksap` — separately gated |

### Daily pick

EBM and MKSAP each surface one item per day deterministically (hash of today's date → index into the list). Same item all day, rotates at local midnight. No backend state — purely client-side.

### Editing list items

- Open any editable section → click **Add** (or the edit button on an existing item).
- The modal supports a title, optional URL, markdown body, optional image upload (goes to R2 if configured, else fails with a toast), and tags.
- Saves go to `/api/list/<section>` (POST) or `/api/list/<section>/<id>` (PUT/DELETE).
- All writes require an editor password (`EDITOR_PASSWORD` for ebm/uw/abx-extras/uci-antibiogram, `MKSAP_PASSWORD` for mksap).

### MKSAP gate

The MKSAP section is gated by a **separate password** (default: `ElaineWR`). It works in two layers:

1. **Client-side gate** — decrypts a sentinel stored in `SECRETS.mksapSentinel` (`script.js`) to verify the password is right. Wrong password = decryption fails.
2. **Server-side bearer auth** — every read or write to `/api/list/mksap` requires `Authorization: Bearer <MKSAP_PASSWORD>`. The server uses `process.env.MKSAP_PASSWORD` for the comparison.

If `MKSAP_PASSWORD` is not set on the server, MKSAP API calls return 401. Set the env var in Vercel and redeploy.

The MKSAP password lives in `sessionStorage` once unlocked (cleared when the browser tab closes, or when you click **Lock**).

### Rotating the MKSAP password

1. Run `tools/encrypt-urls.html` locally → use it to encrypt the literal string `MKSAP_UNLOCKED` with the new password (or generate a fresh sentinel via the helper).
2. Replace `SECRETS.mksapSentinel` in `script.js` with the new ciphertext.
3. Update `MKSAP_PASSWORD` env var in Vercel to the new password.
4. Commit + redeploy.

Both layers must use the same password — the client uses it to unlock the UI, and sends it as the bearer token; the server uses it as the expected password.

### Editing the UWorld Flow Sheet TOC in-browser

Each entry in the UWorld sub-TOC has a pencil icon (visible on hover when the editor is unlocked). Clicking it opens a small modal where you can:

- Rename the entry (fix OCR misreads)
- Move it to a different category (existing category dropdown, or type a new category name)
- Reset to default (only shown if this entry is currently overridden)

Edits live in the KV section `uw-toc-overrides` — one record per overridden page, keyed by `p<page-number>`. The renderer fetches the base `uw-flowsheets-toc.json` plus the overrides, merges them (override wins per field), and renders. The orange dot next to an entry title means "this entry has been edited from the default."

Why an overrides layer instead of editing the base JSON directly? The base JSON is version-controlled in the repo and represents the OCR-generated defaults; if you re-run OCR (e.g., after improving the script), your manual edits aren't lost. Overrides survive any re-OCR. To wipe all overrides and start fresh: delete every item in the `uw-toc-overrides` KV section (or visit `/seed.html` and inspect — though the seed tool only manages the main KB store right now).

### Adding new reference sections (developer)

To add a new editable list section (e.g., "Procedure videos"):

1. Add the section to the allowlists in `api/list/[section].js` and `api/list/[section]/[id].js`.
2. Add an entry to `REFERENCE_TOC` in `script.js` (`type: 'list'` with `section: 'your-section-name'`).
3. Optionally add `dailyPick: true` to surface a daily item.

To add a new static section (image, embed, etc.):

1. Add a `REFERENCE_TOC` entry with `type` of `poster`, `embed`, or `external`.

---

## Local preview

```sh
python3 -m http.server 8000
# open http://localhost:8000
```

---

## Repo layout

```
.
├── index.html              # Page structure + tabs
├── script.js               # KB renderer, secure gate, dot phrases, image modal
├── styles.css              # Bootstrap + custom (KB sidebar/cards, gate, etc.)
├── reference_data.json     # 425 KB entries with id/category/tags/links
├── dotphrases.txt          # Documentation templates
├── images/                 # Reference images (algorithms, tables, schemas)
├── tools/                  # LOCAL ONLY — gitignored
│   └── encrypt-urls.html   # Run locally to generate SECRETS
└── .gitignore
```

**Last Updated:** May 2026
**Version:** 2026.6
