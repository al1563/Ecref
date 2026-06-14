// Safety net for the KV write path.
//
// Background: pasting an image into the rich-text editor inlines the bytes
// as `data:image/...;base64,...` inside the entry body. A single screenshot
// can add 500 KB+ to one entry. Multiple of these per entry pushed the
// `database` blob in Vercel KV past the 10 MB per-request ceiling and
// blocked saves. We added a client-side paste interceptor that uploads to
// R2 instead — this is the matching server check, so even an out-of-date
// client (or a future bug) can't bloat the DB again.
//
// We allow `data:image/...` inside the upload-image endpoint itself —
// that's how images legitimately reach the server. All other entry/list
// write paths reject payloads containing the marker.

const BASE64_IMG_MARKER = /data:image\/[a-z0-9+.\-]+;base64,/i;

export function containsInlineBase64Image(value) {
    if (value == null) return false;
    if (typeof value === 'string') return BASE64_IMG_MARKER.test(value);
    if (Array.isArray(value)) {
        for (const v of value) if (containsInlineBase64Image(v)) return true;
        return false;
    }
    if (typeof value === 'object') {
        for (const k of Object.keys(value)) {
            if (containsInlineBase64Image(value[k])) return true;
        }
    }
    return false;
}

// Returns true (and sends a 413 response) if `body` contains any inline
// base64 image data. Returns false otherwise. Callers should `return`
// immediately on true so the handler stops processing.
export function rejectIfBase64(body, res) {
    if (containsInlineBase64Image(body)) {
        res.status(413).json({
            error: 'Inline base64 images are not allowed in this payload. '
                 + 'Use /api/upload-image to store the image first, then '
                 + 'reference the returned URL in the entry body.',
        });
        return true;
    }
    return false;
}
