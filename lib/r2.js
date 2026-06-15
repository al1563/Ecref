// Cloudflare R2 wrapper using the S3-compatible API.
// Required env vars:
//   R2_ACCOUNT_ID         your Cloudflare account ID
//   R2_ACCESS_KEY_ID      R2 API token access key
//   R2_SECRET_ACCESS_KEY  R2 API token secret
//   R2_BUCKET             bucket name (e.g. "ecref-images")
//   R2_PUBLIC_URL         public URL prefix (e.g. "https://pub-XXX.r2.dev"
//                         or your custom domain), NO trailing slash

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

let _client = null;

export function isR2Configured() {
    return !!(process.env.R2_ACCOUNT_ID
        && process.env.R2_ACCESS_KEY_ID
        && process.env.R2_SECRET_ACCESS_KEY
        && process.env.R2_BUCKET
        && process.env.R2_PUBLIC_URL);
}

function getClient() {
    if (_client) return _client;
    if (!isR2Configured()) throw new Error('R2 not configured (missing env vars)');
    _client = new S3Client({
        region: 'auto',
        endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY_ID,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
        },
    });
    return _client;
}

// Returns the public URL of the uploaded image.
export async function uploadImage({ key, contentBuffer, contentType }) {
    const client = getClient();
    await client.send(new PutObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: key,
        Body: contentBuffer,
        ContentType: contentType,
        CacheControl: 'public, max-age=31536000, immutable',
    }));
    return publicUrlFor(key);
}

// Builds the public URL for a given object key.
export function publicUrlFor(key) {
    const base = process.env.R2_PUBLIC_URL.replace(/\/+$/, '');
    return `${base}/${key}`;
}

// Returns a short-lived presigned PUT URL the client uploads directly to R2.
// Bypasses Vercel's 4.5 MB platform body limit. Default TTL 5 minutes —
// enough for a slow connection to push a multi-MB file without leaving the
// URL valid long enough to be useful if accidentally logged.
export async function presignPut({ key, contentType, expiresIn = 300 }) {
    const client = getClient();
    const cmd = new PutObjectCommand({
        Bucket: process.env.R2_BUCKET,
        Key: key,
        ContentType: contentType,
        CacheControl: 'public, max-age=31536000, immutable',
    });
    const uploadUrl = await getSignedUrl(client, cmd, { expiresIn });
    return { uploadUrl, publicUrl: publicUrlFor(key) };
}
