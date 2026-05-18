// Cloudflare R2 wrapper using the S3-compatible API.
// Required env vars:
//   R2_ACCOUNT_ID         your Cloudflare account ID
//   R2_ACCESS_KEY_ID      R2 API token access key
//   R2_SECRET_ACCESS_KEY  R2 API token secret
//   R2_BUCKET             bucket name (e.g. "ecref-images")
//   R2_PUBLIC_URL         public URL prefix (e.g. "https://pub-XXX.r2.dev"
//                         or your custom domain), NO trailing slash

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

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
    const base = process.env.R2_PUBLIC_URL.replace(/\/+$/, '');
    return `${base}/${key}`;
}
