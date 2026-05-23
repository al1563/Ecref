// Vercel KV (Upstash Redis) wrapper for the medical-reference database.
// Auto-discovers credentials from env vars set by Vercel's Marketplace
// integration (Upstash for Redis).

import { Redis } from '@upstash/redis';

const DB_KEY = 'database';
let _redis = null;

function getRedis() {
    if (!_redis) {
        // Throws if env vars are missing — caller catches & returns 503.
        _redis = Redis.fromEnv();
    }
    return _redis;
}

export async function getAllEntries() {
    const raw = await getRedis().get(DB_KEY);
    if (!raw) return [];
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
}

export async function setAllEntries(entries) {
    if (!Array.isArray(entries)) throw new Error('entries must be an array');
    await getRedis().set(DB_KEY, JSON.stringify(entries));
}

export async function addEntry(entry) {
    const entries = await getAllEntries();
    entries.push(entry);
    await setAllEntries(entries);
    return entry;
}

export async function updateEntry(id, patch) {
    const entries = await getAllEntries();
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return null;
    entries[idx] = { ...entries[idx], ...patch, id };
    await setAllEntries(entries);
    return entries[idx];
}

export async function deleteEntry(id) {
    const entries = await getAllEntries();
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return false;
    entries.splice(idx, 1);
    await setAllEntries(entries);
    return true;
}

export function isKvConfigured() {
    return !!(
        (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) ||
        (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN)
    );
}

// ---- Generic list storage (used by Reference tab: ebm, uw, abx-extras, mksap) ----

const LIST_PREFIX = 'ecref:list:';

export async function getList(section) {
    const raw = await getRedis().get(LIST_PREFIX + section);
    if (!raw) return [];
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
}

export async function setList(section, items) {
    if (!Array.isArray(items)) throw new Error('items must be an array');
    await getRedis().set(LIST_PREFIX + section, JSON.stringify(items));
}

export async function addListItem(section, item) {
    const items = await getList(section);
    items.push(item);
    await setList(section, items);
    return item;
}

export async function updateListItem(section, id, patch) {
    const items = await getList(section);
    const idx = items.findIndex(i => i.id === id);
    if (idx === -1) return null;
    items[idx] = { ...items[idx], ...patch, id };
    await setList(section, items);
    return items[idx];
}

export async function deleteListItem(section, id) {
    const items = await getList(section);
    const idx = items.findIndex(i => i.id === id);
    if (idx === -1) return false;
    items.splice(idx, 1);
    await setList(section, items);
    return true;
}
