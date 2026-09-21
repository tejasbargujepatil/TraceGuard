// lib/scanners/gcp/auth.ts
// GCP service account JWT authentication — no external dependencies.

import { createSign } from 'crypto';
import type { GCPCredentials } from '../types';

interface TokenCache {
  token: string;
  expiresAt: number;
}

const cache = new Map<string, TokenCache>();

export async function getGCPAccessToken(creds: GCPCredentials): Promise<string> {
  const cacheKey = creds.client_email;
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: creds.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform.read-only',
    aud: creds.token_uri,
    exp: now + 3600,
    iat: now,
  };

  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${body}`);
  const signature = signer.sign(creds.private_key, 'base64url');
  const jwt = `${header}.${body}.${signature}`;

  const response = await fetch(creds.token_uri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`GCP token error: ${response.status} ${text}`);
  }

  const data = await response.json() as { access_token: string; expires_in: number };
  const expiresAt = Date.now() + (data.expires_in - 30) * 1000;
  cache.set(cacheKey, { token: data.access_token, expiresAt });
  return data.access_token;
}

export async function gcpFetch<T>(url: string, token: string): Promise<T> {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`GCP API ${res.status}: ${url} — ${text.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}
