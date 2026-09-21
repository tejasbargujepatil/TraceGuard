// lib/scanners/credentials.ts
// AES-256-GCM encryption for cloud credentials stored in Sanity.
// The master key lives in CREDENTIAL_ENCRYPTION_KEY (env var only, never in Sanity).

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import type { EncryptedCredential, CloudCredentials } from './types';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits

function getMasterKey(): Buffer {
  const hex = process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error(
      'CREDENTIAL_ENCRYPTION_KEY must be a 64-character hex string (32 bytes). ' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypt cloud credentials for storage in Sanity.
 * Returns an EncryptedCredential object (iv + tag + ciphertext, all hex-encoded).
 */
export function encryptCredentials(credentials: CloudCredentials): EncryptedCredential {
  const key = getMasterKey();
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const plaintext = JSON.stringify(credentials);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
  };
}

/**
 * Decrypt cloud credentials retrieved from Sanity.
 */
export function decryptCredentials(encrypted: EncryptedCredential): CloudCredentials {
  const key = getMasterKey();
  const iv = Buffer.from(encrypted.iv, 'hex');
  const tag = Buffer.from(encrypted.tag, 'hex');
  const data = Buffer.from(encrypted.data, 'hex');

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8')) as CloudCredentials;
}

/**
 * Validate that we can read from an AWS account with the given credentials.
 * Returns { valid: true } or { valid: false, error: string }.
 */
export async function validateAWSCredentials(
  credentials: import('./types').AWSCredentials
): Promise<{ valid: boolean; accountId?: string; error?: string }> {
  try {
    const { STSClient, GetCallerIdentityCommand } = await import('@aws-sdk/client-sts');
    const sts = new STSClient({
      region: credentials.region,
      credentials: {
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
        sessionToken: credentials.sessionToken,
      },
    });
    const result = await sts.send(new GetCallerIdentityCommand({}));
    return { valid: true, accountId: result.Account };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}

/**
 * Validate GCP service account credentials.
 */
export async function validateGCPCredentials(
  credentials: import('./types').GCPCredentials
): Promise<{ valid: boolean; projectId?: string; error?: string }> {
  try {
    // Sign a JWT with the service account private key and exchange for a token
    const { createSign } = await import('crypto');
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: credentials.client_email, scope: 'https://www.googleapis.com/auth/cloud-platform.read-only', aud: credentials.token_uri, exp: now + 3600, iat: now };
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${body}`);
    const signature = signer.sign(credentials.private_key, 'base64url');
    const jwt = `${header}.${body}.${signature}`;

    const res = await fetch(credentials.token_uri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
    });
    if (!res.ok) { const t = await res.text(); throw new Error(`Token error: ${res.status} ${t}`); }
    return { valid: true, projectId: credentials.project_id };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}


/**
 * Load credentials for an account — either from env vars (credentialMode: 'env')
 * or by decrypting from Sanity (credentialMode: 'encrypted').
 */
export function loadEnvAWSCredentials(): import('./types').AWSCredentials | null {
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const region = process.env.AWS_REGION || 'us-east-1';
  if (!accessKeyId || !secretAccessKey) return null;
  return { accessKeyId, secretAccessKey, region, sessionToken: process.env.AWS_SESSION_TOKEN };
}

export function loadEnvGCPCredentials(): import('./types').GCPCredentials | null {
  const raw = process.env.GCP_SERVICE_ACCOUNT_JSON;
  if (!raw) return null;
  try {
    return JSON.parse(raw) as import('./types').GCPCredentials;
  } catch {
    return null;
  }
}

/** Generate a new random encryption key (for setup instructions) */
export function generateEncryptionKey(): string {
  return randomBytes(KEY_LENGTH).toString('hex');
}
