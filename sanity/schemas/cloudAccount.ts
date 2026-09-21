import { defineType, defineField } from 'sanity';

export const cloudAccount = defineType({
  name: 'cloudAccount',
  title: 'Cloud Account',
  type: 'document',
  fields: [
    defineField({ name: 'name', type: 'string', title: 'Account Name' }),
    defineField({ name: 'provider', type: 'string', title: 'Provider', options: { list: ['aws', 'gcp'] } }),
    defineField({ name: 'cloudAccountId', type: 'string', title: 'AWS Account ID / GCP Project ID' }),
    defineField({ name: 'regions', type: 'array', of: [{ type: 'string' }], title: 'Regions to Scan' }),
    defineField({ name: 'credentialMode', type: 'string', options: { list: ['encrypted', 'env'] } }),
    defineField({ name: 'encryptedCredential', type: 'string', title: 'Encrypted Credential Blob (AES-256-GCM JSON)' }),
    defineField({ name: 'status', type: 'string', options: { list: ['connected', 'scanning', 'error', 'disconnected'] } }),
    defineField({ name: 'lastScannedAt', type: 'datetime' }),
    defineField({ name: 'lastScanFindingCount', type: 'number' }),
    defineField({ name: 'lastScanCriticalCount', type: 'number' }),
    defineField({ name: 'lastScanHighCount', type: 'number' }),
    defineField({ name: 'errorMessage', type: 'string' }),
    defineField({ name: 'createdAt', type: 'datetime' }),
  ],
});
