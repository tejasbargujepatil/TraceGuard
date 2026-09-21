// lib/scanners/gcp/index.ts
export const GCP_SERVICE_KEYS = ['gcs', 'gcpiam', 'compute', 'cloudsql', 'bigquery', 'functions', 'gke', 'kms', 'logging'] as const;
export type GCPServiceKey = typeof GCP_SERVICE_KEYS[number];
