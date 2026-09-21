// Sanity client configuration
// Used server-side for the investigation agent

import { createClient } from '@sanity/client';

const projectId = process.env.SANITY_PROJECT_ID || process.env.NEXT_PUBLIC_SANITY_PROJECT_ID || '';
const dataset = process.env.SANITY_DATASET || process.env.NEXT_PUBLIC_SANITY_DATASET || 'production';
const apiVersion = process.env.SANITY_API_VERSION || '2024-01-01';

// Server-side authenticated client (for writes and agent queries)
export const sanityClient = createClient({
  projectId: projectId || 'placeholder',  // Sanity requires non-empty string; we guard calls upstream
  dataset,
  apiVersion,
  token: process.env.SANITY_API_TOKEN,
  useCdn: false, // Always fresh data for security investigations
});

// Public read-only client (for client-side rendering via next-sanity)
export const publicSanityClient = createClient({
  projectId: projectId || 'placeholder',
  dataset,
  apiVersion,
  useCdn: true,
});
