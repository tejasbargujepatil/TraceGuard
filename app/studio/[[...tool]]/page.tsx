// Sanity Studio embedded at /studio
// Judges can use this to inspect the structured content model

'use client';

import { NextStudio } from 'next-sanity/studio';
import config from '@/sanity/sanity.config';

export default function StudioPage() {
  return <NextStudio config={config} />;
}
