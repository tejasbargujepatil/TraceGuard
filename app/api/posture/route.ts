// app/api/posture/route.ts
import { NextResponse } from 'next/server';

const EMPTY_POSTURE = {
  totalFindings: 0,
  criticalFindings: 0,
  highFindings: 0,
  mediumFindings: 0,
  lowFindings: 0,
  openFindings: 0,
  openInvestigations: 0,
  totalPolicies: 0,
  evidenceSources: 0,
};

export async function GET() {
  try {
    if (!process.env.SANITY_PROJECT_ID && !process.env.NEXT_PUBLIC_SANITY_PROJECT_ID) {
      return NextResponse.json({ ...EMPTY_POSTURE, error: 'Sanity not configured' });
    }
    const { getSecurityPosture } = await import('@/lib/sanity/queries');
    const posture = await getSecurityPosture();
    return NextResponse.json(posture);
  } catch (err) {
    console.error('[/api/posture]', err);
    return NextResponse.json(EMPTY_POSTURE);
  }
}
