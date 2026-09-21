// app/api/findings/route.ts
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    if (!process.env.SANITY_PROJECT_ID && !process.env.NEXT_PUBLIC_SANITY_PROJECT_ID) {
      return NextResponse.json({ findings: [], error: 'Sanity not configured' }, { status: 200 });
    }
    const { getAllFindings } = await import('@/lib/sanity/queries');
    const findings = await getAllFindings();
    return NextResponse.json({ findings });
  } catch (err) {
    console.error('[/api/findings]', err);
    const message = err instanceof Error ? err.message : 'Failed to fetch findings';
    return NextResponse.json({ findings: [], error: message }, { status: 200 });
  }
}
