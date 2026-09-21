// app/api/approve/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const { investigationDocId, action, approvedBy, rejectionReason } = await req.json();

    if (!investigationDocId || !action) {
      return NextResponse.json({ error: 'investigationDocId and action are required' }, { status: 400 });
    }

    if (!process.env.SANITY_PROJECT_ID && !process.env.NEXT_PUBLIC_SANITY_PROJECT_ID) {
      return NextResponse.json({ error: 'Sanity not configured' }, { status: 503 });
    }

    if (!process.env.SANITY_API_TOKEN) {
      return NextResponse.json({ error: 'SANITY_API_TOKEN required for write operations' }, { status: 503 });
    }

    const { updateInvestigationStatus } = await import('@/lib/sanity/queries');

    const newStatus = action === 'approve' ? 'approved' : 'rejected';
    await updateInvestigationStatus(investigationDocId, newStatus, {
      approvedBy: approvedBy || 'Security Team',
      approvedAt: new Date().toISOString(),
      rejectionReason: action === 'reject' ? rejectionReason : undefined,
    });

    return NextResponse.json({ success: true, status: newStatus });
  } catch (err) {
    console.error('[/api/approve]', err);
    const message = err instanceof Error ? err.message : 'Approval failed';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
