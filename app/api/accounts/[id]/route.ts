import { NextResponse } from 'next/server';
import { sanityClient } from '@/lib/sanity/client';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  try {
    const id = params.id;
    const account = await sanityClient.fetch(`*[_type == 'cloudAccount' && _id == $id][0]`, { id });
    if (!account) {
      return NextResponse.json({ error: 'Account not found' }, { status: 404 });
    }
    return NextResponse.json({ account });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  try {
    const id = params.id;
    await sanityClient.delete(id);
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
