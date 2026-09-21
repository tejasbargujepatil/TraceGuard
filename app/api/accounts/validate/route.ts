import { NextResponse } from 'next/server';
import { validateAWSCredentials, validateGCPCredentials } from '@/lib/scanners/credentials';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { provider, credentials } = body;

    if (!provider || !credentials) {
      return NextResponse.json({ error: 'Provider and credentials are required' }, { status: 400 });
    }

    if (provider === 'aws') {
      const result = await validateAWSCredentials(credentials);
      return NextResponse.json(result);
    } else if (provider === 'gcp') {
      const result = await validateGCPCredentials(credentials);
      return NextResponse.json(result);
    } else {
      return NextResponse.json({ error: 'Invalid provider' }, { status: 400 });
    }
  } catch (error) {
    return NextResponse.json({ valid: false, error: (error as Error).message }, { status: 500 });
  }
}
