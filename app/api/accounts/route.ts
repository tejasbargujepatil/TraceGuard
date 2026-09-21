import { NextResponse } from 'next/server';
import { sanityClient } from '@/lib/sanity/client';
import { encryptCredentials } from '@/lib/scanners/credentials';

export async function GET() {
  try {
    const accounts = await sanityClient.fetch(`*[_type == 'cloudAccount'] | order(createdAt desc)`);
    return NextResponse.json({ accounts });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    if (!process.env.CREDENTIAL_ENCRYPTION_KEY) {
      return NextResponse.json({ error: 'CREDENTIAL_ENCRYPTION_KEY is not set on the server' }, { status: 500 });
    }

    const body = await req.json();
    const { name, provider, cloudAccountId, regions, credentialMode, credentials } = body;

    let encryptedCredential = '';
    if (credentialMode === 'encrypted' && credentials) {
      const encrypted = encryptCredentials(credentials);
      encryptedCredential = JSON.stringify(encrypted);
    }

    const doc = {
      _type: 'cloudAccount',
      name,
      provider,
      cloudAccountId,
      regions: regions || [],
      credentialMode,
      encryptedCredential,
      status: 'connected',
      createdAt: new Date().toISOString(),
    };

    const result = await sanityClient.create(doc);
    return NextResponse.json({ account: result });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
