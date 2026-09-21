import { NextResponse } from 'next/server';
import { sanityClient } from '@/lib/sanity/client';
import { decryptCredentials, loadEnvAWSCredentials, loadEnvGCPCredentials } from '@/lib/scanners/credentials';
import { runServiceScan } from '@/lib/scanners/engine';
import { ScanJob, CloudCredentials } from '@/lib/scanners/types';

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const body = await req.json();
    const { service } = body;

    if (!service) {
      return NextResponse.json({ error: 'Service is required' }, { status: 400 });
    }

    const account = await sanityClient.fetch(`*[_type == 'cloudAccount' && _id == $id][0]`, { id });
    if (!account) {
      return NextResponse.json({ error: 'Account not found' }, { status: 404 });
    }

    let credentials: CloudCredentials;

    if (account.credentialMode === 'env') {
      if (account.provider === 'aws') {
        const envCreds = loadEnvAWSCredentials();
        if (!envCreds) throw new Error('AWS credentials not found in env vars');
        credentials = envCreds;
      } else {
        const envCreds = loadEnvGCPCredentials();
        if (!envCreds) throw new Error('GCP credentials not found in env vars');
        credentials = envCreds;
      }
    } else {
      if (!account.encryptedCredential) {
        throw new Error('Encrypted credentials not found in account');
      }
      credentials = decryptCredentials(JSON.parse(account.encryptedCredential));
    }

    const job: ScanJob = {
      accountId: account._id,
      provider: account.provider,
      cloudAccountId: account.cloudAccountId,
      credentials,
      regions: account.regions || [],
      services: [service],
    };

    const result = await runServiceScan(job, service);

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
