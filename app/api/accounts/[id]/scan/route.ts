import { NextResponse } from 'next/server';
import { sanityClient } from '@/lib/sanity/client';
import { decryptCredentials, loadEnvAWSCredentials, loadEnvGCPCredentials } from '@/lib/scanners/credentials';
import { runServiceScan, updateAccountScanStatus } from '@/lib/scanners/engine';
import { ScanJob, CloudCredentials } from '@/lib/scanners/types';

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const body = await req.json();
    const { service, isFirst, isFinal, runningTotal } = body;

    if (!service) {
      return NextResponse.json({ error: 'Service is required' }, { status: 400 });
    }

    const account = await sanityClient.fetch(`*[_type == 'cloudAccount' && _id == $id][0]`, { id });
    if (!account) {
      return NextResponse.json({ error: 'Account not found' }, { status: 404 });
    }

    // Mark account as scanning on the first service call
    if (isFirst) {
      await updateAccountScanStatus(id, 'scanning');
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

    // On the final service, update account status with totals
    if (isFinal) {
      const totalFindings = (runningTotal ?? 0) + result.findingCount;
      // Count critical/high from result findings
      const critical = result.findings.filter((f) => f.severity === 'critical').length;
      const high = result.findings.filter((f) => f.severity === 'high').length;
      await updateAccountScanStatus(id, 'connected', {
        total: totalFindings,
        critical,
        high,
      });
    }

    return NextResponse.json(result);
  } catch (error) {
    // On error, revert account status back to connected
    try {
      const { id } = await params;
      await updateAccountScanStatus(id, 'error', undefined, (error as Error).message);
    } catch { /* best effort */ }
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
