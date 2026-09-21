'use client';

import { useState } from 'react';
import { X, ChevronRight, ChevronLeft, Loader2, CheckCircle, AlertCircle, Cloud } from 'lucide-react';
import type { AWSCredentials, GCPCredentials } from '@/lib/scanners/types';

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
  'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
  'ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1',
];

interface Props { open: boolean; onClose: () => void; onSuccess: () => void; }
type Step = 'provider' | 'credentials' | 'validate' | 'name' | 'saving';
type Provider = 'aws' | 'gcp';

interface ValidationResult { valid: boolean; accountId?: string; error?: string; }

export function AddAccountModal({ open, onClose, onSuccess }: Props) {
  const [step, setStep] = useState<Step>('provider');
  const [provider, setProvider] = useState<Provider>('aws');
  const [awsCreds, setAwsCreds] = useState({ accessKeyId: '', secretAccessKey: '', sessionToken: '', region: 'us-east-1' });
  const [gcpJson, setGcpJson] = useState('');
  const [regions, setRegions] = useState<string[]>(['us-east-1', 'us-west-2', 'eu-west-1']);
  const [name, setName] = useState('');
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  if (!open) return null;

  function resetAndClose() {
    setStep('provider'); setProvider('aws'); setValidation(null); setError('');
    setAwsCreds({ accessKeyId: '', secretAccessKey: '', sessionToken: '', region: 'us-east-1' });
    setGcpJson(''); setName(''); setSaving(false);
    onClose();
  }

  async function handleValidate() {
    setValidating(true); setValidation(null); setError('');
    try {
      let credentials: AWSCredentials | GCPCredentials;
      if (provider === 'aws') {
        if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) { setError('Access Key ID and Secret are required'); setValidating(false); return; }
        credentials = { accessKeyId: awsCreds.accessKeyId, secretAccessKey: awsCreds.secretAccessKey, sessionToken: awsCreds.sessionToken || undefined, region: awsCreds.region } as AWSCredentials;
      } else {
        if (!gcpJson.trim()) { setError('Service account JSON is required'); setValidating(false); return; }
        try { credentials = JSON.parse(gcpJson) as GCPCredentials; }
        catch { setError('Invalid JSON format'); setValidating(false); return; }
      }
      const res = await fetch('/api/accounts/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider, credentials }) });
      const data = await res.json() as ValidationResult;
      setValidation(data);
      if (data.valid) {
        if (!name) setName(provider === 'aws' ? `AWS ${data.accountId ?? ''}`.trim() : `GCP ${(credentials as GCPCredentials).project_id ?? ''}`.trim());
        setTimeout(() => setStep('name'), 800);
      }
    } catch (e) { setValidation({ valid: false, error: (e as Error).message }); }
    setValidating(false);
  }

  async function handleSave() {
    if (!name.trim()) { setError('Account name is required'); return; }
    setSaving(true); setError('');
    try {
      let credentials: AWSCredentials | GCPCredentials;
      if (provider === 'aws') { credentials = { accessKeyId: awsCreds.accessKeyId, secretAccessKey: awsCreds.secretAccessKey, sessionToken: awsCreds.sessionToken || undefined, region: awsCreds.region } as AWSCredentials; }
      else { credentials = JSON.parse(gcpJson) as GCPCredentials; }

      const res = await fetch('/api/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, provider, cloudAccountId: validation?.accountId ?? '', regions: provider === 'aws' ? regions : ['global'], credentialMode: 'encrypted', credentials }),
      });
      if (!res.ok) { const d = await res.json() as { error?: string }; throw new Error(d.error ?? 'Save failed'); }
      onSuccess(); resetAndClose();
    } catch (e) { setError((e as Error).message); setSaving(false); }
  }

  function toggleRegion(r: string) { setRegions(prev => prev.includes(r) ? prev.filter(x => x !== r) : [...prev, r]); }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-700 rounded-xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Connect Cloud Account</h2>
            <p className="text-sm text-slate-400 mt-0.5">Step {['provider','credentials','validate','name'].indexOf(step)+1} of 4</p>
          </div>
          <button onClick={resetAndClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"><X className="w-4 h-4" /></button>
        </div>

        <div className="p-6">
          {error && <div className="mb-4 p-3 rounded-lg bg-red-950/50 border border-red-800 text-red-300 text-sm flex items-center gap-2"><AlertCircle className="w-4 h-4 shrink-0" />{error}</div>}

          {/* Step 1: Provider */}
          {step === 'provider' && (
            <div className="space-y-3">
              <p className="text-sm text-slate-400 mb-4">Choose your cloud provider to get started.</p>
              {(['aws', 'gcp'] as Provider[]).map(p => (
                <button key={p} onClick={() => setProvider(p)} className={`w-full flex items-center gap-4 p-4 rounded-xl border-2 transition-all text-left ${provider === p ? 'border-blue-500 bg-blue-950/30' : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'}`}>
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-xl font-bold ${p === 'aws' ? 'bg-orange-950 text-orange-400' : 'bg-blue-950 text-blue-400'}`}>{p === 'aws' ? '☁' : '⬡'}</div>
                  <div>
                    <div className="font-medium text-slate-100">{p === 'aws' ? 'Amazon Web Services' : 'Google Cloud Platform'}</div>
                    <div className="text-xs text-slate-400 mt-0.5">{p === 'aws' ? 'Scan 20+ AWS services with IAM read-only credentials' : 'Scan 10+ GCP services with service account JSON'}</div>
                  </div>
                  {provider === p && <CheckCircle className="w-5 h-5 text-blue-400 ml-auto shrink-0" />}
                </button>
              ))}
            </div>
          )}

          {/* Step 2: Credentials */}
          {step === 'credentials' && (
            <div className="space-y-4">
              <p className="text-xs text-amber-400 bg-amber-950/30 border border-amber-800/50 rounded-lg p-3">🔒 Credentials are encrypted with AES-256-GCM before storage. The raw values are never readable in the database.</p>
              {provider === 'aws' ? (
                <>
                  <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Access Key ID *</label><input value={awsCreds.accessKeyId} onChange={e => setAwsCreds(p => ({ ...p, accessKeyId: e.target.value }))} placeholder="AKIAIOSFODNN7EXAMPLE" className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono" /></div>
                  <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Secret Access Key *</label><input type="password" value={awsCreds.secretAccessKey} onChange={e => setAwsCreds(p => ({ ...p, secretAccessKey: e.target.value }))} placeholder="••••••••••••••••••••••••••••••••••••••••" className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono" /></div>
                  <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Session Token (optional)</label><input value={awsCreds.sessionToken} onChange={e => setAwsCreds(p => ({ ...p, sessionToken: e.target.value }))} placeholder="For temporary credentials / STS" className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono" /></div>
                  <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Primary Region</label><select value={awsCreds.region} onChange={e => setAwsCreds(p => ({ ...p, region: e.target.value }))} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500">{AWS_REGIONS.map(r => <option key={r} value={r}>{r}</option>)}</select></div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1.5">Regions to Scan</label>
                    <div className="max-h-36 overflow-y-auto grid grid-cols-2 gap-1 bg-slate-800/50 rounded-lg p-2 border border-slate-700">
                      {AWS_REGIONS.map(r => (
                        <label key={r} className="flex items-center gap-2 cursor-pointer hover:bg-slate-700/50 rounded px-2 py-1">
                          <input type="checkbox" checked={regions.includes(r)} onChange={() => toggleRegion(r)} className="rounded" />
                          <span className="text-xs text-slate-300 font-mono">{r}</span>
                        </label>
                      ))}
                    </div>
                    <p className="text-xs text-slate-500 mt-1">{regions.length} region{regions.length !== 1 ? 's' : ''} selected</p>
                  </div>
                </>
              ) : (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">Service Account JSON *</label>
                  <textarea value={gcpJson} onChange={e => setGcpJson(e.target.value)} rows={10} placeholder={'{\n  "type": "service_account",\n  "project_id": "my-project",\n  "private_key_id": "...",\n  ...\n}'} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono resize-none" />
                  <p className="text-xs text-slate-500 mt-1">Paste the full contents of your service account JSON key file.</p>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Validate */}
          {step === 'validate' && (
            <div className="flex flex-col items-center py-8 gap-4">
              {validating ? (
                <><Loader2 className="w-10 h-10 text-blue-400 animate-spin" /><p className="text-slate-300 font-medium">Validating credentials…</p><p className="text-sm text-slate-500">Connecting to {provider === 'aws' ? 'AWS STS' : 'GCP token endpoint'}</p></>
              ) : validation?.valid ? (
                <><CheckCircle className="w-10 h-10 text-emerald-400" /><p className="text-slate-100 font-medium">Connection verified</p>{validation.accountId && <p className="text-sm text-slate-400">Account ID: <span className="text-slate-200 font-mono">{validation.accountId}</span></p>}</>
              ) : validation && !validation.valid ? (
                <><AlertCircle className="w-10 h-10 text-red-400" /><p className="text-slate-100 font-medium">Validation failed</p><p className="text-sm text-red-400 text-center max-w-xs">{validation.error}</p></>
              ) : null}
            </div>
          )}

          {/* Step 4: Name */}
          {step === 'name' && (
            <div className="space-y-4">
              <p className="text-sm text-slate-400">Give this account a friendly name for the dashboard.</p>
              <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Account Name *</label><input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. ACME Production AWS" className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500" autoFocus /></div>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700 text-sm space-y-1">
                <div className="flex justify-between"><span className="text-slate-400">Provider</span><span className="text-slate-200 uppercase font-medium">{provider}</span></div>
                {validation?.accountId && <div className="flex justify-between"><span className="text-slate-400">Account ID</span><span className="text-slate-200 font-mono text-xs">{validation.accountId}</span></div>}
                <div className="flex justify-between"><span className="text-slate-400">Regions</span><span className="text-slate-200">{regions.length} selected</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Credentials</span><span className="text-emerald-400">Encrypted (AES-256-GCM)</span></div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-slate-700">
          <button onClick={() => { setError(''); const steps: Step[] = ['provider','credentials','validate','name']; const i = steps.indexOf(step); if (i > 0) setStep(steps[i-1]); }} disabled={step === 'provider'} className="flex items-center gap-1.5 px-4 py-2 text-sm text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
            <ChevronLeft className="w-4 h-4" /> Back
          </button>

          <div className="flex gap-2">
            <button onClick={resetAndClose} className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors">Cancel</button>

            {step === 'provider' && <button onClick={() => setStep('credentials')} className="flex items-center gap-1.5 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Next <ChevronRight className="w-4 h-4" /></button>}
            {step === 'credentials' && <button onClick={() => { setStep('validate'); setTimeout(handleValidate, 100); }} className="flex items-center gap-1.5 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Validate <ChevronRight className="w-4 h-4" /></button>}
            {step === 'validate' && validation && !validation.valid && <button onClick={() => { setStep('validate'); setTimeout(handleValidate, 100); }} className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Retry</button>}
            {step === 'name' && <button onClick={handleSave} disabled={saving || !name.trim()} className="flex items-center gap-1.5 px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors">{saving ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : <><Cloud className="w-4 h-4" /> Add Account</>}</button>}
          </div>
        </div>
      </div>
    </div>
  );
}
