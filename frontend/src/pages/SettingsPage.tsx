import { useState } from 'react';
import type { Connection, ConnectionTestResult } from '../types';

type SettingsPageProps = {
  connection: Connection;
  onChange: (connection: Connection) => void;
  onSave: () => void;
  onTest: () => void;
  testing: boolean;
  saving: boolean;
  testResult?: ConnectionTestResult | null;
};

type FieldProps = {
  label: string;
  value: string | number;
  type?: string;
  onChange: (value: string) => void;
};

function Field({ label, value, type = 'text', onChange }: FieldProps) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-[0.2em] text-slate">{label}</span>
      <input type={type} value={value} onChange={(event) => onChange(event.target.value)} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember" />
    </label>
  );
}

export function SettingsPage({ connection, onChange, onSave, onTest, testing, saving, testResult }: SettingsPageProps) {
  const [showSecrets, setShowSecrets] = useState(false);

  return (
    <div className="grid gap-6 xl:grid-cols-[1.2fr,0.8fr]">
      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate">Connections</p>
            <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Indexer, Manager and Ollama</h3>
          </div>
          <button type="button" className="rounded-2xl border border-ink/10 px-4 py-3 text-sm text-ink" onClick={() => setShowSecrets((value) => !value)}>
            {showSecrets ? 'Hide secrets' : 'Show secrets'}
          </button>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <Field label="Connection name" value={connection.name} onChange={(value) => onChange({ ...connection, name: value })} />
          <Field label="Lookback hours" value={connection.lookback_hours} type="number" onChange={(value) => onChange({ ...connection, lookback_hours: Number(value) })} />
          <Field label="Indexer URL" value={connection.indexer_url} onChange={(value) => onChange({ ...connection, indexer_url: value })} />
          <Field label="Indexer index pattern" value={connection.indexer_index_pattern} onChange={(value) => onChange({ ...connection, indexer_index_pattern: value })} />
          <Field label="Indexer user" value={connection.indexer_username} onChange={(value) => onChange({ ...connection, indexer_username: value })} />
          <Field label="Indexer password" type={showSecrets ? 'text' : 'password'} value={connection.indexer_password} onChange={(value) => onChange({ ...connection, indexer_password: value })} />
          <Field label="Manager URL" value={connection.manager_url || ''} onChange={(value) => onChange({ ...connection, manager_url: value })} />
          <Field label="Manager user" value={connection.manager_username || ''} onChange={(value) => onChange({ ...connection, manager_username: value })} />
          <Field label="Manager password" type={showSecrets ? 'text' : 'password'} value={connection.manager_password || ''} onChange={(value) => onChange({ ...connection, manager_password: value })} />
          <Field label="Ollama URL" value={connection.ollama_url} onChange={(value) => onChange({ ...connection, ollama_url: value })} />
          <Field label="Ollama model" value={connection.ollama_model} onChange={(value) => onChange({ ...connection, ollama_model: value })} />
        </div>

        <div className="mt-8 border-t border-ink/10 pt-6">
          <p className="text-xs uppercase tracking-[0.3em] text-slate">Remote VM Script</p>
          <h4 className="mt-2 font-['Space_Grotesk'] text-lg font-semibold text-ink">SSH trigger for the Wazuh VM</h4>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <label className="inline-flex items-center gap-2 text-sm text-slate md:col-span-2">
              <input type="checkbox" checked={connection.vm_enabled} onChange={(event) => onChange({ ...connection, vm_enabled: event.target.checked })} />
              Enable remote VM script execution
            </label>
            <Field label="VM host" value={connection.vm_host || ''} onChange={(value) => onChange({ ...connection, vm_host: value })} />
            <Field label="VM SSH port" value={connection.vm_port} type="number" onChange={(value) => onChange({ ...connection, vm_port: Number(value) })} />
            <Field label="VM username" value={connection.vm_username || ''} onChange={(value) => onChange({ ...connection, vm_username: value })} />
            <Field label="VM password" type={showSecrets ? 'text' : 'password'} value={connection.vm_password || ''} onChange={(value) => onChange({ ...connection, vm_password: value })} />
            <Field label="Remote script path" value={connection.vm_script_path} onChange={(value) => onChange({ ...connection, vm_script_path: value })} />
            <Field label="Remote Python path" value={connection.vm_python_path} onChange={(value) => onChange({ ...connection, vm_python_path: value })} />
            <Field label="Remote TXT report path" value={connection.vm_report_txt_path} onChange={(value) => onChange({ ...connection, vm_report_txt_path: value })} />
            <Field label="Remote JSON report path" value={connection.vm_report_json_path} onChange={(value) => onChange({ ...connection, vm_report_json_path: value })} />
          </div>
        </div>

        <div className="mt-8 border-t border-ink/10 pt-6">
          <p className="text-xs uppercase tracking-[0.3em] text-slate">Run Presets</p>
          <h4 className="mt-2 font-['Space_Grotesk'] text-lg font-semibold text-ink">Preconfigured checkboxes for app-triggered runs</h4>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <label className="block">
              <span className="text-xs uppercase tracking-[0.2em] text-slate">Default mode</span>
              <select value={connection.default_analysis_mode} onChange={(event) => onChange({ ...connection, default_analysis_mode: event.target.value as 'local' | 'vm-script' })} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember">
                <option value="local">Local backend analysis</option>
                <option value="vm-script">Remote VM script</option>
              </select>
            </label>
            <Field label="Default query size" value={connection.default_query_size} type="number" onChange={(value) => onChange({ ...connection, default_query_size: Number(value) })} />
            <label className="inline-flex items-center gap-2 text-sm text-slate">
              <input type="checkbox" checked={connection.default_only_windows} onChange={(event) => onChange({ ...connection, default_only_windows: event.target.checked, default_only_linux: event.target.checked ? false : connection.default_only_linux })} />
              Windows only
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-slate">
              <input type="checkbox" checked={connection.default_only_linux} onChange={(event) => onChange({ ...connection, default_only_linux: event.target.checked, default_only_windows: event.target.checked ? false : connection.default_only_windows })} />
              Linux only
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-slate">
              <input type="checkbox" checked={connection.default_include_noise} onChange={(event) => onChange({ ...connection, default_include_noise: event.target.checked })} />
              Include noise / benign patterns
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-slate">
              <input type="checkbox" checked={connection.default_run_ai} onChange={(event) => onChange({ ...connection, default_run_ai: event.target.checked })} />
              Run AI assessment
            </label>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button type="button" onClick={onSave} className="rounded-2xl bg-ember px-4 py-3 text-sm font-medium text-white" disabled={saving}>
            {saving ? 'Saving...' : 'Save connection'}
          </button>
          <button type="button" onClick={onTest} className="rounded-2xl border border-ink/10 px-4 py-3 text-sm font-medium text-ink" disabled={testing}>
            {testing ? 'Testing...' : 'Test connectivity'}
          </button>
          <label className="inline-flex items-center gap-2 text-sm text-slate">
            <input type="checkbox" checked={connection.verify_ssl} onChange={(event) => onChange({ ...connection, verify_ssl: event.target.checked })} />
            Verify SSL certificates
          </label>
        </div>
      </section>

      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">Connectivity</p>
        <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Last Test Result</h3>

        <div className="mt-5 space-y-4">
          <div className="rounded-2xl bg-shell/70 p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate">Indexer</p>
            <p className="mt-2 font-medium text-ink">{testResult?.indexer.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-2 text-sm text-slate">{testResult?.indexer.detail || 'No connectivity test executed yet.'}</p>
          </div>
          <div className="rounded-2xl bg-shell/70 p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate">Ollama</p>
            <p className="mt-2 font-medium text-ink">{testResult?.ollama.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-2 text-sm text-slate">{testResult?.ollama.detail || 'No connectivity test executed yet.'}</p>
          </div>
          <div className="rounded-2xl bg-shell/70 p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate">VM script</p>
            <p className="mt-2 font-medium text-ink">{testResult?.vm_script.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-2 text-sm text-slate">{testResult?.vm_script.detail || 'No VM script connectivity test executed yet.'}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
