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
      <span className="text-[10px] uppercase tracking-[0.2em]" style={{ color: 'var(--soc-muted-fg)' }}>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1.5 w-full rounded px-3 py-1.5 text-[12.5px] outline-none transition"
        style={{
          background: 'var(--soc-input)',
          border: '1px solid var(--soc-border)',
          color: 'var(--soc-foreground)',
        }}
      />
    </label>
  );
}

export function SettingsPage({ connection, onChange, onSave, onTest, testing, saving, testResult }: SettingsPageProps) {
  const [showSecrets, setShowSecrets] = useState(false);

  return (
    <div className="grid gap-4 xl:grid-cols-[1.2fr,0.8fr] h-full overflow-y-auto" style={{ padding: '12px' }}>
      <section className="rounded-lg p-4" style={{ background: 'var(--soc-panel)', border: '1px solid var(--soc-border)' }}>
        <div className="flex items-start justify-between gap-4 border-b pb-3" style={{ borderColor: 'var(--soc-border)' }}>
          <div>
            <p className="text-[10px] uppercase tracking-[0.3em]" style={{ color: 'var(--soc-muted-fg)' }}>Connections</p>
            <h3 className="mt-1 text-sm font-semibold" style={{ color: 'var(--soc-foreground)' }}>Indexer, Manager and Ollama</h3>
          </div>
          <button
            type="button"
            className="rounded px-3 py-1 text-[12px] transition"
            style={{ border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)', background: 'var(--soc-card)' }}
            onClick={() => setShowSecrets((value) => !value)}
          >
            {showSecrets ? 'Hide secrets' : 'Show secrets'}
          </button>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
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

        <div className="mt-5 border-t pt-4" style={{ borderColor: 'var(--soc-border)' }}>
          <p className="text-[10px] uppercase tracking-[0.3em]" style={{ color: 'var(--soc-muted-fg)' }}>Remote VM Script</p>
          <h4 className="mt-1 text-sm font-semibold" style={{ color: 'var(--soc-foreground)' }}>SSH trigger for the Wazuh VM</h4>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <label className="inline-flex items-center gap-2 text-[12px] md:col-span-2" style={{ color: 'var(--soc-muted-fg)' }}>
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

        <div className="mt-5 border-t pt-4" style={{ borderColor: 'var(--soc-border)' }}>
          <p className="text-[10px] uppercase tracking-[0.3em]" style={{ color: 'var(--soc-muted-fg)' }}>Run Presets</p>
          <h4 className="mt-1 text-sm font-semibold" style={{ color: 'var(--soc-foreground)' }}>Preconfigured checkboxes for app-triggered runs</h4>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <label className="block">
              <span className="text-[10px] uppercase tracking-[0.2em]" style={{ color: 'var(--soc-muted-fg)' }}>Default mode</span>
              <select
                value={connection.default_analysis_mode}
                onChange={(event) => onChange({ ...connection, default_analysis_mode: event.target.value as 'local' | 'vm-script' })}
                className="mt-1.5 w-full rounded px-3 py-1.5 text-[12.5px] outline-none transition"
                style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
              >
                <option value="local">Local backend analysis</option>
                <option value="vm-script">Remote VM script</option>
              </select>
            </label>
            <Field label="Default query size" value={connection.default_query_size} type="number" onChange={(value) => onChange({ ...connection, default_query_size: Number(value) })} />
            <label className="inline-flex items-center gap-2 text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
              <input type="checkbox" checked={connection.default_only_windows} onChange={(event) => onChange({ ...connection, default_only_windows: event.target.checked, default_only_linux: event.target.checked ? false : connection.default_only_linux })} />
              Windows only
            </label>
            <label className="inline-flex items-center gap-2 text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
              <input type="checkbox" checked={connection.default_only_linux} onChange={(event) => onChange({ ...connection, default_only_linux: event.target.checked, default_only_windows: event.target.checked ? false : connection.default_only_windows })} />
              Linux only
            </label>
            <label className="inline-flex items-center gap-2 text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
              <input type="checkbox" checked={connection.default_include_noise} onChange={(event) => onChange({ ...connection, default_include_noise: event.target.checked })} />
              Include noise / benign patterns
            </label>
            <label className="inline-flex items-center gap-2 text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
              <input type="checkbox" checked={connection.default_run_ai} onChange={(event) => onChange({ ...connection, default_run_ai: event.target.checked })} />
              Run AI assessment
            </label>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onSave}
            className="rounded px-3 py-1.5 text-[12.5px] font-medium text-white transition"
            style={{ background: 'var(--soc-primary)' }}
            disabled={saving}
          >
            {saving ? 'Saving...' : 'Save connection'}
          </button>
          <button
            type="button"
            onClick={onTest}
            className="rounded px-3 py-1.5 text-[12.5px] font-medium transition"
            style={{ border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)', background: 'var(--soc-card)' }}
            disabled={testing}
          >
            {testing ? 'Testing...' : 'Test connectivity'}
          </button>
          <label className="inline-flex items-center gap-2 text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
            <input type="checkbox" checked={connection.verify_ssl} onChange={(event) => onChange({ ...connection, verify_ssl: event.target.checked })} />
            Verify SSL certificates
          </label>
        </div>
      </section>

      <section className="rounded-lg p-4 h-fit" style={{ background: 'var(--soc-panel)', border: '1px solid var(--soc-border)' }}>
        <p className="text-[10px] uppercase tracking-[0.3em]" style={{ color: 'var(--soc-muted-fg)' }}>Connectivity</p>
        <h3 className="mt-1 text-sm font-semibold" style={{ color: 'var(--soc-foreground)' }}>Last Test Result</h3>

        <div className="mt-4 space-y-3">
          <div className="rounded p-3" style={{ background: 'var(--soc-card)', border: '1px solid var(--soc-border)' }}>
            <p className="text-[10px] uppercase tracking-[0.2em]" style={{ color: 'var(--soc-muted-fg)' }}>Indexer</p>
            <p className="mt-1 text-[12.5px] font-medium" style={{ color: testResult?.indexer.ok ? 'var(--soc-success)' : 'var(--soc-muted-fg)' }}>{testResult?.indexer.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{testResult?.indexer.detail || 'No connectivity test executed yet.'}</p>
          </div>
          <div className="rounded p-3" style={{ background: 'var(--soc-card)', border: '1px solid var(--soc-border)' }}>
            <p className="text-[10px] uppercase tracking-[0.2em]" style={{ color: 'var(--soc-muted-fg)' }}>Ollama</p>
            <p className="mt-1 text-[12.5px] font-medium" style={{ color: testResult?.ollama.ok ? 'var(--soc-success)' : 'var(--soc-muted-fg)' }}>{testResult?.ollama.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{testResult?.ollama.detail || 'No connectivity test executed yet.'}</p>
          </div>
          <div className="rounded p-3" style={{ background: 'var(--soc-card)', border: '1px solid var(--soc-border)' }}>
            <p className="text-[10px] uppercase tracking-[0.2em]" style={{ color: 'var(--soc-muted-fg)' }}>VM script</p>
            <p className="mt-1 text-[12.5px] font-medium" style={{ color: testResult?.vm_script.ok ? 'var(--soc-success)' : 'var(--soc-muted-fg)' }}>{testResult?.vm_script.ok ? 'Reachable' : 'Not tested / failed'}</p>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{testResult?.vm_script.detail || 'No VM script connectivity test executed yet.'}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
