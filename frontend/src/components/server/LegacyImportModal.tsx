import { useState } from 'react';
import { X, Upload } from 'lucide-react';

type Props = {
  onImport: (format: 'json' | 'csv', data: string, autoLink: boolean) => void;
  onClose: () => void;
  importing?: boolean;
};

export function LegacyImportModal({ onImport, onClose, importing = false }: Props) {
  const [format, setFormat] = useState<'json' | 'csv'>('json');
  const [text, setText] = useState('');
  const [autoLink, setAutoLink] = useState(true);

  const inputCls = 'w-full rounded px-2 py-1.5 text-[12px] outline-none focus:ring-1 focus:ring-cyan-500/50';
  const inp = { style: { background: 'var(--soc-sidebar-accent)', color: 'var(--soc-fg)', border: '1px solid var(--soc-border)' } };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="rounded-lg shadow-2xl w-[560px]" style={{ background: 'var(--soc-sidebar)', border: '1px solid var(--soc-border)' }}>
        <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'var(--soc-border)' }}>
          <div>
            <div className="font-semibold text-sm">Import Legacy Connections</div>
            <div className="text-[10px] mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
              Paste JSON or CSV from the legacy SSH/RDP Manager. Passwords will NOT be imported.
            </div>
          </div>
          <button type="button" onClick={onClose}><X size={16} /></button>
        </div>

        <div className="p-4 space-y-3">
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Format</label>
              <select className={inputCls} {...inp} value={format} onChange={e => setFormat(e.target.value as 'json' | 'csv')}>
                <option value="json">JSON (legacy .json export)</option>
                <option value="csv">CSV (exported spreadsheet)</option>
              </select>
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                <input type="checkbox" checked={autoLink} onChange={e => setAutoLink(e.target.checked)} />
                Auto-link to Unified Hosts
              </label>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--soc-muted-fg)' }}>
              Paste {format.toUpperCase()} data
            </label>
            <textarea
              className={`${inputCls} resize-none font-mono text-[11px]`}
              {...inp}
              rows={12}
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder={format === 'json'
                ? '{"ssh": {"my-server": {"host": "10.0.0.1", "user": "admin", "port": "22", "tags": [], "favorite": false}}, "rdp": {}}'
                : 'name,hostname,ip,protocol,port,username,tags,favorite,mac\nmy-server,server.example.com,,ssh,22,admin,,false,'}
            />
          </div>

          <div className="rounded px-3 py-2 text-[11px]" style={{ background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)', color: 'rgba(234,179,8,0.8)' }}>
            ⚠ Passwords and private key material in the legacy export will be silently skipped.
            Set up SSH agent or key-based auth after import.
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t" style={{ borderColor: 'var(--soc-border)' }}>
          <button type="button" onClick={onClose}
            className="px-3 py-1.5 rounded text-[11px]" style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
            Cancel
          </button>
          <button
            type="button"
            disabled={!text.trim() || importing}
            onClick={() => onImport(format, text.trim(), autoLink)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40"
          >
            <Upload size={12} />
            {importing ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </div>
  );
}
