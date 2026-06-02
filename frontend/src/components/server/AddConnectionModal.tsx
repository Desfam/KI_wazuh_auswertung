import { useState } from 'react';
import { X } from 'lucide-react';
import type { ServerConnectionInput, ServerProtocol, ServerAuthType } from '../../types';

type Props = {
  initial?: Partial<ServerConnectionInput>;
  onSave: (data: ServerConnectionInput) => void;
  onClose: () => void;
  title?: string;
};

const PROTOCOLS: ServerProtocol[] = ['ssh', 'rdp', 'winrm'];

export function AddConnectionModal({ initial, onSave, onClose, title = 'Add Connection' }: Props) {
  const [name, setName]       = useState(initial?.name ?? '');
  const [hostname, setHostname] = useState(initial?.hostname ?? '');
  const [ip, setIp]           = useState(initial?.ip ?? '');
  const [protocol, setProtocol] = useState<ServerProtocol>((initial?.protocol as ServerProtocol) ?? 'ssh');
  const [port, setPort]       = useState(initial?.port ?? (protocol === 'rdp' ? 3389 : 22));
  const [username, setUsername] = useState(initial?.username ?? '');
  const [authType, setAuthType] = useState<ServerAuthType>((initial?.auth_type as ServerAuthType) ?? 'agent');
  const [keyRef, setKeyRef]   = useState(initial?.key_ref ?? '');
  const [os, setOs]           = useState(initial?.os ?? '');
  const [tags, setTags]       = useState((initial?.tags ?? []).join(', '));
  const [favorite, setFavorite] = useState(initial?.favorite ?? false);
  const [mac, setMac]         = useState(initial?.mac ?? '');
  const [notes, setNotes]     = useState(initial?.notes ?? '');
  const [error, setError]     = useState('');

  function handleProtocolChange(p: ServerProtocol) {
    setProtocol(p);
    setPort(p === 'rdp' ? 3389 : p === 'winrm' ? 5985 : 22);
  }

  function handleSave() {
    if (!name.trim()) { setError('Name is required.'); return; }
    if (!hostname.trim() && !ip.trim()) { setError('Hostname or IP is required.'); return; }
    onSave({
      name: name.trim(),
      hostname: hostname.trim(),
      ip: ip.trim(),
      protocol,
      port: Number(port),
      username: username.trim(),
      auth_type: authType,
      key_ref: keyRef.trim(),
      os: os.trim(),
      tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      favorite,
      mac: mac.trim(),
      notes: notes.trim(),
    });
  }

  const labelCls = 'block text-[10px] font-semibold uppercase tracking-wider mb-1';
  const inputCls = 'w-full rounded px-2 py-1.5 text-[12px] outline-none focus:ring-1 focus:ring-cyan-500/50';
  const inp = { style: { background: 'var(--soc-sidebar-accent)', color: 'var(--soc-fg)', border: '1px solid var(--soc-border)' } };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="rounded-lg shadow-2xl w-[520px] max-h-[90vh] overflow-y-auto"
        style={{ background: 'var(--soc-sidebar)', border: '1px solid var(--soc-border)' }}>
        <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: 'var(--soc-border)' }}>
          <span className="font-semibold text-sm">{title}</span>
          <button type="button" onClick={onClose}><X size={16} /></button>
        </div>

        <div className="p-4 space-y-3">
          {error && <div className="text-[11px] text-red-400 bg-red-500/10 rounded px-3 py-2">{error}</div>}

          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Name *</label>
              <input className={inputCls} {...inp} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. prod-web-01" />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Hostname</label>
              <input className={inputCls} {...inp} value={hostname} onChange={e => setHostname(e.target.value)} placeholder="server.example.com" />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>IP</label>
              <input className={inputCls} {...inp} value={ip} onChange={e => setIp(e.target.value)} placeholder="10.0.0.1" />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Protocol</label>
              <select className={inputCls} {...inp} value={protocol} onChange={e => handleProtocolChange(e.target.value as ServerProtocol)}>
                {PROTOCOLS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Port</label>
              <input className={inputCls} {...inp} type="number" value={port} onChange={e => setPort(Number(e.target.value))} />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>OS</label>
              <input className={inputCls} {...inp} value={os} onChange={e => setOs(e.target.value)} placeholder="linux / windows" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Username</label>
              <input className={inputCls} {...inp} value={username} onChange={e => setUsername(e.target.value)} placeholder="admin" />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Auth Type</label>
              <select className={inputCls} {...inp} value={authType} onChange={e => setAuthType(e.target.value as ServerAuthType)}>
                <option value="none">None</option>
                <option value="agent">SSH Agent</option>
                <option value="key_ref">Key File</option>
                <option value="credential_ref">Credential Ref</option>
              </select>
            </div>
          </div>

          {authType === 'key_ref' && (
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Key File Path</label>
              <input className={inputCls} {...inp} value={keyRef} onChange={e => setKeyRef(e.target.value)} placeholder="~/.ssh/id_ed25519" />
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Tags (comma-separated)</label>
              <input className={inputCls} {...inp} value={tags} onChange={e => setTags(e.target.value)} placeholder="prod, linux, web" />
            </div>
            <div>
              <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>MAC (for WoL)</label>
              <input className={inputCls} {...inp} value={mac} onChange={e => setMac(e.target.value)} placeholder="AA:BB:CC:DD:EE:FF" />
            </div>
          </div>

          <div>
            <label className={labelCls} style={{ color: 'var(--soc-muted-fg)' }}>Notes</label>
            <textarea className={`${inputCls} resize-none`} {...inp} rows={2} value={notes} onChange={e => setNotes(e.target.value)} />
          </div>

          <div className="flex items-center gap-2">
            <input type="checkbox" id="fav-check" checked={favorite} onChange={e => setFavorite(e.target.checked)} />
            <label htmlFor="fav-check" className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>Mark as favorite</label>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t" style={{ borderColor: 'var(--soc-border)' }}>
          <button type="button" onClick={onClose}
            className="px-3 py-1.5 rounded text-[11px]" style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
            Cancel
          </button>
          <button type="button" onClick={handleSave}
            className="px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white">
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
