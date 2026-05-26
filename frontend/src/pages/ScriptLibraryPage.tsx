import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Edit3,
  FileCode2,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldOff,
  Terminal,
  Trash2,
  X,
  XCircle,
} from 'lucide-react';
import { createScript, deleteScript, getScripts, logAuditAction, runFetchWazuhEvents, runFetchEventsPerHost, updateScript } from '../services/api';
import type { FetchWazuhEventsResult, FetchEventsPerHostResult, HostFetchResult } from '../services/api';
import type { ScriptEntry } from '../types';

// ── helpers ──────────────────────────────────────────────────────────────────

function cx(...args: (string | false | null | undefined)[]): string {
  return args.filter(Boolean).join(' ');
}

function flag(v: number | undefined): boolean {
  return v === 1;
}

function riskColor(r: string): string {
  switch (r) {
    case 'critical': return 'text-red-400';
    case 'high':     return 'text-orange-400';
    case 'medium':   return 'text-yellow-400';
    case 'low':      return 'text-emerald-400';
    default:         return 'text-slate-400';
  }
}

function riskBadge(r: string): string {
  switch (r) {
    case 'critical': return 'bg-red-500/15 text-red-300 border border-red-500/30';
    case 'high':     return 'bg-orange-500/15 text-orange-300 border border-orange-500/30';
    case 'medium':   return 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
    case 'low':      return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30';
    default:         return 'bg-slate-500/15 text-slate-300 border border-slate-500/25';
  }
}

function platformBadge(p: string): string {
  switch (p) {
    case 'windows': return 'bg-blue-500/15 text-blue-300 border border-blue-500/25';
    case 'linux':   return 'bg-orange-400/15 text-orange-300 border border-orange-400/25';
    case 'both':    return 'bg-purple-500/15 text-purple-300 border border-purple-500/25';
    case 'network': return 'bg-teal-500/15 text-teal-300 border border-teal-500/25';
    default:        return 'bg-slate-500/15 text-slate-300 border border-slate-500/25';
  }
}

function fmtDate(iso: string): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

// ── EMPTY FORM ────────────────────────────────────────────────────────────────

const EMPTY_FORM: Partial<ScriptEntry> = {
  script_id: '',
  name: '',
  description: '',
  platform: 'windows',
  category: 'collection',
  executor: 'powershell',
  risk_level: 'low',
  requires_admin: 0,
  readonly: 1,
  dangerous: 0,
  enabled: 1,
  parameters_json: '{}',
  script_body: '',
};

// ── CATEGORIES ────────────────────────────────────────────────────────────────

const KNOWN_CATEGORIES = [
  'collection', 'system_state', 'persistence', 'users', 'network',
  'fim', 'authentication', 'process', 'malware', 'threat_intel', 'other',
];

const KNOWN_EXECUTORS = [
  'powershell', 'cmd', 'bash', 'python', 'wmi', 'api', 'ssh',
];

// ── CHIP helper ───────────────────────────────────────────────────────────────

function Chip({ label, variant }: { label: string; variant: 'ok' | 'warn' | 'danger' | 'muted' | 'disabled' }) {
  const cls: Record<string, string> = {
    ok:       'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25',
    warn:     'bg-yellow-500/15  text-yellow-300  border border-yellow-500/25',
    danger:   'bg-red-500/15     text-red-300     border border-red-500/25',
    muted:    'bg-slate-500/15   text-slate-400   border border-slate-500/20',
    disabled: 'bg-slate-700/40   text-slate-500   border border-slate-600/20',
  };
  return (
    <span className={cx('inline-block rounded px-1.5 py-0.5 text-[10px] font-bold whitespace-nowrap', cls[variant])}>
      {label}
    </span>
  );
}

// ── STAT CARD ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }: { label: string; value: number; sub?: string; accent?: string }) {
  return (
    <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] px-5 py-4">
      <p className="text-[11px] font-semibold uppercase tracking-widest text-white/40">{label}</p>
      <p className={cx('mt-1 text-3xl font-bold tabular-nums', accent ?? 'text-white/90')}>{value}</p>
      {sub && <p className="mt-0.5 text-[11px] text-white/35">{sub}</p>}
    </div>
  );
}

// ── SELECT helper ─────────────────────────────────────────────────────────────

function FilterSelect({ label, value, onChange, options }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[11px] text-white/35">{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="rounded border border-white/[0.09] bg-white/[0.04] px-2 py-1 text-[11px] text-white/75 focus:outline-none focus:border-cyan-500/50 appearance-none cursor-pointer"
      >
        {options.map(o => (
          <option key={o.value} value={o.value} style={{ background: '#0c1a27' }}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

// ── FORM FIELD ────────────────────────────────────────────────────────────────

function FormField({ label, children, warn }: { label: string; children: React.ReactNode; warn?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[11px] font-semibold uppercase tracking-wider text-white/45">{label}</label>
      {children}
      {warn && <p className="text-[10.5px] text-yellow-400/80 flex items-center gap-1"><AlertTriangle size={11} />{warn}</p>}
    </div>
  );
}

function FormInput({ value, onChange, placeholder, disabled }: {
  value: string; onChange: (v: string) => void; placeholder?: string; disabled?: boolean;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className="rounded border border-white/[0.09] bg-white/[0.04] px-3 py-1.5 text-[12px] text-white/85 placeholder-white/25 focus:outline-none focus:border-cyan-500/50 disabled:opacity-40"
    />
  );
}

function FormSelect({ value, onChange, options }: {
  value: string; onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="rounded border border-white/[0.09] bg-[#0c1a27] px-3 py-1.5 text-[12px] text-white/85 focus:outline-none focus:border-cyan-500/50"
    >
      {options.map(o => (
        <option key={o.value} value={o.value} style={{ background: '#0c1a27' }}>{o.label}</option>
      ))}
    </select>
  );
}

function FormToggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer select-none text-[12px] text-white/70">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cx(
          'relative inline-flex h-5 w-9 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none',
          checked ? 'bg-cyan-500' : 'bg-white/15'
        )}
      >
        <span className={cx('inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform', checked ? 'translate-x-4' : 'translate-x-0')} />
      </button>
      {label}
    </label>
  );
}

// ── MAIN COMPONENT ────────────────────────────────────────────────────────────

export function ScriptLibraryPage() {
  const [scripts, setScripts] = useState<ScriptEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // filters
  const [search, setSearch] = useState('');
  const [filterPlatform, setFilterPlatform] = useState('all');
  const [filterCategory, setFilterCategory] = useState('all');
  const [filterRisk, setFilterRisk] = useState('all');
  const [filterEnabled, setFilterEnabled] = useState('all');
  const [filterDangerous, setFilterDangerous] = useState('all');

  // sort
  const [sortCol, setSortCol] = useState<keyof ScriptEntry>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  // detail drawer
  const [selected, setSelected] = useState<ScriptEntry | null>(null);

  // create/edit form
  const [formOpen, setFormOpen] = useState(false);
  const [formMode, setFormMode] = useState<'create' | 'edit'>('create');
  const [formData, setFormData] = useState<Partial<ScriptEntry>>(EMPTY_FORM);
  const [formSaving, setFormSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // delete confirm
  const [deleteTarget, setDeleteTarget] = useState<ScriptEntry | null>(null);

  // runner panel (fetch_wazuh_events)
  const [runHours,  setRunHours]  = useState(72);
  const [runLimit,  setRunLimit]  = useState(1000);
  const [runHost,   setRunHost]   = useState('');
  const [runBusy,   setRunBusy]   = useState(false);
  const [runResult, setRunResult] = useState<FetchWazuhEventsResult | null>(null);
  const [runError,  setRunError]  = useState<string | null>(null);

  // runner panel (fetch_events_per_host)
  const [phHours,  setPhHours]  = useState(72);
  const [phLimit,  setPhLimit]  = useState(1000);
  const [phBusy,   setPhBusy]   = useState(false);
  const [phResult, setPhResult] = useState<FetchEventsPerHostResult | null>(null);
  const [phError,  setPhError]  = useState<string | null>(null);

  // ── fetch ──────────────────────────────────────────────────────────────────
  const fetchScripts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getScripts();
      setScripts(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load scripts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void fetchScripts(); }, [fetchScripts]);

  // ── derived categories from data ──────────────────────────────────────────
  const dynamicCategories = useMemo(() => {
    const cats = new Set(scripts.map(s => s.category).filter(Boolean));
    return Array.from(cats).sort();
  }, [scripts]);

  // ── filtered + sorted ─────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let list = scripts;
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.script_id.toLowerCase().includes(q) ||
        (s.description ?? '').toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q)
      );
    }
    if (filterPlatform !== 'all') list = list.filter(s => s.platform === filterPlatform);
    if (filterCategory !== 'all') list = list.filter(s => s.category === filterCategory);
    if (filterRisk !== 'all') list = list.filter(s => s.risk_level === filterRisk);
    if (filterEnabled === 'enabled') list = list.filter(s => flag(s.enabled));
    if (filterEnabled === 'disabled') list = list.filter(s => !flag(s.enabled));
    if (filterDangerous === 'safe') list = list.filter(s => !flag(s.dangerous));
    if (filterDangerous === 'dangerous') list = list.filter(s => flag(s.dangerous));

    return [...list].sort((a, b) => {
      const av = a[sortCol] ?? '';
      const bv = b[sortCol] ?? '';
      const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [scripts, search, filterPlatform, filterCategory, filterRisk, filterEnabled, filterDangerous, sortCol, sortDir]);

  // ── stat counts ──────────────────────────────────────────────────────────
  const totalCount    = scripts.length;
  const enabledCount  = scripts.filter(s => flag(s.enabled)).length;
  const readonlyCount = scripts.filter(s => flag(s.readonly)).length;
  const dangerCount   = scripts.filter(s => flag(s.dangerous)).length;

  // ── sort toggle ───────────────────────────────────────────────────────────
  function toggleSort(col: keyof ScriptEntry) {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
  }

  function SortIcon({ col }: { col: keyof ScriptEntry }) {
    if (sortCol !== col) return <ChevronDown size={11} className="opacity-25" />;
    return sortDir === 'asc' ? <ChevronUp size={11} className="text-cyan-400" /> : <ChevronDown size={11} className="text-cyan-400" />;
  }

  // ── open detail ──────────────────────────────────────────────────────────
  function openDetail(s: ScriptEntry) {
    setSelected(s);
    void logAuditAction({
      action_type: 'script_opened',
      source_page: 'script_library',
      details_json: { script_id: s.script_id, name: s.name } as Record<string, unknown>,
    }).catch(() => {});
  }

  // ── open create form ──────────────────────────────────────────────────────
  function openCreate() {
    setFormData({ ...EMPTY_FORM });
    setFormMode('create');
    setFormError(null);
    setFormOpen(true);
  }

  // ── open edit form ────────────────────────────────────────────────────────
  function openEdit(s: ScriptEntry) {
    setFormData({ ...s });
    setFormMode('edit');
    setFormError(null);
    setFormOpen(true);
    setSelected(null);
  }

  // ── duplicate ─────────────────────────────────────────────────────────────
  function openDuplicate(s: ScriptEntry) {
    setFormData({
      ...s,
      id: undefined as unknown as number,
      script_id: s.script_id + '_copy',
      name: s.name + ' (copy)',
      created_at: undefined as unknown as string,
      updated_at: undefined as unknown as string,
    });
    setFormMode('create');
    setFormError(null);
    setFormOpen(true);
    setSelected(null);
    void logAuditAction({
      action_type: 'script_duplicated',
      source_page: 'script_library',
      details_json: { original_script_id: s.script_id } as Record<string, unknown>,
    }).catch(() => {});
  }

  // ── save form ─────────────────────────────────────────────────────────────
  async function handleSave() {
    if (!formData.script_id?.trim()) { setFormError('script_id is required'); return; }
    if (!formData.name?.trim())      { setFormError('name is required'); return; }
    if (!formData.platform)          { setFormError('platform is required'); return; }
    if (!formData.executor?.trim())  { setFormError('executor is required'); return; }

    setFormSaving(true);
    setFormError(null);
    try {
      if (formMode === 'create') {
        await createScript(formData);
        void logAuditAction({
          action_type: 'script_created',
          source_page: 'script_library',
          details_json: { script_id: formData.script_id, name: formData.name } as Record<string, unknown>,
        }).catch(() => {});
      } else {
        await updateScript(formData.script_id!, formData);
        void logAuditAction({
          action_type: 'script_updated',
          source_page: 'script_library',
          details_json: { script_id: formData.script_id, name: formData.name } as Record<string, unknown>,
        }).catch(() => {});
      }
      setFormOpen(false);
      await fetchScripts();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setFormSaving(false);
    }
  }

  // ── delete ────────────────────────────────────────────────────────────────
  async function handleDelete(s: ScriptEntry) {
    try {
      await deleteScript(s.script_id);
      void logAuditAction({
        action_type: 'script_deleted',
        source_page: 'script_library',
        details_json: { script_id: s.script_id, name: s.name } as Record<string, unknown>,
      }).catch(() => {});
      setDeleteTarget(null);
      setSelected(null);
      await fetchScripts();
    } catch (e) {
      console.error('Delete failed', e);
    }
  }

  // ── formData helpers ──────────────────────────────────────────────────────
  function setField<K extends keyof ScriptEntry>(key: K, value: ScriptEntry[K]) {
    setFormData(prev => ({ ...prev, [key]: value }));
  }

  const formDangerous = flag(formData.dangerous);
  const formReadonly  = flag(formData.readonly);
  const showSafetyWarn = formDangerous || !formReadonly;

  // ── RENDER ────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col" style={{ fontFamily: "'Inter', 'Space Grotesk', system-ui, sans-serif" }}>

      {/* ── HEADER ── */}
      <div
        className="flex items-start justify-between border-b px-6 py-5"
        style={{ borderColor: 'rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.015)' }}
      >
        <div>
          <div className="flex items-center gap-2">
            <Terminal size={18} className="text-cyan-400" />
            <h1 className="text-lg font-bold" style={{ color: 'var(--soc-foreground, #e8eaed)' }}>Script Library</h1>
          </div>
          <p className="mt-0.5 text-[12px]" style={{ color: 'var(--soc-muted-fg, #6b7f8e)' }}>
            Read-only triage script catalog for future Tactical RMM / SSH / RDP execution
          </p>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <button
            type="button"
            onClick={() => void fetchScripts()}
            className="flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-[12px] text-white/60 hover:bg-white/[0.07] hover:text-white/80 transition"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
          <button
            type="button"
            onClick={openCreate}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-[12px] text-cyan-300 hover:bg-cyan-500/15 transition"
          >
            <Plus size={13} />
            New Script
          </button>
        </div>
      </div>

      {/* ── STAT CARDS ── */}
      <div className="grid grid-cols-2 gap-3 px-6 py-4 sm:grid-cols-4">
        <StatCard label="Total Scripts"    value={totalCount}    sub="in catalog" />
        <StatCard label="Enabled"          value={enabledCount}  sub="active in catalog"       accent="text-emerald-300" />
        <StatCard label="Read-only"        value={readonlyCount} sub="safe for Phase 1"         accent="text-cyan-300" />
        <StatCard label="Dangerous"        value={dangerCount}   sub="disabled — Phase 2+"      accent="text-red-400" />
      </div>

      {/* ── FILTER BAR ── */}
      <div
        className="flex flex-wrap items-center gap-3 border-b px-6 py-3"
        style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.12)' }}
      >
        {/* Search */}
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/30 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search scripts…"
            className="rounded border border-white/[0.09] bg-white/[0.04] pl-7 pr-3 py-1 text-[12px] text-white/80 placeholder-white/25 focus:outline-none focus:border-cyan-500/50 w-48"
          />
          {search && (
            <button type="button" onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60">
              <X size={12} />
            </button>
          )}
        </div>

        <FilterSelect
          label="Platform"
          value={filterPlatform}
          onChange={setFilterPlatform}
          options={[
            { value: 'all', label: 'All Platforms' },
            { value: 'windows', label: 'Windows' },
            { value: 'linux',   label: 'Linux' },
            { value: 'both',    label: 'Both' },
            { value: 'network', label: 'Network' },
          ]}
        />

        <FilterSelect
          label="Category"
          value={filterCategory}
          onChange={setFilterCategory}
          options={[
            { value: 'all', label: 'All Categories' },
            ...dynamicCategories.map(c => ({ value: c, label: c })),
          ]}
        />

        <FilterSelect
          label="Risk"
          value={filterRisk}
          onChange={setFilterRisk}
          options={[
            { value: 'all',      label: 'All Risk' },
            { value: 'low',      label: 'Low' },
            { value: 'medium',   label: 'Medium' },
            { value: 'high',     label: 'High' },
            { value: 'critical', label: 'Critical' },
          ]}
        />

        <FilterSelect
          label="State"
          value={filterEnabled}
          onChange={setFilterEnabled}
          options={[
            { value: 'all',      label: 'All States' },
            { value: 'enabled',  label: 'Enabled' },
            { value: 'disabled', label: 'Disabled' },
          ]}
        />

        <FilterSelect
          label="Safety"
          value={filterDangerous}
          onChange={setFilterDangerous}
          options={[
            { value: 'all',       label: 'All Safety' },
            { value: 'safe',      label: 'Safe (read-only)' },
            { value: 'dangerous', label: 'Dangerous' },
          ]}
        />

        <span className="ml-auto text-[11px] text-white/30">
          {filtered.length} of {totalCount}
        </span>
      </div>

      {/* ── MAIN AREA ── */}
      <div className="flex min-h-0 flex-1 overflow-hidden">

        {/* ── TABLE ── */}
        <div className={cx('flex min-h-0 flex-1 flex-col overflow-auto', selected ? 'hidden lg:flex' : '')}>
          {loading ? (
            <div className="flex flex-1 items-center justify-center text-[12px] text-white/30">
              <RefreshCw size={14} className="mr-2 animate-spin text-cyan-400" />
              Loading scripts…
            </div>
          ) : error ? (
            <div className="flex flex-1 items-center justify-center gap-2 text-[12px] text-red-400">
              <XCircle size={14} />
              {error}
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-1 items-center justify-center text-[12px] text-white/25">
              No scripts match the current filters.
            </div>
          ) : (
            <table className="w-full text-[12px]" style={{ borderCollapse: 'separate', borderSpacing: 0 }}>
              <thead>
                <tr style={{ background: 'rgba(0,0,0,0.25)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  {(
                    [
                      { col: 'name' as const,       label: 'Name',       w: '' },
                      { col: 'script_id' as const,  label: 'Script ID',  w: '160px' },
                      { col: 'platform' as const,   label: 'Platform',   w: '90px' },
                      { col: 'category' as const,   label: 'Category',   w: '110px' },
                      { col: 'executor' as const,   label: 'Executor',   w: '95px' },
                      { col: 'risk_level' as const, label: 'Risk',       w: '80px' },
                      { col: 'readonly' as const,   label: 'RO',         w: '42px' },
                      { col: 'dangerous' as const,  label: 'Danger',     w: '55px' },
                      { col: 'enabled' as const,    label: 'Enabled',    w: '58px' },
                      { col: 'updated_at' as const, label: 'Updated',    w: '90px' },
                    ] as { col: keyof ScriptEntry; label: string; w: string }[]
                  ).map(({ col, label, w }) => (
                    <th
                      key={col}
                      onClick={() => toggleSort(col)}
                      style={{ width: w || undefined, padding: '7px 10px', textAlign: 'left', cursor: 'pointer', color: 'rgba(255,255,255,0.35)', fontWeight: 700, fontSize: '10px', letterSpacing: '0.06em', textTransform: 'uppercase', userSelect: 'none', whiteSpace: 'nowrap' }}
                    >
                      <span className="flex items-center gap-1">
                        {label}
                        <SortIcon col={col} />
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => {
                  const isSelected = selected?.script_id === s.script_id;
                  return (
                    <tr
                      key={s.script_id}
                      onClick={() => openDetail(s)}
                      className={cx(
                        'cursor-pointer border-b transition-colors',
                        isSelected
                          ? 'bg-cyan-500/[0.08]'
                          : flag(s.dangerous)
                          ? 'hover:bg-red-500/[0.04]'
                          : 'hover:bg-white/[0.03]'
                      )}
                      style={{ borderColor: 'rgba(255,255,255,0.045)' }}
                    >
                      {/* Name */}
                      <td style={{ padding: '7px 10px', color: 'rgba(255,255,255,0.85)' }}>
                        <span className="font-medium">{s.name}</span>
                        {s.description && (
                          <span className="ml-2 text-[11px] text-white/25 truncate max-w-[200px] inline-block align-middle">
                            {s.description.slice(0, 60)}{s.description.length > 60 ? '…' : ''}
                          </span>
                        )}
                      </td>
                      {/* Script ID */}
                      <td style={{ padding: '7px 10px' }}>
                        <code className="text-[10.5px] text-cyan-400/80">{s.script_id}</code>
                      </td>
                      {/* Platform */}
                      <td style={{ padding: '7px 10px' }}>
                        <span className={cx('rounded px-1.5 py-0.5 text-[10px] font-bold', platformBadge(s.platform))}>
                          {s.platform.toUpperCase()}
                        </span>
                      </td>
                      {/* Category */}
                      <td style={{ padding: '7px 10px', color: 'rgba(255,255,255,0.5)', fontSize: '11px' }}>{s.category}</td>
                      {/* Executor */}
                      <td style={{ padding: '7px 10px', color: 'rgba(255,255,255,0.45)', fontSize: '11px', fontFamily: 'monospace' }}>{s.executor}</td>
                      {/* Risk */}
                      <td style={{ padding: '7px 10px' }}>
                        <span className={cx('rounded px-1.5 py-0.5 text-[10px] font-bold capitalize', riskBadge(s.risk_level))}>
                          {s.risk_level}
                        </span>
                      </td>
                      {/* Readonly */}
                      <td style={{ padding: '7px 10px', textAlign: 'center' }}>
                        {flag(s.readonly)
                          ? <Shield size={13} className="text-emerald-400 inline" />
                          : <ShieldOff size={13} className="text-orange-400 inline" />}
                      </td>
                      {/* Dangerous */}
                      <td style={{ padding: '7px 10px', textAlign: 'center' }}>
                        {flag(s.dangerous)
                          ? <AlertTriangle size={13} className="text-red-400 inline" />
                          : <span className="text-white/20 text-[10px]">—</span>}
                      </td>
                      {/* Enabled */}
                      <td style={{ padding: '7px 10px', textAlign: 'center' }}>
                        {flag(s.enabled)
                          ? <CheckCircle size={13} className="text-emerald-400 inline" />
                          : <XCircle size={13} className="text-slate-500 inline" />}
                      </td>
                      {/* Updated */}
                      <td style={{ padding: '7px 10px', color: 'rgba(255,255,255,0.3)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                        {fmtDate(s.updated_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* ── DETAIL DRAWER ── */}
        {selected && (
          <div
            className="flex flex-col border-l overflow-y-auto"
            style={{
              width: '380px',
              minWidth: '340px',
              flexShrink: 0,
              borderColor: 'rgba(255,255,255,0.07)',
              background: 'rgba(0,10,20,0.55)',
            }}
          >
            {/* Drawer header */}
            <div
              className="flex items-start justify-between border-b px-4 py-3 sticky top-0 z-10"
              style={{ borderColor: 'rgba(255,255,255,0.07)', background: 'rgba(0,10,20,0.85)', backdropFilter: 'blur(8px)' }}
            >
              <div className="flex items-center gap-2 min-w-0">
                <FileCode2 size={14} className="text-cyan-400 flex-shrink-0" />
                <p className="text-[13px] font-semibold text-white/90 truncate">{selected.name}</p>
              </div>
              <button type="button" onClick={() => setSelected(null)} className="text-white/30 hover:text-white/70 ml-2 flex-shrink-0">
                <X size={15} />
              </button>
            </div>

            {/* Drawer body */}
            <div className="flex-1 px-4 py-4 space-y-4 text-[12px]">

              {/* Badges row */}
              <div className="flex flex-wrap gap-1.5">
                <span className={cx('rounded px-1.5 py-0.5 text-[10px] font-bold', platformBadge(selected.platform))}>
                  {selected.platform.toUpperCase()}
                </span>
                <span className={cx('rounded px-1.5 py-0.5 text-[10px] font-bold capitalize', riskBadge(selected.risk_level))}>
                  {selected.risk_level}
                </span>
                {flag(selected.readonly)  && <Chip label="READ-ONLY" variant="ok" />}
                {!flag(selected.readonly) && <Chip label="WRITE"     variant="warn" />}
                {flag(selected.dangerous) && <Chip label="DANGEROUS" variant="danger" />}
                {flag(selected.enabled)   ? <Chip label="ENABLED"  variant="ok" /> : <Chip label="DISABLED" variant="disabled" />}
                {flag(selected.requires_admin) && <Chip label="ADMIN" variant="warn" />}
              </div>

              {/* Safety warning */}
              {(flag(selected.dangerous) || !flag(selected.readonly)) && (
                <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] px-3 py-2">
                  <AlertTriangle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-[11px] text-red-300/90">
                    This script is not considered safe for Phase 1. Execution will remain disabled.
                  </p>
                </div>
              )}

              {/* Info grid */}
              <div className="grid grid-cols-2 gap-x-3 gap-y-2">
                {([
                  ['script_id',  selected.script_id],
                  ['category',   selected.category],
                  ['executor',   selected.executor],
                  ['created',    fmtDate(selected.created_at)],
                  ['updated',    fmtDate(selected.updated_at)],
                ] as [string, string][]).map(([k, v]) => (
                  <div key={k}>
                    <p className="text-[10px] uppercase tracking-wider text-white/30 font-semibold">{k}</p>
                    <p className="text-[11.5px] text-white/75 font-mono truncate">{v || '—'}</p>
                  </div>
                ))}
              </div>

              {/* Description */}
              {selected.description && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-white/30 font-semibold mb-1">Description</p>
                  <p className="text-[12px] text-white/65 leading-relaxed">{selected.description}</p>
                </div>
              )}

              {/* Parameters */}
              {selected.parameters_json && selected.parameters_json !== '{}' && selected.parameters_json !== 'null' && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-white/30 font-semibold mb-1">Parameters</p>
                  <pre className="rounded border border-white/[0.07] bg-black/30 p-2.5 text-[10.5px] text-cyan-300/80 overflow-x-auto max-h-28 scrollbar-thin">
                    {(() => {
                      try { return JSON.stringify(JSON.parse(selected.parameters_json!), null, 2); }
                      catch { return selected.parameters_json; }
                    })()}
                  </pre>
                </div>
              )}

              {/* Script body */}
              {selected.script_body && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-white/30 font-semibold mb-1">Script Body</p>
                  <pre className="rounded border border-white/[0.07] bg-black/40 p-2.5 text-[10.5px] text-green-300/80 overflow-auto max-h-48 scrollbar-thin font-mono leading-relaxed whitespace-pre-wrap">
                    {selected.script_body}
                  </pre>
                </div>
              )}

              {/* Run panel — live for local_runner scripts, disabled otherwise */}
              {selected.executor === 'local_runner' ? (
                selected.script_id === 'fetch_events_per_host' ? (
                  /* ── Per-host panel ─────────────────────────────────────── */
                  <div className="rounded-xl border border-purple-500/20 bg-purple-500/[0.05] p-3.5 space-y-3">
                    <div className="flex items-center gap-2 mb-0.5">
                      <Play size={12} className="text-purple-400" />
                      <p className="text-[11px] font-bold uppercase tracking-widest text-purple-300/70">Fetch per Host</p>
                    </div>
                    <p className="text-[10.5px] text-white/35 leading-relaxed">
                      Discovers all active agents automatically and saves one JSON file per host.
                    </p>

                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className="block text-[10px] text-white/40 mb-1">Hours lookback</label>
                        <input
                          type="number" min={1} max={8760}
                          value={phHours}
                          onChange={e => setPhHours(Number(e.target.value))}
                          className="w-full rounded border border-white/[0.08] bg-black/40 px-2.5 py-1.5 text-[12px] text-white/80 outline-none focus:border-purple-500/40"
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-white/40 mb-1">Events per host (max 100,000)</label>
                        <input
                          type="number" min={1} max={100000}
                          value={phLimit}
                          onChange={e => setPhLimit(Number(e.target.value))}
                          className="w-full rounded border border-white/[0.08] bg-black/40 px-2.5 py-1.5 text-[12px] text-white/80 outline-none focus:border-purple-500/40"
                        />
                      </div>
                    </div>

                    <button
                      type="button"
                      disabled={phBusy}
                      onClick={async () => {
                        setPhBusy(true);
                        setPhResult(null);
                        setPhError(null);
                        try {
                          const res = await runFetchEventsPerHost({ hours: phHours, limit_per_host: phLimit });
                          setPhResult(res);
                        } catch (e) {
                          setPhError(e instanceof Error ? e.message : 'Execution failed');
                        } finally {
                          setPhBusy(false);
                        }
                      }}
                      className="w-full flex items-center justify-center gap-2 rounded-lg border border-purple-500/30 bg-purple-500/15 py-2 text-[12px] font-semibold text-purple-200 hover:bg-purple-500/25 transition disabled:opacity-50 disabled:cursor-wait"
                    >
                      {phBusy
                        ? <><RefreshCw size={13} className="animate-spin" /> Fetching from all hosts…</>
                        : <><Play size={13} /> Fetch Events for every Host</>}
                    </button>

                    {phError && (
                      <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] px-3 py-2">
                        <XCircle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
                        <p className="text-[11px] text-red-300">{phError}</p>
                      </div>
                    )}

                    {phResult && (
                      <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.05] px-3 py-2.5 space-y-2">
                        <div className="flex items-center gap-1.5 mb-1">
                          <CheckCircle size={12} className="text-emerald-400" />
                          <p className="text-[11px] font-bold text-emerald-300">
                            Completed — {phResult.hosts_processed} hosts · {phResult.total_events.toLocaleString()} total events
                          </p>
                        </div>
                        <div className="max-h-52 overflow-y-auto space-y-1 pr-1 scrollbar-thin">
                          {phResult.results.map((r: HostFetchResult) => (
                            <div key={r.host} className={`flex items-center justify-between gap-2 rounded px-2 py-1.5 text-[10.5px] border ${r.status === 'ok' ? 'border-white/[0.06] bg-white/[0.02]' : 'border-red-500/20 bg-red-500/[0.05]'}`}>
                              <span className="font-mono text-white/70 truncate flex-1">{r.host}</span>
                              {r.status === 'ok' ? (
                                <>
                                  <span className="text-white/35 whitespace-nowrap">{r.events_fetched.toLocaleString()} events · {r.file_size_kb.toFixed(0)} KB</span>
                                  <a
                                    href={`http://127.0.0.1:8000/runner/download-events?filename=${encodeURIComponent(r.file_path.split(/[\\/]/).pop() ?? '')}`}
                                    download
                                    className="flex items-center gap-1 rounded border border-emerald-500/25 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-200 hover:bg-emerald-500/20 transition whitespace-nowrap"
                                  >
                                    <Download size={10} /> Export
                                  </a>
                                </>
                              ) : (
                                <span className="text-red-300/70 text-[10px] truncate">{r.error}</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  /* ── Single-file panel (fetch_wazuh_events) ─────────────── */
                  <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/[0.05] p-3.5 space-y-3">
                  <div className="flex items-center gap-2 mb-0.5">
                    <Play size={12} className="text-cyan-400" />
                    <p className="text-[11px] font-bold uppercase tracking-widest text-cyan-300/70">Run Parameters</p>
                  </div>

                  {/* Parameter inputs */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[10px] text-white/40 mb-1">Hours lookback</label>
                      <input
                        type="number" min={1} max={8760}
                        value={runHours}
                        onChange={e => setRunHours(Number(e.target.value))}
                        className="w-full rounded border border-white/[0.08] bg-black/40 px-2.5 py-1.5 text-[12px] text-white/80 outline-none focus:border-cyan-500/40"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-white/40 mb-1">Event limit (max 100,000)</label>
                      <input
                        type="number" min={1} max={100000}
                        value={runLimit}
                        onChange={e => setRunLimit(Number(e.target.value))}
                        className="w-full rounded border border-white/[0.08] bg-black/40 px-2.5 py-1.5 text-[12px] text-white/80 outline-none focus:border-cyan-500/40"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-[10px] text-white/40 mb-1">Host filter <span className="text-white/25">(optional, wildcard)</span></label>
                    <input
                      type="text"
                      placeholder="e.g. KS-01* or leave blank for all"
                      value={runHost}
                      onChange={e => setRunHost(e.target.value)}
                      className="w-full rounded border border-white/[0.08] bg-black/40 px-2.5 py-1.5 text-[12px] text-white/80 outline-none focus:border-cyan-500/40 placeholder-white/20"
                    />
                  </div>

                  {/* Run button */}
                  <button
                    type="button"
                    disabled={runBusy}
                    onClick={async () => {
                      setRunBusy(true);
                      setRunResult(null);
                      setRunError(null);
                      try {
                        const res = await runFetchWazuhEvents({
                          hours: runHours,
                          limit: runLimit,
                          host_filter: runHost || null,
                        });
                        setRunResult(res);
                      } catch (e) {
                        setRunError(e instanceof Error ? e.message : 'Execution failed');
                      } finally {
                        setRunBusy(false);
                      }
                    }}
                    className="w-full flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/15 py-2 text-[12px] font-semibold text-cyan-200 hover:bg-cyan-500/25 transition disabled:opacity-50 disabled:cursor-wait"
                  >
                    {runBusy
                      ? <><RefreshCw size={13} className="animate-spin" /> Fetching from Wazuh…</>
                      : <><Play size={13} /> Fetch Events</>}
                  </button>

                  {/* Error */}
                  {runError && (
                    <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] px-3 py-2">
                      <XCircle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
                      <p className="text-[11px] text-red-300">{runError}</p>
                    </div>
                  )}

                  {/* Result */}
                  {runResult && (
                    <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.05] px-3 py-2.5 space-y-1">
                      <div className="flex items-center gap-1.5 mb-1">
                        <CheckCircle size={12} className="text-emerald-400" />
                        <p className="text-[11px] font-bold text-emerald-300">Completed — {runResult.events_fetched} events saved</p>
                      </div>
                      <p className="text-[10.5px] text-white/50 font-mono break-all">{runResult.file_path}</p>
                      <p className="text-[10.5px] text-white/40">
                        {runResult.file_size_kb.toFixed(1)} KB &nbsp;·&nbsp; {runResult.agent_count} agent{runResult.agent_count !== 1 ? 's' : ''}
                        {runResult.agents.length > 0 && (
                          <span className="text-white/30"> ({runResult.agents.slice(0, 5).join(', ')}{runResult.agents.length > 5 ? '…' : ''})</span>
                        )}
                      </p>
                      {runResult.earliest && (
                        <p className="text-[10px] text-white/30">
                          {runResult.earliest.slice(0, 19).replace('T', ' ')} → {runResult.latest?.slice(0, 19).replace('T', ' ')}
                        </p>
                      )}
                      {/* Download button */}
                      <a
                        href={`http://127.0.0.1:8000/runner/download-events?filename=${encodeURIComponent(runResult.file_path.split(/[\\/]/).pop() ?? '')}`}
                        download
                        className="mt-2 flex items-center justify-center gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-3 py-1.5 text-[11.5px] font-semibold text-emerald-200 hover:bg-emerald-500/20 transition"
                      >
                        <Download size={12} />
                        Export JSON — save anywhere on your PC
                      </a>
                    </div>
                  )}
                </div>
                )  /* end inner ternary: fetch_events_per_host vs fetch_wazuh_events */
              ) : (
                <div className="pt-1">
                  <button
                    type="button"
                    disabled
                    title="Script execution is disabled in Phase 1."
                    className="w-full flex items-center justify-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.03] py-2 text-[12px] text-white/25 cursor-not-allowed"
                  >
                    <Terminal size={13} />
                    Run Script — Phase 1 Disabled
                  </button>
                  <p className="mt-1 text-center text-[10px] text-white/20">Script execution is disabled in Phase 1.</p>
                </div>
              )}
            </div>

            {/* Drawer actions */}
            <div
              className="flex items-center gap-2 border-t px-4 py-3 sticky bottom-0"
              style={{ borderColor: 'rgba(255,255,255,0.07)', background: 'rgba(0,10,20,0.85)', backdropFilter: 'blur(8px)' }}
            >
              <button
                type="button"
                onClick={() => openEdit(selected)}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/25 bg-cyan-500/10 px-3 py-1.5 text-[12px] text-cyan-300 hover:bg-cyan-500/15 transition"
              >
                <Edit3 size={12} />
                Edit
              </button>
              <button
                type="button"
                onClick={() => openDuplicate(selected)}
                className="flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-[12px] text-white/60 hover:bg-white/[0.07] hover:text-white/80 transition"
              >
                <Copy size={12} />
                Duplicate
              </button>
              <button
                type="button"
                onClick={() => setDeleteTarget(selected)}
                className="ml-auto flex items-center gap-1.5 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 text-[12px] text-red-400 hover:bg-red-500/[0.1] transition"
              >
                <Trash2 size={12} />
                Delete
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── CREATE / EDIT MODAL ── */}
      {formOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}>
          <div
            className="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-2xl border shadow-2xl overflow-hidden"
            style={{ borderColor: 'rgba(0,217,255,0.15)', background: '#050f1a' }}
          >
            {/* Modal header */}
            <div
              className="flex items-center justify-between border-b px-5 py-4"
              style={{ borderColor: 'rgba(255,255,255,0.07)' }}
            >
              <div className="flex items-center gap-2">
                <FileCode2 size={16} className="text-cyan-400" />
                <h2 className="text-[14px] font-semibold text-white/90">
                  {formMode === 'create' ? 'New Script' : `Edit: ${formData.name}`}
                </h2>
              </div>
              <button type="button" onClick={() => setFormOpen(false)} className="text-white/30 hover:text-white/70">
                <X size={16} />
              </button>
            </div>

            {/* Modal body */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">

              {/* Safety warning */}
              {showSafetyWarn && (
                <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] px-3 py-2">
                  <AlertTriangle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-[11px] text-red-300/90">
                    This script is not considered safe for Phase 1. Execution will remain disabled.
                  </p>
                </div>
              )}

              {/* Error */}
              {formError && (
                <div className="flex items-center gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.07] px-3 py-2 text-[12px] text-red-300">
                  <XCircle size={13} />
                  {formError}
                </div>
              )}

              {/* Field grid */}
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Script ID *">
                  <FormInput value={formData.script_id ?? ''} onChange={v => setField('script_id', v)} placeholder="e.g. win_get_processes" disabled={formMode === 'edit'} />
                </FormField>
                <FormField label="Name *">
                  <FormInput value={formData.name ?? ''} onChange={v => setField('name', v)} placeholder="Human-readable name" />
                </FormField>
              </div>

              <FormField label="Description">
                <textarea
                  value={formData.description ?? ''}
                  onChange={e => setField('description', e.target.value)}
                  placeholder="What does this script do?"
                  rows={2}
                  className="rounded border border-white/[0.09] bg-white/[0.04] px-3 py-1.5 text-[12px] text-white/85 placeholder-white/25 focus:outline-none focus:border-cyan-500/50 resize-none"
                />
              </FormField>

              <div className="grid grid-cols-2 gap-4">
                <FormField label="Platform *">
                  <FormSelect
                    value={formData.platform ?? 'windows'}
                    onChange={v => setField('platform', v as ScriptEntry['platform'])}
                    options={[
                      { value: 'windows', label: 'Windows' },
                      { value: 'linux',   label: 'Linux' },
                      { value: 'both',    label: 'Both' },
                      { value: 'network', label: 'Network' },
                    ]}
                  />
                </FormField>
                <FormField label="Category">
                  <FormSelect
                    value={formData.category ?? 'collection'}
                    onChange={v => setField('category', v)}
                    options={[...new Set([...KNOWN_CATEGORIES, formData.category ?? ''])].filter(Boolean).map(c => ({ value: c, label: c }))}
                  />
                </FormField>
                <FormField label="Executor *">
                  <FormSelect
                    value={formData.executor ?? 'powershell'}
                    onChange={v => setField('executor', v)}
                    options={[...new Set([...KNOWN_EXECUTORS, formData.executor ?? ''])].filter(Boolean).map(e => ({ value: e, label: e }))}
                  />
                </FormField>
                <FormField label="Risk Level" warn={formData.risk_level === 'high' || formData.risk_level === 'critical' ? 'High-risk scripts cannot be executed in Phase 1.' : undefined}>
                  <FormSelect
                    value={formData.risk_level ?? 'low'}
                    onChange={v => setField('risk_level', v)}
                    options={[
                      { value: 'low',      label: 'Low' },
                      { value: 'medium',   label: 'Medium' },
                      { value: 'high',     label: 'High' },
                      { value: 'critical', label: 'Critical' },
                    ]}
                  />
                </FormField>
              </div>

              {/* Toggles */}
              <div className="flex flex-wrap gap-6 pt-1">
                <FormToggle label="Enabled"       checked={flag(formData.enabled)}       onChange={v => setField('enabled',       v ? 1 : 0)} />
                <FormToggle label="Read-only"     checked={flag(formData.readonly)}      onChange={v => setField('readonly',      v ? 1 : 0)} />
                <FormToggle
                  label="Dangerous"
                  checked={flag(formData.dangerous)}
                  onChange={v => setField('dangerous', v ? 1 : 0)}
                />
                <FormToggle label="Requires Admin" checked={flag(formData.requires_admin)} onChange={v => setField('requires_admin', v ? 1 : 0)} />
              </div>

              {/* Parameters JSON */}
              <FormField label="Parameters JSON">
                <textarea
                  value={formData.parameters_json ?? '{}'}
                  onChange={e => setField('parameters_json', e.target.value)}
                  rows={3}
                  placeholder='{"param1": "description"}'
                  className="rounded border border-white/[0.09] bg-black/30 px-3 py-1.5 text-[11.5px] text-cyan-300/80 placeholder-white/20 focus:outline-none focus:border-cyan-500/50 resize-none font-mono"
                />
              </FormField>

              {/* Script body */}
              <FormField label="Script Body">
                <textarea
                  value={formData.script_body ?? ''}
                  onChange={e => setField('script_body', e.target.value)}
                  rows={8}
                  placeholder="# Script content here…"
                  className="rounded border border-white/[0.09] bg-black/40 px-3 py-1.5 text-[11.5px] text-green-300/80 placeholder-white/20 focus:outline-none focus:border-cyan-500/50 resize-y font-mono leading-relaxed"
                />
              </FormField>
            </div>

            {/* Modal footer */}
            <div
              className="flex items-center justify-end gap-3 border-t px-5 py-4"
              style={{ borderColor: 'rgba(255,255,255,0.07)' }}
            >
              <button type="button" onClick={() => setFormOpen(false)} className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-4 py-1.5 text-[12px] text-white/60 hover:bg-white/[0.07] transition">
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleSave()}
                disabled={formSaving}
                className="flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-[12px] text-cyan-300 hover:bg-cyan-500/15 transition disabled:opacity-50"
              >
                {formSaving && <RefreshCw size={12} className="animate-spin" />}
                {formMode === 'create' ? 'Create Script' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── DELETE CONFIRM ── */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)' }}>
          <div
            className="w-full max-w-sm rounded-2xl border shadow-2xl p-6"
            style={{ borderColor: 'rgba(255,80,80,0.2)', background: '#050f1a' }}
          >
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={16} className="text-red-400" />
              <h3 className="text-[14px] font-semibold text-white/90">Delete Script?</h3>
            </div>
            <p className="text-[12px] text-white/55 mb-5">
              Are you sure you want to delete{' '}
              <span className="font-semibold text-white/80">{deleteTarget.name}</span>{' '}
              (<code className="text-cyan-400/80">{deleteTarget.script_id}</code>)?
              This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button type="button" onClick={() => setDeleteTarget(null)} className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-4 py-1.5 text-[12px] text-white/60 hover:bg-white/[0.07] transition">
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleDelete(deleteTarget)}
                className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-[12px] text-red-300 hover:bg-red-500/15 transition"
              >
                <Trash2 size={12} />
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
