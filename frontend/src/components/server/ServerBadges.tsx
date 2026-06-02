import type { ServerConnection } from '../../types';

export function ProtocolBadge({ protocol }: { protocol: string }) {
  const styles: Record<string, string> = {
    ssh:   'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    rdp:   'bg-green-500/15 text-green-300 border-green-500/30',
    winrm: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border uppercase ${styles[protocol] ?? 'bg-slate-500/15 text-slate-300 border-slate-500/30'}`}>
      {protocol}
    </span>
  );
}

export function PolicyBadge({ policy }: { policy?: string }) {
  if (!policy || policy === 'allowed') return null;
  const styles: Record<string, string> = {
    blocked:          'bg-red-500/15 text-red-300 border-red-500/30',
    review_required:  'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
    phase1_blocked:   'bg-orange-500/15 text-orange-300 border-orange-500/30',
  };
  const labels: Record<string, string> = {
    blocked: 'BLOCKED',
    review_required: 'REVIEW',
    phase1_blocked: 'PHASE 1',
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border uppercase ${styles[policy] ?? 'bg-slate-500/15 text-slate-300 border-slate-500/30'}`}>
      {labels[policy] ?? policy}
    </span>
  );
}

export function StatusDot({ status }: { status?: string | null }) {
  if (!status) return <span className="inline-block w-2 h-2 rounded-full bg-slate-600 mr-1.5" />;
  const s = status.toLowerCase();
  if (s === 'ok' || s === 'online' || s === 'active') return <span className="inline-block w-2 h-2 rounded-full bg-green-400 mr-1.5" />;
  if (s === 'offline' || s === 'error' || s === 'blocked') return <span className="inline-block w-2 h-2 rounded-full bg-red-400 mr-1.5" />;
  if (s === 'review_required' || s === 'unavailable') return <span className="inline-block w-2 h-2 rounded-full bg-yellow-400 mr-1.5" />;
  return <span className="inline-block w-2 h-2 rounded-full bg-slate-400 mr-1.5" />;
}

export function FavoriteStar({ favorite, onClick }: { favorite: boolean; onClick?: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-sm transition-colors ${favorite ? 'text-yellow-400' : 'text-slate-600 hover:text-slate-400'}`}
      title={favorite ? 'Remove from favorites' : 'Add to favorites'}
    >
      ★
    </button>
  );
}

export function TagChip({ tag }: { tag: string }) {
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono"
      style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
      {tag}
    </span>
  );
}

export function connDisplayHost(conn: ServerConnection): string {
  return conn.hostname || conn.ip || '—';
}
