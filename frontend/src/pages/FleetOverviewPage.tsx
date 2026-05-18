import { useEffect, useRef, useState } from 'react';
import FleetOverviewDashboard from '../components/fullscan/FleetOverviewDashboard';
import { getFleetOverview } from '../services/fleet';
import type { FleetHost } from '../services/fleet';

type Props = {
  active?: boolean;
  onSwitchTab?: (tab: string, payload?: unknown) => void;
};

export default function FleetOverviewPage({ active, onSwitchTab }: Props) {
  const [hosts, setHosts] = useState<FleetHost[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  async function load() {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setLoading(true);
    setError(null);
    try {
      const data = await getFleetOverview();
      if (ctrl.signal.aborted) return;
      setHosts(data);
      setLastRefresh(new Date());
    } catch (e) {
      if (ctrl.signal.aborted) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (active) load();
    return () => abortRef.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  function handleOpenHost(host: string) {
    onSwitchTab?.('hosts', { host });
  }

  function handleOpenIncidents() {
    onSwitchTab?.('findings');
  }

  if (loading && !hosts.length) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center space-y-3">
          <div className="h-10 w-10 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
          <div className="text-[13px] font-mono text-muted-foreground">Fleet Overview wird geladen…</div>
        </div>
      </div>
    );
  }

  if (error && !hosts.length) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center space-y-3 max-w-sm">
          <div className="text-critical text-[14px] font-mono">{error}</div>
          <button
            onClick={load}
            className="h-8 px-4 rounded-md border border-border text-[12px] font-mono hover:bg-accent"
          >
            Erneut versuchen
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col min-h-0">
      {(loading || lastRefresh) && (
        <div className="px-4 py-1 border-b border-border flex items-center gap-2">
          {loading && (
            <span className="h-3 w-3 rounded-full border border-primary border-t-transparent animate-spin inline-block" />
          )}
          <span className="text-[11px] font-mono text-muted-foreground">
            {loading ? 'Aktualisierung…' : `Zuletzt aktualisiert: ${lastRefresh?.toLocaleTimeString('de-DE')}`}
          </span>
        </div>
      )}
      <div className="flex-1 min-h-0 overflow-hidden">
        <FleetOverviewDashboard
          hosts={hosts}
          onRescan={load}
          onOpenHost={handleOpenHost}
          onOpenIncidents={handleOpenIncidents}
          onOpenScanReport={() => onSwitchTab?.('fullscan')}
        />
      </div>
    </div>
  );
}
