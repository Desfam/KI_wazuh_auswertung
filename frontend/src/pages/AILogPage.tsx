import type { AIServiceStatus, AIServiceTestResult } from '../types';

type AILogPageProps = {
  status: AIServiceStatus | null;
  testing: boolean;
  switching: boolean;
  testResult: AIServiceTestResult | null;
  onToggle: (next: boolean) => void;
  onTest: () => void;
  onRefresh: () => void;
};

export function AILogPage({ status, testing, switching, testResult, onToggle, onTest, onRefresh }: AILogPageProps) {
  const running = !!status?.running;

  return (
    <div className="grid gap-6 xl:grid-cols-[0.9fr,1.1fr]">
      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">AI Service</p>
        <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Ollama Control</h3>

        <div className="mt-5 space-y-4">
          <div className="rounded-2xl bg-shell/70 p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate">Switch</p>
            <label className="mt-3 inline-flex items-center gap-3 text-sm text-ink">
              <input type="checkbox" checked={running} onChange={(event) => onToggle(event.target.checked)} disabled={switching} />
              {running ? 'AI is running' : 'AI is stopped'}
            </label>
            <p className="mt-2 text-sm text-slate">Starts `OLLAMA_HOST=0.0.0.0:11434` with `ollama serve`.</p>
          </div>

          <div className="rounded-2xl bg-shell/70 p-4 text-sm text-slate">
            <p><span className="font-medium text-ink">Host:</span> {status?.host || '0.0.0.0:11434'}</p>
            <p className="mt-1"><span className="font-medium text-ink">PID:</span> {status?.pid ?? 'n/a'}</p>
            <p className="mt-1"><span className="font-medium text-ink">Last error:</span> {status?.last_error || 'none'}</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button type="button" onClick={onTest} disabled={!running || testing} className="rounded-2xl bg-ember px-4 py-3 text-sm font-medium text-white disabled:opacity-50">
              {testing ? 'Testing...' : 'Test /api/generate'}
            </button>
            <button type="button" onClick={onRefresh} className="rounded-2xl border border-ink/10 px-4 py-3 text-sm font-medium text-ink">
              Refresh
            </button>
          </div>

          <div className="rounded-2xl bg-shell/70 p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate">Test result</p>
            <p className="mt-2 font-medium text-ink">{testResult ? (testResult.ok ? 'Success' : 'Failed') : 'Not run yet'}</p>
            <p className="mt-2 text-sm text-slate">{testResult?.detail || 'Press the test button while AI is running.'}</p>
          </div>
        </div>
      </section>

      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">AI Log</p>
        <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Runtime Output</h3>
        <pre className="mt-5 max-h-[40rem] overflow-auto whitespace-pre-wrap rounded-2xl bg-ink p-5 font-['IBM_Plex_Mono'] text-sm leading-7 text-shell">{status?.logs?.length ? status.logs.join('\n') : 'No log lines yet.'}</pre>
      </section>
    </div>
  );
}