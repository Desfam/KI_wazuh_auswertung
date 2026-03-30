type TimelineBarsProps = {
  findingsBySeverity: Array<{ label: string; value: number; tone: string }>;
};

export function TimelineBars({ findingsBySeverity }: TimelineBarsProps) {
  const max = Math.max(...findingsBySeverity.map((item) => item.value), 1);

  return (
    <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
      <p className="text-xs uppercase tracking-[0.3em] text-slate">Severity Distribution</p>
      <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Current Triage Spread</h3>
      <div className="mt-6 space-y-4">
        {findingsBySeverity.map((item) => (
          <div key={item.label}>
            <div className="mb-2 flex items-center justify-between text-sm text-slate">
              <span>{item.label}</span>
              <span>{item.value}</span>
            </div>
            <div className="h-3 rounded-full bg-shell">
              <div className={`h-3 rounded-full ${item.tone}`} style={{ width: `${(item.value / max) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
