type StatCardProps = {
  label: string;
  value: string | number;
  hint: string;
  accent?: 'ember' | 'pine' | 'brass' | 'signal';
};

const accents = {
  ember: 'from-ember/25 to-white',
  pine: 'from-pine/25 to-white',
  brass: 'from-brass/30 to-white',
  signal: 'from-signal/25 to-white'
};

export function StatCard({ label, value, hint, accent = 'ember' }: StatCardProps) {
  return (
    <section className={`rounded-[1.75rem] border border-ink/10 bg-gradient-to-br ${accents[accent]} p-5 shadow-panel`}>
      <p className="text-xs uppercase tracking-[0.28em] text-slate">{label}</p>
      <p className="mt-4 font-['Space_Grotesk'] text-4xl font-semibold text-ink">{value}</p>
      <p className="mt-3 text-sm leading-6 text-slate">{hint}</p>
    </section>
  );
}
