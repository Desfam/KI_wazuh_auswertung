type StatCardProps = {
  label: string;
  value: string | number;
  hint: string;
  accent?: 'ember' | 'pine' | 'brass' | 'signal';
};

const accentColors: Record<string, { border: string; iconBg: string; iconText: string }> = {
  ember: { border: '#727cf5', iconBg: 'bg-[#727cf5]/15', iconText: 'text-[#727cf5]' },
  pine:  { border: '#0acf97', iconBg: 'bg-[#0acf97]/15', iconText: 'text-[#0acf97]' },
  brass: { border: '#ffbc00', iconBg: 'bg-[#ffbc00]/15', iconText: 'text-[#e6a800]' },
  signal:{ border: '#fa5c7c', iconBg: 'bg-[#fa5c7c]/15', iconText: 'text-[#fa5c7c]' },
};

export function StatCard({ label, value, hint, accent = 'ember' }: StatCardProps) {
  const { border, iconBg, iconText } = accentColors[accent];
  return (
    <section
      className="rounded bg-white shadow-[0_0_35px_0_rgba(154,161,171,0.15)] dark:bg-[#3d4451] dark:shadow-[0_0_35px_0_rgba(0,0,0,0.25)]"
      style={{ borderLeft: `3px solid ${border}` }}
    >
      <div className="p-5">
        <div className={`mb-4 inline-flex h-10 w-10 items-center justify-center rounded-lg ${iconBg}`}>
          <span className={`text-lg font-bold ${iconText}`}>◈</span>
        </div>
        <p className="text-2xl font-bold text-[#313a46] dark:text-[#ced4da]">{value}</p>
        <p className="mt-1 text-[10px] font-semibold uppercase tracking-widest text-[#98a6ad]">{label}</p>
        <p className="mt-2 text-xs text-[#98a6ad]">{hint}</p>
      </div>
    </section>
  );
}
