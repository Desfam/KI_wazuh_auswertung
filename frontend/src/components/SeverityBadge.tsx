type SeverityBadgeProps = {
  severity?: string | null;
};

const styles: Record<string, string> = {
  critical: 'bg-signal text-white border-signal',
  high: 'bg-ember text-white border-ember',
  medium: 'bg-brass/20 text-ink border-brass/30',
  low: 'bg-pine/15 text-pine border-pine/20'
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const resolved = (severity || 'low').toLowerCase();
  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] ${styles[resolved] || styles.low}`}>{resolved}</span>;
}
