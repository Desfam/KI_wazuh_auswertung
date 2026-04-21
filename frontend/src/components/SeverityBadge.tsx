type SeverityBadgeProps = {
  severity?: string | null;
};

const styles: Record<string, string> = {
  critical: 'bg-[#fa5c7c]/15 text-[#fa5c7c] border-[#fa5c7c]/25',
  high:     'bg-[#ffbc00]/15 text-[#e6a800] border-[#ffbc00]/25',
  medium:   'bg-[#39afd1]/15 text-[#39afd1] border-[#39afd1]/25',
  low:      'bg-[#0acf97]/15 text-[#0acf97] border-[#0acf97]/25',
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const resolved = (severity || 'low').toLowerCase();
  return (
    <span className={`inline-flex rounded border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-[0.15em] ${
      styles[resolved] || styles.low
    }`}>{resolved}</span>
  );
}
