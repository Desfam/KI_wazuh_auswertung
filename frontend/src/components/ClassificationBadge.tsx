/**
 * ClassificationBadge — compact, color-coded badge for `final_classification`.
 *
 * Classification values (from classification_engine.py):
 *   escalated            – critical risk, immediate action
 *   known_but_suspicious – entity in baseline, BUT behavior/volume changed
 *   needs_investigation  – new entity, medium risk
 *   expected_for_profile – new but profile allows it
 *   accepted_baseline    – analyst-accepted deviation
 *   known_benign         – entity known, no anomalies
 *   false_positive       – analyst-dismissed
 *   unknown              – no baseline context
 */

type ClassificationStyle = {
  label: string;
  cls: string;
};

const STYLES: Record<string, ClassificationStyle> = {
  escalated:            { label: 'ESCALATED',        cls: 'bg-critical/20 text-critical border-critical/60 font-bold' },
  known_but_suspicious: { label: 'KNOWN·SUSPICIOUS', cls: 'bg-warning/20 text-warning border-warning/50 font-semibold' },
  needs_investigation:  { label: 'INVESTIGATE',      cls: 'bg-amber-500/20 text-amber-400 border-amber-500/40' },
  expected_for_profile: { label: 'PROFILE-EXPECTED', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
  accepted_baseline:    { label: 'ACCEPTED',         cls: 'bg-success/10 text-success/70 border-success/20' },
  known_benign:         { label: 'KNOWN-BENIGN',     cls: 'bg-success/10 text-success border-success/30' },
  false_positive:       { label: 'FALSE-POS',        cls: 'bg-muted/15 text-muted-foreground border-muted/20' },
  unknown:              { label: 'UNKNOWN',           cls: 'bg-muted/10 text-muted-foreground/60 border-muted/15' },
};

type Props = {
  value: string;
  className?: string;
};

export function ClassificationBadge({ value, className = '' }: Props) {
  const style = STYLES[value] ?? STYLES['unknown'];
  return (
    <span
      className={`shrink-0 inline-flex items-center h-[15px] px-1.5 rounded-sm text-[9px] font-mono uppercase tracking-wider border ${style.cls} ${className}`}
    >
      {style.label}
    </span>
  );
}

/** Returns true for classifications that warrant analyst attention */
export function isActionable(classification: string): boolean {
  return classification === 'escalated' || classification === 'known_but_suspicious' || classification === 'needs_investigation';
}

/** Sort key: highest-priority classifications first */
export function classificationSortKey(classification: string): number {
  const ORDER: Record<string, number> = {
    escalated:            0,
    known_but_suspicious: 1,
    needs_investigation:  2,
    expected_for_profile: 3,
    unknown:              4,
    known_benign:         5,
    accepted_baseline:    6,
    false_positive:       7,
  };
  return ORDER[classification] ?? 4;
}
