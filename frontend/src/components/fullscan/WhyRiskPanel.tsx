import { CheckCircle2 } from 'lucide-react';

type Props = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  result: any;
};

export default function WhyRiskPanel({ result }: Props) {
  const summary = result?.summary ?? {};
  const breakdown = summary.risk_breakdown ?? result?.raw_json?.risk_breakdown ?? {};
  const riskLevel = (summary.risk_level ?? 'LOW').toUpperCase();

  const tiMatches: unknown[] = Array.isArray(result?.threat_intel) ? result.threat_intel : [];
  const tiScore: number = breakdown.ti_score ?? 0;
  const behaviorScore: number = breakdown.behavior_score ?? 0;
  const deviationScore: number = breakdown.deviation_score ?? 0;
  const attackChainScore: number = breakdown.attack_chain_score ?? 0;
  const caps: string[] = Array.isArray(breakdown.caps_applied) ? breakdown.caps_applied : [];

  const isHighRisk = riskLevel === 'HIGH' || riskLevel === 'CRITICAL';

  // Build evidence-based reasons
  const bullets: string[] = [];

  if (!isHighRisk) {
    if (behaviorScore === 0)
      bullets.push('Keine verdächtigen Prozesse oder Befehlsmuster');
    if (attackChainScore === 0)
      bullets.push('Keine Angriffsketten-Indikatoren');
    if (deviationScore === 0)
      bullets.push('Keine persistierenden Änderungen');
    if (tiScore === 0 && tiMatches.length === 0)
      bullets.push('Keine Verbindung zu bekannten C2-Infrastruktur');
    if (caps.some((c) => c.includes('sysadmin') || c.includes('profile'))) {
      const profileMatch = caps.find((c) => c.includes('sysadmin') || c.includes('profile'));
      const profileLabel = profileMatch?.replace(/cap:|profile_cap:|sysadmin_/gi, '') ?? 'Baseline';
      bullets.push(`Verhalten entspricht dem ${profileLabel.trim() || 'Baseline'}-Profil`);
    } else {
      bullets.push('Verhalten entspricht dem Baseline-Profil');
    }
    if (caps.includes('no_real_threat'))
      bullets.push('Keine realen Bedrohungsindikatoren erkannt');
  }

  // High risk reasons
  const highBullets: string[] = [];
  if (isHighRisk) {
    if (behaviorScore > 0)
      highBullets.push(`Verdächtige Prozess-/Befehlsmuster erkannt (Score: ${behaviorScore.toFixed(1)})`);
    if (attackChainScore > 0)
      highBullets.push(`Angriffsketten-Indikatoren vorhanden (Score: ${attackChainScore.toFixed(1)})`);
    if (tiMatches.length > 0)
      highBullets.push(`${tiMatches.length} Threat-Intelligence-Treffer`);
    if (deviationScore > 0)
      highBullets.push(`Baseline-Abweichungen festgestellt (Score: ${deviationScore.toFixed(1)})`);
  }

  if (!isHighRisk && bullets.length === 0) return null;
  if (isHighRisk && highBullets.length === 0) return null;

  return (
    <div className={`rounded-lg border overflow-hidden ${
      isHighRisk
        ? 'border-high/25 bg-high/5'
        : 'border-success/20 bg-success/5'
    }`}>
      <div className="px-4 py-2.5 border-b border-inherit">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          {isHighRisk ? 'Warum das Risiko erhöht ist' : 'Warum das Risiko niedrig ist'}
        </span>
      </div>
      <div className="px-4 py-3 space-y-1.5">
        {(isHighRisk ? highBullets : bullets).map((line, i) => (
          <div key={i} className="flex items-start gap-2 text-[11px] font-mono text-muted-foreground">
            <CheckCircle2
              className={`h-3.5 w-3.5 mt-px shrink-0 ${isHighRisk ? 'text-high' : 'text-success'}`}
            />
            <span>{line}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
