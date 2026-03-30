import type { FindingGroup } from '../types';
import { SeverityBadge } from './SeverityBadge';

type FindingsTableProps = {
  findings: FindingGroup[];
};

function formatChecks(checks: FindingGroup['recommended_checks']) {
  if (Array.isArray(checks)) {
    return checks.join(' | ');
  }

  return checks || 'No checks recorded';
}

export function FindingsTable({ findings }: FindingsTableProps) {
  return (
    <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate">Findings</p>
          <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Grouped Security Events</h3>
        </div>
        <p className="text-sm text-slate">{findings.length} grouped findings</p>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full border-separate border-spacing-y-2 text-sm">
          <thead>
            <tr className="text-left uppercase tracking-[0.22em] text-slate">
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2">Platform</th>
              <th className="px-3 py-2">Event</th>
              <th className="px-3 py-2">Count</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Checks</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id} className="rounded-2xl bg-shell/50 text-ink">
                <td className="rounded-l-2xl px-3 py-3 align-top"><SeverityBadge severity={finding.ai_severity || finding.local_severity} /></td>
                <td className="px-3 py-3 align-top font-medium">{finding.host}</td>
                <td className="px-3 py-3 align-top uppercase tracking-[0.15em] text-slate">{finding.platform}</td>
                <td className="px-3 py-3 align-top">
                  <div className="font-medium text-ink">{finding.event_id || finding.rule_id || 'n/a'}</div>
                  <div className="mt-1 text-xs text-slate">{finding.rule_description || 'No rule description'}</div>
                </td>
                <td className="px-3 py-3 align-top">{finding.count}</td>
                <td className="px-3 py-3 align-top">{finding.confidence}%</td>
                <td className="max-w-sm px-3 py-3 align-top text-slate">{finding.reason || 'No model reason stored'}</td>
                <td className="rounded-r-2xl px-3 py-3 align-top text-slate">{formatChecks(finding.recommended_checks)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
