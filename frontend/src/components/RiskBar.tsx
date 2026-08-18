import { severityColor } from './SeverityBadge';
import SeverityBadge from './SeverityBadge';

interface Props {
  counts: Record<string, number>;
  total: number;
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

export default function RiskBar({ counts, total }: Props) {
  if (total === 0) return (
    <div className="flex items-center gap-2 text-green-400 text-sm">
      <span className="text-green-500">✓</span> No vulnerabilities detected
    </div>
  );

  return (
    <div className="space-y-2.5">
      {/* Stacked bar */}
      <div className="flex rounded-full overflow-hidden h-2 bg-gray-800 gap-px">
        {SEVERITIES.map(s => {
          const count = counts[s] ?? 0;
          if (count === 0) return null;
          const pct = (count / total) * 100;
          return (
            <div key={s} style={{ width: `${pct}%`, backgroundColor: severityColor(s) }}
              title={`${s}: ${count}`} />
          );
        })}
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {SEVERITIES.map(s => {
          const count = counts[s] ?? 0;
          if (count === 0) return null;
          return (
            <div key={s} className="flex items-center gap-1.5">
              <SeverityBadge severity={s} showDot />
              <span className="text-white font-bold text-sm">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Simple horizontal progress bar for a single severity row */
export function SeverityRow({ severity, count, max }: { severity: string; count: number; max: number }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="w-24 flex-shrink-0">
        <SeverityBadge severity={severity} showDot />
      </div>
      <div className="flex-1 bg-gray-800 rounded-full h-1.5 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: severityColor(severity) }}
        />
      </div>
      <span className="text-white font-bold text-sm w-6 text-right">{count}</span>
    </div>
  );
}
