type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

const config: Record<Severity, { badge: string; glow: string; dot: string }> = {
  Critical: {
    badge: 'bg-red-500/10 text-red-400 border border-red-500/30',
    glow: 'shadow-[0_0_8px_rgba(239,68,68,0.35)]',
    dot: 'bg-red-500',
  },
  High: {
    badge: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
    glow: 'shadow-[0_0_8px_rgba(249,115,22,0.35)]',
    dot: 'bg-orange-500',
  },
  Medium: {
    badge: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
    glow: '',
    dot: 'bg-yellow-400',
  },
  Low: {
    badge: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
    glow: '',
    dot: 'bg-blue-400',
  },
  Informational: {
    badge: 'bg-gray-500/10 text-gray-400 border border-gray-600/30',
    glow: '',
    dot: 'bg-gray-500',
  },
};

const fallback = config.Informational;

interface Props {
  severity: string;
  size?: 'sm' | 'md';
  showDot?: boolean;
}

export default function SeverityBadge({ severity, size = 'sm', showDot = false }: Props) {
  const c = config[severity as Severity] ?? fallback;
  const px = size === 'md' ? 'px-3 py-1 text-sm' : 'px-2.5 py-0.5 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold rounded-full ${px} ${c.badge} ${c.glow}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />}
      {severity}
    </span>
  );
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#60a5fa',
    Informational: '#6b7280',
  };
  return map[severity] ?? '#6b7280';
}
