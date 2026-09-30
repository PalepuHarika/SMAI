import { useEffect, useRef, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Navbar from '@/components/Navbar';
import api from '@/api/client';
import { VulnerabilityReport, VerifiedVulnerability } from '@/types';
import SeverityBadge from '@/components/SeverityBadge';
import DiffViewer from '@/components/DiffViewer';
import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter';
import js from 'react-syntax-highlighter/dist/esm/languages/prism/javascript';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

SyntaxHighlighter.registerLanguage('solidity', js);

// ─────────────────────────────────────────── helpers ──
function fmtTimestamp(ts: string): string {
  if (!ts) return '—';
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    }).format(new Date(ts));
  } catch {
    return ts;
  }
}

function getFriendlyName(id: string): string {
  const map: Record<string, string> = {
    'reentrancy': 'Reentrancy',
    'tx-origin': 'tx.origin Authorization Bypass',
    'floating-pragma': 'Floating Pragma',
    'unprotected-selfdestruct': 'Unprotected Self-Destruct',
    'unchecked-call': 'Unchecked Call Return Value',
    'missing-access-control': 'Missing Access Control',
    'integer-overflow': 'Integer Overflow / Underflow',
    'timestamp-dependence': 'Timestamp Dependence',
  };
  return map[id] || id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function getModeLabel(mode: string): string {
  if (mode === 'hybrid') return 'Hybrid (Static + RAG + AI)';
  if (mode === 'rag') return 'RAG Only (Static + Knowledge)';
  if (mode === 'ai') return 'AI Only (Static + Qwen)';
  return mode;
}

function getModeColor(mode: string): string {
  if (mode === 'hybrid') return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
  if (mode === 'rag') return 'bg-purple-500/10 text-purple-300 border-purple-500/30';
  if (mode === 'ai') return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
  return 'bg-gray-700 text-gray-300 border-gray-600';
}

function getRiskColors(risk: string | undefined) {
  if (risk === 'Critical Risk') return { text: 'text-red-400', border: 'border-red-500/30', bg: 'bg-red-500/10', stroke: '#ef4444' };
  if (risk === 'High Risk') return { text: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/10', stroke: '#f97316' };
  if (risk === 'Moderate Risk') return { text: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10', stroke: '#eab308' };
  return { text: 'text-green-400', border: 'border-green-500/30', bg: 'bg-green-500/10', stroke: '#22c55e' };
}

function getScoreStroke(score: number): string {
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

// ─────────────────────────────────────────── Phase 2: Score Gauge ──
function ScoreGauge({ score, risk }: { score: number; risk: string | undefined }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const fill = circ * (score / 100);
  const stroke = getScoreStroke(score);
  const riskColors = getRiskColors(risk);

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          {/* track */}
          <circle cx="60" cy="60" r={r} fill="none" stroke="#1f2937" strokeWidth="10" />
          {/* progress */}
          <circle
            cx="60" cy="60" r={r}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${fill} ${circ}`}
            style={{ transition: 'stroke-dasharray 0.8s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-extrabold text-white leading-none">{score}</span>
          <span className="text-gray-500 text-[10px]">/100</span>
        </div>
      </div>
      <p className={`mt-1.5 text-[10px] font-bold uppercase tracking-widest ${riskColors.text}`}>
        {risk ?? 'Unknown Risk'}
      </p>
      <p className="text-gray-600 text-[9px] mt-0.5 uppercase tracking-wider">Security Score</p>
    </div>
  );
}

// ─────────────────────────────────────────── Phase 1: Report Header ──
interface ReportHeaderProps {
  report: VulnerabilityReport;
  mode: string;
  confirmedCount: number;
  rejectedCount: number;
  unverifiedCount: number;
}

function ReportHeader({ report, mode, confirmedCount, rejectedCount, unverifiedCount }: ReportHeaderProps) {
  const riskColors = getRiskColors(report.risk_level);
  const isSafe = report.findings.length === 0;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden mb-6 shadow-lg">
      {/* Top stripe */}
      <div className="h-1 w-full bg-gradient-to-r from-blue-600 via-blue-500 to-indigo-600" />

      <div className="p-6 md:p-8">
        {/* Title row */}
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-6">
          <div>
            <p className="text-gray-500 text-xs font-bold uppercase tracking-widest mb-1">Security Scan Report</p>
            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
              {report.contract_name}
            </h1>
            <p className="text-gray-500 text-sm mt-1">{fmtTimestamp(report.timestamp)}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Analysis mode badge */}
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full border ${getModeColor(mode)}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-current opacity-70" />
              {getModeLabel(mode)}
            </span>
            {/* Overall verdict */}
            {isSafe ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-full border bg-green-500/10 text-green-400 border-green-500/30">
                ✓ NO ISSUES FOUND
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-full border bg-amber-500/10 text-amber-400 border-amber-500/30">
                ⚠ VULNERABILITIES DETECTED
              </span>
            )}
          </div>
        </div>

        {/* Metrics grid — responsive, wraps safely */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {/* Score gauge spans 2 cols always */}
          <div className={`col-span-2 sm:col-span-1 lg:col-span-2 flex items-center justify-center rounded-xl border py-4 ${isSafe ? 'border-green-500/20 bg-green-500/5' : `${riskColors.border} ${riskColors.bg}`}`}>
            <ScoreGauge score={report.security_score ?? 0} risk={report.risk_level} />
          </div>

          <MetricTile label="Risk Level" value={report.risk_level ?? 'Unknown'} valueClass={riskColors.text} />
          <MetricTile label="Total" value={String(report.findings.length)} />
          <MetricTile label="Confirmed" value={String(confirmedCount)} valueClass="text-green-400" />
          <MetricTile label="Rejected" value={String(rejectedCount)} valueClass="text-gray-400" />
          <MetricTile label="Unverified" value={String(unverifiedCount)} valueClass="text-amber-400" />
        </div>

        {/* Severity breakdown if there are findings */}
        {!isSafe && (
          <div className="mt-4 flex flex-wrap gap-2 pt-4 border-t border-gray-800">
            {['Critical', 'High', 'Medium', 'Low', 'Informational'].map(sev => {
              const count = report.severity_counts[sev] || 0;
              if (!count) return null;
              return <SeverityBadge key={sev} severity={sev} showDot size="sm" />;
            })}
            <span className="text-gray-600 text-xs self-center ml-1">
              {report.findings.length} finding{report.findings.length !== 1 ? 's' : ''} total
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function MetricTile({ label, value, valueClass = 'text-white' }: { label: string; value: string; valueClass?: string }) {
  return (
    <div className="bg-gray-950/60 rounded-xl border border-gray-800 px-3 py-2.5 flex flex-col justify-center min-w-0">
      <p className="text-gray-500 text-[10px] font-bold uppercase tracking-wider mb-0.5 truncate">{label}</p>
      <p className={`text-xl font-extrabold ${valueClass} leading-none`}>{value}</p>
    </div>
  );
}

// ─────────────────────────────────────────── Source Code Panel ──
interface SourcePanelProps {
  source: string;
  findings: VerifiedVulnerability[];
  selectedFindingId: string | null;
  onSelectFinding: (id: string | null) => void;
}

function SourceCodePanel({ source, findings, selectedFindingId, onSelectFinding }: SourcePanelProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  const activeFindings = selectedFindingId
    ? findings.filter(f => f.finding_id === selectedFindingId)
    : findings;

  const highlightLines: number[] = Array.from(
    new Set(activeFindings.flatMap(f => f.affected_lines ?? []))
  ).sort((a, b) => a - b);

  useEffect(() => {
    if (!containerRef.current || highlightLines.length === 0) return;
    const lineHeight = 19.2;
    const offset = (highlightLines[0] - 1) * lineHeight;
    containerRef.current.scrollTop = Math.max(0, offset - 80);
  }, [selectedFindingId]); // eslint-disable-line react-hooks/exhaustive-deps

  const lineProps = useCallback(
    (lineNumber: number): React.HTMLAttributes<HTMLElement> => {
      if (!highlightLines.includes(lineNumber)) return {};
      return {
        style: {
          display: 'block',
          backgroundColor: 'rgba(239,68,68,0.12)',
          borderLeft: '3px solid #ef4444',
          marginLeft: '-3px',
          paddingLeft: '4px',
        },
      };
    },
    [highlightLines] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const activeFinding = selectedFindingId ? findings.find(f => f.finding_id === selectedFindingId) : null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col h-full min-w-0">
      {/* Panel header */}
      <div className="px-4 py-3 border-b border-gray-800 bg-gray-900/80 flex-shrink-0 min-w-0">
        <div className="flex items-center justify-between mb-2 gap-2">
          <h3 className="text-white font-bold text-sm flex items-center gap-2 truncate">
            <span className="text-blue-400 font-mono text-xs flex-shrink-0">{'<>'}</span>
            <span className="truncate">{activeFinding ? getFriendlyName(activeFinding.vulnerability) : 'Vulnerable Source Code'}</span>
          </h3>
          {selectedFindingId && (
            <button
              onClick={() => onSelectFinding(null)}
              className="text-[11px] text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-2 py-0.5 rounded transition-colors flex-shrink-0"
            >
              Show All
            </button>
          )}
        </div>

        {/* Finding toolbar */}
        {findings.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {findings.map((f, idx) => {
              const isActive = selectedFindingId === f.finding_id;
              const firstLine = f.affected_lines?.[0];
              return (
                <button
                  key={f.finding_id}
                  onClick={() => onSelectFinding(isActive ? null : f.finding_id)}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded border transition-all flex items-center gap-1
                    ${isActive
                      ? 'bg-blue-600/20 border-blue-500 text-blue-300'
                      : 'bg-gray-950 border-gray-700 text-gray-400 hover:border-gray-500 hover:text-gray-200'
                    }`}
                >
                  <span className="font-bold">#{idx + 1}</span>
                  <span className="hidden sm:inline max-w-[90px] truncate">{getFriendlyName(f.vulnerability)}</span>
                  {firstLine != null && <span className="text-gray-500 text-[10px]">L{firstLine}</span>}
                </button>
              );
            })}
          </div>
        )}

        {highlightLines.length > 0 && (
          <p className="text-[11px] text-red-400 mt-2 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />
            Lines {highlightLines.slice(0, 8).join(', ')}{highlightLines.length > 8 ? ` +${highlightLines.length - 8} more` : ''} flagged
          </p>
        )}
      </div>

      {/* Scrollable code area — overflow-x-auto keeps long lines inside the panel */}
      <div ref={containerRef} className="overflow-y-auto overflow-x-auto flex-1" style={{ maxHeight: '560px' }}>
        <SyntaxHighlighter
          language="solidity"
          style={vscDarkPlus}
          showLineNumbers
          wrapLines
          lineProps={lineProps}
          customStyle={{
            margin: 0,
            borderRadius: 0,
            fontSize: '0.72rem',
            lineHeight: '1.6',
            background: 'transparent',
            padding: '12px 0',
            minWidth: 0,
          }}
          lineNumberStyle={{
            color: '#374151',
            minWidth: '3em',
            paddingRight: '1.2em',
            userSelect: 'none',
            textAlign: 'right',
          }}
        >
          {source}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────── Accordion Section ──
function AccordionSection({
  title,
  icon,
  defaultOpen = false,
  children,
  badge,
}: {
  title: string;
  icon?: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
  badge?: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-t border-gray-800/60">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-3.5 text-left hover:bg-gray-800/30 transition-colors"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-gray-300">
          {icon && <span className="text-gray-500">{icon}</span>}
          {title}
          {badge}
        </span>
        <span className={`text-gray-500 text-xs transition-transform duration-200 ${open ? 'rotate-180' : ''}`}>▾</span>
      </button>
      {open && (
        <div className="px-5 pb-5 space-y-3">
          {children}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────── Code Block ──
function CodeBlock({ code, startLine = 1 }: { code: string; startLine?: number }) {
  return (
    <div className="rounded-lg overflow-hidden border border-gray-800 text-xs bg-[#0d1117] min-w-0">
      <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800/80 border-b border-gray-700">
        <span className="w-2 h-2 rounded-full bg-red-500/70" />
        <span className="w-2 h-2 rounded-full bg-yellow-500/70" />
        <span className="w-2 h-2 rounded-full bg-green-500/70" />
      </div>
      <div className="overflow-x-auto">
        <SyntaxHighlighter
          language="solidity"
          style={vscDarkPlus}
          showLineNumbers
          startingLineNumber={startLine}
          wrapLines
          customStyle={{ margin: 0, borderRadius: 0, fontSize: '0.71rem', lineHeight: '1.6', background: 'transparent', padding: '10px 0' }}
          lineNumberStyle={{ color: '#374151', minWidth: '3em', paddingRight: '1em', userSelect: 'none', textAlign: 'right' }}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────── Finding Card (Phases 3, 5–9) ──
function FindingCard({
  f,
  index,
  isActive,
  onSelect,
  analysisId,
  onUpdateFinding,
}: {
  f: VerifiedVulnerability;
  index: number;
  isActive: boolean;
  onSelect: () => void;
  analysisId?: string;
  onUpdateFinding?: (updated: VerifiedVulnerability) => void;
}) {
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState('');

  const handleVerifyFix = async () => {
    if (!analysisId || !f.fixed_code || f.fixed_code === 'N/A') return;
    setVerifying(true);
    setVerifyError('');
    try {
      const res = await api.post('/api/analysis/verify-fix', {
        analysis_id: analysisId,
        finding_id: f.finding_id,
        fixed_code: f.fixed_code,
      });
      if (onUpdateFinding) {
        onUpdateFinding({
          ...f,
          fix_verified: res.data.fix_verified,
          fix_verification_reason: res.data.verification_reason,
        });
      }
    } catch (err: any) {
      setVerifyError(err.response?.data?.detail || 'Fix verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const isConfirmed = f.verification_status === 'CONFIRMED';
  const isRejected = f.verification_status === 'REJECTED';
  const isUnverified = !isConfirmed && !isRejected;

  const hasRag = Boolean(f.retrieved_knowledge && f.retrieved_knowledge.length > 0);
  const hasBeforeAfter = Boolean(
    f.original_code && f.original_code !== 'Code unavailable' && f.original_code !== 'N/A' &&
    f.fixed_code && f.fixed_code !== 'N/A'
  );

  const statusChip = isConfirmed
    ? <span className="text-[11px] font-bold text-green-400 bg-green-500/10 border border-green-500/30 px-2 py-0.5 rounded-full">✓ AI Confirmed</span>
    : isRejected
      ? <span className="text-[11px] font-bold text-gray-400 bg-gray-700/50 border border-gray-600/40 px-2 py-0.5 rounded-full">✗ Rejected</span>
      : <span className="text-[11px] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded-full">⚠ Unverified</span>;

  return (
    <div
      id={`finding-${f.finding_id}`}
      className={`border rounded-xl overflow-hidden mb-4 shadow-sm transition-all duration-200 min-w-0
        ${isActive ? 'border-blue-500/50 shadow-blue-950/30 shadow-md' : 'border-gray-800 bg-gray-900'}`}
    >
      {/* ── Card Header (always visible, clickable) ── */}
      <div
        className="p-5 cursor-pointer hover:bg-gray-800/40 transition-colors"
        onClick={onSelect}
      >
        {/* Top row: number + severity + SWC + status */}
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <span className="text-gray-600 text-xs font-mono font-bold">#{index + 1}</span>
          <SeverityBadge severity={f.severity} showDot />
          {f.swc_id && (
            <span className="text-[11px] font-mono text-gray-500 bg-gray-800 px-2 py-0.5 rounded border border-gray-700">
              {f.swc_id}
            </span>
          )}
          {statusChip}
        </div>

        {/* Name */}
        <h3 className="text-lg font-bold text-white mb-2 capitalize">
          {getFriendlyName(f.vulnerability)}
        </h3>

        {/* Quick stats */}
        <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-gray-400 mb-3">
          {f.function && (
            <span>Function: <code className="text-gray-300 font-mono">{f.function}</code></span>
          )}
          <span>
            Affected Lines:{' '}
            <code className="text-gray-300 font-mono">
              {f.affected_lines?.length ? f.affected_lines.join(', ') : 'N/A'}
            </code>
          </span>
          <span>
            Confidence:{' '}
            <span className="text-white font-semibold">{(f.confidence * 100).toFixed(1)}%</span>
          </span>
        </div>

        {/* Short explanation preview */}
        {f.explanation && (
          <p className="text-gray-400 text-sm leading-relaxed line-clamp-2">
            {f.explanation}
          </p>
        )}
      </div>

      {/* ── UNVERIFIED banner ── */}
      {isUnverified && (
        <div className="mx-5 mb-4 rounded-lg bg-amber-950/40 border border-amber-500/40 px-4 py-3">
          <p className="text-amber-400 font-bold text-xs uppercase tracking-wide mb-1">⚠ Verification Incomplete</p>
          <p className="text-amber-200/70 text-xs leading-relaxed">
            AI verification could not be completed. This result requires manual security review.{' '}
            <strong className="text-amber-300">Do not assume the contract is safe.</strong>
          </p>
        </div>
      )}

      {/* ══ ACCORDION SECTIONS ══ */}

      {/* Phase 3: What is the problem */}
      <AccordionSection title="What is the problem?" icon="❓" defaultOpen>
        <p className="text-gray-300 text-sm leading-relaxed">{f.explanation || 'No explanation available.'}</p>
        {f.contract && (
          <p className="text-xs text-gray-500 mt-2">
            Contract: <code className="text-gray-400 font-mono">{f.contract}</code>
            {f.function && <> · Function: <code className="text-gray-400 font-mono">{f.function}</code></>}
          </p>
        )}
      </AccordionSection>

      {/* Phase 3: Where is it */}
      <AccordionSection title="Where is it in my code?" icon="📍">
        <div className="text-sm text-gray-400 mb-3">
          Found at{' '}
          {f.contract && <><code className="text-gray-300 font-mono">{f.contract}</code> → </>}
          {f.function && <><code className="text-gray-300 font-mono">{f.function}()</code> · </>}
          Lines: <code className="text-gray-300 font-mono">{f.affected_lines?.join(', ') || 'N/A'}</code>
        </div>
        {f.original_code && f.original_code !== 'Code unavailable' ? (
          <CodeBlock code={f.original_code} startLine={f.affected_lines?.[0] ?? 1} />
        ) : (
          <p className="text-gray-600 text-xs italic">Code snippet unavailable — see source viewer.</p>
        )}
      </AccordionSection>

      {/* Phase 5: Static Analysis */}
      <AccordionSection
        title="Static Analysis"
        icon="🔎"
        badge={
          <span className="text-[10px] text-gray-600 font-mono ml-2">
            {f.swc_id || f.vulnerability}
          </span>
        }
      >
        <div className="space-y-3">
          <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-gray-500 font-bold uppercase tracking-wider mb-1">Detection Reason</p>
            <p className="text-sm text-gray-300 font-mono leading-relaxed break-words">
              {f.static_evidence || 'Static evidence not available.'}
            </p>
          </div>

          <details className="group">
            <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-300 select-none list-none flex items-center gap-1">
              <span className="transition-transform group-open:rotate-90">▶</span> View Technical Details
            </summary>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div className="bg-gray-950/60 rounded border border-gray-800 p-2">
                <span className="block text-gray-600 uppercase text-[10px] mb-0.5">Category</span>
                <span className="text-gray-300 font-mono">{f.vulnerability}</span>
              </div>
              <div className="bg-gray-950/60 rounded border border-gray-800 p-2">
                <span className="block text-gray-600 uppercase text-[10px] mb-0.5">SWC ID</span>
                <span className="text-gray-300 font-mono">{f.swc_id || 'N/A'}</span>
              </div>
              <div className="bg-gray-950/60 rounded border border-gray-800 p-2">
                <span className="block text-gray-600 uppercase text-[10px] mb-0.5">Static Confidence</span>
                <span className="text-gray-300 font-mono">
                  {f.static_confidence != null ? `${(f.static_confidence * 100).toFixed(1)}%` : 'N/A'}
                </span>
              </div>
              <div className="bg-gray-950/60 rounded border border-gray-800 p-2">
                <span className="block text-gray-600 uppercase text-[10px] mb-0.5">Finding ID</span>
                <span className="text-gray-400 font-mono text-[10px] break-all">{f.finding_id}</span>
              </div>
            </div>
          </details>
        </div>
      </AccordionSection>

      {/* Phase 6: RAG Evidence */}
      <AccordionSection
        title="Security Knowledge Used"
        icon="📚"
        badge={
          hasRag
            ? <span className="text-[10px] text-purple-400 font-semibold ml-2">RAG</span>
            : <span className="text-[10px] text-gray-600 ml-2">not used</span>
        }
      >
        {hasRag ? (
          <div className="space-y-2">
            <p className="text-[11px] text-gray-500 uppercase font-bold tracking-wider">Retrieved Security Knowledge</p>
            {(f.retrieved_knowledge ?? []).map((k, i) => {
              const name = String((k as Record<string,unknown>).name || (k as Record<string,unknown>).vulnerability || 'Security Pattern');
              const desc = String((k as Record<string,unknown>).description || '');
              const swc = String((k as Record<string,unknown>).swc_id || '');
              return (
                <div key={i} className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-300 text-xs font-semibold">{name}</span>
                    {swc && <span className="text-gray-600 text-[10px] font-mono">{swc}</span>}
                  </div>
                  {desc && <p className="text-gray-400 text-xs leading-relaxed line-clamp-3">{desc}</p>}
                </div>
              );
            })}
            {f.rag_similarity_score != null && (
              <p className="text-[10px] text-gray-600">
                Top retrieval relevance score: <span className="text-gray-400 font-mono">{f.rag_similarity_score.toFixed(4)}</span>
                {' '}(higher = closer match to known vulnerability patterns)
              </p>
            )}
            {f.rag_explanation && (
              <div className="bg-gray-950/60 rounded border border-gray-800 p-3">
                <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider mb-1">RAG Explanation</p>
                <p className="text-xs text-gray-300 leading-relaxed">{f.rag_explanation}</p>
              </div>
            )}
          </div>
        ) : (
          <p className="text-gray-500 text-sm italic">
            RAG was not used for this scan. Switch to Hybrid or RAG Only mode to include security knowledge retrieval.
          </p>
        )}
      </AccordionSection>

      {/* Phase 7: AI Verification */}
      <AccordionSection
        title="AI Verification"
        icon="🤖"
        badge={
          isConfirmed
            ? <span className="text-[10px] text-green-400 font-semibold ml-2">Confirmed</span>
            : isRejected
              ? <span className="text-[10px] text-gray-400 font-semibold ml-2">Rejected</span>
              : <span className="text-[10px] text-amber-400 font-semibold ml-2">Incomplete</span>
        }
      >
        <div className="space-y-3">
          {/* Model + status */}
          <div className="flex flex-wrap gap-3">
            <div className="bg-gray-950/60 rounded border border-gray-800 p-3 flex-1 min-w-[130px]">
              <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider mb-0.5">AI Model</p>
              <p className="text-gray-300 text-sm font-mono">{f.model_used ?? 'Qwen2.5-Coder'}</p>
            </div>
            <div className="bg-gray-950/60 rounded border border-gray-800 p-3 flex-1 min-w-[130px]">
              <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider mb-0.5">Status</p>
              {isConfirmed
                ? <p className="text-green-400 font-bold text-sm">✓ Confirmed</p>
                : isRejected
                  ? <p className="text-gray-400 font-bold text-sm">✗ Rejected</p>
                  : <p className="text-amber-400 font-bold text-sm">⚠ Incomplete</p>}
            </div>
            <div className="bg-gray-950/60 rounded border border-gray-800 p-3 flex-1 min-w-[130px]">
              <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider mb-0.5">Confidence</p>
              <p className="text-white font-bold text-sm">{(f.confidence * 100).toFixed(1)}%</p>
            </div>
          </div>

          {/* Disclaimer */}
          <p className="text-[11px] text-gray-600 italic">
            Note: The static analyzer classification is authoritative. AI verification supplements, but does not override, static analysis results.
          </p>

          {/* Explanation */}
          {f.explanation && (
            <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
              <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider mb-1">AI Explanation</p>
              <p className="text-gray-300 text-sm leading-relaxed">{f.explanation}</p>
            </div>
          )}

          {/* Attack scenario (not for unverified) */}
          {!isUnverified && f.attack_scenario && (
            <div className="bg-red-950/10 rounded-lg border border-red-500/10 p-3">
              <p className="text-[10px] text-red-500/80 uppercase font-bold tracking-wider mb-1">⚡ Attack Scenario</p>
              <p className="text-gray-300 text-sm leading-relaxed">{f.attack_scenario}</p>
            </div>
          )}

          {/* Fallback warning */}
          {f.fallback_used && (
            <div className="bg-amber-950/20 rounded border border-amber-500/20 p-3">
              <p className="text-amber-400 text-xs font-bold mb-0.5">⚠ Fallback Used</p>
              <p className="text-amber-200/70 text-xs">{f.fallback_reason || 'AI inference was unavailable; static analysis result was used as-is.'}</p>
            </div>
          )}
        </div>
      </AccordionSection>

      {/* Phase 8: Remediation */}
      <AccordionSection title="Recommended Fix" icon="🛠">
        <div className="space-y-3">
          {/* Problem summary */}
          <div className="bg-red-950/10 rounded-lg border border-red-500/10 p-3">
            <p className="text-[10px] text-red-400/80 uppercase font-bold tracking-wider mb-1">Problem</p>
            <p className="text-gray-300 text-sm leading-relaxed">
              {f.static_evidence || f.explanation || 'See explanation above.'}
            </p>
          </div>

          {/* Recommendation */}
          <div className="bg-green-950/10 rounded-lg border border-green-500/10 p-3">
            <p className="text-[10px] text-green-400/80 uppercase font-bold tracking-wider mb-1">Recommended Solution</p>
            <p className="text-gray-300 text-sm leading-relaxed">
              {f.recommendation || 'Review the affected code manually.'}
            </p>
          </div>

          {/* Fixed code & verification */}
          {f.fixed_code && f.fixed_code !== 'N/A' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">Example Corrected Code</p>
                {analysisId && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleVerifyFix();
                    }}
                    disabled={verifying}
                    className="text-xs px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 disabled:opacity-50 transition-colors flex items-center gap-1.5"
                  >
                    {verifying && <span className="w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />}
                    {verifying ? 'Verifying...' : 'Re-verify Fix'}
                  </button>
                )}
              </div>
              <CodeBlock code={f.fixed_code} />

              {verifyError && (
                <p className="text-xs text-red-400">{verifyError}</p>
              )}

              {/* Fix Verification Status */}
              <div
                className={`rounded-lg border p-3 ${
                  f.fix_verified
                    ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                    : 'bg-amber-950/20 border-amber-500/30 text-amber-300'
                }`}
              >
                <div className="flex items-center gap-2 font-bold text-xs tracking-wider">
                  <span>{f.fix_verified ? '✓ FIX VERIFIED' : '⚠ FIX NOT VERIFIED'}</span>
                </div>
                <p className="text-xs mt-1 text-gray-300">
                  {f.fix_verification_reason || (
                    f.fix_verified
                      ? 'Vulnerability resolved and no new High/Critical findings'
                      : (f.fix_verified === false
                          ? 'Target vulnerability still detected'
                          : 'Verification unavailable')
                  )}
                </p>
                <p className="text-[10px] text-gray-500 mt-1.5">
                  Compiler verification: not performed (solc not available in runtime). Automated verification does not guarantee the contract is completely secure.
                </p>
              </div>
            </div>
          )}

          <p className="text-[11px] text-gray-600 italic">
            ⚠ Fix requires manual review. Do not deploy automatically generated code without audit.
          </p>
        </div>
      </AccordionSection>

      {/* Phase 9: Before / After diff */}
      {hasBeforeAfter && (
        <AccordionSection title="Before / After — Vulnerable vs. Fixed" icon="↔">
          <DiffViewer
            original={f.original_code}
            fixed={f.fixed_code}
            label="Vulnerable code → Suggested fix"
          />
          <p className="text-[11px] text-gray-600 italic mt-2">
            Red lines show the vulnerable code. Green lines show the suggested replacement. Fix requires manual review.
          </p>
        </AccordionSection>
      )}
    </div>
  );
}

// ─────────────────────────────────────────── Safe Contract Banner ──
function SafeBanner({ report }: { report: VulnerabilityReport }) {
  return (
    <div className="bg-gray-900 border border-green-500/20 rounded-xl p-8 text-center shadow-lg">
      <div className="text-green-500 text-5xl mb-4">✓</div>
      <h2 className="text-2xl font-extrabold text-white mb-2">No Vulnerabilities Detected</h2>
      <p className="text-gray-400 text-sm mb-6 max-w-md mx-auto">
        Your contract did not trigger any of the known vulnerability checks. No issues were detected.
      </p>
      <div className="grid grid-cols-2 gap-3 max-w-xs mx-auto mb-4">
        <div className="bg-gray-950 rounded-lg p-3 border border-gray-800">
          <p className="text-gray-500 text-[10px] uppercase font-bold mb-1">Security Score</p>
          <p className="text-white text-xl font-extrabold">{report.security_score ?? '—'} / 100</p>
        </div>
        <div className="bg-gray-950 rounded-lg p-3 border border-gray-800">
          <p className="text-gray-500 text-[10px] uppercase font-bold mb-1">Risk Level</p>
          <p className="text-green-400 text-lg font-extrabold">{report.risk_level ?? 'Safe'}</p>
        </div>
      </div>
      <p className="text-gray-600 text-xs max-w-sm mx-auto">
        No automated scanner can guarantee a contract is completely secure. Manual audit is always recommended for financial code.
      </p>
    </div>
  );
}

// ─────────────────────────────────────────── Phase 3: Blockchain Audit Integrity ──
interface BlockchainSectionProps {
  report: VulnerabilityReport;
  analysisId: string;
}

function BlockchainSection({ report, analysisId }: BlockchainSectionProps) {
  const [registering, setRegistering] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [registerResult, setRegisterResult] = useState<any>(null);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [showDetails, setShowDetails] = useState(false);

  const isRegistered = report.on_chain_status === 'registered';

  const handleRegister = async () => {
    setRegistering(true);
    setRegisterResult(null);
    try {
      const res = await api.post(`/api/analysis/${analysisId}/register-on-chain`);
      setRegisterResult(res.data);
    } catch (err: any) {
      setRegisterResult({ error: err.response?.data?.detail || 'Registration failed' });
    } finally {
      setRegistering(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.get(`/api/analysis/${analysisId}/verify-on-chain`);
      setVerifyResult(res.data);
    } catch (err: any) {
      setVerifyResult({ error: err.response?.data?.detail || 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  if (!isRegistered && !registerResult) {
    // Show registration option
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <span className="text-blue-400 text-lg">⛓</span>
            <h3 className="text-sm font-bold text-white">Blockchain Audit Registry</h3>
          </div>
          <span className="text-[10px] text-gray-500 bg-gray-800 px-2 py-0.5 rounded">Optional</span>
        </div>
        <p className="text-gray-400 text-xs mb-4 leading-relaxed">
          Register this audit's integrity hashes on-chain for verifiable provenance. This does NOT prove the security analysis is correct — only that these specific hashes were recorded.
        </p>
        <button
          onClick={handleRegister}
          disabled={registering}
          className="text-xs px-4 py-2 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 disabled:opacity-50 transition-colors flex items-center gap-2"
        >
          {registering && <span className="w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />}
          {registering ? 'Registering...' : 'Register on Blockchain'}
        </button>
        {registerResult && (
          <div className={`mt-3 rounded-lg border p-3 ${
            registerResult.registered
              ? 'bg-green-950/20 border-green-500/30 text-green-300'
              : 'bg-gray-800 border-gray-700 text-gray-400'
          }`}>
            <p className="text-xs font-semibold mb-1">
              {registerResult.registered ? '✓ Registered' : 'Registration Unavailable'}
            </p>
            <p className="text-[10px]">{registerResult.message}</p>
          </div>
        )}
      </div>
    );
  }

  // Show registered status
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-green-400 text-lg">⛓</span>
          <h3 className="text-sm font-bold text-white">Blockchain Audit Registry</h3>
        </div>
        {isRegistered && (
          <span className="text-[10px] text-green-400 bg-green-500/10 border border-green-500/30 px-2 py-0.5 rounded-full">
            ✓ Registered
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
        <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
          <p className="text-[10px] text-gray-500 uppercase font-bold mb-1">Audit ID</p>
          <p className="text-gray-300 text-xs font-mono break-all">{report.audit_id || '—'}</p>
        </div>
        <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
          <p className="text-[10px] text-gray-500 uppercase font-bold mb-1">Transaction Hash</p>
          <p className="text-gray-300 text-xs font-mono break-all">{report.tx_hash || '—'}</p>
        </div>
        <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
          <p className="text-[10px] text-gray-500 uppercase font-bold mb-1">Registry Address</p>
          <p className="text-gray-300 text-xs font-mono break-all">{report.registry_address || '—'}</p>
        </div>
        <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
          <p className="text-[10px] text-gray-500 uppercase font-bold mb-1">Chain ID</p>
          <p className="text-gray-300 text-xs font-mono">{report.chain_id || '—'}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <button
          onClick={handleVerify}
          disabled={verifying}
          className="text-xs px-3 py-1.5 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 border border-purple-500/30 disabled:opacity-50 transition-colors flex items-center gap-1.5"
        >
          {verifying && <span className="w-2.5 h-2.5 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />}
          {verifying ? 'Verifying...' : 'Verify Integrity'}
        </button>
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-xs px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-400 border border-gray-700 transition-colors"
        >
          {showDetails ? 'Hide Details' : 'Show Details'}
        </button>
      </div>

      {verifyResult && (
        <div className={`mb-3 rounded-lg border p-3 ${
          verifyResult.verified
            ? 'bg-green-950/20 border-green-500/30 text-green-300'
            : 'bg-amber-950/20 border-amber-500/30 text-amber-300'
        }`}>
          <p className="text-xs font-semibold mb-1">
            {verifyResult.verified ? '✓ Integrity Verified' : '⚠ Integrity Check Failed'}
          </p>
          <p className="text-[10px]">{verifyResult.message}</p>
        </div>
      )}

      {showDetails && (
        <div className="border-t border-gray-800 pt-4 mt-4 space-y-3">
          <p className="text-[11px] text-gray-500 italic leading-relaxed">
            Blockchain registration proves that these hashes were recorded on-chain and can be checked later. It does NOT prove that the security analysis itself is correct.
          </p>
          <div className="grid grid-cols-1 gap-2">
            <div className="bg-gray-950/40 rounded border border-gray-800 p-2">
              <p className="text-[10px] text-gray-600 uppercase font-bold mb-0.5">Source Hash (Local)</p>
              <p className="text-gray-400 text-[10px] font-mono break-all">{report.source_hash || '—'}</p>
            </div>
            <div className="bg-gray-950/40 rounded border border-gray-800 p-2">
              <p className="text-[10px] text-gray-600 uppercase font-bold mb-0.5">Report Hash (Local)</p>
              <p className="text-gray-400 text-[10px] font-mono break-all">{report.report_hash || '—'}</p>
            </div>
            {verifyResult && verifyResult.on_chain_contract_hash && (
              <div className="bg-gray-950/40 rounded border border-gray-800 p-2">
                <p className="text-[10px] text-gray-600 uppercase font-bold mb-0.5">Source Hash (On-Chain)</p>
                <p className="text-gray-400 text-[10px] font-mono break-all">{verifyResult.on_chain_contract_hash}</p>
              </div>
            )}
            {verifyResult && verifyResult.on_chain_report_hash && (
              <div className="bg-gray-950/40 rounded border border-gray-800 p-2">
                <p className="text-[10px] text-gray-600 uppercase font-bold mb-0.5">Report Hash (On-Chain)</p>
                <p className="text-gray-400 text-[10px] font-mono break-all">{verifyResult.on_chain_report_hash}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────── Main Page ──
export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<VulnerabilityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pollCount, setPollCount] = useState(0);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  // Read persisted mode from sessionStorage
  const mode = (id ? sessionStorage.getItem(`smai_mode_${id}`) : null) ?? '';

  useEffect(() => {
    if (!id) return;
    let timer: number;
    const fetchReport = async () => {
      try {
        const r = await api.get(`/api/analysis/${id}`);
        if (r.data.status === 'PENDING') {
          timer = window.setTimeout(() => setPollCount(p => p + 1), 2000);
        } else if (r.data.status === 'FAILED') {
          setError('Analysis failed during execution.');
          setLoading(false);
        } else {
          setReport(r.data);
          setLoading(false);
        }
      } catch {
        setError('Backend connection unavailable. Make sure the SMAI backend is running and try again.');
        setLoading(false);
      }
    };
    fetchReport();
    return () => clearTimeout(timer);
  }, [id, pollCount]);

  const handleSelectFinding = useCallback((findingId: string | null) => {
    setSelectedFindingId(prev => (prev === findingId ? null : findingId));
    if (findingId) {
      setTimeout(() => {
        document.getElementById(`finding-${findingId}`)?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 50);
    }
  }, []);

  // ── Loading ──
  if (loading) return (
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <Navbar />
      <div className="flex-1 flex flex-col items-center justify-center gap-4 text-gray-400">
        <div className="w-10 h-10 border-4 border-gray-700 border-t-blue-500 rounded-full animate-spin" />
        <h2 className="text-xl font-bold text-white">Analyzing your contract…</h2>
        <p className="text-sm text-gray-500">SMAI is performing static analysis and AI verification.</p>
      </div>
    </div>
  );

  // ── Error ──
  if (error || !report) return (
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <Navbar />
      <div className="max-w-2xl mx-auto px-6 py-16 text-center flex-1 flex flex-col justify-center">
        <h2 className="text-xl font-bold text-white mb-3">Connection Error</h2>
        <p className="text-gray-400 mb-8 text-sm">{error || 'Report data unavailable.'}</p>
        <button onClick={() => navigate('/scan')} className="bg-gray-800 hover:bg-gray-700 text-white px-6 py-2 rounded-lg mx-auto">
          ← Back to Scanner
        </button>
      </div>
    </div>
  );

  const isSafe = report.findings.length === 0;
  const confirmedCount = report.findings.filter(f => f.verification_status === 'CONFIRMED').length;
  const rejectedCount = report.findings.filter(f => f.verification_status === 'REJECTED').length;
  const unverifiedCount = report.findings.filter(f => f.verification_status === 'UNVERIFIED' || !f.verification_status).length;
  const hasSource = Boolean(report.source_code);

  return (
    <div className="min-h-screen bg-gray-950 font-sans pb-20 overflow-x-hidden">
      <Navbar />
      <div className="max-w-7xl mx-auto px-4 md:px-6 py-6 w-full">

        {/* Back nav */}
        <button onClick={() => navigate('/scan')} className="text-gray-500 hover:text-gray-300 text-sm mb-5 flex items-center gap-2">
          ← Back to Scanner
        </button>

        {/* Phase 1: Professional header */}
        <ReportHeader
          report={report}
          mode={mode}
          confirmedCount={confirmedCount}
          rejectedCount={rejectedCount}
          unverifiedCount={unverifiedCount}
        />

        {/* Unverified warning banner (issue 3) */}
        {!isSafe && unverifiedCount > 0 && confirmedCount === 0 && rejectedCount === 0 && (
          <div className="mb-6 flex items-start gap-3 bg-amber-950/30 border border-amber-500/30 rounded-xl px-5 py-4">
            <span className="text-amber-400 text-lg flex-shrink-0">⚠</span>
            <div>
              <p className="text-amber-400 font-bold text-sm">Verification Incomplete</p>
              <p className="text-amber-200/70 text-sm mt-0.5 leading-relaxed">
                Static analysis detected findings, but AI verification was not completed. Manual security review is recommended.
              </p>
            </div>
          </div>
        )}
        {!isSafe && unverifiedCount > 0 && (confirmedCount > 0 || rejectedCount > 0) && (
          <div className="mb-6 flex items-start gap-3 bg-amber-950/20 border border-amber-500/20 rounded-xl px-5 py-3">
            <span className="text-amber-400 text-sm flex-shrink-0 mt-0.5">⚠</span>
            <p className="text-amber-200/60 text-sm leading-relaxed">
              {unverifiedCount} finding{unverifiedCount !== 1 ? 's' : ''} could not be AI-verified. Manual review is recommended for unverified items.
            </p>
          </div>
        )}

        {/* Safe banner */}
        {isSafe && <SafeBanner report={report} />}

        {/* Phase 3: Blockchain Audit Integrity section */}
        <BlockchainSection report={report} analysisId={report.analysis_id} />

        {/* Phase 4: Two-column layout */}
        {!isSafe && (
          <>
            {/* Mobile: source viewer above findings */}
            {hasSource && (
              <div className="lg:hidden mb-6 min-w-0">
                <SourceCodePanel
                  source={report.source_code!}
                  findings={report.findings}
                  selectedFindingId={selectedFindingId}
                  onSelectFinding={setSelectedFindingId}
                />
              </div>
            )}

            {/* Desktop: two-column grid */}
            <div
              className="lg:grid lg:gap-6 w-full"
              style={{ gridTemplateColumns: hasSource ? 'minmax(0,1fr) minmax(0,420px)' : '1fr' }}
            >
              {/* LEFT: Findings — min-w-0 prevents overflow */}
              <div className="min-w-0">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-bold text-white">Vulnerability Findings</h2>
                  <span className="text-gray-500 text-sm">{report.findings.length} total</span>
                </div>

                {report.findings.map((f, idx) => (
                  <FindingCard
                    key={f.finding_id}
                    f={f}
                    index={idx}
                    isActive={selectedFindingId === f.finding_id}
                    onSelect={() => handleSelectFinding(f.finding_id)}
                    analysisId={report.analysis_id}
                    onUpdateFinding={(updated) => {
                      setReport(prev => {
                        if (!prev) return prev;
                        return {
                          ...prev,
                          findings: prev.findings.map(item => item.finding_id === updated.finding_id ? updated : item)
                        };
                      });
                    }}
                  />
                ))}
              </div>

              {/* RIGHT: Source viewer (desktop only, sticky) */}
              {hasSource && (
                <div className="hidden lg:block min-w-0">
                  <div className="sticky top-4">
                    <SourceCodePanel
                      source={report.source_code!}
                      findings={report.findings}
                      selectedFindingId={selectedFindingId}
                      onSelectFinding={setSelectedFindingId}
                    />
                  </div>
                </div>
              )}
            </div>

            {!hasSource && (
              <div className="mt-4 bg-gray-900 border border-gray-800 rounded-xl p-5 text-sm text-gray-500">
                Source code viewer unavailable — re-scan the contract to enable line highlighting.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
