import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
const CodeViewer = lazy(() => import('@/components/CodeViewer'));
import Navbar from '@/components/Navbar';
import SeverityBadge from '@/components/SeverityBadge';
import DiffViewer from '@/components/DiffViewer';
import RiskBar from '@/components/RiskBar';
import api from '@/api/client';
import type { VulnerabilityReport, VerifiedVulnerability } from '@/types';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

function FindingCard({ f, idx }: { f: VerifiedVulnerability; idx: number }) {
  const [open, setOpen] = useState(idx === 0);
  const [activeTab, setActiveTab] = useState<'explanation' | 'code' | 'diff'>('explanation');
  const hasDiff = !!f.fixed_code && f.fixed_code !== f.original_code && f.fixed_code.trim().length > 0;

  return (
    <div className={`rounded-xl overflow-hidden border transition-colors ${f.severity === 'Critical' || f.severity === 'High'
        ? 'border-red-500/20 shadow-[0_0_12px_rgba(239,68,68,0.08)]'
        : 'border-gray-800'
      } bg-gray-900`}>
      <button onClick={() => setOpen(o => !o)}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-800/40 transition-colors">
        <div className="flex items-center gap-3 text-left">
          <span className="text-gray-500 text-xs font-mono w-5">#{idx + 1}</span>
          <div>
            <p className="text-white font-semibold text-sm">{f.vulnerability}</p>
            <p className="text-gray-400 text-xs mt-0.5">
              Lines&nbsp;
              <span className="text-amber-400 font-mono">{f.affected_lines.join(', ')}</span>
              &nbsp;·&nbsp;Confidence&nbsp;
              <span className="text-gray-300">{(f.confidence * 100).toFixed(0)}%</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={f.severity} size="md" showDot />
          <span className="text-gray-500 text-sm">{open ? '▲' : '▼'}</span>
        </div>
      </button>

      {open && (
        <div className="border-t border-gray-800">
          <div className="flex border-b border-gray-800 bg-gray-900">
            {(['explanation', 'code', ...(hasDiff ? ['diff'] : [])] as const).map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab as typeof activeTab)}
                className={`px-5 py-2.5 text-xs font-semibold capitalize transition-colors border-b-2 ${activeTab === tab
                  ? 'text-white border-blue-500'
                  : 'text-gray-500 border-transparent hover:text-gray-300'
                  }`}>
                {tab === 'code' ? '📄 Code' : tab === 'diff' ? '🛠 Fix Diff' : '💡 Explanation'}
              </button>
            ))}
          </div>
          <div className="p-5 space-y-4">
            {activeTab === 'explanation' && (
              <>
                {f.evidence && f.evidence.length > 0 && (
                  <div className="bg-blue-950/20 border border-blue-500/15 rounded-lg p-4 mb-4">
                    <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">📜 Grounded Evidence</p>
                    <ul className="text-sm text-gray-300 list-disc list-inside">
                      {f.evidence.map((ev, i) => (
                        <li key={i}>
                          Function: <code className="text-blue-300 bg-blue-950/50 px-1 rounded">{ev.function}</code> 
                          (Lines: {ev.lines.join(', ')})
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">🔎 Static Evidence</p>
                  <div className="bg-amber-950/30 border border-amber-500/20 rounded-lg px-4 py-3 text-amber-300 text-xs font-mono leading-relaxed">
                    {f.static_evidence}
                  </div>
                </div>
                <div>
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">💡 Explanation</p>
                  <p className="text-sm text-gray-300 leading-relaxed">{f.explanation}</p>
                </div>
                <div className="bg-red-950/20 border border-red-500/15 rounded-lg p-4">
                  <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">⚡ Attack Scenario</p>
                  <p className="text-sm text-gray-300 leading-relaxed">{f.attack_scenario}</p>
                </div>
                <div className="bg-green-950/20 border border-green-500/15 rounded-lg p-4">
                  <p className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-2">✅ Recommendation</p>
                  <p className="text-sm text-gray-300 leading-relaxed">{f.recommendation}</p>
                </div>
              </>
            )}
            {activeTab === 'code' && (
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                  Flagged code context — affected lines highlighted
                </p>
                <Suspense fallback={<div className='text-gray-500 text-xs p-4'>Loading highlighter...</div>}>
                <CodeViewer
                  code={f.original_code}
                  language="solidity"
                  highlightLines={f.affected_lines}
                />
                </Suspense>
              </div>
            )}
            {activeTab === 'diff' && hasDiff && (
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                  Inline diff — vulnerable pattern vs. secure remediation
                </p>
                <DiffViewer original={f.original_code} fixed={f.fixed_code} label={`${f.vulnerability} — Fix`} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<VulnerabilityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pollCount, setPollCount] = useState(0);

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
        setError('Report not found or access denied.');
        setLoading(false);
      }
    };
    fetchReport();
    return () => clearTimeout(timer);
  }, [id, pollCount]);

  if (loading) return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      <Navbar />
      <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
        <div className="animate-spin text-4xl mb-4">⚙️</div>
        <p className="font-semibold text-white">Analyzing Smart Contract...</p>
        <p className="text-sm mt-2 text-gray-500">Running static analysis and LLM verification.</p>
      </div>
    </div>
  );

  if (error || !report) return (
    <div className="min-h-screen bg-gray-950"><Navbar />
      <div className="max-w-2xl mx-auto px-6 py-16 text-center">
        <p className="text-red-400 mb-4">{error || 'Report unavailable.'}</p>
        <button onClick={() => navigate('/history')} className="text-blue-400 hover:text-blue-300 text-sm">← Back to History</button>
      </div>
    </div>
  );

  const totalFindings = report.total_findings;

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="mb-6">
          <button onClick={() => navigate('/history')} className="text-gray-500 hover:text-gray-300 text-sm mb-3 block">← Back to History</button>
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white font-mono">{report.contract_name}</h1>
              <p className="text-gray-400 text-sm mt-1">{new Date(report.timestamp).toLocaleString()}</p>
            </div>
            <span className={`text-sm font-semibold px-4 py-2 rounded-full border ${
              report.is_vulnerable ? 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.2)]' : 'bg-green-500/10 text-green-400 border-green-500/30'
            }`}>
              {report.is_vulnerable ? '⚠ Vulnerable' : '✓ Clean'}
            </span>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6 space-y-4">
          <p className="text-gray-300 text-sm leading-relaxed">{report.summary}</p>
          {totalFindings > 0 && <RiskBar counts={report.severity_counts} total={totalFindings} />}
        </div>
        {report.findings.length === 0 ? (
          <div className="text-center py-16 bg-gray-900 border border-green-500/10 rounded-xl shadow-[0_0_24px_rgba(34,197,94,0.06)]">
            <p className="text-4xl mb-3">✅</p>
            <p className="text-white font-semibold">No vulnerabilities detected</p>
            <p className="text-gray-400 text-sm mt-1">Static analysis found no suspicious patterns in this contract.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold">Findings ({report.findings.length})</h2>
              <div className="flex gap-2">
                {SEVERITIES.filter(s => (report.severity_counts[s] ?? 0) > 0).map(s => (
                  <div key={s} className="flex items-center gap-1">
                    <SeverityBadge severity={s} showDot />
                    <span className="text-white text-xs font-bold">{report.severity_counts[s]}</span>
                  </div>
                ))}
              </div>
            </div>
            {report.findings.map((f, i) => <FindingCard key={f.finding_id} f={f} idx={i} />)}
          </div>
        )}
      </div>
    </div>
  );
}
