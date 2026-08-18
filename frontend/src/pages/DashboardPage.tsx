import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from '@/components/Navbar';
import SeverityBadge from '@/components/SeverityBadge';
import { SeverityRow } from '@/components/RiskBar';
import api from '@/api/client';
import type { AnalysisHistoryItem } from '@/types';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

export default function DashboardPage() {
  const [history, setHistory] = useState<AnalysisHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.get('/api/analysis/history').then(r => setHistory(r.data)).finally(() => setLoading(false));
  }, []);

  // Aggregate metrics
  const totalVulns = history.reduce((s, h) => s + h.total_findings, 0);
  const criticalHigh = history.reduce(
    (s, h) => s + (h.severity_counts?.Critical ?? 0) + (h.severity_counts?.High ?? 0), 0
  );
  const vulnerableScans = history.filter(h => h.is_vulnerable).length;

  // Aggregated severity counts across all scans
  const aggregatedSeverity: Record<string, number> = {};
  history.forEach(h => {
    Object.entries(h.severity_counts ?? {}).forEach(([k, v]) => {
      aggregatedSeverity[k] = (aggregatedSeverity[k] ?? 0) + v;
    });
  });
  const maxSeverity = Math.max(...Object.values(aggregatedSeverity), 1);

  const recent = history.slice(0, 7);

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* Top Row */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-gray-400 text-sm mt-1">Your vulnerability scanning overview</p>
          </div>
          <button onClick={() => navigate('/scan')}
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
            + New Scan
          </button>
        </div>

        <div className="grid grid-cols-12 gap-5">

          {/* ── Left column: Stat Cards + Risk Distribution ── */}
          <div className="col-span-12 lg:col-span-4 space-y-4">

            {/* Stat Cards */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Total Scans', value: history.length, sub: `${vulnerableScans} vulnerable`, color: 'text-blue-400' },
                { label: 'Findings', value: totalVulns, sub: 'across all scans', color: 'text-orange-400' },
                { label: 'Critical / High', value: criticalHigh, sub: 'immediate risks', color: 'text-red-400' },
                {
                  label: 'Clean Rate',
                  value: history.length > 0 ? `${Math.round(((history.length - vulnerableScans) / history.length) * 100)}%` : '—',
                  sub: 'no findings', color: 'text-green-400'
                },
              ].map(({ label, value, sub, color }) => (
                <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <p className="text-gray-400 text-xs mb-1">{label}</p>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-gray-600 text-xs mt-1">{sub}</p>
                </div>
              ))}
            </div>

            {/* Risk Distribution Chart */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h2 className="text-white font-semibold text-sm mb-4">Risk Distribution</h2>
              {totalVulns === 0 ? (
                <div className="flex items-center gap-2 text-green-400 text-sm py-2">
                  <span>✓</span> No vulnerabilities detected
                </div>
              ) : (
                <div className="space-y-3">
                  {SEVERITIES.map(s => (
                    <SeverityRow key={s} severity={s} count={aggregatedSeverity[s] ?? 0} max={maxSeverity} />
                  ))}
                </div>
              )}
            </div>

            {/* Pipeline Reference Card */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h2 className="text-white font-semibold text-sm mb-3">Analysis Pipeline</h2>
              <div className="space-y-2 text-xs text-gray-400">
                {[
                  ['🔍', 'Static Analyzer', 'Flags suspicious code patterns'],
                  ['✂️', 'Code Extractor', 'Isolates function & state context'],
                  ['📚', 'RAG Retrieval', 'Fetches matching SWC / CWE knowledge'],
                  ['🤖', 'LLM Reasoner', 'Verifies & explains findings'],
                  ['📋', 'Structured Report', 'Auditable evidence + fix diff'],
                ].map(([icon, step, desc]) => (
                  <div key={step} className="flex gap-2.5 items-start">
                    <span>{icon}</span>
                    <div>
                      <span className="text-gray-200 font-medium">{step}</span>
                      <span className="text-gray-500"> — {desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Right column: Recent Scans feed ── */}
          <div className="col-span-12 lg:col-span-8">
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden h-full">
              <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
                <h2 className="text-white font-semibold">Recent Scans</h2>
                <button onClick={() => navigate('/history')} className="text-blue-400 hover:text-blue-300 text-sm">
                  View all →
                </button>
              </div>

              {loading ? (
                <div className="p-10 text-center text-gray-500 text-sm">Loading...</div>
              ) : recent.length === 0 ? (
                <div className="p-10 text-center">
                  <p className="text-gray-500 text-sm mb-3">No scans yet.</p>
                  <button onClick={() => navigate('/scan')}
                    className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg">
                    Run your first scan →
                  </button>
                </div>
              ) : (
                <div className="divide-y divide-gray-800/60">
                  {recent.map(item => {
                    const topSev = ['Critical', 'High', 'Medium', 'Low'].find(
                      s => (item.severity_counts?.[s] ?? 0) > 0
                    );
                    return (
                      <div key={item.id}
                        onClick={() => navigate(`/report/${item.id}`)}
                        className="flex items-center gap-4 px-5 py-3.5 hover:bg-gray-800/30 cursor-pointer transition-colors group">

                        {/* Status icon */}
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 text-sm ${
                          item.is_vulnerable
                            ? 'bg-red-500/10 border border-red-500/30 text-red-400'
                            : 'bg-green-500/10 border border-green-500/30 text-green-400'
                        }`}>
                          {item.is_vulnerable ? '⚠' : '✓'}
                        </div>

                        {/* Contract info */}
                        <div className="flex-1 min-w-0">
                          <p className="text-white text-sm font-mono truncate group-hover:text-blue-300 transition-colors">
                            {item.contract_name}
                          </p>
                          <p className="text-gray-500 text-xs mt-0.5">
                            {new Date(item.created_at).toLocaleString()}
                          </p>
                        </div>

                        {/* Findings badge */}
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {item.total_findings > 0 ? (
                            <>
                              {topSev && <SeverityBadge severity={topSev} showDot />}
                              <span className="text-gray-400 text-xs">{item.total_findings} found</span>
                            </>
                          ) : (
                            <span className="text-green-400 text-xs">Clean</span>
                          )}
                        </div>

                        <span className="text-gray-600 group-hover:text-gray-400 text-sm transition-colors">→</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
