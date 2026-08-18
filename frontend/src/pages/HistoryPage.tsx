import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from '@/components/Navbar';
import SeverityBadge from '@/components/SeverityBadge';
import api from '@/api/client';
import type { AnalysisHistoryItem } from '@/types';

export default function HistoryPage() {
  const [history, setHistory] = useState<AnalysisHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'vulnerable' | 'clean'>('all');
  const navigate = useNavigate();

  useEffect(() => {
    api.get('/api/analysis/history').then(r => setHistory(r.data)).finally(() => setLoading(false));
  }, []);

  const filtered = history.filter(h => {
    const matchSearch = h.contract_name.toLowerCase().includes(search.toLowerCase());
    const matchFilter = filter === 'all' || (filter === 'vulnerable' ? h.is_vulnerable : !h.is_vulnerable);
    return matchSearch && matchFilter;
  });

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Scan History</h1>
            <p className="text-gray-400 text-sm mt-1">{history.length} total scans</p>
          </div>
          <button onClick={() => navigate('/scan')}
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
            + New Scan
          </button>
        </div>

        {/* Filters */}
        <div className="flex gap-3 mb-6">
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search contracts..."
            className="bg-gray-900 border border-gray-800 text-white rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-gray-500 w-64" />
          {(['all', 'vulnerable', 'clean'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors capitalize ${filter === f ? 'bg-blue-600 text-white' : 'bg-gray-900 border border-gray-800 text-gray-400 hover:text-white'}`}>
              {f}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="text-center py-16 text-gray-400">Loading...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 bg-gray-900 border border-gray-800 rounded-xl">
            <p className="text-gray-400">No scans match your filter.</p>
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800">
                  <th className="px-5 py-3 text-left">Contract</th>
                  <th className="px-5 py-3 text-left">Date</th>
                  <th className="px-5 py-3 text-left">Findings</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(item => (
                  <tr key={item.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3 text-white text-sm font-mono">{item.contract_name}</td>
                    <td className="px-5 py-3 text-gray-400 text-sm">{new Date(item.created_at).toLocaleString()}</td>
                    <td className="px-5 py-3 text-sm font-medium">
                      {item.total_findings > 0
                        ? <span className="text-orange-400">{item.total_findings}</span>
                        : <span className="text-green-400">0</span>}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex gap-1 flex-wrap">
                        {['Critical', 'High'].map(s => (item.severity_counts?.[s] ?? 0) > 0 && (
                          <div key={s} className="flex items-center gap-1">
                            <SeverityBadge severity={s} />
                            <span className="text-white text-xs font-bold">{item.severity_counts[s]}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${item.is_vulnerable ? 'bg-red-900/60 text-red-300 border border-red-700' : 'bg-green-900/60 text-green-300 border border-green-700'}`}>
                        {item.is_vulnerable ? 'Vulnerable' : 'Clean'}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <button onClick={() => navigate(`/report/${item.id}`)} className="text-blue-400 hover:text-blue-300 text-xs">
                        View →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
