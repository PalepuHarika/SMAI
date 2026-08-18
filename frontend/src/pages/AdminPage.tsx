import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from '@/components/Navbar';
import SeverityBadge from '@/components/SeverityBadge';
import api from '@/api/client';
import type { AdminAnalytics, AdminUser, AdminAnalysis } from '@/types';

type Tab = 'overview' | 'users' | 'analyses';

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('overview');
  const [analytics, setAnalytics] = useState<AdminAnalytics | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [analyses, setAnalyses] = useState<AdminAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      api.get('/api/admin/analytics').then(r => setAnalytics(r.data)),
      api.get('/api/admin/users').then(r => setUsers(r.data)),
      api.get('/api/admin/analyses').then(r => setAnalyses(r.data)),
    ]).finally(() => setLoading(false));
  }, []);

  const severities = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white">Admin Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">System-wide analytics and user management</p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-gray-900 border border-gray-800 rounded-lg p-1 w-fit">
          {(['overview', 'users', 'analyses'] as Tab[]).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-5 py-2 rounded-md text-sm font-medium capitalize transition-colors ${tab === t ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>
              {t}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="text-center py-16 text-gray-400">Loading...</div>
        ) : tab === 'overview' && analytics ? (
          <div className="space-y-6">
            {/* Stat Cards */}
            <div className="grid grid-cols-4 gap-4">
              {[
                { label: 'Total Users', value: analytics.total_users, color: 'text-blue-400' },
                { label: 'Total Scans', value: analytics.total_analyses, color: 'text-purple-400' },
                { label: 'Total Vulnerabilities', value: analytics.total_vulnerabilities, color: 'text-orange-400' },
                { label: 'Vulnerable Ratio', value: `${(analytics.vulnerable_contracts_ratio * 100).toFixed(0)}%`, color: 'text-red-400' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                  <p className="text-gray-400 text-sm">{label}</p>
                  <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
                </div>
              ))}
            </div>

            {/* Severity Distribution */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h2 className="text-white font-semibold mb-4">Severity Distribution</h2>
              <div className="flex gap-4 flex-wrap">
                {severities.map(s => (
                  <div key={s} className="flex items-center gap-2">
                    <SeverityBadge severity={s} />
                    <span className="text-white font-bold">{analytics.severity_distribution[s] ?? 0}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Category Distribution */}
            {Object.keys(analytics.category_distribution).length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <h2 className="text-white font-semibold mb-4">Vulnerability Categories</h2>
                <div className="space-y-2">
                  {Object.entries(analytics.category_distribution)
                    .sort(([,a],[,b]) => b - a)
                    .map(([cat, count]) => (
                      <div key={cat} className="flex items-center justify-between">
                        <span className="text-gray-300 text-sm">{cat}</span>
                        <span className="text-white font-bold text-sm">{count}</span>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>

        ) : tab === 'users' ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800">
                  <th className="px-5 py-3 text-left">Email</th>
                  <th className="px-5 py-3 text-left">Role</th>
                  <th className="px-5 py-3 text-left">Scans</th>
                  <th className="px-5 py-3 text-left">Joined</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3 text-white text-sm">{u.email}</td>
                    <td className="px-5 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${u.role === 'ADMIN' ? 'bg-purple-900/60 text-purple-300 border border-purple-700' : 'bg-blue-900/60 text-blue-300 border border-blue-700'}`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-gray-300 text-sm">{u.scan_count}</td>
                    <td className="px-5 py-3 text-gray-400 text-sm">{new Date(u.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800">
                  <th className="px-5 py-3 text-left">User</th>
                  <th className="px-5 py-3 text-left">Contract</th>
                  <th className="px-5 py-3 text-left">Date</th>
                  <th className="px-5 py-3 text-left">Findings</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {analyses.map(a => (
                  <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3 text-gray-300 text-sm">{a.user_email}</td>
                    <td className="px-5 py-3 text-white text-sm font-mono">{a.contract_name}</td>
                    <td className="px-5 py-3 text-gray-400 text-sm">{new Date(a.created_at).toLocaleDateString()}</td>
                    <td className="px-5 py-3 text-sm font-medium">
                      {a.total_findings > 0 ? <span className="text-orange-400">{a.total_findings}</span> : <span className="text-green-400">0</span>}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${a.is_vulnerable ? 'bg-red-900/60 text-red-300 border border-red-700' : 'bg-green-900/60 text-green-300 border border-green-700'}`}>
                        {a.is_vulnerable ? 'Vulnerable' : 'Clean'}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <button onClick={() => navigate(`/report/${a.id}`)} className="text-blue-400 hover:text-blue-300 text-xs">
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
