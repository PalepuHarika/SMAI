import { useEffect, useState } from 'react';
import Navbar from '@/components/Navbar';
import api from '@/api/client';
import type { AnalysisHistoryItem } from '@/types';

function Value({ label, value }: { label: string; value?: string | number }) {
  return (
    <div className="bg-gray-950/60 rounded-lg border border-gray-800 p-3">
      <p className="text-[10px] text-gray-500 uppercase font-bold mb-1">{label}</p>
      <p className="text-gray-300 text-xs font-mono break-all">{value || 'Not available'}</p>
    </div>
  );
}

export default function TrustRegistryPage() {
  const [items, setItems] = useState<AnalysisHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get('/api/analysis/history')
      .then(response => setItems(response.data))
      .catch(err => setError(err.response?.data?.detail || 'Could not load trust records.'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <div className="max-w-6xl mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold text-white">Trust Registry</h1>
        <p className="text-gray-400 text-sm mt-1 mb-8">Integrity, provenance, and blockchain evidence for your scans.</p>
        {loading && <p className="text-gray-400">Loading trust records...</p>}
        {error && <p className="text-red-400">{error}</p>}
        {!loading && !error && items.length === 0 && <p className="text-gray-400">No audit evidence is available yet.</p>}
        <div className="space-y-5">
          {items.map(item => (
            <section key={item.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                <div>
                  <h2 className="text-white font-semibold">{item.contract_name}</h2>
                  <p className="text-gray-500 text-xs">{new Date(item.created_at).toLocaleString()}</p>
                </div>
                <span className="text-xs text-gray-400">{item.on_chain_status || 'Not registered on-chain'}</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Value label="Source SHA-256" value={item.source_hash} />
                <Value label="Source Keccak-256" value={item.source_keccak256} />
                <Value label="Report hash" value={item.report_hash} />
                <Value label="Findings Merkle root" value={item.findings_merkle_root} />
                <Value label="Analyzer version" value={item.analyzer_version} />
                <Value label="AI model" value={item.model_used} />
                <Value label="RAG version" value={item.rag_version} />
                <Value label="Compiler version" value={item.compiler_version} />
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
