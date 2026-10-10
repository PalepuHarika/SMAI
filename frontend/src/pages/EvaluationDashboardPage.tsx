import React, { useState, useEffect } from 'react';
import api from '@/api/client';
import Navbar from '@/components/Navbar';

function EvaluationPageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-[#0b0f19]">
      <Navbar />
      <main className="smai-evaluation max-w-7xl mx-auto p-5 sm:p-8">{children}</main>
    </div>
  );
}

export default function EvaluationDashboardPage() {
  const [data, setData] = useState<any>(null);
  const [rawData, setRawData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('summary');
  
  // Filters
  const [selectedDataset, setSelectedDataset] = useState('Stored evaluation results');
  const [selectedPrompt, setSelectedPrompt] = useState('P1');

  useEffect(() => {
    Promise.all([
      api.get('/api/evaluation/metrics').then(res => res.data),
      api.get('/api/evaluation/raw').then(res => res.data)
    ])
      .then(([metricsData, rawResult]) => {
        if (metricsData.detail) setError(metricsData.detail);
        else setData(metricsData);
        
        if (!rawResult.detail) setRawData(rawResult);
        setLoading(false);
      })
      .catch(err => {
        setError(err.response?.data?.detail || err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return (
    <EvaluationPageShell>
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-[#111827] px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400 shadow-sm">
        Loading benchmark metrics and ablation suite data...
      </div>
    </EvaluationPageShell>
  );
  if (error) return (
    <EvaluationPageShell>
      <div className="mx-auto max-w-md rounded-xl border border-red-200 dark:border-red-500/30 bg-red-50 dark:bg-red-950/30 p-12 text-center">
        <h2 className="text-sm font-bold text-red-800 dark:text-red-300">Evaluation Data Unavailable</h2>
        <p className="mt-1 text-xs text-red-700/80 dark:text-red-400">{error}</p>
      </div>
    </EvaluationPageShell>
  );
  if (!data) return (
    <EvaluationPageShell>
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-[#111827] px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400 shadow-sm">
        No evaluation data available.
      </div>
    </EvaluationPageShell>
  );

  // Derive unique filters
  const recordedDatasets = Array.from(new Set(Object.values(data).map((v: any) => v.dataset).filter(Boolean)));
  const allDatasets = recordedDatasets.length > 0 ? recordedDatasets : ['Stored evaluation results'];
  const activeDataset = allDatasets.includes(selectedDataset) ? selectedDataset : allDatasets[0];
  const allPrompts = Array.from(new Set(Object.values(data).map((v: any) => v.prompt).filter(Boolean)));

  // Filter keys based on selected dataset and prompt (Static mode is prompt-agnostic)
  const modes = Object.keys(data).filter(key =>
    (data[key].dataset || 'Stored evaluation results') === activeDataset &&
    (!data[key].prompt || data[key].model === 'static' || data[key].prompt === selectedPrompt)
  );
  
  return (
    <EvaluationPageShell>
      <header className="mb-7">
        <h1 className="text-2xl font-extrabold tracking-tight text-gray-900 dark:text-white">Evaluation Suite</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Empirical performance metrics, ablation studies, and confidence calibration.</p>
      </header>
      
      <div className="mb-6 flex flex-wrap items-center gap-5 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-[#111827] p-5 shadow-sm">
        <div className="flex flex-col">
          <label className="text-[10px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-1">Benchmark Dataset</label>
          <select 
            value={activeDataset}
            onChange={e => setSelectedDataset(e.target.value)}
            className="min-w-56 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 px-3 py-2 text-sm text-gray-800 dark:text-gray-100 outline-none focus:ring-2 focus:ring-blue-500"
          >
            {allDatasets.map(ds => <option key={ds} value={ds}>{ds}</option>)}
          </select>
        </div>
        
        {allPrompts.length > 0 ? <div className="flex flex-col">
          <label className="text-[10px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-1">Prompt Condition</label>
          <select 
            value={selectedPrompt} 
            onChange={e => setSelectedPrompt(e.target.value)}
            className="min-w-48 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 px-3 py-2 text-sm text-gray-800 dark:text-gray-100 outline-none focus:ring-2 focus:ring-blue-500"
          >
            {allPrompts.map(p => <option key={p} value={p}>{p === 'P0' ? 'P0 (Baseline)' : p === 'P1' ? 'P1 (Source-Grounding)' : p}</option>)}
          </select>
        </div> : <p className="text-sm text-gray-500 dark:text-gray-400">Prompt metadata is not present in these stored results.</p>}
      </div>

      <div className="mb-6 flex gap-2 overflow-x-auto border-b border-gray-200 dark:border-gray-800 pb-3">
        <button onClick={() => setActiveTab('summary')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'summary' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Overall Metrics</button>
        <button onClick={() => setActiveTab('comparison')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'comparison' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Model & RAG Ablation</button>
        <button onClick={() => setActiveTab('prompt_ablation')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'prompt_ablation' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Prompt Ablation (P0 vs P1)</button>
        <button onClick={() => setActiveTab('details')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'details' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Vulnerability & Severity</button>
        <button onClick={() => setActiveTab('grounding')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'grounding' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Grounding & Confidence</button>
        <button onClick={() => setActiveTab('contracts')} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${activeTab === 'contracts' ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'}`}>Contract-Level</button>
      </div>
      
      {activeTab === 'summary' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {modes.map(mode => (
            <div key={mode} className="bg-white p-6 rounded-lg shadow border border-gray-200">
              <h2 className="text-xl font-bold mb-4">{mode}</h2>
              <div className="space-y-2">
                <div className="flex justify-between"><span className="text-gray-600">Precision:</span><span className="font-semibold">{(data[mode].metrics.precision * 100).toFixed(1)}%</span></div>
                <div className="flex justify-between"><span className="text-gray-600">Recall:</span><span className="font-semibold">{(data[mode].metrics.recall * 100).toFixed(1)}%</span></div>
                <div className="flex justify-between"><span className="text-gray-600">F1 Score:</span><span className="font-semibold">{(data[mode].metrics.f1 * 100).toFixed(1)}%</span></div>
                <div className="flex justify-between"><span className="text-gray-600">Accuracy:</span><span className="font-semibold">{(data[mode].metrics.accuracy * 100).toFixed(1)}%</span></div>
                <div className="flex justify-between"><span className="text-gray-600">FPR:</span><span className="font-semibold">{(data[mode].metrics.fpr * 100).toFixed(1)}%</span></div>
                <div className="flex justify-between"><span className="text-gray-600">FNR:</span><span className="font-semibold">{(data[mode].metrics.fnr * 100).toFixed(1)}%</span></div>
                <div className="mt-4 pt-4 border-t">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">TP: {data[mode].TP}</span>
                    <span className="text-gray-500">TN: {data[mode].TN}</span>
                    <span className="text-gray-500">FP: {data[mode].FP}</span>
                    <span className="text-gray-500">FN: {data[mode].FN}</span>
                  </div>
                </div>
                <div className="mt-2 text-sm text-red-600">Infra Failures (OOM/Timeout): {data[mode].infra_failures}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'comparison' && (
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200 overflow-x-auto">
           <h2 className="text-xl font-bold mb-4">Comparison Matrix (Static vs RAG vs Model)</h2>
           <table className="w-full text-left border-collapse min-w-max">
             <thead>
               <tr className="bg-gray-100">
                 <th className="p-3 border">Mode/Model</th>
                 <th className="p-3 border">Precision</th>
                 <th className="p-3 border">Recall</th>
                 <th className="p-3 border">F1</th>
                 <th className="p-3 border">Accuracy</th>
                 <th className="p-3 border">Failures</th>
               </tr>
             </thead>
             <tbody>
               {modes.map(mode => (
                 <tr key={mode} className="border-b hover:bg-gray-50">
                   <td className="p-3 border font-semibold">{mode}</td>
                   <td className="p-3 border">{(data[mode].metrics.precision * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[mode].metrics.recall * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[mode].metrics.f1 * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[mode].metrics.accuracy * 100).toFixed(1)}%</td>
                   <td className="p-3 border text-red-600">{data[mode].infra_failures}</td>
                 </tr>
               ))}
             </tbody>
           </table>
        </div>
      )}

      {activeTab === 'prompt_ablation' && (
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200 overflow-x-auto">
           <h2 className="text-xl font-bold mb-4">Prompt Ablation (P0 vs P1)</h2>
           <p className="mb-4 text-gray-600">Comparing the Minimal Baseline Auditing Prompt (P0) against the Source-Grounding Prompt (P1).</p>
           <table className="w-full text-left border-collapse min-w-max">
             <thead>
               <tr className="bg-gray-100">
                 <th className="p-3 border">Configuration</th>
                 <th className="p-3 border">Prompt</th>
                 <th className="p-3 border">Precision</th>
                 <th className="p-3 border">Recall</th>
                 <th className="p-3 border">F1</th>
                 <th className="p-3 border">FPR</th>
               </tr>
             </thead>
             <tbody>
              {Object.keys(data).filter(k => data[k].prompt && data[k].model !== 'static' && (data[k].dataset || 'Stored evaluation results') === activeDataset).map(key => (
                <tr key={key} className="border-b hover:bg-gray-50">
                  <td className="p-3 border font-semibold">{data[key].mode || key} - {data[key].model || 'Model not recorded'}</td>
                   <td className="p-3 border">{data[key].prompt}</td>
                   <td className="p-3 border">{(data[key].metrics.precision * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[key].metrics.recall * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[key].metrics.f1 * 100).toFixed(1)}%</td>
                   <td className="p-3 border">{(data[key].metrics.fpr * 100).toFixed(1)}%</td>
                 </tr>
              ))}
            </tbody>
           </table>
           {allPrompts.length === 0 && <p className="mt-4 text-sm text-gray-600">Prompt-ablation comparisons are unavailable because the stored metrics do not include prompt metadata.</p>}
        </div>
      )}

      {activeTab === 'details' && (
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
          <h2 className="text-xl font-bold mb-4">Per-Vulnerability Breakdown</h2>
          {modes.map(mode => (
            <div key={mode} className="mb-8">
              <h3 className="text-lg font-semibold bg-gray-100 p-2 rounded">{mode}</h3>
              <table className="w-full text-left border-collapse mt-2">
                <thead><tr><th className="p-2 border">Vulnerability</th><th className="p-2 border">TP</th><th className="p-2 border">TN</th><th className="p-2 border">FP</th><th className="p-2 border">FN</th></tr></thead>
                <tbody>
                  {Object.entries(data[mode].vuln_classes).map(([vuln, counts]: [string, any]) => (
                    <tr key={vuln}>
                      <td className="p-2 border">{vuln}</td><td className="p-2 border text-green-600">{counts.TP}</td><td className="p-2 border text-green-600">{counts.TN}</td><td className="p-2 border text-red-600">{counts.FP}</td><td className="p-2 border text-red-600">{counts.FN}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h4 className="font-semibold mt-6 mb-2">Severity Confusion Matrix (Predicted vs Actual)</h4>
              <table className="w-full text-left border-collapse mt-2">
                <thead><tr className="bg-gray-50"><th className="p-2 border">Predicted \ Actual</th><th className="p-2 border">Critical</th><th className="p-2 border">High</th><th className="p-2 border">Medium</th><th className="p-2 border">Low</th><th className="p-2 border">Informational</th></tr></thead>
                <tbody>
                  {Object.entries(data[mode].severity_matrix).map(([pred, actuals]: [string, any]) => (
                    <tr key={pred}>
                      <td className="p-2 border font-semibold">{pred}</td>
                      <td className="p-2 border">{actuals["Critical"] || 0}</td><td className="p-2 border">{actuals["High"] || 0}</td><td className="p-2 border">{actuals["Medium"] || 0}</td><td className="p-2 border">{actuals["Low"] || 0}</td><td className="p-2 border">{actuals["Informational"] || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'grounding' && (
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
          <h2 className="text-xl font-bold mb-4">Grounding & Confidence Calibration</h2>
          {modes.map(mode => (
            <div key={mode} className="mb-6 border-b pb-4">
              <h3 className="text-lg font-semibold mb-2">{mode}</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold">Grounding Quality</h4>
                  <ul className="list-disc pl-5">
                    <li>Fully/Partially Grounded: {data[mode].partially_grounded}</li>
                    <li>Generic but Valid: {data[mode].generic}</li>
                    <li>Hallucinated: {data[mode].hallucinated}</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold">Confidence Calibration</h4>
                  <ul className="list-disc pl-5">
                    <li>Mean Confidence (Correct): {(data[mode].metrics.mean_conf_correct * 100).toFixed(1)}%</li>
                    <li>Mean Confidence (Incorrect): {(data[mode].metrics.mean_conf_incorrect * 100).toFixed(1)}%</li>
                  </ul>
                  {Math.abs(data[mode].metrics.mean_conf_correct - data[mode].metrics.mean_conf_incorrect) < 0.1 && (
                    <span className="inline-block mt-2 px-2 py-1 bg-red-100 text-red-800 text-xs rounded">Confidence is not calibrated</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'contracts' && (
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200 overflow-x-auto">
          <h2 className="text-xl font-bold mb-4">Contract-Level Results</h2>
          <table className="w-full text-left border-collapse text-sm min-w-max">
            <thead>
              <tr className="bg-gray-100">
                <th className="p-2 border">Contract</th>
                <th className="p-2 border">Mode</th>
                <th className="p-2 border">Model</th>
                <th className="p-2 border">Prompt</th>
                <th className="p-2 border">Is Vuln?</th>
                <th className="p-2 border">Vulnerability</th>
                <th className="p-2 border">Severity</th>
                <th className="p-2 border">Fallback?</th>
              </tr>
            </thead>
            <tbody>
              {rawData.filter(r => (r.dataset || 'Internal Diagnostic Suite') === activeDataset).map((r, i) => (
                <tr key={i} className="border-b hover:bg-gray-50">
                  <td className="p-2 border">{r.contract}</td>
                  <td className="p-2 border">{r.mode}</td>
                  <td className="p-2 border">{r.model}</td>
                  <td className="p-2 border">{r.prompt || 'Not recorded'}</td>
                  <td className="p-2 border">{r.is_vulnerable !== null ? r.is_vulnerable.toString() : 'Error'}</td>
                  <td className="p-2 border">{r.vulnerability || '-'}</td>
                  <td className="p-2 border">{r.severity || '-'}</td>
                  <td className="p-2 border">{r.fallback_used ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </EvaluationPageShell>
  );
}
