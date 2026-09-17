import { useEffect, useState, Suspense } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Navbar from '@/components/Navbar';
import api from '@/api/client';
import { VulnerabilityReport, VerifiedVulnerability } from '@/types';
import CodeViewer from '@/components/CodeViewer';

function getFriendlyVulnerabilityName(id: string): string {
  const map: Record<string, string> = {
    'reentrancy': 'Reentrancy',
    'tx-origin': 'tx.origin Authorization Bypass',
    'floating-pragma': 'Floating Pragma',
    'unprotected-selfdestruct': 'Unprotected Self-Destruct',
    'unchecked-call': 'Unchecked Call Return Value',
    'missing-access-control': 'Missing Access Control',
    'integer-overflow': 'Integer Overflow/Underflow',
    'timestamp-dependence': 'Timestamp Dependence'
  };
  return map[id] || id.replace(/-/g, ' ');
}

function getSeverityColor(sev: string) {
  if (sev === 'Critical') return 'text-red-500';
  if (sev === 'High') return 'text-orange-500';
  if (sev === 'Medium') return 'text-yellow-400';
  return 'text-blue-400';
}

function getRiskColor(risk: string | undefined) {
  if (risk === 'Critical Risk') return 'text-red-500 border-red-500/30 bg-red-500/10';
  if (risk === 'High Risk') return 'text-orange-500 border-orange-500/30 bg-orange-500/10';
  if (risk === 'Moderate Risk') return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
  return 'text-green-400 border-green-500/30 bg-green-500/10';
}

function FindingCard({ f }: { f: VerifiedVulnerability }) {
  const [expanded, setExpanded] = useState(false);
  const [techDetails, setTechDetails] = useState(false);

  const isConfirmed = f.verification_status === 'CONFIRMED';
  const isUnverified = f.verification_status === 'UNVERIFIED' || !f.verification_status;
  
  const friendlyName = getFriendlyVulnerabilityName(f.vulnerability);
  const sevColor = getSeverityColor(f.severity);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden mb-4 shadow-sm">
      {/* Finding Header (always visible) */}
      <div 
        className="p-5 cursor-pointer hover:bg-gray-800/50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4"
        onClick={() => setExpanded(!expanded)}
      >
        <div>
          <div className="flex items-center gap-3 mb-2">
            <span className={`text-xs font-bold uppercase px-2 py-1 rounded border border-gray-700 ${sevColor}`}>
              {isUnverified ? '⚠ POTENTIAL' : '🔴 ' + f.severity.toUpperCase()}
            </span>
            <span className="text-gray-400 text-sm font-mono">{f.swc_id || 'Unknown SWC'}</span>
          </div>
          <h3 className="text-xl font-bold text-white capitalize">{friendlyName}</h3>
          
          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-sm">
            <div>
              <span className="text-gray-500">Function: </span>
              <code className="text-gray-300 font-mono bg-gray-950 px-1.5 py-0.5 rounded">{f.function || 'Global/Unknown'}</code>
            </div>
            <div>
              <span className="text-gray-500">Lines: </span>
              <span className="text-gray-300 font-mono">{f.affected_lines?.join(', ') || 'N/A'}</span>
            </div>
          </div>
        </div>

        <div className="flex flex-col items-start md:items-end gap-2 border-t border-gray-800 md:border-none pt-4 md:pt-0">
          <div className="text-sm">
            <span className="text-gray-500">AI Verification: </span>
            {isConfirmed ? (
              <span className="text-green-400 font-bold">✓ CONFIRMED</span>
            ) : isUnverified ? (
              <span className="text-amber-500 font-bold">⚠ VERIFICATION INCOMPLETE</span>
            ) : (
              <span className="text-gray-400 font-bold">✗ REJECTED</span>
            )}
          </div>
          <div className="text-sm">
            <span className="text-gray-500">Confidence: </span>
            <span className="text-white font-semibold">{(f.confidence * 100).toFixed(1)}%</span>
          </div>
          <button className="text-blue-400 text-sm font-medium mt-2 hover:text-blue-300">
            {expanded ? 'Hide details' : 'Understand This Issue →'}
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="p-5 border-t border-gray-800 bg-gray-950/30">
          
          {/* Warning for unverified */}
          {isUnverified && (
            <div className="mb-8 bg-amber-950/30 border border-amber-500/40 rounded-lg p-5">
              <h4 className="text-amber-500 font-bold text-lg mb-2 flex items-center gap-2">
                ⚠ VERIFICATION INCOMPLETE
              </h4>
              <p className="text-amber-200/80 mb-4 text-sm leading-relaxed">
                SMAI's static analyzer detected a potential security issue, but AI verification could not be completed.
                <br/><br/>
                <strong className="text-amber-400 block mb-1">IMPORTANT: This does NOT mean the contract is safe.</strong>
                Review the affected code manually before deployment.
              </p>
            </div>
          )}

          {isConfirmed && (
            <div className="mb-6">
              <h4 className="text-red-400 font-bold flex items-center gap-2 mb-2">
                🔴 CONFIRMED VULNERABILITY
              </h4>
            </div>
          )}

          <div className="space-y-8">
            {/* 1. What is the problem */}
            <section>
              <h4 className="text-white font-bold text-sm uppercase tracking-wider mb-2">1. What is the problem?</h4>
              <p className="text-gray-300 leading-relaxed text-sm">
                {f.explanation || "Not available"}
              </p>
            </section>

            {/* 2. Where is it & 3. Code */}
            <section>
              <h4 className="text-white font-bold text-sm uppercase tracking-wider mb-2">2 & 3. Where is the problem in my code?</h4>
              <div className="mb-3 text-sm text-gray-400">
                Found in <code className="text-gray-300 font-mono">{f.contract || 'contract'}</code> inside <code className="text-gray-300 font-mono">{f.function || 'unknown function'}</code> on lines <code className="text-gray-300 font-mono">{f.affected_lines?.join(', ') || 'N/A'}</code>.
              </div>
              <div className="rounded-lg overflow-hidden border border-gray-800">
                <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 text-xs text-gray-500 font-mono flex justify-between">
                  <span>Affected lines</span>
                </div>
                <Suspense fallback={<div className="p-4 text-gray-500 text-sm">Loading code...</div>}>
                  <CodeViewer code={f.original_code || "Code unavailable"} language="solidity" highlightLines={f.affected_lines} />
                </Suspense>
              </div>
            </section>

            {/* 4. Why was it flagged */}
            <section>
              <h4 className="text-white font-bold text-sm uppercase tracking-wider mb-3">4. Why did SMAI flag this?</h4>
              
              <div className="space-y-3">
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                  <h5 className="text-gray-400 text-xs font-bold uppercase mb-2">Static Evidence</h5>
                  <p className="text-sm text-gray-300 font-mono">{f.static_evidence || "Not available"}</p>
                </div>
                
                {f.retrieved_knowledge && f.retrieved_knowledge.length > 0 && (
                  <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                    <h5 className="text-gray-400 text-xs font-bold uppercase mb-2">Security Evidence (RAG)</h5>
                    <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                      {f.retrieved_knowledge.map((k, i) => (
                        <li key={i}>{String(k.name || k.vulnerability || 'Security Pattern')}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </section>

            {/* 5. What could happen */}
            <section>
              <h4 className="text-white font-bold text-sm uppercase tracking-wider mb-2">5. How could this be exploited?</h4>
              {isUnverified ? (
                <div className="bg-amber-950/20 border border-amber-500/20 rounded-lg p-4">
                  <p className="text-sm text-amber-300">
                    <strong className="block mb-1">⚡ ATTACK SCENARIO</strong>
                    AI verification was unavailable, so SMAI could not generate a verified attack scenario. Review the affected lines manually.
                  </p>
                </div>
              ) : (
                <p className="text-gray-300 leading-relaxed text-sm bg-red-950/10 border border-red-500/10 p-4 rounded-lg">
                  {f.attack_scenario || "Not available"}
                </p>
              )}
            </section>

            {/* 6. How do I fix it */}
            <section>
              <h4 className="text-white font-bold text-sm uppercase tracking-wider mb-2">6. How should it be fixed?</h4>
              <p className="text-gray-300 leading-relaxed text-sm bg-green-950/10 border border-green-500/10 p-4 rounded-lg mb-3">
                {f.recommendation || "Not available"}
              </p>
              {f.fixed_code && f.fixed_code !== 'N/A' && (
                <div className="rounded-lg overflow-hidden border border-gray-800">
                  <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 text-xs text-green-400 font-mono font-bold">
                    Suggested Fix
                  </div>
                  <Suspense fallback={<div className="p-4 text-gray-500">Loading code...</div>}>
                    <CodeViewer code={f.fixed_code} language="solidity" highlightLines={[]} />
                  </Suspense>
                </div>
              )}
            </section>

            {/* 7. Technical Details */}
            <section>
              <button 
                onClick={() => setTechDetails(!techDetails)}
                className="text-gray-500 hover:text-gray-300 text-sm font-semibold uppercase tracking-wider flex items-center gap-2"
              >
                7. Technical Details {techDetails ? '▲' : '▼'}
              </button>
              
              {techDetails && (
                <div className="mt-4 bg-gray-900 border border-gray-800 rounded-lg p-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="block text-gray-500 text-xs">Category</span>
                    <span className="text-gray-300 font-mono">{f.vulnerability}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-xs">SWC ID</span>
                    <span className="text-gray-300 font-mono">{f.swc_id || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-xs">Backend Status</span>
                    <span className="text-gray-300 font-mono">{f.verification_status || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="block text-gray-500 text-xs">Raw Confidence</span>
                    <span className="text-gray-300 font-mono">{f.confidence}</span>
                  </div>
                </div>
              )}
            </section>

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
        setError('Backend connection unavailable. Make sure the SMAI backend is running and try again.');
        setLoading(false);
      }
    };
    fetchReport();
    return () => clearTimeout(timer);
  }, [id, pollCount]);

  if (loading) return (
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <Navbar />
      <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
        <div className="animate-spin text-4xl mb-6">⟳</div>
        <h2 className="text-xl font-bold text-white mb-2">Analyzing your contract...</h2>
        <p className="text-sm text-gray-500">SMAI is performing static analysis and AI verification.</p>
      </div>
    </div>
  );

  if (error || !report) return (
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <Navbar />
      <div className="max-w-2xl mx-auto px-6 py-16 text-center w-full flex-1 flex flex-col justify-center">
        <h2 className="text-xl font-bold text-white mb-2">Backend connection unavailable</h2>
        <p className="text-gray-400 mb-8">{error}</p>
        <button onClick={() => navigate('/scan')} className="bg-gray-800 hover:bg-gray-700 text-white px-6 py-2 rounded-lg inline-block mx-auto">
          Try Again
        </button>
      </div>
    </div>
  );

  const isSafe = report.findings.length === 0;
  const riskClass = getRiskColor(report.risk_level);

  return (
    <div className="min-h-screen bg-gray-950 font-sans pb-20">
      <Navbar />
      <div className="max-w-4xl mx-auto px-4 md:px-6 py-8">
        
        {/* Navigation */}
        <button onClick={() => navigate('/scan')} className="text-gray-500 hover:text-gray-300 text-sm mb-6 flex items-center gap-2">
          ← Back to Scanner
        </button>

        {/* OVERALL SUMMARY BANNER */}
        {isSafe ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 md:p-12 text-center shadow-lg mb-8">
            <div className="text-green-500 text-6xl mb-4">✓</div>
            <h1 className="text-3xl font-extrabold text-white mb-8 tracking-tight">NO VULNERABILITIES DETECTED</h1>
            
            <div className="grid grid-cols-2 gap-4 max-w-sm mx-auto mb-8">
              <div className="bg-gray-950 rounded-lg p-4 border border-gray-800">
                <p className="text-gray-500 text-xs font-bold uppercase mb-1">Security Score</p>
                <p className="text-2xl font-bold text-white">{report.security_score} / 100</p>
              </div>
              <div className="bg-gray-950 rounded-lg p-4 border border-gray-800">
                <p className="text-gray-500 text-xs font-bold uppercase mb-1">Risk Level</p>
                <p className="text-xl font-bold text-green-400 uppercase">{report.risk_level}</p>
              </div>
            </div>

            <p className="text-gray-300 leading-relaxed max-w-xl mx-auto mb-6">
              Your contract did not trigger any of the known vulnerability checks used by SMAI. No issues were detected by the current analysis.
            </p>
            <p className="text-gray-500 text-xs max-w-md mx-auto">
              Important note: No automated scanner can guarantee that a smart contract is completely secure. Manual review is always recommended for critical financial code.
            </p>
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 md:p-8 shadow-lg mb-8">
            <h1 className="text-2xl font-extrabold text-white mb-6 flex items-center gap-3">
              <span className="text-amber-500">⚠</span> SECURITY ISSUES DETECTED
            </h1>
            
            <div className="flex flex-wrap gap-4 mb-6">
              <div className="bg-gray-950 rounded-lg p-4 border border-gray-800 min-w-[140px]">
                <p className="text-gray-500 text-xs font-bold uppercase mb-1">Security Score</p>
                <p className="text-2xl font-bold text-white">{report.security_score} / 100</p>
              </div>
              <div className={`rounded-lg p-4 border min-w-[140px] ${riskClass}`}>
                <p className="text-current/60 text-xs font-bold uppercase mb-1">Risk Level</p>
                <p className="text-xl font-bold text-current uppercase">{report.risk_level}</p>
              </div>
            </div>

            <p className="text-gray-300 text-sm mb-4">
              Your score reflects the security findings identified during this scan. 
              <strong> {report.findings.length} security {report.findings.length === 1 ? 'issue was' : 'issues were'} detected.</strong>
            </p>

            {/* Severity Breakdown */}
            <div className="flex gap-3">
              {['Critical', 'High', 'Medium', 'Low', 'Informational'].map(sev => {
                const count = report.severity_counts[sev] || 0;
                if (count === 0) return null;
                return (
                  <span key={sev} className="text-xs font-bold px-3 py-1 bg-gray-950 border border-gray-800 rounded text-gray-300">
                    <span className={getSeverityColor(sev)}>{count}</span> {sev}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {/* FINDINGS LIST */}
        {!isSafe && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">Vulnerability Findings</h2>
              <span className="text-gray-500 text-sm">{report.findings.length} total</span>
            </div>
            
            {report.findings.map(f => (
              <FindingCard key={f.finding_id} f={f} />
            ))}
          </div>
        )}

      </div>
    </div>
  );
}
