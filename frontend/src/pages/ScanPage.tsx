import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Editor, { OnMount } from '@monaco-editor/react';
import Navbar from '@/components/Navbar';
import api from '@/api/client';
import * as monaco from 'monaco-editor';

export default function ScanPage() {
  const navigate = useNavigate();
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  
  const [contractName, setContractName] = useState('Contract.sol');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Initial template
  const defaultCode = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Example {\n    // paste your contract here...\n}';

  const handleEditorDidMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setContractName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = (ev.target?.result as string) ?? '';
      if (editorRef.current) {
        editorRef.current.setValue(text);
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    // Get the latest content directly from the editor instance
    const sourceCode = editorRef.current?.getValue() || '';
    
    if (!sourceCode.trim()) { 
      setError('Please enter or upload Solidity source code.'); 
      return; 
    }
    
    setLoading(true);
    try {
      const res = await api.post('/api/analysis', { contract_name: contractName, source_code: sourceCode });
      navigate(`/report/${res.data.analysis_id}`, { state: { report: res.data } });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } }).response?.data?.detail;
      setError(msg || 'Scan failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      <Navbar />
      <div className="max-w-5xl w-full mx-auto px-6 py-8 flex-1 flex flex-col">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">New Contract Scan</h1>
          <p className="text-gray-400 text-sm mt-1">Upload or paste your Solidity source code to begin vulnerability analysis</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex-1 flex flex-col">
          <form onSubmit={handleSubmit} className="flex-1 flex flex-col space-y-5">
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-300 mb-1">Contract Name</label>
                <input type="text" value={contractName} onChange={e => setContractName(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Upload .sol File</label>
                <label className="flex items-center gap-2 bg-gray-800 border border-gray-700 hover:border-gray-600 text-gray-300 rounded-lg px-4 py-2.5 text-sm cursor-pointer transition-colors h-[42px]">
                  📁 Choose file
                  <input type="file" accept=".sol" className="hidden" onChange={handleFileUpload} />
                </label>
              </div>
            </div>

            <div className="flex-1 flex flex-col min-h-[400px]">
              <label className="block text-sm font-medium text-gray-300 mb-1 flex justify-between items-center">
                <span>Solidity Source Code</span>
                <span className="text-xs text-gray-500 font-mono">VS Code Intellisense Active</span>
              </label>
              
              {/* Force a fixed/absolute layout context for Monaco to prevent collapsing or flex stealing focus */}
              <div className="flex-1 relative rounded-lg overflow-hidden border border-gray-700 focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500 transition-all bg-[#1e1e1e]">
                <div className="absolute inset-0">
                  <Editor
                    height="100%"
                    width="100%"
                    language="solidity"
                    theme="vs-dark"
                    defaultValue={defaultCode}
                    onMount={handleEditorDidMount}
                    options={{
                      minimap: { enabled: false },
                      fontSize: 14,
                      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                      padding: { top: 16, bottom: 16 },
                      scrollBeyondLastLine: false,
                      smoothScrolling: true,
                      cursorBlinking: "smooth",
                      cursorSmoothCaretAnimation: "on",
                      formatOnPaste: true,
                      suggestOnTriggerCharacters: true,
                    }}
                    loading={
                      <div className="h-full w-full flex items-center justify-center text-gray-400 text-sm">
                        Loading Editor...
                      </div>
                    }
                  />
                </div>
              </div>
            </div>

            {error && (
              <div className="bg-red-900/40 border border-red-700 text-red-300 rounded-lg px-4 py-2.5 text-sm">{error}</div>
            )}

            {loading && (
              <div className="bg-blue-900/30 border border-blue-700 text-blue-300 rounded-lg px-4 py-3 text-sm">
                <div className="flex items-center gap-3">
                  <div className="animate-spin text-lg">⚙️</div>
                  <div>
                    <p className="font-medium">Scanning contract...</p>
                    <p className="text-blue-400/80 text-xs mt-0.5">Running static analysis → RAG retrieval → LLM verification</p>
                  </div>
                </div>
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-lg px-4 py-3 text-sm transition-colors mt-auto">
              {loading ? 'Analyzing...' : '🔍 Analyze Contract'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
