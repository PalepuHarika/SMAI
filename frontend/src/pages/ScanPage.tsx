import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Editor, { OnMount } from '@monaco-editor/react';
import Navbar from '@/components/Navbar';
import api from '@/api/client';

export default function ScanPage() {
  const navigate = useNavigate();
  const editorRef = useRef<any>(null);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progressStep, setProgressStep] = useState(0);

  const defaultCode = `pragma solidity ^0.8.0;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}`;

  const [code, setCode] = useState(defaultCode);

  const handleEditorDidMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  const loadExample = () => {
    const exampleCode = `pragma solidity ^0.8.0;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}`;
    setCode(exampleCode);
    if (editorRef.current) {
      editorRef.current.setValue(exampleCode);
    }
  };

  const handleClear = () => {
    setCode('');
    if (editorRef.current) {
      editorRef.current.setValue('');
    }
  };

  const handleSubmit = async () => {
    setError('');
    const sourceCode = code || editorRef.current?.getValue() || '';
    
    if (!sourceCode.trim()) { 
      setError('Check that the submitted code is valid Solidity.'); 
      return; 
    }
    
    setLoading(true);
    setProgressStep(1);
    
    try {
      const interval = setInterval(() => {
        setProgressStep(prev => (prev < 4 ? prev + 1 : prev));
      }, 1500);

      const res = await api.post('/api/analysis', { 
        contract_name: 'Scan.sol', 
        source_code: sourceCode, 
        mode: 'C' 
      });
      
      clearInterval(interval);
      setProgressStep(5);
      navigate(`/report/${res.data.analysis_id}`, { state: { report: res.data } });
    } catch (err: unknown) {
      setProgressStep(0);
      const msg = (err as { response?: { data?: { detail?: string } } }).response?.data?.detail;
      setError(msg ? `Analysis took too long or failed: ${msg}` : 'Backend connection unavailable. Make sure the SMAI backend is running and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col font-sans">
      <Navbar />
      <div className="max-w-6xl w-full mx-auto px-6 py-8 flex-1 flex flex-col">
        
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-white mb-2">Scan Smart Contract</h1>
          <p className="text-gray-400 text-base">Paste your Solidity code below. SMAI will analyze it for known security risks.</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl flex flex-col overflow-hidden shadow-lg">
          
          {/* Top Actions Toolbar */}
          <div className="flex items-center justify-between p-4 border-b border-gray-800 bg-gray-900/80">
            <div className="flex gap-3">
              <button onClick={handleClear} disabled={loading} className="text-sm px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors cursor-pointer font-medium">
                Clear
              </button>
              <button onClick={loadExample} disabled={loading} className="text-sm px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors cursor-pointer font-medium">
                Example Contract
              </button>
            </div>
            <button onClick={handleSubmit} disabled={loading} className="text-sm font-bold px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors shadow-lg cursor-pointer">
              {loading ? 'Scanning...' : 'Scan Contract'}
            </button>
          </div>

          {/* Editor Area with explicit pixel height */}
          <div className="w-full relative bg-gray-950" style={{ height: '500px', minHeight: '450px' }}>
            <Editor
              height="100%"
              width="100%"
              language="solidity"
              theme="vs-dark"
              value={code}
              onChange={(val) => setCode(val || '')}
              onMount={handleEditorDidMount}
              loading={<div className="p-6 text-gray-400 font-mono text-sm">Loading code editor...</div>}
              options={{
                automaticLayout: true,
                minimap: { enabled: false },
                fontSize: 14,
                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                padding: { top: 16, bottom: 16 },
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                readOnly: loading,
              }}
            />
            
            {/* Loading Overlay */}
            {loading && (
              <div className="absolute inset-0 bg-gray-950/80 backdrop-blur-sm flex flex-col items-center justify-center z-10">
                <h3 className="text-xl font-bold text-white mb-6">Analyzing your contract...</h3>
                <div className="space-y-4 w-64">
                  <div className={`flex items-center gap-3 ${progressStep >= 1 ? 'text-blue-400' : 'text-gray-600'}`}>
                    <span className="text-lg">{progressStep > 1 ? '✓' : '→'}</span>
                    <span className="font-medium">Static Analysis</span>
                  </div>
                  <div className={`flex items-center gap-3 ${progressStep >= 2 ? 'text-blue-400' : 'text-gray-600'}`}>
                    <span className="text-lg">{progressStep > 2 ? '✓' : '→'}</span>
                    <span className="font-medium">Security Evidence</span>
                  </div>
                  <div className={`flex items-center gap-3 ${progressStep >= 3 ? 'text-blue-400' : 'text-gray-600'}`}>
                    <span className="text-lg">{progressStep > 3 ? '✓' : '→'}</span>
                    <span className="font-medium">AI Verification</span>
                  </div>
                  <div className={`flex items-center gap-3 ${progressStep >= 4 ? 'text-blue-400' : 'text-gray-600'}`}>
                    <span className="text-lg">{progressStep > 4 ? '✓' : '→'}</span>
                    <span className="font-medium">Security Report</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {error && (
          <div className="mt-6 p-4 bg-red-950/50 border border-red-500/30 rounded-lg">
            <p className="text-red-400 font-semibold mb-1">Error</p>
            <p className="text-red-300/80 text-sm">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
