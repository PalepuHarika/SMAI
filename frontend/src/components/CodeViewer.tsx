import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter';
import js from 'react-syntax-highlighter/dist/esm/languages/prism/javascript';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

// Register javascript as a stand-in for Solidity
SyntaxHighlighter.registerLanguage('solidity', js);

interface Props {
  code: string;
  language?: string;
  highlightLines?: number[];
  startLine?: number;
}

export default function CodeViewer({ code, language = 'solidity', highlightLines = [], startLine = 1 }: Props) {
  const lineProps = (lineNumber: number): React.HTMLAttributes<HTMLElement> => {
    // The syntax highlighter lineNumber is already adjusted by startLine
    const isHighlighted = highlightLines.includes(lineNumber);
    if (!isHighlighted) return {};
    return {
      style: {
        display: 'block',
        backgroundColor: 'rgba(239, 68, 68, 0.12)',
        borderLeft: '3px solid #ef4444',
        marginLeft: '-3px',
        paddingLeft: '4px',
      },
    };
  };

  return (
    <div className="rounded-lg overflow-hidden border border-gray-700 text-xs bg-[#0d1117]">
      {/* Mac-style header */}
      <div className="flex items-center gap-1.5 px-4 py-2 bg-gray-800 border-b border-gray-700">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
        <span className="ml-3 text-gray-400 text-xs font-mono">{language}</span>
        {highlightLines.length > 0 && (
          <span className="ml-auto text-red-400 text-xs font-medium flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />
            Lines {highlightLines.join(', ')} flagged
          </span>
        )}
      </div>

      <SyntaxHighlighter
        language={language}
        style={vscDarkPlus}
        showLineNumbers
        startingLineNumber={startLine}
        wrapLines
        lineProps={lineProps}
        customStyle={{
          margin: 0,
          borderRadius: 0,
          fontSize: '0.75rem',
          lineHeight: '1.6',
          background: 'transparent',
          padding: '16px 0',
        }}
        lineNumberStyle={{
          color: '#4b5563',
          minWidth: '3.5em',
          paddingRight: '1.5em',
          userSelect: 'none',
          textAlign: 'right'
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
}
