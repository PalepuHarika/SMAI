import * as Diff from 'diff';

interface Props {
  original: string;
  fixed: string;
  label?: string;
}

export default function DiffViewer({ original, fixed, label = 'Diff — Vulnerable vs. Fixed' }: Props) {
  // Use the diff package for accurate line-level LCS diffing
  const diffs = Diff.diffLines(original, fixed);
  
  const hasChanges = diffs.some(part => part.added || part.removed);

  return (
    <div className="rounded-lg overflow-hidden border border-gray-700 text-xs">
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <span className="text-gray-300 text-xs font-semibold">{label}</span>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-red-400 text-xs">
            <span className="w-2.5 h-2.5 rounded-sm bg-red-500/30 border border-red-500/50" /> Vulnerable
          </span>
          <span className="flex items-center gap-1 text-green-400 text-xs">
            <span className="w-2.5 h-2.5 rounded-sm bg-green-500/30 border border-green-500/50" /> Fixed
          </span>
        </div>
      </div>
      
      {!hasChanges ? (
        <div className="px-4 py-3 bg-[#0d1117] text-gray-400 text-xs">No differences detected.</div>
      ) : (
        <div className="bg-[#0d1117] overflow-x-auto py-2">
          {diffs.map((part, index) => {
            const bgClass = part.added ? 'bg-green-500/10 border-l-2 border-green-500 text-green-200' 
                          : part.removed ? 'bg-red-500/10 border-l-2 border-red-500 text-red-200' 
                          : 'text-gray-300';
            const prefix = part.added ? '+' : part.removed ? '−' : ' ';
            const prefixColor = part.added ? 'text-green-400' : part.removed ? 'text-red-400' : 'text-gray-600';
            
            // diffLines can return a string with multiple newlines, so we map over them
            const lines = part.value.replace(/\n$/, '').split('\n');
            
            return lines.map((line, lineIndex) => (
              <div key={`${index}-${lineIndex}`} className={`flex font-mono leading-6 ${bgClass}`}>
                <span className={`select-none w-8 text-center flex-shrink-0 ${prefixColor}`}>
                  {prefix}
                </span>
                <span className="pl-2 whitespace-pre">
                  {line || ' '}
                </span>
              </div>
            ));
          })}
        </div>
      )}
    </div>
  );
}
