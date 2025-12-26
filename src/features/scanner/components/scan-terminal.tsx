import React, { useEffect, useState, useRef } from 'react';
import { TR_SEQUENCE, EN_SEQUENCE, type ScanLog } from '../constants/terminal-sequences';

interface ScanTerminalProps {
  onComplete: () => void;
  lang: 'tr' | 'en';
}

const ScanTerminal: React.FC<ScanTerminalProps> = ({ onComplete, lang }) => {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const sequence = lang === 'tr' ? TR_SEQUENCE : EN_SEQUENCE;

  useEffect(() => {
    let stepIndex = 0;
    
    const addNextLog = () => {
      if (stepIndex >= sequence.length) {
        setTimeout(onComplete, 800);
        return;
      }

      const currentStep = sequence[stepIndex];
      setLogs(prev => [...prev, currentStep]);
      stepIndex++;

      const nextDelay = currentStep.type === 'info' ? 1000 : 600;
      setTimeout(addNextLog, nextDelay);
    };

    const initialTimeout = setTimeout(addNextLog, 400);
    return () => clearTimeout(initialTimeout);
  }, [onComplete, sequence]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const progress = Math.min(Math.round((logs.length / sequence.length) * 100), 100);

  const getLogColor = (type: ScanLog['type']) => {
    switch (type) {
      case 'success': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      case 'info': return 'text-blue-400 font-bold';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto mt-8">
      <div className="flex justify-between items-end mb-2 px-1">
        <span className="text-xs font-mono text-cyber-green/70">
          {progress < 100 ? "CORE_SCAN_IN_PROGRESS..." : "CORE_SCAN_COMPLETE"}
        </span>
        <span className="text-xs font-mono text-cyber-green font-bold">{progress}%</span>
      </div>
      
      <div className="w-full h-1 bg-gray-900 rounded-full mb-4 overflow-hidden border border-gray-800">
        <div 
          className="h-full bg-cyber-green shadow-[0_0_10px_rgba(0,255,65,0.4)] transition-all duration-300 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div className="bg-cyber-black border border-gray-800 rounded-lg p-5 font-mono text-sm shadow-2xl relative overflow-hidden">
        <div className="flex items-center gap-1.5 mb-4 border-b border-gray-800 pb-3">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/50"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/50"></div>
          <span className="ml-2 text-gray-600 text-[10px] tracking-widest uppercase">{lang === 'tr' ? 'Sistem Terminali' : 'System Terminal'}</span>
        </div>
        
        <div 
          ref={scrollRef}
          className="h-64 overflow-y-auto space-y-2 scrollbar-hide relative z-10"
        >
          {logs.map((log, index) => (
            <div key={index} className="flex items-start animate-fade-in">
              <span className="text-gray-700 mr-3 shrink-0 text-[10px]">[{new Date().toLocaleTimeString(lang === 'tr' ? 'tr-TR' : 'en-US', { hour12: false, minute: '2-digit', second: '2-digit' })}]</span>
              <span className={`break-all ${getLogColor(log.type)}`}>
                {log.text}
              </span>
            </div>
          ))}
          {progress < 100 && (
            <div className="flex items-center">
              <span className="text-gray-700 mr-3 shrink-0 text-[10px]">[{new Date().toLocaleTimeString(lang === 'tr' ? 'tr-TR' : 'en-US', { hour12: false, minute: '2-digit', second: '2-digit' })}]</span>
              <span className="w-2 h-4 bg-cyber-green/50 inline-block align-middle animate-pulse"></span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanTerminal;