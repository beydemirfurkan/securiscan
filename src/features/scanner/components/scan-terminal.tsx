import React, { useEffect, useState, useRef, useCallback } from 'react';
import { TR_MESSAGES, EN_MESSAGES, TR_SEQUENCE, EN_SEQUENCE, type ScanLog } from '../constants/terminal-sequences';
import { API_BASE_URL } from '../../../config/constants';

interface ScanProgress {
  phase: string;
  message: string;
  progress: number;
  type: 'info' | 'success' | 'warning' | 'error' | 'neutral';
  details?: string;
}

interface ScanTerminalProps {
  onComplete: () => void;
  lang: 'tr' | 'en';
  scanId?: string;
  useSSE?: boolean;
}

const ScanTerminal: React.FC<ScanTerminalProps> = ({ onComplete, lang, scanId, useSSE = true }) => {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [progress, setProgress] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const messages = lang === 'tr' ? TR_MESSAGES : EN_MESSAGES;
  const fallbackSequence = lang === 'tr' ? TR_SEQUENCE : EN_SEQUENCE;

  // Add log entry
  const addLog = useCallback((log: ScanLog) => {
    setLogs(prev => {
      // Avoid duplicate consecutive messages
      if (prev.length > 0 && prev[prev.length - 1].text === log.text) {
        return prev;
      }
      return [...prev, log];
    });
  }, []);

  // Handle SSE progress updates
  useEffect(() => {
    if (!useSSE || !scanId) {
      // Fallback to fake progress
      let stepIndex = 0;
      
      const addNextLog = () => {
        if (stepIndex >= fallbackSequence.length) {
          setProgress(100);
          setIsComplete(true);
          setTimeout(onComplete, 800);
          return;
        }

        const currentStep = fallbackSequence[stepIndex];
        addLog(currentStep);
        setProgress(Math.round(((stepIndex + 1) / fallbackSequence.length) * 100));
        stepIndex++;

        const nextDelay = currentStep.type === 'info' ? 1000 : 600;
        setTimeout(addNextLog, nextDelay);
      };

      const initialTimeout = setTimeout(addNextLog, 400);
      return () => clearTimeout(initialTimeout);
    }

    // Use SSE for real-time progress
    const eventSource = new EventSource(`${API_BASE_URL}/scan/progress/${scanId}`);
    eventSourceRef.current = eventSource;

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === 'connected') {
          addLog({ text: lang === 'tr' ? 'Bağlantı kuruldu' : 'Connected', type: 'success' });
          return;
        }

        if (data.type === 'progress') {
          const progressData = data as ScanProgress;
          
          // Get message from phase
          const messageInfo = messages[progressData.phase];
          if (messageInfo) {
            const logText = progressData.details 
              ? `${messageInfo.text} (${progressData.details})`
              : messageInfo.text;
            
            addLog({ 
              text: logText, 
              type: progressData.type || messageInfo.type,
              details: progressData.details 
            });
          }
          
          setProgress(progressData.progress);
        }

        if (data.type === 'complete') {
          setProgress(100);
          setIsComplete(true);
          addLog({ 
            text: lang === 'tr' ? 'Tarama tamamlandı!' : 'Scan complete!', 
            type: 'success' 
          });
          setTimeout(onComplete, 800);
        }

        if (data.type === 'error') {
          addLog({ 
            text: `${lang === 'tr' ? 'Hata' : 'Error'}: ${data.error}`, 
            type: 'error' 
          });
        }
      } catch (e) {
        console.error('SSE parse error:', e);
      }
    };

    eventSource.onerror = () => {
      console.log('SSE connection error, falling back to polling');
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [scanId, useSSE, lang, messages, fallbackSequence, addLog, onComplete]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

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
          <span className="ml-2 text-gray-600 text-[10px] tracking-widest uppercase">
            {lang === 'tr' ? 'Sistem Terminali' : 'System Terminal'}
          </span>
          {scanId && (
            <span className="ml-auto text-gray-700 text-[8px] font-mono">
              ID: {scanId.slice(0, 8)}
            </span>
          )}
        </div>
        
        <div 
          ref={scrollRef}
          className="h-64 overflow-y-auto space-y-2 scrollbar-hide relative z-10"
        >
          {logs.map((log, index) => (
            <div key={index} className="flex items-start animate-fade-in">
              <span className="text-gray-700 mr-3 shrink-0 text-[10px]">
                [{new Date().toLocaleTimeString(lang === 'tr' ? 'tr-TR' : 'en-US', { 
                  hour12: false, 
                  minute: '2-digit', 
                  second: '2-digit' 
                })}]
              </span>
              <span className={`break-all ${getLogColor(log.type)}`}>
                {log.text}
              </span>
            </div>
          ))}
          {!isComplete && (
            <div className="flex items-center">
              <span className="text-gray-700 mr-3 shrink-0 text-[10px]">
                [{new Date().toLocaleTimeString(lang === 'tr' ? 'tr-TR' : 'en-US', { 
                  hour12: false, 
                  minute: '2-digit', 
                  second: '2-digit' 
                })}]
              </span>
              <span className="w-2 h-4 bg-cyber-green/50 inline-block align-middle animate-pulse"></span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanTerminal;
