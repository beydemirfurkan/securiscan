import React, { useState, useEffect } from 'react';
import ScanTerminal from './features/scanner/components/scan-terminal';
import ReportDashboard from './features/report/components/report-dashboard';
import { useTranslation } from './i18n';
import { useScan } from './hooks/use-scan';
import { ShieldAlert, ShieldCheck, Zap, Cpu, Globe, Languages } from 'lucide-react';
import { APP_CONFIG } from './config/constants';

const App: React.FC = () => {
  const { lang, t, changeLanguage } = useTranslation();

  const {
    url,
    setUrl,
    status,
    report,
    error,
    validationError,
    isTerminalReady,
    scanId,
    startScan,
    reset,
    handleTerminalComplete,
    clearValidationError,
    refetchReport,
  } = useScan(lang);

  const prevLangRef = React.useRef(lang);
  useEffect(() => {
    if (prevLangRef.current !== lang && report && status === 'COMPLETE') {
      refetchReport(report.targetUrl);
    }
    prevLangRef.current = lang;
  }, [lang, report, status, refetchReport]);

  const startScanProcess = (e: React.FormEvent) => {
    e.preventDefault();
    startScan(url);
  };

  const resetApp = () => {
    reset();
  };

  return (
    <div className="min-h-screen bg-cyber-black text-gray-200 selection:bg-cyber-green selection:text-black font-sans flex flex-col overflow-x-hidden">
      <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute inset-0 opacity-[0.03]"
             style={{ backgroundImage: 'linear-gradient(#00ff41 1px, transparent 1px), linear-gradient(90deg, #00ff41 1px, transparent 1px)', backgroundSize: '50px 50px' }}>
        </div>
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[500px] bg-cyber-green/5 blur-[120px] rounded-full"></div>
      </div>

      <header className="relative z-50 border-b border-white/5 bg-cyber-black/80 backdrop-blur-xl p-4 sticky top-0">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2 cursor-pointer group" onClick={resetApp}>
            <div className="bg-cyber-green/10 p-1.5 rounded-lg border border-cyber-green/20 group-hover:border-cyber-green/50 transition-all">
              <ShieldCheck className="w-6 h-6 text-cyber-green" />
            </div>
            <h1 className="text-xl font-bold tracking-tighter text-white">
              SECURISCAN<span className="text-cyber-green">.AI</span>
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center bg-white/5 border border-white/10 rounded-full p-1 shadow-inner">
              <div className="px-2 text-gray-500">
                <Languages className="w-3.5 h-3.5" />
              </div>
              <button
                onClick={() => changeLanguage('tr')}
                className={`px-3 py-1 text-[10px] font-bold rounded-full transition-all duration-300 ${lang === 'tr' ? 'bg-cyber-green text-black shadow-[0_0_12px_rgba(0,255,65,0.4)]' : 'text-gray-400 hover:text-white'}`}
              >
                TR
              </button>
              <button
                onClick={() => changeLanguage('en')}
                className={`px-3 py-1 text-[10px] font-bold rounded-full transition-all duration-300 ${lang === 'en' ? 'bg-cyber-green text-black shadow-[0_0_12px_rgba(0,255,65,0.4)]' : 'text-gray-400 hover:text-white'}`}
              >
                EN
              </button>
            </div>

            <button onClick={resetApp} className="hidden sm:block text-xs font-mono text-cyber-green border border-cyber-green/30 px-3 py-1.5 rounded-lg hover:bg-cyber-green hover:text-black transition-all">
              {lang === 'tr' ? 'PANEL' : 'DASHBOARD'}
            </button>
          </div>
        </div>
      </header>

      <main className="relative z-10 flex-grow flex flex-col">
        {status === 'IDLE' && (
          <div className="flex-grow flex flex-col items-center justify-center py-12 px-4 max-w-7xl mx-auto w-full space-y-20 animate-fade-in">

            <div className="text-center space-y-8 max-w-4xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-mono text-cyber-green tracking-widest uppercase">
                <Zap className="w-3 h-3" /> {t.tagline}
              </div>

              <h2 className="text-4xl md:text-6xl tracking-tight leading-[1.1] text-white">
                <span className="font-medium opacity-90">{t.heroTitle_1}</span> <br/>
                <span className="font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyber-green via-emerald-400 to-blue-500">
                  {t.heroTitle_2}
                </span>
              </h2>

              <p className="text-gray-400 text-lg md:text-xl max-w-2xl mx-auto font-light leading-relaxed">
                {t.heroSubtitle}
              </p>

              <form onSubmit={startScanProcess} className="w-full max-w-2xl mx-auto relative group pt-4">
                <div className="absolute -inset-1 bg-gradient-to-r from-cyber-green/50 to-blue-600/50 rounded-2xl blur-xl opacity-20 group-hover:opacity-40 transition duration-1000"></div>
                <div className="relative flex p-1.5 bg-cyber-dark/80 backdrop-blur-md rounded-2xl border border-white/10 shadow-2xl">
                  <div className="flex items-center pl-4 pr-2 text-gray-500">
                    <Globe className="w-5 h-5" />
                  </div>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value);
                      if (validationError) clearValidationError();
                    }}
                    placeholder={t.placeholder}
                    className={`flex-grow bg-transparent text-white px-2 py-4 focus:outline-none font-mono text-sm ${validationError ? 'placeholder-red-400' : 'placeholder-gray-600'}`}
                  />
                  <button
                    type="submit"
                    className="bg-cyber-green hover:bg-green-400 text-black font-bold px-8 py-4 rounded-xl transition-all flex items-center gap-2 shadow-[0_0_20px_rgba(0,255,65,0.3)] hover:shadow-cyber-green/50 active:scale-95"
                  >
                    {t.startButton}
                  </button>
                </div>
                {validationError && (
                  <div className="absolute left-0 right-0 -bottom-8 flex justify-center">
                    <p className="text-[10px] text-red-500 font-mono flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3" /> {validationError}
                    </p>
                  </div>
                )}
              </form>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full mt-12">
              <div className="group bg-cyber-dark/50 border border-white/5 p-8 rounded-3xl hover:bg-cyber-dark hover:border-cyber-green/30 transition-all duration-500">
                <h4 className="text-lg font-bold text-white mb-2">{t.feature1Title}</h4>
                <p className="text-sm text-gray-500 leading-relaxed">{t.feature1Desc}</p>
              </div>
              <div className="group bg-cyber-dark/50 border border-white/5 p-8 rounded-3xl hover:bg-cyber-dark hover:border-cyber-green/30 transition-all duration-500">
                <h4 className="text-lg font-bold text-white mb-2">{t.feature2Title}</h4>
                <p className="text-sm text-gray-500 leading-relaxed">{t.feature2Desc}</p>
              </div>
              <div className="group bg-cyber-dark/50 border border-white/5 p-8 rounded-3xl hover:bg-cyber-dark hover:border-cyber-green/30 transition-all duration-500">
                <h4 className="text-lg font-bold text-white mb-2">{t.feature3Title}</h4>
                <p className="text-sm text-gray-500 leading-relaxed">{t.feature3Desc}</p>
              </div>
            </div>
          </div>
        )}

        {status === 'SCANNING' && (
          <div className="flex-grow flex flex-col items-center justify-center w-full p-4 animate-fade-in relative">
             <div className="mb-8 text-center relative z-10">
               <div className="inline-block p-3 rounded-full bg-cyber-green/10 mb-4 animate-spin-slow">
                 <Cpu className="w-8 h-8 text-cyber-green" />
               </div>
               <h3 className="text-3xl font-bold text-white mb-2">{t.terminalProcessing}</h3>
               <div className="flex items-center justify-center gap-2 font-mono text-sm">
                 <span className="text-gray-500">{t.terminalTarget}:</span>
                 <span className="text-cyber-green animate-pulse">{url}</span>
               </div>
             </div>
             <div className="relative z-10 w-full">
               <ScanTerminal
                 onComplete={handleTerminalComplete}
                 lang={lang}
                 scanId={scanId || undefined}
                 useSSE={false}
               />
             </div>
          </div>
        )}

        {status === 'COMPLETE' && report && (
          <div className="relative w-full p-4 md:p-8">
             <ReportDashboard report={report} onReset={resetApp} lang={lang} />
          </div>
        )}

        {status === 'ERROR' && (
           <div className="flex-grow flex flex-col items-center justify-center max-w-xl mx-auto text-center animate-fade-in p-6">
             <ShieldAlert className="w-16 h-16 text-red-500 mb-6" />
             <h2 className="text-3xl font-bold text-white mb-4">{lang === 'tr' ? 'Analiz Başarısız' : 'Analysis Failed'}</h2>
             <p className="text-gray-400 mb-8">{error}</p>
             <button onClick={resetApp} className="bg-white/5 hover:bg-white/10 text-white px-10 py-3 rounded-xl border border-white/10 transition-all">
               {lang === 'tr' ? 'TEKRAR DENE' : 'TRY AGAIN'}
             </button>
           </div>
        )}
      </main>

      <footer className="relative z-50 border-t border-white/5 p-8 bg-cyber-black">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2">
             <ShieldCheck className="w-5 h-5 text-cyber-green/50" />
             <span className="text-gray-500 text-xs font-mono">SECURISCAN ENGINE v{APP_CONFIG.version} // {lang === 'tr' ? 'STABİL VERSİYON' : 'STABLE RELEASE'}</span>
          </div>
          <p className="text-gray-600 text-[10px] font-mono">&copy; {new Date().getFullYear()} SecuriScan AI</p>
        </div>
      </footer>
    </div>
  );
};

export default App;
