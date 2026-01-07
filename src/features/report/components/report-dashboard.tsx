import React, { useState, useMemo, useCallback } from 'react';
import { SecurityReport, Severity, TechStackItem, ActionPlanItem } from '../../../types';
import VulnerabilityCard from './vulnerability-card';
import { translations } from '../../../i18n';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { X, Download, Shield, Globe, FileText, Lock, Settings, ChevronRight, AlertTriangle, Map, Database, Eye, Clock, Zap, ExternalLink, Cpu, TrendingDown, ArrowUpDown, ChevronUp, ChevronDown, Loader2, CheckCircle, XCircle, Server, FileSearch, Bug, ShieldAlert, FolderSearch } from 'lucide-react';
import { exportToPdf, exportToJson } from '../../../services/report-exporter.service';

interface Props {
  report: SecurityReport;
  onReset: () => void;
  lang: 'tr' | 'en';
}

type SortKey = 'priority' | 'estimatedTime';
type SortOrder = 'asc' | 'desc';

// Toast notification types
type ToastType = 'success' | 'error' | 'loading';

interface Toast {
  id: string;
  type: ToastType;
  message: string;
}

const ReportDashboard: React.FC<Props> = ({ report, onReset, lang }) => {
  const [selectedTech, setSelectedTech] = useState<TechStackItem | null>(null);
  const [sortConfig, setSortConfig] = useState<{ key: SortKey; order: SortOrder } | null>(null);
  const [isExporting, setIsExporting] = useState<'pdf' | 'json' | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [showExportMenu, setShowExportMenu] = useState(false);
  
  const t = translations[lang];

  // Toast notification helpers
  const addToast = useCallback((type: ToastType, message: string) => {
    const id = Date.now().toString();
    setToasts(prev => [...prev, { id, type, message }]);
    
    // Auto-remove after 4 seconds (except loading)
    if (type !== 'loading') {
      setTimeout(() => {
        setToasts(prev => prev.filter(toast => toast.id !== id));
      }, 4000);
    }
    return id;
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  // Export handlers
  const handleExportPdf = useCallback(async () => {
    setIsExporting('pdf');
    setShowExportMenu(false);
    const loadingToastId = addToast('loading', lang === 'tr' ? 'PDF oluşturuluyor...' : 'Generating PDF...');
    
    try {
      const result = await exportToPdf(report, { language: lang });
      removeToast(loadingToastId);
      
      if (result.success) {
        addToast('success', lang === 'tr' 
          ? `PDF başarıyla indirildi: ${result.filename}` 
          : `PDF downloaded successfully: ${result.filename}`);
      } else {
        addToast('error', result.error || (lang === 'tr' ? 'PDF oluşturulamadı' : 'Failed to generate PDF'));
      }
    } catch (error) {
      removeToast(loadingToastId);
      addToast('error', lang === 'tr' ? 'PDF oluşturulurken hata oluştu' : 'Error generating PDF');
    } finally {
      setIsExporting(null);
    }
  }, [report, lang, addToast, removeToast]);

  const handleExportJson = useCallback(async () => {
    setIsExporting('json');
    setShowExportMenu(false);
    const loadingToastId = addToast('loading', lang === 'tr' ? 'JSON oluşturuluyor...' : 'Generating JSON...');
    
    try {
      const result = await exportToJson(report, { language: lang });
      removeToast(loadingToastId);
      
      if (result.success) {
        addToast('success', lang === 'tr' 
          ? `JSON başarıyla indirildi: ${result.filename}` 
          : `JSON downloaded successfully: ${result.filename}`);
      } else {
        addToast('error', result.error || (lang === 'tr' ? 'JSON oluşturulamadı' : 'Failed to generate JSON'));
      }
    } catch (error) {
      removeToast(loadingToastId);
      addToast('error', lang === 'tr' ? 'JSON oluşturulurken hata oluştu' : 'Error generating JSON');
    } finally {
      setIsExporting(null);
    }
  }, [report, lang, addToast, removeToast]);

  const severityCount = {
    [Severity.CRITICAL]: report.vulnerabilities.filter(v => v.severity === Severity.CRITICAL).length,
    [Severity.HIGH]: report.vulnerabilities.filter(v => v.severity === Severity.HIGH).length,
    [Severity.MEDIUM]: report.vulnerabilities.filter(v => v.severity === Severity.MEDIUM).length,
    [Severity.LOW]: report.vulnerabilities.filter(v => v.severity === Severity.LOW).length,
    [Severity.INFO]: report.vulnerabilities.filter(v => v.severity === Severity.INFO).length,
  };

  const criticalFindings = useMemo(() => [...report.vulnerabilities]
    .sort((a, b) => b.cvssScore - a.cvssScore)
    .slice(0, 2), [report.vulnerabilities]);

  const urgentActionsPreview = useMemo(() => report.actionPlan
    .filter(a => a.priority === 'URGENT' || a.priority === 'HIGH')
    .slice(0, 2), [report.actionPlan]);

  const parseTimeValue = (timeStr: string): number => {
    const t = timeStr.toLowerCase();
    if (t.includes('dakika') || t.includes('minute')) return parseInt(t) || 0;
    if (t.includes('saat') || t.includes('hour')) {
      const matches = t.match(/\d+/g);
      if (!matches) return 0;
      const average = matches.reduce((acc, val) => acc + parseInt(val), 0) / matches.length;
      return average * 60;
    }
    return 0;
  };

  const priorityWeight = { 'URGENT': 3, 'HIGH': 2, 'MEDIUM': 1 };

  const sortedActionPlan = useMemo(() => {
    const items = [...report.actionPlan];
    if (!sortConfig) return items;

    return items.sort((a, b) => {
      let valA: number = 0;
      let valB: number = 0;

      if (sortConfig.key === 'priority') {
        valA = priorityWeight[a.priority as keyof typeof priorityWeight] || 0;
        valB = priorityWeight[b.priority as keyof typeof priorityWeight] || 0;
      } else if (sortConfig.key === 'estimatedTime') {
        valA = parseTimeValue(a.estimatedTime);
        valB = parseTimeValue(b.estimatedTime);
      }

      if (valA < valB) return sortConfig.order === 'asc' ? -1 : 1;
      if (valA > valB) return sortConfig.order === 'asc' ? 1 : -1;
      return 0;
    });
  }, [report.actionPlan, sortConfig]);

  const handleSort = (key: SortKey) => {
    let order: SortOrder = 'desc';
    if (sortConfig?.key === key && sortConfig.order === 'desc') {
      order = 'asc';
    }
    setSortConfig({ key, order });
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-500 border-green-500';
    if (score >= 70) return 'text-yellow-500 border-yellow-500';
    if (score >= 50) return 'text-orange-500 border-orange-500';
    return 'text-red-500 border-red-500';
  };

  const getScoreLabel = (score: number) => {
    if (score >= 90) return t.riskLevels.low;
    if (score >= 70) return t.riskLevels.medium;
    if (score >= 50) return t.riskLevels.high;
    return t.riskLevels.critical;
  };

  return (
    <div className="w-full max-w-7xl mx-auto pb-20 animate-fade-in relative space-y-16">
      
      {/* Header Summary */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-gray-800 pb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="bg-cyber-green/20 text-cyber-green text-[10px] font-bold px-2 py-0.5 rounded border border-cyber-green/30 uppercase tracking-widest">PRO ANALİZ</span>
            <h2 className="text-3xl font-bold text-white font-mono flex items-center gap-3">
              {t.reportTitle}
            </h2>
          </div>
          <p className="text-gray-400 font-mono text-sm">{report.targetUrl} • {report.scanTimestamp}</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="relative">
            <button 
              onClick={() => setShowExportMenu(!showExportMenu)}
              disabled={isExporting !== null}
              className="bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 px-4 py-2 rounded-lg transition-colors border border-blue-500/50 font-mono text-sm flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isExporting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              {isExporting === 'pdf' ? (lang === 'tr' ? 'PDF İndiriliyor...' : 'Downloading PDF...') :
               isExporting === 'json' ? (lang === 'tr' ? 'JSON İndiriliyor...' : 'Downloading JSON...') :
               'PDF / JSON'}
            </button>
            
            {/* Export dropdown menu */}
            {showExportMenu && !isExporting && (
              <div className="absolute top-full left-0 mt-2 bg-cyber-dark border border-gray-700 rounded-lg shadow-xl z-50 min-w-[160px] overflow-hidden">
                <button
                  onClick={handleExportPdf}
                  className="w-full px-4 py-3 text-left text-sm text-gray-300 hover:bg-blue-500/10 hover:text-blue-400 transition-colors flex items-center gap-2 border-b border-gray-800"
                >
                  <FileText className="w-4 h-4" />
                  {lang === 'tr' ? 'PDF İndir' : 'Download PDF'}
                </button>
                <button
                  onClick={handleExportJson}
                  className="w-full px-4 py-3 text-left text-sm text-gray-300 hover:bg-green-500/10 hover:text-green-400 transition-colors flex items-center gap-2"
                >
                  <Database className="w-4 h-4" />
                  {lang === 'tr' ? 'JSON İndir' : 'Download JSON'}
                </button>
              </div>
            )}
          </div>
          <button onClick={onReset} className="bg-cyber-gray hover:bg-gray-700 text-white px-6 py-2 rounded-lg transition-colors border border-gray-600 font-mono text-sm">
            {lang === 'tr' ? 'Yeni Tarama' : 'New Scan'}
          </button>
        </div>
      </div>

      {/* 0. SECTION: EXECUTIVE BRIEFING */}
      <section className="bg-gradient-to-br from-cyber-dark to-black border border-cyber-green/20 rounded-3xl p-8 relative overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)]">
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-green/5 blur-[100px] pointer-events-none"></div>
        <div className="relative z-10">
          <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] flex items-center gap-2 mb-8">
            <FileText className="w-4 h-4" /> 00 // {t.executiveBriefing}
          </h3>
          
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
            <div className="lg:col-span-3 flex flex-col items-center justify-center border-r border-gray-800/50 pr-8">
              <div className={`text-5xl font-bold font-mono mb-2 ${getScoreColor(report.overallScore)}`}>
                {report.overallScore}
              </div>
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">{t.securityScore}</div>
              <span className={`px-4 py-1 rounded-full text-[10px] font-bold border ${getScoreColor(report.overallScore)} bg-black/40`}>
                {getScoreLabel(report.overallScore)}
              </span>
            </div>

            <div className="lg:col-span-4 space-y-4 border-r border-gray-800/50 pr-8">
              <h4 className="text-red-500 text-[10px] font-bold uppercase tracking-widest flex items-center gap-2 mb-4">
                <AlertTriangle className="w-3 h-3" /> {t.criticalFindings}
              </h4>
              <div className="space-y-3">
                {criticalFindings.map((f, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 bg-red-500/5 border border-red-500/10 rounded-xl">
                    <div className="w-6 h-6 rounded bg-red-500/20 flex items-center justify-center text-[10px] font-bold text-red-500 shrink-0">
                      {f.cvssScore}
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white mb-1">{f.title}</div>
                      <div className="text-[10px] text-gray-500 line-clamp-1">{f.location}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 space-y-4">
              <h4 className="text-cyber-green text-[10px] font-bold uppercase tracking-widest flex items-center gap-2 mb-4">
                <Zap className="w-3 h-3" /> {t.strategicActions}
              </h4>
              <div className="space-y-3">
                {urgentActionsPreview.map((a, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 bg-cyber-green/5 border border-cyber-green/10 rounded-xl">
                    <div className="w-6 h-6 rounded bg-cyber-green/20 flex items-center justify-center text-[10px] font-bold text-cyber-green shrink-0">!</div>
                    <div>
                      <div className="text-xs font-bold text-white mb-1">{a.task}</div>
                      <div className="text-[10px] text-gray-500 flex items-center gap-2 italic">
                        <TrendingDown className="w-3 h-3 text-orange-500/50" />
                        {a.delayImpact}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 1. SECTION: DETAYLI RİSK ANALİZİ */}
      <section className="space-y-6">
        <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
          01 // {lang === 'tr' ? 'DETAYLI RİSK ANALİZİ' : 'DETAILED RISK ANALYSIS'}
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="bg-cyber-dark border border-gray-800 rounded-xl p-8 flex flex-col items-center justify-center relative overflow-hidden h-72 shadow-2xl">
            <h3 className="text-gray-500 uppercase text-[10px] font-bold tracking-widest mb-6 text-center">{t.vulnerabilityDistribution}</h3>
            <div className="h-full w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={Object.entries(severityCount).map(([name, value]) => ({ name, value }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    <Cell fill="#ef4444" />
                    <Cell fill="#f97316" />
                    <Cell fill="#eab308" />
                    <Cell fill="#3b82f6" />
                    <Cell fill="#9ca3af" />
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#111', borderColor: '#333', color: '#fff' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="lg:col-span-3 bg-cyber-dark border border-gray-800 rounded-xl p-8 h-72">
             <div className="flex items-center gap-3 mb-4">
                <Shield className="text-cyber-green w-5 h-5" />
                <h3 className="text-white font-bold text-lg">{t.summaryFindings}</h3>
             </div>
             <p className="text-gray-400 text-sm leading-relaxed mb-6 italic">"{report.summary}"</p>
             <div className="grid grid-cols-3 gap-4 border-t border-gray-800 pt-6">
                <div>
                   <span className="text-[10px] text-gray-500 uppercase block mb-1">{t.vulnerabilitiesDetected}</span>
                   <span className="text-2xl font-bold text-white font-mono">{report.vulnerabilities.length}</span>
                </div>
                <div>
                   <span className="text-[10px] text-gray-500 uppercase block mb-1">{t.subdomainsCount}</span>
                   <span className="text-2xl font-bold text-white font-mono">{report.subdomains.length}</span>
                </div>
                <div>
                   <span className="text-[10px] text-gray-500 uppercase block mb-1">{t.leaksCount}</span>
                   <span className="text-2xl font-bold text-red-500 font-mono">{report.darkWebLeaks.length}</span>
                </div>
             </div>
          </div>
        </div>
      </section>

      {/* 3. SECTION: ACTION PLAN */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
            03 // {t.actionPlan}
          </h3>
        </div>
        <div className="bg-cyber-dark border border-gray-800 rounded-xl overflow-hidden shadow-2xl overflow-x-auto">
           <table className="w-full text-left text-sm min-w-[800px]">
              <thead className="bg-gray-900/50 text-[10px] text-gray-500 uppercase font-bold border-b border-gray-800">
                 <tr>
                    <th className="px-6 py-4">{t.step}</th>
                    <th className="px-6 py-4">{t.task}</th>
                    <th className="px-6 py-4 cursor-pointer select-none" onClick={() => handleSort('priority')}>{t.priority}</th>
                    <th className="px-6 py-4 cursor-pointer select-none" onClick={() => handleSort('estimatedTime')}>{t.estTime}</th>
                    <th className="px-6 py-4">{t.delayImpact}</th>
                    <th className="px-6 py-4">{t.effort}</th>
                 </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                 {sortedActionPlan.map((item, i) => (
                   <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-6 py-5 font-mono text-gray-600">0{i+1}</td>
                      <td className="px-6 py-5"><div className="text-gray-300 font-medium">{item.task}</div></td>
                      <td className="px-6 py-5">
                         <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${item.priority === 'URGENT' ? 'text-red-500 border-red-500/20 bg-red-500/5' : 'text-orange-500 border-orange-500/20 bg-orange-500/5'}`}>
                            {item.priority}
                         </span>
                      </td>
                      <td className="px-6 py-5 font-mono text-xs text-blue-400">{item.estimatedTime}</td>
                      <td className="px-6 py-5 text-xs text-gray-400 italic">{item.delayImpact}</td>
                      <td className="px-6 py-5 text-gray-500 font-mono text-xs">{item.effort}</td>
                   </tr>
                 ))}
              </tbody>
           </table>
        </div>
      </section>

      {/* 4. SECTION: VULNERABILITIES */}
      <section className="space-y-6">
        <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
          04 // {lang === 'tr' ? 'TESPİT EDİLEN ZAFİYETLER' : 'IDENTIFIED VULNERABILITIES'} ({report.vulnerabilities.length})
        </h3>
        <div className="space-y-4">
          {report.vulnerabilities.map(v => <VulnerabilityCard key={v.id} vuln={v} lang={lang} />)}
        </div>
      </section>

      {/* 5. SECTION: TECH STACK */}
      <section className="space-y-6">
        <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
          05 // {t.techStackTitle}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {report.techStackDetected.map((tech, i) => {
            // Find CVE correlations for this technology
            const techCves = report.cveCorrelations?.find(c => c.technology.toLowerCase() === tech.name.toLowerCase());
            
            return (
              <div key={i} onClick={() => setSelectedTech(tech)} className="group bg-cyber-dark border border-gray-800 p-6 rounded-xl hover:border-cyber-green/50 hover:bg-white/[0.02] transition-all cursor-pointer relative">
                <div className="w-10 h-10 bg-cyber-green/5 rounded-lg flex items-center justify-center mb-4 border border-cyber-green/10">
                   <Cpu className="w-5 h-5 text-cyber-green" />
                </div>
                <h4 className="text-white font-bold mb-2 font-mono">{tech.name}</h4>
                <p className="text-gray-500 text-xs leading-relaxed mb-4 line-clamp-2">{tech.description}</p>
                
                {/* CVE Badge */}
                {techCves && techCves.totalCount > 0 && (
                  <div className="flex items-center gap-2 mt-3 pt-3 border-t border-gray-800">
                    <Bug className="w-3.5 h-3.5 text-red-400" />
                    <span className="text-[10px] font-bold text-red-400">
                      {techCves.totalCount} CVE{techCves.totalCount > 1 ? 's' : ''} {lang === 'tr' ? 'bulundu' : 'found'}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* 5b. SECTION: CVE CORRELATIONS */}
      {report.cveCorrelations && report.cveCorrelations.length > 0 && (
        <section className="space-y-6">
          <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
            05b // {lang === 'tr' ? 'CVE KORELASYONLARI' : 'CVE CORRELATIONS'}
          </h3>
          <div className="bg-cyber-dark border border-gray-800 rounded-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-gray-800 flex items-center gap-3">
              <Bug className="w-5 h-5 text-red-400" />
              <span className="text-white font-bold">
                {lang === 'tr' ? 'Tespit Edilen Teknolojilere Ait Bilinen Güvenlik Açıkları' : 'Known Vulnerabilities for Detected Technologies'}
              </span>
            </div>
            <div className="divide-y divide-gray-800">
              {report.cveCorrelations.map((correlation, idx) => (
                <div key={idx} className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Cpu className="w-4 h-4 text-cyber-green" />
                      <span className="text-white font-bold font-mono">{correlation.technology}</span>
                      {correlation.version && (
                        <span className="text-gray-500 text-xs font-mono">v{correlation.version}</span>
                      )}
                    </div>
                    <span className="text-[10px] font-bold px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                      {correlation.totalCount} CVE
                    </span>
                  </div>
                  <div className="space-y-3">
                    {correlation.cves.slice(0, 3).map((cve, cveIdx) => (
                      <div key={cveIdx} className="flex items-start gap-4 p-3 bg-black/30 rounded-lg border border-gray-800/50">
                        <div className={`w-10 h-10 rounded flex items-center justify-center text-[10px] font-bold shrink-0 ${
                          cve.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          cve.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                          cve.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                          'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}>
                          {cve.cvssScore.toFixed(1)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-white font-mono text-sm font-bold">{cve.id}</span>
                            {cve.hasExploit && (
                              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                                EXPLOIT
                              </span>
                            )}
                          </div>
                          <p className="text-gray-400 text-xs line-clamp-2">{cve.description}</p>
                          <a 
                            href={cve.nvdUrl} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-[10px] text-blue-400 hover:text-blue-300 flex items-center gap-1 mt-2"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <ExternalLink className="w-3 h-3" />
                            NVD {lang === 'tr' ? 'Detayları' : 'Details'}
                          </a>
                        </div>
                      </div>
                    ))}
                    {correlation.cves.length > 3 && (
                      <div className="text-center text-gray-500 text-xs py-2">
                        +{correlation.cves.length - 3} {lang === 'tr' ? 'daha fazla CVE' : 'more CVEs'}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* 6. SECTION: HTTP METHODS & ROBOTS ANALYSIS */}
      {(report.httpMethods || report.robotsAnalysis) && (
        <section className="space-y-6">
          <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
            06 // {lang === 'tr' ? 'SUNUCU YAPILANDIRMASI' : 'SERVER CONFIGURATION'}
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* HTTP Methods Card */}
            {report.httpMethods && (
              <div className="bg-cyber-dark border border-gray-800 rounded-xl p-6 shadow-2xl">
                <div className="flex items-center gap-3 mb-6">
                  <Server className="w-5 h-5 text-blue-400" />
                  <h4 className="text-white font-bold">HTTP {lang === 'tr' ? 'Metodları' : 'Methods'}</h4>
                </div>
                
                {/* Allowed Methods */}
                <div className="mb-4">
                  <span className="text-[10px] text-gray-500 uppercase font-bold block mb-2">
                    {lang === 'tr' ? 'İzin Verilen Metodlar' : 'Allowed Methods'}
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {report.httpMethods.allowed.length > 0 ? (
                      report.httpMethods.allowed.map((method, i) => (
                        <span 
                          key={i} 
                          className={`text-xs font-mono px-2 py-1 rounded border ${
                            report.httpMethods?.dangerous.includes(method)
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : 'bg-gray-800 text-gray-300 border-gray-700'
                          }`}
                        >
                          {method}
                        </span>
                      ))
                    ) : (
                      <span className="text-gray-500 text-xs italic">
                        {lang === 'tr' ? 'Tespit edilemedi' : 'Not detected'}
                      </span>
                    )}
                  </div>
                </div>
                
                {/* Dangerous Methods Warning */}
                {report.httpMethods.dangerous.length > 0 && (
                  <div className="mt-4 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      <span className="text-red-400 text-xs font-bold uppercase">
                        {lang === 'tr' ? 'Tehlikeli Metodlar Aktif' : 'Dangerous Methods Enabled'}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {report.httpMethods.dangerous.map((method, i) => (
                        <span key={i} className="text-xs font-mono px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                          {method}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Robots.txt Analysis Card */}
            {report.robotsAnalysis && (
              <div className="bg-cyber-dark border border-gray-800 rounded-xl p-6 shadow-2xl">
                <div className="flex items-center gap-3 mb-6">
                  <FolderSearch className="w-5 h-5 text-yellow-400" />
                  <h4 className="text-white font-bold">Robots.txt & Security.txt</h4>
                </div>
                
                {/* Security.txt Status */}
                <div className="mb-4 p-3 rounded-lg border ${report.robotsAnalysis.hasSecurityTxt ? 'bg-green-500/5 border-green-500/20' : 'bg-yellow-500/5 border-yellow-500/20'}">
                  <div className="flex items-center gap-2">
                    {report.robotsAnalysis.hasSecurityTxt ? (
                      <>
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-green-400 text-xs font-bold">
                          security.txt {lang === 'tr' ? 'mevcut' : 'present'}
                        </span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-4 h-4 text-yellow-400" />
                        <span className="text-yellow-400 text-xs font-bold">
                          security.txt {lang === 'tr' ? 'bulunamadı' : 'not found'}
                        </span>
                      </>
                    )}
                  </div>
                </div>
                
                {/* Sensitive Paths */}
                {report.robotsAnalysis.sensitivePaths.length > 0 && (
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase font-bold block mb-2">
                      {lang === 'tr' ? 'Hassas Yollar (robots.txt)' : 'Sensitive Paths (robots.txt)'}
                    </span>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {report.robotsAnalysis.sensitivePaths.map((path, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 bg-orange-500/5 border border-orange-500/20 rounded">
                          <FileSearch className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                          <span className="text-orange-300 text-xs font-mono truncate">{path}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {report.robotsAnalysis.sensitivePaths.length === 0 && (
                  <div className="text-gray-500 text-xs italic">
                    {lang === 'tr' ? 'Hassas yol tespit edilmedi' : 'No sensitive paths detected'}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      )}
      
      {/* 7. SECTION: NETWORK */}
      <section className="space-y-6">
        <h3 className="text-cyber-green font-mono text-xs uppercase tracking-[0.3em] border-l-2 border-cyber-green pl-3 mb-6">
          07 // {t.networkIntel}
        </h3>
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: 'IP', val: report.networkInfo.ip, icon: Globe },
              { label: lang === 'tr' ? 'KONUM' : 'LOCATION', val: report.networkInfo.location, icon: Map },
              { label: 'ISP', val: report.networkInfo.organization, icon: Database },
              { label: lang === 'tr' ? 'SUNUCU' : 'SERVER', val: report.networkInfo.serverType, icon: Settings }
            ].map((stat, i) => (
              <div key={i} className="bg-cyber-dark border border-gray-800 p-6 rounded-xl hover:border-gray-700 transition-colors">
                <span className="text-[10px] text-gray-600 uppercase font-mono block mb-2">{stat.label}</span>
                <div className="text-sm font-mono text-gray-200 truncate">{stat.val}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg border backdrop-blur-sm animate-fade-in max-w-sm ${
              toast.type === 'success' 
                ? 'bg-green-500/10 border-green-500/30 text-green-400' 
                : toast.type === 'error'
                ? 'bg-red-500/10 border-red-500/30 text-red-400'
                : 'bg-blue-500/10 border-blue-500/30 text-blue-400'
            }`}
          >
            {toast.type === 'success' && <CheckCircle className="w-5 h-5 shrink-0" />}
            {toast.type === 'error' && <XCircle className="w-5 h-5 shrink-0" />}
            {toast.type === 'loading' && <Loader2 className="w-5 h-5 shrink-0 animate-spin" />}
            <span className="text-sm font-mono">{toast.message}</span>
            {toast.type !== 'loading' && (
              <button 
                onClick={() => removeToast(toast.id)}
                className="ml-2 hover:opacity-70 transition-opacity"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Click outside to close export menu */}
      {showExportMenu && (
        <div 
          className="fixed inset-0 z-40" 
          onClick={() => setShowExportMenu(false)}
        />
      )}
    </div>
  );
};

export default ReportDashboard;