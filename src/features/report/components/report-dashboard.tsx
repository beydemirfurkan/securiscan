import React, { useState, useMemo } from 'react';
import { SecurityReport, Severity, TechStackItem, ActionPlanItem } from '../../../types';
import VulnerabilityCard from './vulnerability-card';
import { translations } from '../../../i18n';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { X, Download, Shield, Globe, FileText, Lock, Settings, ChevronRight, AlertTriangle, Map, Database, Eye, Clock, Zap, ExternalLink, Cpu, TrendingDown, ArrowUpDown, ChevronUp, ChevronDown } from 'lucide-react';

interface Props {
  report: SecurityReport;
  onReset: () => void;
  lang: 'tr' | 'en';
}

type SortKey = 'priority' | 'estimatedTime';
type SortOrder = 'asc' | 'desc';

const ReportDashboard: React.FC<Props> = ({ report, onReset, lang }) => {
  const [selectedTech, setSelectedTech] = useState<TechStackItem | null>(null);
  const [sortConfig, setSortConfig] = useState<{ key: SortKey; order: SortOrder } | null>(null);
  
  const t = translations[lang];

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
          <button 
            onClick={() => {}}
            className="bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 px-4 py-2 rounded-lg transition-colors border border-blue-500/50 font-mono text-sm flex items-center gap-2"
          >
            <Download className="w-4 h-4" /> PDF / JSON
          </button>
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
          {report.techStackDetected.map((tech, i) => (
            <div key={i} onClick={() => setSelectedTech(tech)} className="group bg-cyber-dark border border-gray-800 p-6 rounded-xl hover:border-cyber-green/50 hover:bg-white/[0.02] transition-all cursor-pointer relative">
              <div className="w-10 h-10 bg-cyber-green/5 rounded-lg flex items-center justify-center mb-4 border border-cyber-green/10">
                 <Cpu className="w-5 h-5 text-cyber-green" />
              </div>
              <h4 className="text-white font-bold mb-2 font-mono">{tech.name}</h4>
              <p className="text-gray-500 text-xs leading-relaxed mb-4 line-clamp-2">{tech.description}</p>
            </div>
          ))}
        </div>
      </section>
      
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
    </div>
  );
};

export default ReportDashboard;