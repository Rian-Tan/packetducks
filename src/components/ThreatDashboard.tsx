import React, { useState } from "react";
import { ThreatIntel } from "../types";
import { checkSingleVirusTotal } from "../services/geminiService";
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  AlertOctagon,
  Activity,
  ExternalLink,
  Bug,
  Search,
  Loader2
} from "lucide-react";

interface ThreatDashboardProps {
  data: ThreatIntel | null;
  loading: boolean;
}

export const ThreatDashboard: React.FC<ThreatDashboardProps> = ({
  data,
  loading,
}) => {
  const [manualChecks, setManualChecks] = useState<Record<string, string>>({});
  const [checkingIps, setCheckingIps] = useState<Record<string, boolean>>({});
  const [checkErrors, setCheckErrors] = useState<Record<string, string>>({});

  if (loading) {
    return (
      <div className="w-full h-64 flex flex-col items-center justify-center space-y-4 bg-cyber-800/30 rounded-xl border border-cyber-700 animate-pulse">
        <Activity className="w-12 h-12 text-cyber-500 animate-bounce" />
        <p className="text-cyber-400 font-mono">
          Analysing for threats & checking VirusTotal...
        </p>
      </div>
    );
  }

  if (!data) return null;

  const handleManualCheck = async (ip: string) => {
    setCheckingIps(prev => ({ ...prev, [ip]: true }));
    setCheckErrors(prev => ({ ...prev, [ip]: '' }));
    
    try {
      const result = await checkSingleVirusTotal(ip);
      setManualChecks(prev => ({ ...prev, [ip]: result }));
    } catch (err: any) {
      setCheckErrors(prev => ({ ...prev, [ip]: 'Check failed' }));
    } finally {
      setCheckingIps(prev => ({ ...prev, [ip]: false }));
    }
  };

  const getScoreColor = (score: number) => {
    if (score < 30) return "text-cyber-success border-cyber-success";
    if (score < 70) return "text-cyber-warning border-cyber-warning";
    return "text-cyber-danger border-cyber-danger";
  };

  const getVirusTotalStatus = (val: string) => {
    const parts = val.split('/');
    if (parts.length === 2) {
        const count = parseInt(parts[0], 10);
        const total = parseInt(parts[1], 10);
        return { count, total, isMalicious: count > 0, label: val };
    }
    return { count: 0, total: 0, isMalicious: false, label: val };
  };

  return (
    <div className="space-y-6">
      {/* Risk Score Card */}
      <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-6 flex flex-col items-center justify-center relative overflow-hidden">
        <div
          className={`absolute inset-0 opacity-10 ${data.riskScore > 50 ? "bg-red-500" : "bg-green-500"}`}
        ></div>
        <h3 className="text-gray-400 font-mono text-sm uppercase mb-2">
          Composite Risk Score
        </h3>
        <div
          className={`text-5xl font-bold font-mono border-4 rounded-full w-32 h-32 flex items-center justify-center ${getScoreColor(data.riskScore)}`}
        >
          {data.riskScore}
        </div>
      </div>

      {/* Summary Card */}
      <div className="md:col-span-2 bg-cyber-800 border border-cyber-700 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="text-cyber-accent" />
          <h3 className="text-lg font-semibold text-gray-100">
            AI Threat Assessment
          </h3>
        </div>
        <p className="text-gray-300 leading-relaxed text-sm border-l-2 border-cyber-accent pl-4">
          {data.summary}
        </p>
      </div>

      {/* IOCs */}
      <div className="bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-700 bg-cyber-900/50 flex justify-between items-center">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <AlertOctagon className="text-cyber-danger" size={20} />
            Indicators of Compromise
          </h3>
          <span className="text-xs font-mono text-gray-500">
            {data.iocs.length} detected
          </span>
        </div>
        <div className="divide-y divide-cyber-700">
          {data.iocs.length === 0 ? (
            <div className="p-8 text-center text-gray-500 flex flex-col items-center">
              <ShieldCheck size={48} className="mb-2 opacity-50" />
              <p>No high-confidence IOCs detected in this sample.</p>
            </div>
          ) : (
            data.iocs.map((ioc, idx) => {
              const vtValue = ioc.virusTotalDetections || manualChecks[ioc.value];
              const isIp = ioc.type && ioc.type.toUpperCase() === 'IP';
              const isLoading = checkingIps[ioc.value];
              const error = checkErrors[ioc.value];

              return (
              <div
                key={idx}
                className="p-4 flex items-start gap-4 hover:bg-cyber-700/30 transition-colors"
              >
                <div
                  className={`mt-1 p-1 rounded ${
                    ioc.severity === "CRITICAL"
                      ? "bg-red-500/20 text-red-400"
                      : ioc.severity === "HIGH"
                        ? "bg-orange-500/20 text-orange-400"
                        : "bg-yellow-500/20 text-yellow-400"
                  }`}
                >
                  <AlertTriangle size={16} />
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-start">
                    <span className="font-mono text-cyber-accent font-bold">
                      {ioc.value}
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono uppercase ${
                        ioc.severity === "CRITICAL"
                          ? "bg-red-900 text-red-200"
                          : "bg-cyber-700 text-gray-300"
                      }`}
                    >
                      {ioc.severity}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 font-mono mt-1 mb-1">
                    {ioc.type}
                  </div>
                  <p className="text-sm text-gray-300 mb-2">{ioc.description}</p>
                  
                  {/* VirusTotal Display Logic */}
                  {isIp && (
                    <div className="mt-3">
                      {vtValue ? (
                        <div className="flex items-center gap-3 bg-cyber-900/50 p-2 rounded border border-cyber-700 animate-fade-in">
                            {(() => {
                                const status = getVirusTotalStatus(vtValue);
                                return (
                                    <>
                                        <div className={`flex items-center gap-1.5 ${status.isMalicious ? 'text-red-400' : 'text-emerald-400'}`}>
                                            <Bug size={14} className={status.isMalicious ? "text-red-500" : "text-emerald-500"} />
                                            <span className="text-xs font-bold">VirusTotal: {status.label}</span>
                                        </div>
                                        <div className="flex-1 h-1.5 bg-cyber-700 rounded-full overflow-hidden max-w-[100px]">
                                            <div 
                                                className={`h-full rounded-full ${status.isMalicious ? 'bg-red-500' : 'bg-emerald-500'}`}
                                                style={{ width: `${Math.min(100, (status.count / Math.max(status.total, 1)) * 100)}%` }}
                                            ></div>
                                        </div>
                                    </>
                                );
                            })()}
                            <a 
                              href={`https://www.virustotal.com/gui/ip-address/${ioc.value}`} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-xs text-cyber-500 hover:text-cyber-400 flex items-center gap-1 ml-auto"
                            >
                              View Report <ExternalLink size={10} />
                            </a>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                           {!isLoading && !error && (
                             <button 
                               onClick={() => handleManualCheck(ioc.value)}
                               className="flex items-center gap-2 text-xs bg-cyber-700 hover:bg-cyber-600 border border-cyber-600 text-gray-300 px-3 py-1.5 rounded transition-colors"
                             >
                               <Search size={12} />
                               Check VirusTotal
                             </button>
                           )}
                           
                           {isLoading && (
                             <div className="flex items-center gap-2 text-xs text-cyber-400 bg-cyber-900/50 px-3 py-1.5 rounded border border-cyber-700/50">
                               <Loader2 size={12} className="animate-spin" />
                               Checking API...
                             </div>
                           )}

                           {error && (
                             <div className="flex items-center gap-2">
                               <span className="text-xs text-red-400 bg-red-900/20 px-3 py-1.5 rounded border border-red-900/50">
                                 Lookup Failed
                               </span>
                               <button 
                                 onClick={() => handleManualCheck(ioc.value)}
                                 className="text-xs underline text-cyber-500 hover:text-cyber-400"
                               >
                                 Retry
                               </button>
                             </div>
                           )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )})
          )}
        </div>
      </div>

      {/* Recommendations */}
      <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
          <CheckCircle className="text-cyber-success" size={20} />
          Remediation Steps
        </h3>
        <ul className="space-y-2">
          {data.recommendations.map((rec, i) => (
            <li
              key={i}
              className="flex items-start gap-3 text-sm text-gray-300"
            >
              <span className="text-cyber-success mt-1">•</span>
              {rec}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};