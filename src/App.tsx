import React, { useState, useEffect } from 'react';
import { FileUpload } from './components/FileUpload';
import { ProtocolChart } from './components/ProtocolChart';
import { ThreatDashboard } from './components/ThreatDashboard';
import { TimelineView } from './components/TimelineView';
import { parsePcap } from './services/pcapParser';
import { generateThreatIntel, enrichHostsWithGeoIp } from './services/geminiService';
import { PcapAnalysisResult, ThreatIntel } from './types';
import ReportGenerator from './components/ReportGenerator';
import { Network, Activity, Globe, Tag, AlertTriangle } from 'lucide-react';

// New Components
import { Header } from './components/Header';
import { HistoryView } from './components/HistoryView';
import { ThreatDatabaseView } from './components/ThreatDatabaseView';
import { StatsCards } from './components/StatsCards';

// New Services
import * as api from './services/api';
import { calculateHash, getHostStyle } from './services/utils';

const App: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<PcapAnalysisResult | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntel | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'analyze' | 'history' | 'threats'>('analyze');
  const [currentHash, setCurrentHash] = useState<string | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  
  // Deletion State
  const [deletingHash, setDeletingHash] = useState<string | null>(null);
  
  // Manual IoC State
  const [manualIocValue, setManualIocValue] = useState('');
  const [manualIocType, setManualIocType] = useState<'IP' | 'PORT' | 'PATTERN'>('IP');
  const [manualIocDesc, setManualIocDesc] = useState('');
  const [manualIocSeverity, setManualIocSeverity] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('MEDIUM');

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const data = await api.fetchHistory();
      setHistory(data);
    } catch (err) {
      console.error("Failed to fetch history:", err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const restoreDates = (analysis: any): PcapAnalysisResult => {
    return {
      ...analysis,
      startTime: new Date(analysis.startTime),
      endTime: new Date(analysis.endTime),
      hostGeoMap: analysis.hostGeoMap || {}
    };
  };

  const processFile = async (selectedFile: File) => {
    try {
      setFile(selectedFile);
      setIsProcessing(true);
      setError(null);
      setAnalysis(null);
      setThreatIntel(null);

      // 0. Calculate Hash
      const hash = await calculateHash(selectedFile);
      setCurrentHash(hash);
      
      // 1. Check Cache
      const cacheData = await api.checkCache(hash);

      if (cacheData.found) {
        setAnalysis(restoreDates(cacheData.data.analysis));
        setThreatIntel(cacheData.data.intel);
        setIsProcessing(false);
        return;
      }

      // 2. Client-side Parsing
      const result = await parsePcap(selectedFile);

      if (result.totalPackets === 0) {
        throw new Error("No packets found in file. Ensure the file is a valid PCAP (not PCAPNG) and is not empty.");
      }

      // 2.5 Enrich hosts with GeoIP
      const enrichedResult = await enrichHostsWithGeoIp(result);
      setAnalysis(enrichedResult);

      // 3. AI Analysis
      setIsProcessing(false); // Parsing done
      setIsAiLoading(true); // Start AI

      const intelligence = await generateThreatIntel(enrichedResult);
      setThreatIntel(intelligence);

      // 4. Cache Result
      await api.cacheResult({
        hash,
        filename: selectedFile.name,
        analysis: enrichedResult,
        intel: intelligence,
        classification: intelligence.classification || 'Unknown',
        attack_name: intelligence.attackName || null,
        cve_tags: intelligence.cveTags || [],
        forensic_justification: intelligence.forensicJustification || null
      });

      loadHistory(); // Refresh history

    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to parse file. Ensure it is a valid PCAP file.");
      setAnalysis(null);
      setThreatIntel(null);
    } finally {
      setIsProcessing(false);
      setIsAiLoading(false);
    }
  };

  const loadFromHistory = (item: any) => {
    setFile({ name: item.filename } as File);
    setCurrentHash(item.hash);
    setAnalysis(restoreDates(item.analysis));
    setThreatIntel(item.intel);
    setView('analyze');
  };

  const addManualIoc = async () => {
    if (!threatIntel || !manualIocValue || !currentHash) return;

    const newIoc = {
      value: manualIocValue,
      type: manualIocType,
      description: manualIocDesc,
      severity: manualIocSeverity
    };

    const updatedIntel = {
      ...threatIntel,
      manualIocs: [...(threatIntel.manualIocs || []), newIoc]
    };

    setThreatIntel(updatedIntel);
    setManualIocValue('');
    setManualIocDesc('');

    // Update cache
    await api.cacheResult({
      hash: currentHash,
      filename: file?.name || 'Unknown',
      analysis: analysis!,
      intel: updatedIntel,
      classification: updatedIntel.classification || 'Unknown',
      attack_name: updatedIntel.attackName || null,
      cve_tags: updatedIntel.cveTags || [],
      forensic_justification: updatedIntel.forensicJustification || null
    });
    loadHistory();
  };

  const deleteFromHistory = async (hash: string) => {
    try {
      await api.deleteHistoryItem(hash);
      loadHistory();
      if (currentHash === hash) {
        setAnalysis(null);
        setThreatIntel(null);
        setFile(null);
        setCurrentHash(null);
      }
    } catch (err) {
      console.error("Failed to delete history item:", err);
    } finally {
      setDeletingHash(null);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-900 text-slate-200 font-sans selection:bg-cyber-accent selection:text-white">
      <style>{`
        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes scale-in {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }
        .animate-fade-in {
          animation: fade-in 0.2s ease-out forwards;
        }
        .animate-scale-in {
          animation: scale-in 0.2s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
      `}</style>
      
      <Header view={view} setView={setView} fileName={file?.name} />

      <main className="max-w-7xl mx-auto px-4 py-8 pb-20">
        {view === 'threats' ? (
          <ThreatDatabaseView history={history} loadFromHistory={loadFromHistory} />
        ) : view === 'history' ? (
          <HistoryView 
            history={history}
            isLoadingHistory={isLoadingHistory}
            loadFromHistory={loadFromHistory}
            deleteFromHistory={deleteFromHistory}
            deletingHash={deletingHash}
            setDeletingHash={setDeletingHash}
            setView={setView}
          />
        ) : !analysis ? (
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-3">Analyse a PCAP</h2>
              <p className="text-gray-400 max-w-lg mx-auto">
                Upload a PCAP file
              </p>
            </div>
            <FileUpload onFileSelect={processFile} isProcessing={isProcessing} />
            {error && (
              <div className="mt-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg text-red-200 text-sm max-w-lg text-center break-words">
                <p className="font-semibold mb-1">Error Processing File</p>
                {error}
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-8 animate-fade-in">
            <StatsCards 
              totalPackets={analysis.totalPackets}
              uniqueHostsCount={analysis.uniqueHosts.length}
              connectionsCount={analysis.connections.length}
              duration={(analysis.endTime.getTime() - analysis.startTime.getTime()) / 1000}
            />

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Left Col: Charts & Stats */}
              <div className="lg:col-span-2 space-y-8">
                {/* Protocol Distribution */}
                <section id="protocol-chart" className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Network size={20} className="text-cyber-500" />
                      Protocol Distribution
                    </h3>
                  </div>
                  <ProtocolChart data={analysis.protocolCounts} />
                </section>

                {/* Timeline View */}
                <section>
                  <TimelineView analysis={analysis} threatIntel={threatIntel} />
                </section>

                {/* Connection Table */}
                <section className="bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden">
                  <div className="px-6 py-4 border-b border-cyber-700 bg-cyber-900/50">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Activity size={20} className="text-cyber-warning" />
                      Active Conversations
                    </h3>
                  </div>
                  <div className="max-h-80 overflow-y-auto custom-scrollbar">
                    <table className="w-full text-sm text-left">
                      <thead className="text-xs text-gray-400 uppercase bg-cyber-900 sticky top-0">
                        <tr>
                          <th className="px-6 py-3">Source / Host A</th>
                          <th className="px-6 py-3"></th>
                          <th className="px-6 py-3">Destination / Host B</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cyber-700">
                        {analysis.connections.slice(0, 100).map((conn, idx) => (
                          <tr key={idx} className="hover:bg-cyber-700/50 transition-colors">
                            <td className="px-6 py-3 font-mono text-gray-300">{conn.a}</td>
                            <td className="px-6 py-3 text-center text-cyber-600">↔</td>
                            <td className="px-6 py-3 font-mono text-gray-300">{conn.b}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {analysis.connections.length > 100 && (
                      <div className="p-2 text-center text-xs text-gray-500 italic bg-cyber-900">
                        Showing first 100 connections
                      </div>
                    )}
                  </div>
                </section>

                {/* Detected Hosts */}
                <section className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
                  <div className="flex flex-wrap items-center justify-between mb-4 gap-4">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Globe size={20} className="text-cyber-400" />
                      Detected Hosts
                    </h3>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]"></span>Private</span>
                      <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.5)]"></span>Public</span>
                      <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.5)]"></span>Multicast</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2 max-h-60 overflow-y-auto custom-scrollbar p-1">
                    {analysis.uniqueHosts.map(host => {
                      const geo = analysis.hostGeoMap?.[host];
                      return (
                        <span
                          key={host}
                          className={`px-2.5 py-1 border rounded text-xs font-mono transition-colors cursor-default flex items-center gap-2 ${getHostStyle(host)}`}
                          title={geo?.countryName}
                        >
                          {geo?.countryCode && (
                            <img 
                              src={`https://flagcdn.com/w20/${geo.countryCode.toLowerCase()}.png`}
                              alt={geo.countryCode}
                              className="w-4 h-3 object-cover rounded-sm"
                              referrerPolicy="no-referrer"
                            />
                          )}
                          {host}
                        </span>
                      );
                    })}
                  </div>
                </section>
              </div>

              {/* Right Col: Threat Intel */}
              <div className="space-y-8">
                <div id="threat-dashboard">
                  <ThreatDashboard data={threatIntel} loading={isAiLoading} />
                </div>

                {/* Manual IoC Tagging */}
                <section className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
                  <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
                    <Tag size={20} className="text-cyber-accent" />
                    Manual IoC Tagging
                  </h3>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <select 
                        value={manualIocType}
                        onChange={(e) => setManualIocType(e.target.value as any)}
                        className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent"
                      >
                        <option value="IP">IP Address</option>
                        <option value="PORT">Port</option>
                        <option value="PATTERN">Pattern</option>
                      </select>
                      <select 
                        value={manualIocSeverity}
                        onChange={(e) => setManualIocSeverity(e.target.value as any)}
                        className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent"
                      >
                        <option value="LOW">Low</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="HIGH">High</option>
                        <option value="CRITICAL">Critical</option>
                      </select>
                    </div>
                    <input 
                      type="text" 
                      placeholder="IoC Value (e.g. 1.2.3.4)" 
                      value={manualIocValue}
                      onChange={(e) => setManualIocValue(e.target.value)}
                      className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent"
                    />
                    <textarea 
                      placeholder="Forensic Context / Description" 
                      value={manualIocDesc}
                      onChange={(e) => setManualIocDesc(e.target.value)}
                      rows={2}
                      className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent resize-none"
                    />
                    <button 
                      onClick={addManualIoc}
                      disabled={!manualIocValue}
                      className="w-full py-2 bg-cyber-700 hover:bg-cyber-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors border border-cyber-600 text-sm font-semibold"
                    >
                      Add Manual Indicator
                    </button>
                  </div>
                </section>

                {analysis && threatIntel && (
                  <ReportGenerator
                    analysis={analysis}
                    threatIntel={threatIntel}
                    chartElementId='protocol-chart'
                  />
                )}
              </div>
            </div>

            <div className="flex justify-center pt-8">
              <button
                onClick={() => { setAnalysis(null); setFile(null); }}
                className="px-6 py-2 bg-cyber-700 hover:bg-cyber-600 text-white rounded-lg transition-colors border border-cyber-600"
              >
                Analyze Another File
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Confirmation Modal */}
      {deletingHash && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-cyber-800 border border-cyber-700 rounded-2xl p-6 max-w-sm w-full shadow-2xl animate-scale-in">
            <div className="flex items-center gap-3 text-red-400 mb-4">
              <AlertTriangle size={24} />
              <h3 className="text-lg font-bold">Confirm Deletion</h3>
            </div>
            <p className="text-gray-300 text-sm mb-6">
              Are you sure you want to remove this analysis from your history? This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button 
                onClick={() => setDeletingHash(null)}
                className="flex-1 py-2 bg-cyber-700 hover:bg-cyber-600 text-white rounded-lg transition-colors text-sm font-semibold"
              >
                Cancel
              </button>
              <button 
                onClick={() => deleteFromHistory(deletingHash)}
                className="flex-1 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors text-sm font-semibold"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
