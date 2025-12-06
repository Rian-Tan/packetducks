
import React, { useState } from 'react';
import { FileUpload } from './components/FileUpload';
import { ProtocolChart } from './components/ProtocolChart';
import { ThreatDashboard } from './components/ThreatDashboard';
import { parsePcap } from './services/pcapParser';
import { generateThreatIntel } from './services/geminiService';
import { PcapAnalysisResult, ThreatIntel } from './types';
import { Shield, Network, Activity, FileDigit } from 'lucide-react';

const App: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<PcapAnalysisResult | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntel | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const processFile = async (selectedFile: File) => {
    try {
      setFile(selectedFile);
      setIsProcessing(true);
      setError(null);
      setAnalysis(null);
      setThreatIntel(null);

      // 1. Client-side Parsing
      const result = await parsePcap(selectedFile);
      
      if (result.totalPackets === 0) {
        throw new Error("No packets found in file. Ensure the file is a valid PCAP (not PCAPNG) and is not empty.");
      }

      setAnalysis(result);

      // 2. AI Analysis
      setIsProcessing(false); // Parsing done
      setIsAiLoading(true); // Start AI
      
      const intelligence = await generateThreatIntel(result);
      setThreatIntel(intelligence);

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

  return (
    <div className="min-h-screen bg-cyber-900 text-slate-200 font-sans selection:bg-cyber-accent selection:text-white">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-cyber-900/80 backdrop-blur-md border-b border-cyber-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="text-cyber-accent w-8 h-8" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">PacketDuck</h1>
              <p className="text-xs text-cyber-400 font-mono">Quacksome Packet Analyser and Threat Intelligence Dashboard</p>
            </div>
          </div>
          {file && (
            <div className="hidden sm:flex items-center gap-2 text-sm text-gray-400 bg-cyber-800 px-3 py-1.5 rounded-lg border border-cyber-700">
              <FileDigit size={14} />
              <span className="truncate max-w-[150px]">{file.name}</span>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 pb-20">
        {!analysis ? (
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
             <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-3">Analyse a PCAP</h2>
                <p className="text-gray-400 max-w-lg mx-auto">
                  Upload a PCAP file
                </p>
             </div>
             <FileUpload onFileSelect={processFile} isProcessing={isProcessing} />
             {error && (
               <div className="mt-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg text-red-200 text-sm max-w-lg text-center">
                 <p className="font-semibold mb-1">Error Processing File</p>
                 {error}
               </div>
             )}
          </div>
        ) : (
          <div className="space-y-8 animate-fade-in">
            {/* KPI Row */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
                <p className="text-sm text-gray-400 mb-1">Total Packets</p>
                <p className="text-2xl font-mono font-bold text-white">{analysis.totalPackets.toLocaleString()}</p>
              </div>
              <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
                <p className="text-sm text-gray-400 mb-1">Unique Hosts</p>
                <p className="text-2xl font-mono font-bold text-cyber-400">{analysis.uniqueHosts.length}</p>
              </div>
              <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
                <p className="text-sm text-gray-400 mb-1">Conversations</p>
                <p className="text-2xl font-mono font-bold text-cyber-accent">{analysis.connections.length}</p>
              </div>
              <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
                <p className="text-sm text-gray-400 mb-1">Protocols Identified</p>
                <p className="text-2xl font-mono font-bold text-white">{Object.keys(analysis.protocolCounts).length}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Left Col: Charts & Stats */}
              <div className="lg:col-span-2 space-y-8">
                 {/* Protocol Distribution */}
                 <section className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg font-semibold flex items-center gap-2">
                        <Network size={20} className="text-cyber-500" />
                        Protocol Distribution
                      </h3>
                    </div>
                    <ProtocolChart data={analysis.protocolCounts} />
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
              </div>

              {/* Right Col: Threat Intel */}
              <div className="space-y-8">
                 <ThreatDashboard data={threatIntel} loading={isAiLoading} />
                 
                 {/* Host List (Mini) */}
                 <section className="bg-cyber-800 border border-cyber-700 rounded-xl p-6">
                    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Detected Hosts</h3>
                    <div className="flex flex-wrap gap-2">
                      {analysis.uniqueHosts.slice(0, 40).map(host => (
                        <span key={host} className="px-2 py-1 bg-cyber-900 border border-cyber-700 rounded text-xs font-mono text-cyber-400 hover:border-cyber-400 cursor-default transition-colors">
                          {host}
                        </span>
                      ))}
                      {analysis.uniqueHosts.length > 40 && (
                        <span className="px-2 py-1 text-xs text-gray-500">+{analysis.uniqueHosts.length - 40} more</span>
                      )}
                    </div>
                 </section>
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
    </div>
  );
};

export default App;
