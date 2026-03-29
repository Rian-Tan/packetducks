import React, { useState } from 'react';
import { History, Search, Activity, Trash2, Shield, Tag, Clock } from 'lucide-react';

interface HistoryViewProps {
  history: any[];
  isLoadingHistory: boolean;
  loadFromHistory: (item: any) => void;
  deleteFromHistory: (hash: string) => Promise<void>;
  deletingHash: string | null;
  setDeletingHash: (hash: string | null) => void;
  setView: (view: 'analyze' | 'history' | 'threats') => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  history,
  isLoadingHistory,
  loadFromHistory,
  deleteFromHistory,
  deletingHash,
  setDeletingHash,
  setView
}) => {
  const [historyFilter, setHistoryFilter] = useState('');
  const [historyCategory, setHistoryCategory] = useState('ALL');

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <History className="text-cyber-accent" />
          Analysis History
        </h2>
        
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
            <input 
              type="text" 
              placeholder="Search PCAPs..." 
              value={historyFilter}
              onChange={(e) => setHistoryFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent w-64"
            />
          </div>
          <select 
            value={historyCategory}
            onChange={(e) => setHistoryCategory(e.target.value)}
            className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent"
          >
            <option value="ALL">All Categories</option>
            {Array.from(new Set(history.map(h => h.classification).filter(Boolean))).map(cat => (
              <option key={cat as string} value={cat as string}>{cat as string}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoadingHistory ? (
        <div className="flex flex-col items-center justify-center py-20">
          <Activity className="w-12 h-12 text-cyber-500 animate-spin mb-4" />
          <p className="text-gray-400 font-mono">Loading history...</p>
        </div>
      ) : history.length === 0 ? (
        <div className="bg-cyber-800/50 border border-dashed border-cyber-700 rounded-2xl p-20 text-center">
          <Search size={48} className="mx-auto text-cyber-700 mb-4" />
          <h3 className="text-xl font-semibold text-gray-300 mb-2">No history found</h3>
          <p className="text-gray-500 max-w-sm mx-auto">
            Analyze your first PCAP file to start building your threat intelligence cache.
          </p>
          <button
            onClick={() => setView('analyze')}
            className="mt-6 px-6 py-2 bg-cyber-accent text-white rounded-lg hover:bg-cyber-500 transition-colors"
          >
            Analyze Now
          </button>
        </div>
      ) : (
        <>
          {history.filter(item => {
            const matchesSearch = item.filename.toLowerCase().includes(historyFilter.toLowerCase()) || 
                                (item.attack_name && item.attack_name.toLowerCase().includes(historyFilter.toLowerCase())) ||
                                (item.cve_tags && item.cve_tags.some((cve: string) => cve.toLowerCase().includes(historyFilter.toLowerCase())));
            const matchesCategory = historyCategory === 'ALL' || item.classification === historyCategory;
            return matchesSearch && matchesCategory;
          }).length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {history
                .filter(item => {
                  const matchesSearch = item.filename.toLowerCase().includes(historyFilter.toLowerCase()) || 
                                      (item.attack_name && item.attack_name.toLowerCase().includes(historyFilter.toLowerCase())) ||
                                      (item.cve_tags && item.cve_tags.some((cve: string) => cve.toLowerCase().includes(historyFilter.toLowerCase())));
                  const matchesCategory = historyCategory === 'ALL' || item.classification === historyCategory;
                  return matchesSearch && matchesCategory;
                })
                .map((item) => (
                <div
                  key={item.hash}
                  onClick={() => loadFromHistory(item)}
                  className="bg-cyber-800 border border-cyber-700 rounded-xl p-5 hover:border-cyber-accent transition-all cursor-pointer group relative overflow-hidden"
                >
                  <div className="absolute -bottom-6 -right-6 opacity-5 group-hover:opacity-10 transition-opacity pointer-events-none">
                    <Shield size={140} className="text-cyber-accent" />
                  </div>
                  
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeletingHash(item.hash);
                    }}
                    className="absolute top-3 right-3 p-2 bg-red-500/10 hover:bg-red-500/30 text-red-500 rounded-lg border border-red-500/20 opacity-0 group-hover:opacity-100 transition-all z-10"
                    title="Remove from history"
                  >
                    <Trash2 size={14} />
                  </button>

                  <div className="flex flex-col gap-2 mb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${item.intel.riskScore > 70 ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]' : item.intel.riskScore > 30 ? 'bg-yellow-500' : 'bg-green-500'}`}></div>
                        <span className="text-xs font-mono text-gray-400">Risk: {item.intel.riskScore}</span>
                      </div>
                      <div className="flex flex-wrap gap-1 justify-end max-w-[70%]">
                        {item.attack_name && (
                          <span className="text-[9px] font-mono text-red-400 bg-red-900/20 px-1.5 py-0.5 rounded border border-red-500/30 truncate max-w-[100px]">
                            {item.attack_name}
                          </span>
                        )}
                        {item.cve_tags && item.cve_tags.map((cve: string) => (
                          <span key={cve} className="text-[9px] font-mono text-amber-400 bg-amber-900/20 px-1.5 py-0.5 rounded border border-amber-500/30 whitespace-nowrap">
                            {cve}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <h3 className="text-white font-semibold truncate mb-1 pr-8">{item.filename}</h3>
                  
                  <div className="flex items-center gap-2 mb-4">
                    <Tag size={12} className="text-cyber-accent" />
                    <span className="text-xs font-bold text-cyber-400 tracking-wider uppercase">
                      {item.classification || 'Unclassified'}
                    </span>
                  </div>

                  <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono uppercase tracking-widest">
                      <span>Packets</span>
                      <span className="text-gray-300">{item.analysis.totalPackets.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono uppercase tracking-widest">
                      <span>Hosts</span>
                      <span className="text-gray-300">{item.analysis.uniqueHosts.length}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-3 border-t border-cyber-700">
                    <div className="flex items-center gap-1.5 text-[10px] text-gray-500 font-mono">
                      <Clock size={10} />
                      {new Date(item.timestamp).toLocaleDateString()}
                    </div>
                    <span className="text-[10px] text-cyber-accent font-bold uppercase group-hover:translate-x-1 transition-transform">
                      View Details →
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-10 text-gray-500 italic">No PCAPs match your filters.</div>
          )}
        </>
      )}
    </div>
  );
};
