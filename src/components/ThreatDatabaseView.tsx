import React, { useState } from 'react';
import { Shield, Search, Clock } from 'lucide-react';

interface ThreatDatabaseViewProps {
  history: any[];
  loadFromHistory: (item: any) => void;
}

export const ThreatDatabaseView: React.FC<ThreatDatabaseViewProps> = ({
  history,
  loadFromHistory
}) => {
  const [threatFilter, setThreatFilter] = useState('');

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Shield className="text-cyber-accent" />
          Threat Intelligence Database
        </h2>
        
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
          <input 
            type="text" 
            placeholder="Filter threats, CVEs, or PCAPs..." 
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value)}
            className="bg-cyber-900 border border-cyber-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyber-accent w-64"
          />
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {(() => {
          const filteredAttacks = Array.from(new Set(history.map(h => h.attack_name).filter(Boolean)))
            .filter(attack => {
              const attackName = attack as string;
              const relatedPcaps = history.filter(h => h.attack_name === attackName);
              const cves = Array.from(new Set(relatedPcaps.flatMap(h => h.intel.cveTags || [])));
              
              const matchesSearch = attackName.toLowerCase().includes(threatFilter.toLowerCase()) ||
                                  cves.some(cve => (cve as string).toLowerCase().includes(threatFilter.toLowerCase())) ||
                                  relatedPcaps.some(h => h.filename.toLowerCase().includes(threatFilter.toLowerCase()));
              return matchesSearch;
            });

          if (filteredAttacks.length === 0) {
            return (
              <div className="col-span-full py-20 text-center bg-cyber-800/30 border border-dashed border-cyber-700 rounded-2xl">
                <Search size={48} className="mx-auto text-cyber-700 mb-4" />
                <p className="text-gray-500 italic">No threats match your filter.</p>
              </div>
            );
          }

          return filteredAttacks.map(attack => {
            const attackName = attack as string;
            const relatedPcaps = history.filter(h => h.attack_name === attackName);
            const cves = Array.from(new Set(relatedPcaps.flatMap(h => h.intel.cveTags || [])));
            
            return (
              <div key={attackName} className="bg-cyber-800 border border-cyber-700 rounded-xl p-6 hover:border-cyber-accent transition-all">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold text-white">{attackName}</h3>
                  <span className="px-2 py-1 bg-cyber-900 rounded text-[10px] text-cyber-400 font-mono border border-cyber-700">
                    {relatedPcaps.length} Samples
                  </span>
                </div>
                
                <div className="flex flex-wrap gap-2 mb-4">
                  {cves.map(cve => (
                    <span key={cve} className="px-2 py-0.5 bg-red-900/30 border border-red-500/30 rounded text-[10px] text-red-400 font-mono">
                      {cve}
                    </span>
                  ))}
                </div>
                
                <div className="space-y-2">
                  <p className="text-xs text-gray-500 uppercase tracking-widest font-mono mb-1">Recent Samples</p>
                  {relatedPcaps.slice(0, 3).map(p => (
                    <div key={p.hash} onClick={() => loadFromHistory(p)} className="text-xs text-gray-300 hover:text-cyber-accent cursor-pointer truncate flex items-center gap-2">
                      <Clock size={10} className="text-gray-600" />
                      {p.filename}
                    </div>
                  ))}
                </div>
              </div>
            );
          });
        })()}
      </div>
    </div>
  );
};
