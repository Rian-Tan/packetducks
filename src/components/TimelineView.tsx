import React, { useMemo, useState } from 'react';
import { PcapAnalysisResult, ThreatIntel, PacketSummary } from '../types';
import { AlertTriangle, Key, Network, ShieldAlert, Clock, Info, Filter, ChevronLeft, ChevronRight } from 'lucide-react';
import { COMMON_PORTS } from '../constants';

interface TimelineViewProps {
  analysis: PcapAnalysisResult;
  threatIntel: ThreatIntel | null;
}

interface TimelineEvent {
  id: string;
  timestamp: number;
  offset: string; // "+0.00s"
  type: 'IOC' | 'AUTH' | 'NEW_CONN' | 'SUSPICIOUS_PORT';
  summary: string;
  detail: string;
  severity: 'info' | 'warning' | 'critical';
  packet: PacketSummary;
}

type FilterType = 'ALL' | 'IOC' | 'AUTH' | 'NEW_CONN';

export const TimelineView: React.FC<TimelineViewProps> = ({ analysis, threatIntel }) => {
  const [activeFilter, setActiveFilter] = useState<FilterType>('ALL');
  const [currentPage, setCurrentPage] = useState(0);
  const EVENTS_PER_PAGE = 100;

  const events = useMemo(() => {
    if (!analysis.rawSummary.length) return [];

    const startTs = analysis.rawSummary[0].timestamp;
    const timelineEvents: TimelineEvent[] = [];
    const seenConns = new Set<string>();
    
    // Regex for potential creds in payload
    const authRgx = /(user|pass|login|auth|password|admin)/i;

    analysis.rawSummary.forEach((p, idx) => {
      const offsetMs = p.timestamp - startTs;
      const offsetSec = (offsetMs / 1000).toFixed(2);
      const connKey = [p.srcIp, p.dstIp].sort().join('-');

      let evt: Partial<TimelineEvent> = {
        id: `${p.timestamp}-${idx}`,
        timestamp: p.timestamp,
        offset: `+${offsetSec}s`,
        packet: p
      };

      // 1. IOC Match (Highest Priority)
      if (threatIntel?.iocs) {
        const iocMatch = threatIntel.iocs.find(ioc => 
          ioc.value === p.srcIp || 
          ioc.value === p.dstIp || 
          (ioc.type === 'PORT' && parseInt(ioc.value) === p.dstPort)
        );

        if (iocMatch) {
          evt.type = 'IOC';
          evt.severity = iocMatch.severity === 'CRITICAL' || iocMatch.severity === 'HIGH' ? 'critical' : 'warning';
          evt.summary = `Threat Detected: ${iocMatch.value}`;
          evt.detail = iocMatch.description || 'Matches known indicator of compromise';
          timelineEvents.push(evt as TimelineEvent);
          return;
        }
      }

      // 2. Potential Auth / Cleartext
      if (p.payload && authRgx.test(p.payload)) {
        evt.type = 'AUTH';
        evt.severity = 'warning';
        evt.summary = 'Potential Credential/Auth Data';
        evt.detail = `Payload matches keywords in ${p.protocol} traffic`;
        timelineEvents.push(evt as TimelineEvent);
        return;
      }

      // 3. New Connection Establishment (First packet only)
      if (!seenConns.has(connKey)) {
        seenConns.add(connKey);
        evt.type = 'NEW_CONN';
        evt.severity = 'info';
        evt.summary = 'New Conversation Started';
        const portLabel = p.dstPort ? (COMMON_PORTS[p.dstPort] || p.dstPort) : 'Unknown';
        evt.detail = `${p.srcIp} → ${p.dstIp} (${p.protocol}/${portLabel})`;
        timelineEvents.push(evt as TimelineEvent);
        return;
      }
    });

    return timelineEvents;
  }, [analysis, threatIntel]);

  const filteredEvents = useMemo(() => {
    if (activeFilter === 'ALL') return events;
    return events.filter(e => e.type === activeFilter);
  }, [events, activeFilter]);

  const totalPages = Math.ceil(filteredEvents.length / EVENTS_PER_PAGE);
  const currentEvents = filteredEvents.slice(currentPage * EVENTS_PER_PAGE, (currentPage + 1) * EVENTS_PER_PAGE);

  const getIcon = (type: TimelineEvent['type']) => {
    switch (type) {
      case 'IOC': return <ShieldAlert size={16} />;
      case 'AUTH': return <Key size={16} />;
      case 'NEW_CONN': return <Network size={16} />;
      default: return <Info size={16} />;
    }
  };

  const getColor = (severity: TimelineEvent['severity']) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'warning': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'info': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
    }
  };

  const handlePageChange = (newPage: number) => {
    if (newPage >= 0 && newPage < totalPages) {
      setCurrentPage(newPage);
    }
  };

  if (events.length === 0) {
    return (
      <div className="bg-cyber-800 border border-cyber-700 rounded-xl p-8 text-center text-gray-400">
        <Clock className="w-8 h-8 mx-auto mb-2 text-cyber-600" />
        <p>No major timeline events detected.</p>
      </div>
    );
  }

  return (
    <div className="bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden flex flex-col h-[600px]">
      <div className="px-6 py-4 border-b border-cyber-700 bg-cyber-900/50 flex flex-col gap-4">
        <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold flex items-center gap-2 text-gray-100">
            <Clock size={20} className="text-cyber-400" />
            Event Timeline
            </h3>
            <span className="text-xs text-gray-500 font-mono bg-cyber-900 px-2 py-1 rounded border border-cyber-700">
            Total: {filteredEvents.length} events
            </span>
        </div>
        
        {/* Filters */}
        <div className="flex gap-2 overflow-x-auto pb-1 no-scrollbar">
            {(['ALL', 'IOC', 'AUTH', 'NEW_CONN'] as FilterType[]).map((f) => (
                <button
                    key={f}
                    onClick={() => { setActiveFilter(f); setCurrentPage(0); }}
                    className={`px-3 py-1 text-xs font-medium rounded-fullSz border transition-colors whitespace-nowrap ${
                        activeFilter === f 
                        ? 'bg-cyber-500 text-white border-cyber-400' 
                        : 'bg-cyber-900 text-gray-400 border-cyber-700 hover:border-cyber-500'
                    }`}
                >
                    {f === 'ALL' ? 'All Events' : f === 'NEW_CONN' ? 'Connections' : f === 'AUTH' ? 'Auth / Creds' : 'Threats'}
                </button>
            ))}
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto custom-scrollbar p-6 relative">
        {/* Vertical Line */}
        <div className="absolute left-9 top-6 bottom-6 w-0.5 bg-cyber-700"></div>

        <div className="space-y-6">
          {currentEvents.map((evt) => (
            <div key={evt.id} className="relative pl-10 group animate-fade-in">
              {/* Dot on line */}
              <div className={`absolute left-[9px] -translate-x-1/2 w-4 h-4 rounded-full border-2 border-cyber-800 ${
                evt.severity === 'critical' ? 'bg-red-500' : 
                evt.severity === 'warning' ? 'bg-orange-400' : 'bg-cyber-500'
              } z-10`}></div>

              <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-4">
                {/* Timestamp */}
                <div className="shrink-0 w-16 pt-0.5">
                   <span className="text-xs font-mono text-gray-500">{evt.offset}</span>
                </div>

                {/* Content Card */}
                <div className={`flex-1 p-3 rounded-lg border text-sm transition-colors hover:bg-cyber-700/30 ${getColor(evt.severity)}`}>
                  <div className="flex items-center gap-2 mb-1 font-semibold">
                    {getIcon(evt.type)}
                    <span>{evt.summary}</span>
                  </div>
                  <div className="text-xs opacity-80 font-mono break-all">
                    {evt.detail}
                  </div>
                  {evt.packet.payload && (
                    <div className="mt-2 pt-2 border-t border-white/10 text-xs font-mono text-gray-400 truncate">
                      Payload: {evt.packet.payload.substring(0, 60)}...
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
          
          {currentEvents.length === 0 && (
             <div className="text-center text-gray-500 py-10 italic">
                 No events match this filter.
             </div>
          )}
        </div>
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="px-6 py-3 border-t border-cyber-700 bg-cyber-900/50 flex justify-between items-center">
            <button 
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage === 0}
                className="p-1 rounded hover:bg-cyber-700 text-gray-400 disabled:opacity-30 disabled:hover:bg-transparent transition-colors"
            >
                <ChevronLeft size={20} />
            </button>
            <span className="text-xs text-gray-500 font-mono">
                Page {currentPage + 1} of {totalPages}
            </span>
            <button 
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage >= totalPages - 1}
                className="p-1 rounded hover:bg-cyber-700 text-gray-400 disabled:opacity-30 disabled:hover:bg-transparent transition-colors"
            >
                <ChevronRight size={20} />
            </button>
        </div>
      )}
    </div>
  );
};