import React, { useMemo, useState } from 'react';
import { PcapAnalysisResult, ThreatIntel, PacketSummary } from '../types';
import { 
  AlertTriangle, 
  Key, 
  Network, 
  ShieldAlert, 
  Clock, 
  Info, 
  ChevronLeft, 
  ChevronRight, 
  Zap, 
  GitBranch, 
  Link2,
  Database,
  Terminal,
  Eye,
  Radar,
  FileCode,
  Layers,
  Star,
  X,
  Hash,
  FileText
} from 'lucide-react';
import { COMMON_PORTS } from '../constants';

interface TimelineViewProps {
  analysis: PcapAnalysisResult;
  threatIntel: ThreatIntel | null;
}

interface TimelineEvent {
  id: string;
  timestamp: number;
  offset: string; // "+0.00s"
  type: 'IOC' | 'AUTH' | 'NEW_CONN' | 'SUSPICIOUS_PORT' | 'BURST' | 'PIVOT' | 'WEB_ATTACK' | 'DNS_TUNNEL' | 'SCAN';
  summary: string;
  detail: string;
  severity: 'info' | 'warning' | 'critical';
  packet?: PacketSummary;
  relatedEventId?: string; // Links this event to a previous one (e.g. Pivot source)
  contextId?: string; // ID to group related events visually
  count?: number; // For deduplication
  frameNumber?: number; // Wireshark Frame Number (1-based)
}

type FilterType = 'ALL' | 'IOC' | 'AUTH' | 'WEB' | 'NEW_CONN' | 'BURST' | 'CONTEXT' | 'SCAN' | 'BOOKMARKS';

export const TimelineView: React.FC<TimelineViewProps> = ({ analysis, threatIntel }) => {
  const [activeFilter, setActiveFilter] = useState<FilterType>('ALL');
  const [currentPage, setCurrentPage] = useState(0);
  const [bookmarks, setBookmarks] = useState<Set<string>>(new Set());
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  
  const EVENTS_PER_PAGE = 100;

  const events = useMemo(() => {
    if (!analysis.rawSummary.length) return [];

    const startTs = analysis.rawSummary[0].timestamp;
    const timelineEvents: TimelineEvent[] = [];
    const seenConns = new Set<string>();
    
    // --- Detection Regexes ---
    const authRgx = /(user|pass|login|auth|password|admin)/i;
    
    // SQL Injection: Union select, OR 1=1
    const sqliRgx = /('|"|%27|%22)\s*(or|and)\s+['"]?1['"]?=['"]?1|union\s+select|select\s+.*\s+from/i;
    
    // RCE / Shell: cmd.exe, /bin/sh, whoami, etc.
    const rceRgx = /(cmd\.exe|\/bin\/sh|\/bin\/bash|whoami|cat\s+\/etc\/passwd|powershell)/i;
    
    // XSS: script tags, javascript protocol, common handlers
    // Refined to be stricter about injection context
    const xssRgx = /(<script\b[^>]*>|javascript:[^"'\s]+|on(error|load|click|mouseover|submit)\s*=|vbscript:|alert\()/i;
    
    // Bad User Agents
    const badUzARgx = /User-Agent:\s*(sqlmap|nikto|nmap|curl|python-requests|gobuster|hydra)/i;

    //ZU: Static Assets Regex (to ignore for Web Attacks)
    const staticAssetRgx = /\.(css|js|map|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?|$)/i;

    // Benign HTML/CSS Content Regex (To prevent false positives on Response bodies)
    const safeHtmlRgx = /(<\/(style|script|div|body|html)>|\{\s*[a-zA-Z-]+\s*:\s*#[a-fA-F0-9]+\s*\})/i;

    // --- State Tracking ---
    let currentBurst: { key: string; start: number; count: number; src: string; dst: string } | null = null;
    const BURST_THRESHOLD = 50; // packets
    const BURST_RvTIME = 1000; // ms

    // Port Scan Tracking: SrcIP -> Set of DstPorts
    const portScanTrack: Record<string, Set<number>> = {};
    const SCAN_THRESHOLD = 10; // >10 unique ports = scan

    analysis.rawSummary.forEach((p, idx) => {
      const offsetMs = p.timestamp - startTs;
      const offsetSec = (offsetMs / 1000).toFixed(2);
      const connKey = [p.srcIp, p.dstIp].sort().join('-');
      const burstKey = `${p.srcIp}->${p.dstIp}`; // Directional for burst
      const frameNum = p.frameNumber; // Use the original frame number from parsing

      let evt: Partial<TimelineEvent> = {
        id: `${p.timestamp}-${idx}`,
        timestamp: p.timestamp,
        offset: `+${offsetSec}s`,
        packet: p,
        frameNumber: frameNum
      };

      // --- 1. Burst Logic ---
      if (currentBurst) {
        if (currentBurst.key === burstKey && (p.timestamp - currentBurst.start < BURST_RvTIME)) {
          currentBurst.count++;
        } else {
          // Check if previous ended burst was valid
          if (currentBurst.count > BURST_THRESHOLD) {
             timelineEvents.push({
               id: `burst-${currentBurst.start}`,
               timestamp: currentBurst.start,
               offset: `+${((currentBurst.start - startTs)/1000).toFixed(2)}s`,
               type: 'BURST',
               summary: 'High Traffic Burst',
               detail: `${currentBurst.count} packets sent ${currentBurst.src} → ${currentBurst.dst} in <1s`,
               severity: 'warning'
               // No single frame number for a burst
             });
          }
          // Start new potential burst
          currentBurst = { key: burstKey, start: p.timestamp, count: 1, src: p.srcIp, dst: p.dstIp };
        }
      } else {
        currentBurst = { key: burstKey, start: p.timestamp, count: 1, src: p.srcIp, dst: p.dstIp };
      }

      // --- 2. Port Scan Detection ---
      if (p.dstPort) {
        if (!portScanTrack[p.srcIp]) portScanTrack[p.srcIp] = new Set();
        portScanTrack[p.srcIp].add(p.dstPort);
        
        // Trigger scan event once threshold is crossed (and only once per IP to avoid spam)
        if (portScanTrack[p.srcIp].size === SCAN_THRESHOLD) {
             timelineEvents.push({
               id: `scan-${p.timestamp}`,
               timestamp: p.timestamp,
               offset: `+${offsetSec}s`,
               type: 'SCAN',
               summary: 'Port Scanning Detected',
               detail: `Host ${p.srcIp} has accessed >${SCAN_THRESHOLD} unique ports.`,
               severity: 'warning',
               frameNumber: frameNum // Associate with the packet that tripped the threshold
             });
        }
      }

      // --- 3. IOC Match (Highest Priority) ---
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

      // --- 4. Heuristic Content Analysis ---
      if (p.payload) {
        // Skip heuristic checks for static assets (CSS, JS, Images, etc.) or HTTP Responses
        const isHttpResponse = p.payload.startsWith('HTTP/') || p.payload.includes('HTTP/1.1 200');
        const isStaticAsset = staticAssetRgx.test(p.payload);
        const isSafeHtml = safeHtmlRgx.test(p.payload);

        if (!isHttpResponse && !isStaticAsset && !isSafeHtml) {
          
          // A. Web Attacks (SQLi, XSS, RCE)
          if (sqliRgx.test(p.payload)) {
             timelineEvents.push({ ...evt, type: 'WEB_ATTACK', severity: 'critical', summary: 'SQL Injection Attempt', detail: 'Payload contains SQL syntax patterns' } as TimelineEvent);
             return;
          }
          if (rceRgx.test(p.payload)) {
             timelineEvents.push({ ...evt, type: 'WEB_ATTACK', severity: 'critical', summary: 'Remote Code Execution', detail: 'Payload contains shell command patterns' } as TimelineEvent);
             return;
          }
          if (xssRgx.test(p.payload)) {
             timelineEvents.push({ ...evt, type: 'WEB_ATTACK', severity: 'warning', summary: 'XSS Attempt', detail: 'Payload contains script tags or event handlers' } as TimelineEvent);
             return;
          }
          
          // B. Suspicious Tools / User Agents
          const uaMatch = p.payload.match(badUzARgx);
          if (uaMatch) {
              timelineEvents.push({ ...evt, type: 'WEB_ATTACK', severity: 'warning', summary: 'Suspicious Tool Usage', detail: `User-Agent indicates automated tool: ${uaMatch[1]}` } as TimelineEvent);
              return;
          }

          // C. DNS Tunneling Heuristics (UDP/53 with long payload)
          if (p.protocol === 'UDP' && p.dstPort === 53 && p.payload.length > 60) {
             timelineEvents.push({ ...evt, type: 'DNS_TUNNEL', severity: 'warning', summary: 'Suspicious DNS Query', detail: `Long DNS payload (${p.payload.length} chars) detected. Possible Tunneling/Exfiltration.` } as TimelineEvent);
             return;
          }

          // D. Auth / Creds
          if (authRgx.test(p.payload)) {
              evt.type = 'AUTH';
              evt.severity = 'warning';
              evt.summary = 'Potential Credential/Auth Data';
              evt.detail = `Payload matches keywords in ${p.protocol} traffic`;
              timelineEvents.push(evt as TimelineEvent);
              return;
          }
        }
      }

      // --- 5. New Connection Establishment (First packet only) ---
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

    // Sort events by timestamp
    timelineEvents.sort((a, b) => a.timestamp - b.timestamp);

    // --- Pass 2: Context Linking ---
    const RECENT_WINDOW = 5000;
    const recentIncoming: Record<string, { eventId: string, timestamp: number }> = {};
    const linkedEvents: TimelineEvent[] = [];

    timelineEvents.forEach(evt => {
      let isPivot = false;
      let parentEventId: string | undefined = undefined;

      let src = '', dst = '';
      if (evt.packet) {
        src = evt.packet.srcIp;
        dst = evt.packet.dstIp;
      } else if (evt.type === 'BURST') {
        const match = evt.detail.match(/([\d\.]+) → ([\d\.]+)/);
        if (match) {
           src = match[1];
           dst = match[2];
        }
      }

      if (src && dst) {
        if (recentIncoming[src]) {
          const prev = recentIncoming[src];
          if (evt.timestamp < prev.timestamp + RECENT_WINDOW && evt.timestamp >= prev.timestamp) {
            isPivot = true;
            parentEventId = prev.eventId;
          }
        }
        recentIncoming[dst] = { eventId: evt.id, timestamp: evt.timestamp };
      }

      if (isPivot && parentEventId) {
        if (evt.type === 'NEW_CONN') {
            evt.type = 'PIVOT';
            evt.summary = 'Potential Lateral Movement';
            evt.detail = `Pivot detected: ${src} (previously targeted) accessing ${dst}`;
            evt.severity = 'warning';
        }
        evt.relatedEventId = parentEventId;
        evt.contextId = parentEventId;
      }
      
      linkedEvents.push(evt);
    });

    // --- Pass 3: Deduplication ---
    if (linkedEvents.length === 0) return [];
    
    const deduplicatedEvents: TimelineEvent[] = [];
    let lastEvent = { ...linkedEvents[0], count: 1 };

    for (let i = 1; i < linkedEvents.length; i++) {
      const current = linkedEvents[i];
      // Compare critical fields for equality
      const isSame = 
        current.type === lastEvent.type && 
        current.summary === lastEvent.summary &&
        current.detail === lastEvent.detail &&
        current.severity === lastEvent.severity;

      if (isSame) {
        lastEvent.count = (lastEvent.count || 1) + 1;
      } else {
        deduplicatedEvents.push(lastEvent);
        lastEvent = { ...current, count: 1 };
      }
    }
    deduplicatedEvents.push(lastEvent);

    return deduplicatedEvents;
  }, [analysis, threatIntel]);

  const toggleBookmark = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    setBookmarks(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredEvents = useMemo(() => {
    if (activeFilter === 'BOOKMARKS') return events.filter(e => bookmarks.has(e.id));
    if (activeFilter === 'ALL') return events;
    if (activeFilter === 'CONTEXT') return events.filter(e => e.relatedEventId || e.type === 'PIVOT');
    if (activeFilter === 'WEB') return events.filter(e => e.type === 'WEB_ATTACK' || e.type === 'DNS_TUNNEL');
    return events.filter(e => e.type === activeFilter);
  }, [events, activeFilter, bookmarks]);

  const totalPages = Math.ceil(filteredEvents.length / EVENTS_PER_PAGE);
  const currentEvents = filteredEvents.slice(currentPage * EVENTS_PER_PAGE, (currentPage + 1) * EVENTS_PER_PAGE);

  const getIcon = (type: TimelineEvent['type']) => {
    switch (type) {
      case 'IOC': return <ShieldAlert size={16} />;
      case 'AUTH': return <Key size={16} />;
      case 'NEW_CONN': return <Network size={16} />;
      case 'BURST': return <Zap size={16} />;
      case 'PIVOT': return <GitBranch size={16} />;
      case 'WEB_ATTACK': return <Database size={16} />;
      case 'DNS_TUNNEL': return <Eye size={16} />;
      case 'SCAN': return <Radar size={16} />;
      default: return <Info size={16} />;
    }
  };

  const getColor = (severity: TimelineEvent['severity'], isContext?: boolean) => {
    const base = isContext ? 'border-l-4 border-l-cyber-accent' : '';
    switch (severity) {
      case 'critical': return `${base} bg-red-500/20 text-red-400 border-red-500/50`;
      case 'warning': return `${base} bg-orange-500/20 text-orange-400 border-orange-500/50`;
      case 'info': return `${base} bg-blue-500/20 text-blue-400 border-blue-500/50`;
      default: return `${base} bg-gray-500/20 text-gray-400 border-gray-500/50`;
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
    <>
      <div className="bg-cyber-800 border border-cyber-700 rounded-xl overflow-hidden flex flex-col h-[600px]">
        <div className="px-6 py-4 border-b border-cyber-700 bg-cyber-900/50 flex flex-col gap-4">
          <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold flex items-center gap-2 text-gray-100">
              <Clock size={20} className="text-cyber-400" />
              Event Timeline
              </h3>
              <span className="text-xs text-gray-500 font-mono bg-cyber-900 px-2 py-1 rounded border border-cyber-700">
              {filteredEvents.length} events
              </span>
          </div>
          
          {/* Filters */}
          <div className="flex gap-2 overflow-x-auto pb-1 no-scrollbar">
              {(['ALL', 'IOC', 'WEB', 'SCAN', 'BURST', 'CONTEXT', 'AUTH', 'NEW_CONN', 'BOOKMARKS'] as FilterType[]).map((f) => (
                  <button
                      key={f}
                      onClick={() => { setActiveFilter(f); setCurrentPage(0); }}
                      className={`px-3 py-1 text-xs font-medium rounded-fullSz border transition-colors whitespace-nowrap flex items-center gap-1 ${
                          activeFilter === f 
                          ? 'bg-cyber-500 text-white border-cyber-400' 
                          : 'bg-cyber-900 text-gray-400 border-cyber-700 hover:border-cyber-500'
                      }`}
                  >
                      {f === 'ALL' && <Layers size={12}/>}
                      {f === 'IOC' && <ShieldAlert size={12}/>}
                      {f === 'AUTH' && <Key size={12}/>}
                      {f === 'NEW_CONN' && <Network size={12}/>}
                      {f === 'BURST' && <Zap size={12}/>}
                      {f === 'CONTEXT' && <Link2 size={12}/>}
                      {f === 'WEB' && <Terminal size={12}/>}
                      {f === 'SCAN' && <Radar size={12}/>}
                      {f === 'BOOKMARKS' && <Star size={12} className={activeFilter === 'BOOKMARKS' ? 'fill-white' : ''} />}
                      {f === 'ALL' ? 'All Events' : f === 'NEW_CONN' ? 'Connections' : f === 'AUTH' ? 'Auth' : f === 'CONTEXT' ? 'Linked Context' : f === 'WEB' ? 'Web/DNS' : f === 'BOOKMARKS' ? 'Bookmarks' : f}
                  </button>
              ))}
          </div>
        </div>
        
        {/* Scrollable Container */}
        <div className="flex-1 overflow-y-auto custom-scrollbar relative">
          <div className="relative min-h-full py-6">
              
              {/* Main Vertical Line */}
              <div className="absolute left-8 top-8 bottom-0 w-px bg-cyber-700"></div>

              <div className="space-y-6">
              {currentEvents.map((evt) => {
                  const isContextLinked = !!evt.relatedEventId;
                  const count = evt.count || 1;
                  const isBookmarked = bookmarks.has(evt.id);

                  return (
                  <div key={evt.id} className="relative group animate-fade-in">
                      
                      {/* The Dot */}
                      <div className={`absolute left-8 top-3 -translate-x-1/2 w-3 h-3 rounded-full border-2 border-cyber-800 z-10 shadow-sm transition-transform group-hover:scale-125 ${
                          evt.severity === 'critical' ? 'bg-red-500' : 
                          evt.severity === 'warning' ? 'bg-orange-400' : 
                          evt.severity === 'info' ? 'bg-blue-500' :
                          isContextLinked ? 'bg-cyber-accent' : 'bg-cyber-600'
                      }`}></div>

                      <div className="pl-16 pr-4">
                          <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-4">
                              {/* Timestamp & ID */}
                              <div className="shrink-0 w-24 pt-1 flex flex-col items-start gap-1">
                                  <span className="text-xs font-mono text-gray-500">{evt.offset}</span>
                                  {evt.frameNumber && (
                                    <span className="text-[10px] font-mono text-cyber-500 select-all border border-cyber-800 bg-cyber-900/50 px-1 rounded">#{evt.frameNumber}</span>
                                  )}
                              </div>

                              {/* Content Card */}
                              <div 
                                onClick={() => setSelectedEvent(evt)}
                                className={`flex-1 p-3 rounded-lg border text-sm transition-all hover:bg-cyber-700/50 cursor-pointer relative group/card ${getColor(evt.severity, isContextLinked)}`}
                              >
                                  <div className="flex items-center justify-between mb-1">
                                      <div className="flex items-center gap-2 font-semibold">
                                          {getIcon(evt.type)}
                                          <span>{evt.summary}</span>
                                          {count > 1 && (
                                              <span className="ml-2 text-xs bg-cyber-900/60 text-cyber-300 px-2 py-0.5 rounded-full border border-cyber-700/50 font-mono">
                                                  x{count}
                                              </span>
                                          )}
                                      </div>
                                      <div className="flex items-center gap-2">
                                        {isContextLinked && (
                                            <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-cyber-accent bg-cyber-accent/10 px-2 py-0.5 rounded border border-cyber-accent/20">
                                                <Link2 size={10} />
                                                Context Linked
                                            </div>
                                        )}
                                        <button
                                          onClick={(e) => toggleBookmark(e, evt.id)}
                                          className={`p-1 rounded hover:bg-cyber-900/50 transition-colors ${isBookmarked ? 'text-yellow-400' : 'text-gray-600 hover:text-yellow-200'}`}
                                          title={isBookmarked ? "Remove Bookmark" : "Bookmark Event"}
                                        >
                                          <Star size={16} className={isBookmarked ? 'fill-yellow-400' : ''} />
                                        </button>
                                      </div>
                                  </div>
                                  <div className="text-xs opacity-80 font-mono break-all pr-6">
                                      {evt.detail}
                                  </div>
                                  {evt.packet?.payload && (
                                      <div className="mt-2 pt-2 border-t border-white/10 text-xs font-mono text-gray-400 truncate opacity-60 flex items-center gap-2">
                                          <FileText size={12} />
                                          <span>Payload Preview: {evt.packet.payload.substring(0, 50)}...</span>
                                      </div>
                                  )}
                              </div>
                          </div>
                      </div>
                  </div>
              )})}
              
              {currentEvents.length === 0 && (
                  <div className="text-center text-gray-500 py-10 italic">
                      No events match this filter.
                  </div>
              )}
              </div>
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

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={() => setSelectedEvent(null)}>
          <div 
            className="bg-cyber-800 border border-cyber-600 rounded-xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]" 
            onClick={e => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className={`px-6 py-4 border-b border-cyber-700 flex justify-between items-center ${getColor(selectedEvent.severity)} bg-opacity-10`}>
              <div className="flex items-center gap-3">
                 <div className={`p-2 rounded-lg ${getColor(selectedEvent.severity)} bg-opacity-20`}>
                   {getIcon(selectedEvent.type)}
                 </div>
                 <div>
                   <h3 className="text-lg font-bold text-gray-100">{selectedEvent.summary}</h3>
                   <div className="flex items-center gap-3 text-xs opacity-80">
                      <span className="font-mono">{new Date(selectedEvent.timestamp).toLocaleTimeString()} ({selectedEvent.offset})</span>
                      {selectedEvent.frameNumber && (
                        <span className="px-1.5 py-0.5 bg-black/30 rounded border border-white/10 font-mono">Frame #{selectedEvent.frameNumber}</span>
                      )}
                   </div>
                 </div>
              </div>
              <button 
                onClick={() => setSelectedEvent(null)}
                className="p-2 hover:bg-white/10 rounded-lg transition-colors text-gray-400 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto custom-scrollbar space-y-6">
              
              {/* Context / Detail */}
              <div className="bg-cyber-900/50 p-4 rounded-lg border border-cyber-700/50">
                <h4 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-2">
                  <Info size={14} className="text-cyber-accent" /> Event Context
                </h4>
                <p className="text-sm text-gray-300 leading-relaxed font-mono">
                  {selectedEvent.detail}
                </p>
                {selectedEvent.count && selectedEvent.count > 1 && (
                  <p className="mt-2 text-xs text-cyber-400">
                    * This event occurred {selectedEvent.count} times in sequence.
                  </p>
                )}
              </div>

              {/* Packet Metadata Grid */}
              {selectedEvent.packet && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="p-3 bg-cyber-900 rounded border border-cyber-700">
                    <div className="text-xs text-gray-500 mb-1">Source</div>
                    <div className="font-mono text-sm text-cyber-300 break-all">{selectedEvent.packet.srcIp}:{selectedEvent.packet.srcPort || '-'}</div>
                  </div>
                  <div className="p-3 bg-cyber-900 rounded border border-cyber-700">
                    <div className="text-xs text-gray-500 mb-1">Destination</div>
                    <div className="font-mono text-sm text-cyber-300 break-all">{selectedEvent.packet.dstIp}:{selectedEvent.packet.dstPort || '-'}</div>
                  </div>
                  <div className="p-3 bg-cyber-900 rounded border border-cyber-700">
                    <div className="text-xs text-gray-500 mb-1">Protocol</div>
                    <div className="font-mono text-sm text-cyber-300">{selectedEvent.packet.protocol}</div>
                  </div>
                  <div className="p-3 bg-cyber-900 rounded border border-cyber-700">
                    <div className="text-xs text-gray-500 mb-1">Length</div>
                    <div className="font-mono text-sm text-cyber-300">{selectedEvent.packet.length} bytes</div>
                  </div>
                </div>
              )}

              {/* Payload Viewer */}
              {selectedEvent.packet?.payload && (
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                    <FileCode size={14} className="text-cyber-accent" /> Payload Snippet
                  </h4>
                  <div className="relative">
                    <pre className="block w-full bg-cyber-950 p-4 rounded-lg border border-cyber-700 font-mono text-xs text-cyber-100 overflow-x-auto whitespace-pre-wrap max-h-64 custom-scrollbar">
                      {selectedEvent.packet.payload}
                    </pre>
                    <div className="absolute top-2 right-2 px-2 py-1 bg-cyber-800/80 rounded text-[10px] text-gray-500 border border-cyber-700">
                      ASCII Representation
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-cyber-700 bg-cyber-900/80 flex justify-end gap-3">
               <button
                  onClick={(e) => toggleBookmark(e, selectedEvent.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors text-sm font-medium ${
                    bookmarks.has(selectedEvent.id) 
                      ? 'bg-yellow-500/10 border-yellow-500/50 text-yellow-400 hover:bg-yellow-500/20'
                      : 'bg-cyber-800 border-cyber-600 text-gray-300 hover:bg-cyber-700'
                  }`}
               >
                  <Star size={16} className={bookmarks.has(selectedEvent.id) ? 'fill-yellow-400' : ''} />
                  {bookmarks.has(selectedEvent.id) ? 'Bookmarked' : 'Bookmark Event'}
               </button>
               <button 
                 onClick={() => setSelectedEvent(null)}
                 className="px-4 py-2 bg-cyber-accent hover:bg-cyber-accent-dark text-white rounded-lg text-sm font-medium transition-colors"
               >
                 Close
               </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};