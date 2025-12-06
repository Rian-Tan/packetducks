export enum ProtocolType {
  TCP = 'TCP',
  UDP = 'UDP',
  ICMP = 'ICMP',
  Other = 'Other'
}

export interface PacketSummary {
  timestamp: number;
  srcIp: string;
  dstIp: string;
  protocol: ProtocolType;
  srcPort?: number;
  dstPort?: number;
  length: number;
  flags?: number; // TCP flags
  payload?: string; // ASCII representation of packet body
}

export interface PortUsage {
  sport: number;
  dport: number;
  syn_dst: number;
  synack_src: number;
}

export interface PcapAnalysisResult {
  totalPackets: number;
  protocolCounts: Record<string, number>;
  uniqueHosts: string[];
  connections: { a: string; b: string }[];
  startTime: Date;
  endTime: Date;
  rawSummary: PacketSummary[]; // Kept for AI context
}

export interface ThreatIntel {
  riskScore: number; // 0-100
  summary: string;
  iocs: {
    value: string;
    type: 'IP' | 'PORT' | 'PATTERN';
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }[];
  recommendations: string[];
}
