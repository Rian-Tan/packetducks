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
  hostGeoMap?: Record<string, { countryCode: string; countryName: string }>;
  duplicatePayloads?: { payload: string; count: number; firstSeen: number; lastSeen: number }[];
}

export interface ThreatIntel {
  riskScore: number; // 0-100
  summary: string;
  forensicJustification?: string; // AI's reasoning for the classification
  classification?: string; // e.g. "PlugX", "Emotet", "Normal Traffic"
  attackName?: string; // e.g. "React2Shell", "Log4Shell"
  cveTags?: string[]; // e.g. ["CVE-2021-44228"]
  manualIocs?: {
    value: string;
    type: 'IP' | 'PORT' | 'PATTERN';
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }[];
  iocs: {
    value: string;
    type: 'IP' | 'PORT' | 'PATTERN';
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    virusTotalDetections?: string; // Format "Malicious/Total" e.g. "14/95"
    countryCode?: string; // ISO 3166-1 alpha-2 code
    countryName?: string;
  }[];
  recommendations: string[];
}
