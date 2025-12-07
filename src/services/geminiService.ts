import { GoogleGenAI, Type, Schema } from '@google/genai';
import { PcapAnalysisResult, ThreatIntel, IpInfoData, PacketSummary } from '../types';

const getClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found");
  }
  return new GoogleGenAI({ apiKey });
};

const getVtKey = () => {
  return process.env.VT_API_KEY || "3623edc99f6e538b7b5af487a52027c3f11c15833af26c7f5620412fce7ae6ae";
};

const IPINFO_TOKEN = '04016f0e1f1a5b';

const isPrivateIp = (ip: string): boolean => {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  if (parts.length === 4) {
    if (parts[0] === 10) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] >= 224 && parts[0] <= 239) return true;
    if (parts[0] === 169 && parts[1] === 254) return true; // Link-local
  }
  if (ip === '::1') return true;
  if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  return false;
};

export const enrichIpInfo = async (ips: string[]): Promise<Record<string, IpInfoData>> => {
  const publicIps = ips.filter(ip => !isPrivateIp(ip));
  const targets = publicIps.slice(0, 25); // Limit to 25 to respect potential rate limits/performance
  const results: Record<string, IpInfoData> = {};
  
  await Promise.all(targets.map(async (ip) => {
      try {
          const res = await fetch(`https://api.ipinfo.io/lite/${ip}?token=${IPINFO_TOKEN}`);
          if(res.ok) {
              const data = await res.json();
              results[ip] = data;
          }
      } catch(e) { console.error(`Failed to fetch IP info for ${ip}`, e); }
  }));
  return results;
};

export const checkSingleVirusTotal = async (ip: string): Promise<string> => {
  const apiKey = getVtKey();
  if (!apiKey) {
    throw new Error("VirusTotal API Key not configured");
  }

  // Use public CORS proxy to ensure it works in all environments (Dev/Preview/Prod) without server config
  const targetUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
  const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(targetUrl)}`;
  
  const response = await fetch(proxyUrl, {
      headers: { 'x-apikey': apiKey }
  });

  if (!response.ok) {
    throw new Error(`VT API Error: ${response.status}`);
  }

  const data = await response.json();
  const stats = data.data?.attributes?.last_analysis_stats;
  if (!stats) throw new Error("No stats found in VT response");

  const malicious = stats.malicious || 0;
  const total = (stats.malicious + stats.suspicious + stats.undetected + stats.harmless) || 0;
  return `${malicious}/${total}`;
};

const enrichIocsWithVirusTotal = async (iocs: ThreatIntel['iocs']): Promise<ThreatIntel['iocs']> => {
  // Relaxed type checking (case-insensitive) to catch 'ip' or 'IP'
  const ipIocs = iocs.filter(ioc => ioc.type && ioc.type.toUpperCase() === 'IP');
  
  if (ipIocs.length === 0) return iocs;

  // Limit to 4 to respect free tier rate limit (4 requests/minute)
  const ipsToSearch = ipIocs.slice(0, 4); 
  const results = new Map<string, string>();

  for (const ioc of ipsToSearch) {
    try {
      const result = await checkSingleVirusTotal(ioc.value);
      results.set(ioc.value, result);
    } catch (e) {
      console.warn(`VT lookup error for ${ioc.value}`, e);
    }
  }

  return iocs.map(ioc => {
    // Check type case-insensitively for the map back
    if (ioc.type && ioc.type.toUpperCase() === 'IP' && results.has(ioc.value)) {
      return { ...ioc, virusTotalDetections: results.get(ioc.value) };
    }
    return ioc;
  });
};

// Helper to encode string to Base64 safely for large payloads
const base64Encode = (str: string): string => {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  const len = bytes.byteLength;
  const chunkSize = 0x8000; // 32KB chunks to avoid stack overflow
  for (let i = 0; i < len; i += chunkSize) {
    // @ts-ignore
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
};

// Convert packets to CSV format for the model to process as a file
const packetsToCsv = (packets: PacketSummary[]): string => {
  // Header
  let csv = 'Frame,Timestamp,SrcIP,SrcPort,DstIP,DstPort,Protocol,Length,Info,PayloadSnippet\n';
  
  packets.forEach(p => {
    // Escape payload for CSV (replace quotes and newlines)
    const payloadSafe = p.payload 
      ? `"${p.payload.replace(/"/g, '""').replace(/\n/g, ' ').substring(0, 300)}"` 
      : '""';
    
    // Construct Info string
    let info = "";
    if (p.flags) {
      const flags = [];
      if (p.flags & 0x02) flags.push('SYN');
      if (p.flags & 0x10) flags.push('ACK');
      if (p.flags & 0x01) flags.push('FIN');
      if (p.flags & 0x04) flags.push('RST');
      if (p.flags & 0x08) flags.push('PSH');
      info = flags.join(' ');
    }
    
    csv += `${p.frameNumber},${p.timestamp},${p.srcIp},${p.srcPort || ''},${p.dstIp},${p.dstPort || ''},${p.protocol},${p.length},"${info}",${payloadSafe}\n`;
  });
  
  return csv;
};

export const generateThreatIntel = async (data: PcapAnalysisResult): Promise<ThreatIntel> => {
  const ai = getClient();
  
  // 1. Contextual Data (Top Stats)
  const topProtocols = Object.entries(data.protocolCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 15);

  const ipContext = data.ipInfo 
      ? JSON.stringify(Object.values(data.ipInfo).map(({ ip, as_name, country, asn }) => ({ ip, org: as_name, country, asn })))
      : "No external IP context available.";
  
  const attackStats = data.attackStats ? JSON.stringify(data.attackStats) : "No pre-calculated attack stats.";

  // 2. Prepare the Dataset "File" (CSV)
  // We include a large sample, much larger than the previous plaintext limit.
  // 1.5 Flash has a large context window (1M tokens), but huge PCAPs can exceed it.
  // We cap at 4,000 packets to ensure we stay under the limit (assuming ~250 tokens per line).
  const datasetSlice = data.rawSummary.slice(0, 4000);
  const csvData = packetsToCsv(datasetSlice);
  const base64Csv = base64Encode(csvData);

  const prompt = `
    Analyze the attached Network Traffic Log (CSV file) derived from a PCAP capture.
    Act as a senior Incident Response (IR) analyst conducting post-mortem forensic analysis.
    
    Contextual Intelligence:
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Detected Attack Signatures (Heuristic Scan): ${attackStats}
    - External IP Intelligence (Geo/ASN): ${ipContext}
    
    Your objective is to assess the security posture of this capture based on the attached CSV log.

    CRITICAL DETECTION GUIDELINES:
    1. **EVIDENCE-BASED DETECTION**: You must strictly analyze the attached CSV data. 
    2. **LOOK FOR SPECIFIC PATTERNS IN PAYLOADS**:
       - **Web Attacks**: SQL Injection ('UNION SELECT', 'OR 1=1'), XSS ('<script>'), Path Traversal.
       - **Command Injection**: 'cmd.exe', '/bin/sh', 'whoami', 'powershell'.
       - **Suspicious User-Agents**: 'sqlmap', 'nikto', 'curl', 'python-requests', 'hydra'.
       - **Cleartext Auth**: 'Authorization: Basic', 'password=', 'user='.
       - **Geo-Location Anomalies**: Cross-reference IPs in the CSV with the provided IP Intelligence.
    3. **SCORING RUBRIC**:
       - **0-10 (Clean)**: Standard traffic, no anomalies.
       - **11-40 (Low/Suspicious)**: Cleartext credentials, deprecated protocols, or generic scanning noise.
       - **41-75 (High)**: Strong indicators of attack (SQLi patterns, XSS attempts, known malicious User-Agents).
       - **76-100 (Critical)**: Confirmed compromise (Shell responses, successful data exfiltration, C2 beaconing).

    If the "Detected Attack Signatures" count is high (>0), your Risk Score MUST reflect this (High/Critical), as these are hard regex matches found in the file.
    
    If the capture appears clean, explicitly state "No significant threats detected in the provided sample."

    Return a structured JSON assessment.
  `;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      riskScore: { type: Type.INTEGER, description: "Risk score from 0 (safe) to 100 (critical)." },
      summary: { type: Type.STRING, description: "Executive summary of findings." },
      iocs: {
        type: Type.ARRAY,
        items: {
          type: Type.OBJECT,
          properties: {
            value: { type: Type.STRING, description: "The IP, Port, or Protocol" },
            type: { type: Type.STRING, enum: ['IP', 'PORT', 'PATTERN'] },
            description: { type: Type.STRING, description: "Forensic context on why this is an indicator of compromise" },
            severity: { type: Type.STRING, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] }
          }
        }
      },
      recommendations: {
        type: Type.ARRAY,
        items: { type: Type.STRING }
      }
    },
    required: ["riskScore", "summary", "iocs", "recommendations"]
  };

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [
        {
          role: 'user',
          parts: [
            { text: prompt },
            { 
              inlineData: { 
                mimeType: 'text/csv', 
                data: base64Csv 
              } 
            }
          ]
        }
      ],
      config: {
        responseMimeType: 'application/json',
        responseSchema: schema,
        temperature: 0.1, // Strict/Deterministic
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");
    
    const intel = JSON.parse(text) as ThreatIntel;

    // Enrich with VirusTotal Data (API)
    if (intel.iocs && intel.iocs.length > 0) {
      intel.iocs = await enrichIocsWithVirusTotal(intel.iocs);
    }

    return intel;

  } catch (error) {
    console.error("Gemini Analysis Failed:", error);
    // Fallback
    return {
      riskScore: 0,
      summary: "AI Analysis unavailable. The file may be too large or the API Key is invalid.",
      iocs: [],
      recommendations: ["Manually review cleartext protocols.", "Check API quotas."]
    };
  }
};