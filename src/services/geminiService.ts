import { GoogleGenAI, Type, Schema } from '@google/genai';
import { PcapAnalysisResult, ThreatIntel, IpInfoData } from '../types';

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

export const generateThreatIntel = async (data: PcapAnalysisResult): Promise<ThreatIntel> => {
  const ai = getClient();
  
  // Prepare a concise summary for the LLM to avoid token limits
  const topProtocols = Object.entries(data.protocolCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 15);

  const connectionSample = data.connections.slice(0, 30);
  const hostsSample = data.uniqueHosts.slice(0, 50);

  // Filter for packets that have payload data
  // Increased sample size to reduce false negatives
  const packetsWithPayload = data.rawSummary
    .filter(p => p.payload && p.payload.length > 4) // >4 to ignore tiny noise
    .slice(0, 150); 

  const packetPayloadSample = packetsWithPayload.map(p => ({
    src: p.srcIp,
    dst: p.dstIp,
    proto: p.protocol,
    dstPort: p.dstPort,
    payloadSnippet: p.payload
  }));

  const ipContext = data.ipInfo 
      ? JSON.stringify(Object.values(data.ipInfo).map(({ ip, as_name, country, asn }) => ({ ip, org: as_name, country, asn })))
      : "No external IP context available.";

  const prompt = `
    Analyze the following network traffic summary derived from a PCAP file.
    Act as a senior Incident Response (IR) analyst conducting post-mortem forensic analysis.
    
    Traffic Stats:
    - Total Packets: ${data.totalPackets}
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Unique Hosts Sample: ${JSON.stringify(hostsSample)}
    - Connections Sample: ${JSON.stringify(connectionSample)}
    
    External IP Intelligence (Geo/ASN/ISP):
    ${ipContext}

    Packet Payloads (Sample):
    ${JSON.stringify(packetPayloadSample)}
    
    Your objective is to assess the security posture of this capture.

    CRITICAL DETECTION GUIDELINES:
    1. **EVIDENCE-BASED DETECTION**: You must strictly analyze the "Packet Payloads" provided. Do not hallucinate threats that are not in the data.
    2. **LOOK FOR SPECIFIC PATTERNS**:
       - **Web Attacks**: SQL Injection ('UNION SELECT', 'OR 1=1'), XSS ('<script>'), Path Traversal ('../..').
       - **Command Injection**: 'cmd.exe', '/bin/sh', 'whoami', 'powershell'.
       - **Suspicious User-Agents**: 'sqlmap', 'nikto', 'curl', 'python-requests', 'hydra'.
       - **Cleartext Auth**: 'Authorization: Basic', 'password=', 'user='.
       - **Geo-Location Anomalies**: **USE THE IP INTELLIGENCE PROVIDED**. If a host connects to an IP in a high-risk country (e.g. Russia, China, North Korea) or a known Bulletproof Hosting ASN (as per provided IP Intelligence), and the traffic looks suspicious, flag it immediately.
    3. **CONTEXTUAL ANALYSIS**: If you see standard protocols (HTTP, DNS) behaving normally, mark them as safe. However, if you see binary data in DNS TXT records (Tunneling) or non-HTTP traffic on port 80, flag it.
    4. **SCORING RUBRIC**:
       - **0-10 (Clean)**: Standard traffic, no anomalies.
       - **11-40 (Low/Suspicious)**: Cleartext credentials, deprecated protocols (Telnet), or generic scanning noise.
       - **41-75 (High)**: Strong indicators of attack (SQLi patterns, XSS attempts, known malicious User-Agents, suspicious Geo-IP connections).
       - **76-100 (Critical)**: Confirmed compromise indicators (Shell responses, successful data exfiltration signatures).

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
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: schema,
        temperature: 0.2, // Slightly increased to allow pattern matching flexibility without hallucination
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");
    
    const intel = JSON.parse(text) as ThreatIntel;

    // Step 2: Enrich with VirusTotal Data (API)
    // We do this server-side or via proxy to avoid CORS
    if (intel.iocs && intel.iocs.length > 0) {
      intel.iocs = await enrichIocsWithVirusTotal(intel.iocs);
    }

    return intel;

  } catch (error) {
    console.error("Gemini Analysis Failed:", error);
    // Fallback if AI fails or key missing
    return {
      riskScore: 0,
      summary: "AI Analysis unavailable. Check API Key or network connection.",
      iocs: [],
      recommendations: ["Manually review cleartext protocols."]
    };
  }
};