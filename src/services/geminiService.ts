import { GoogleGenAI, Type, Schema } from '@google/genai';
import { PcapAnalysisResult, ThreatIntel } from '../types';

const getClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found");
  }
  return new GoogleGenAI({ apiKey });
};

const getVtKey = () => {
  return process.env.VT_API_KEY || "";
};

export const checkSingleVirusTotal = async (ip: string): Promise<string> => {
  const apiKey = getVtKey();
  if (!apiKey) {
    throw new Error("VirusTotal API Key not configured");
  }

  // Use local proxy to handle CORS and hide API key if needed
  const targetUrl = `/vt-api/ip_addresses/${ip}`;
  
  const response = await fetch(targetUrl, {
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

const enrichIocsWithGeoIp = async (iocs: ThreatIntel['iocs']): Promise<ThreatIntel['iocs']> => {
    const ipIocs = iocs.filter(ioc => ioc.type && ioc.type.toUpperCase() === 'IP');
    if (ipIocs.length === 0) return iocs;

    // Helper to check if IP is private
    const isPrivateIp = (ip: string) => {
        const parts = ip.split('.').map(Number);
        if (parts[0] === 10) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 127) return true;
        return false;
    };

    const geoResults = new Map<string, { countryCode: string, country: string }>();

    // Fetch GeoIP for public IPs only
    await Promise.all(ipIocs.map(async (ioc) => {
        if (isPrivateIp(ioc.value)) return;
        try {
            const res = await fetch(`https://ipapi.co/${ioc.value}/json/`);
            if (res.ok) {
                const data = await res.json();
                if (!data.error) {
                    geoResults.set(ioc.value, { countryCode: data.country_code, country: data.country_name });
                }
            }
        } catch (e) {
            console.warn(`GeoIP lookup error for ${ioc.value}`, e);
        }
    }));

    return iocs.map(ioc => {
        if (ioc.type && ioc.type.toUpperCase() === 'IP' && geoResults.has(ioc.value)) {
            const geo = geoResults.get(ioc.value)!;
            return { ...ioc, countryCode: geo.countryCode, countryName: geo.country };
        }
        return ioc;
    });
};

export const enrichHostsWithGeoIp = async (analysis: PcapAnalysisResult): Promise<PcapAnalysisResult> => {
  const publicIps = analysis.uniqueHosts.filter(ip => {
    if (ip.includes(':')) return false; // Skip IPv6 for now
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    // Skip private ranges
    if (parts[0] === 10) return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
    if (parts[0] === 192 && parts[1] === 168) return false;
    if (parts[0] === 127) return false;
    if (parts[0] >= 224) return false;
    return true;
  });

  if (publicIps.length === 0) return analysis;

  const geoMap: Record<string, { countryCode: string; countryName: string }> = {};
  
  // Process in batches of 5 to avoid rate limits
  for (let i = 0; i < publicIps.length; i += 5) {
    const batch = publicIps.slice(i, i + 5);
    await Promise.all(batch.map(async (ip) => {
      try {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        if (response.ok) {
          const data = await response.json();
          if (data.country_code) {
            geoMap[ip] = {
              countryCode: data.country_code,
              countryName: data.country_name
            };
          }
        }
      } catch (err) {
        console.error(`GeoIP lookup failed for host ${ip}:`, err);
      }
    }));
    if (i + 5 < publicIps.length) {
      await new Promise(resolve => setTimeout(resolve, 500)); // Small delay between batches
    }
  }

  return {
    ...analysis,
    hostGeoMap: geoMap
  };
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
  const allPacketsWithPayload = data.rawSummary.filter(p => p.payload && p.payload.length > 4);

  // Prioritize suspicious packets
  const suspiciousKeywords = [
    'jndi', 'ldap', 'rmi', 'dns:', 'protocol', 'constructor', '__proto__', 
    '${', '%24%7B', 'nc ', 'bash', 'sh ', 'cmd.exe', 'powershell', 'whoami', 'curl', 'wget',
    'union select', 'select ', 'insert ', 'drop ', 'delete ', 'update ', 'script>',
    '../', '..\\', '/etc/passwd', 'C:\\Windows', 'Authorization:', 'Basic ', 'Bearer ',
    'log4j', 'log4shell', 'exploit', 'payload', 'lower:', 'upper:', 'sys:', 'env:', 'main:',
    'jndi:', 'ldap:', 'rmi:', 'dns:'
  ];

  const suspiciousPackets = allPacketsWithPayload.filter(p => {
    const payloadLower = p.payload!.toLowerCase();
    return suspiciousKeywords.some(keyword => payloadLower.includes(keyword.toLowerCase()));
  });

  const normalPackets = allPacketsWithPayload.filter(p => !suspiciousPackets.includes(p));

  // Combine: All suspicious (up to 150) + some normal to provide context (up to 50)
  const packetsToAnalyze = [
    ...suspiciousPackets.slice(0, 150),
    ...normalPackets.slice(0, 50)
  ].slice(0, 200); // Absolute max 200 packets

  const packetPayloadSample = packetsToAnalyze.map(p => ({
    src: p.srcIp,
    dst: p.dstIp,
    proto: p.protocol,
    dstPort: p.dstPort,
    payloadSnippet: p.payload
  }));

  const prompt = `
    Analyze the following network traffic summary derived from a PCAP file.
    Act as a senior Incident Response (IR) analyst conducting post-mortem forensic analysis.
    
    Traffic Stats:
    - Total Packets: ${data.totalPackets}
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Unique Hosts Sample: ${JSON.stringify(hostsSample)}
    - Connections Sample: ${JSON.stringify(connectionSample)}
    - Duplicate Payloads (Potential Replay Attacks): ${JSON.stringify(data.duplicatePayloads || [])}
    
    Packet Payloads (Sample):
    ${JSON.stringify(packetPayloadSample)}
    
    Your objective is to assess the security posture of this capture.

    CRITICAL DETECTION GUIDELINES:
    1. **EVIDENCE-BASED DETECTION**: You must strictly analyze the "Packet Payloads" provided. Do not hallucinate threats that are not in the data.
    2. **THREAT KNOWLEDGE BASE**:
       - **React2Shell (CVE-2025-55182)**: Look for HTTP requests targeting development servers (often port 3000/8080) with payloads containing shell commands (e.g., 'nc', 'bash', 'sh') or suspicious parameters like 'url=' in a debugging context. It is a Remote Code Execution (RCE) attack, NOT prototype pollution.
       - **Prototype Pollution**: Look for JSON payloads with "__proto__", "constructor", or "prototype" keys being assigned malicious values. This is an object manipulation attack.
       - **Log4Shell (CVE-2021-44228)**: Look for JNDI lookups like '\${jndi:ldap://...}', '\${jndi:rmi://...}', or obfuscated versions like '\${\${lower:j}ndi:ldap://...}'. These can appear in HTTP headers (User-Agent, Referer, X-Api-Version) or POST bodies.
       - **EternalBlue (CVE-2017-0144)**: Look for SMBv1 traffic with suspicious tree connect or session setup requests, often targeting port 445.
       - **Heartbleed (CVE-2014-0160)**: Look for TLS Heartbeat requests with a payload length that exceeds the actual data provided, leading to memory leakage.
       - **Shellshock (CVE-2014-6271)**: Look for '() { :; };' patterns in HTTP headers like User-Agent or Referer.
       - **SQL Injection**: Look for 'UNION SELECT', 'OR 1=1', '--', or sleep functions.
       - **Path Traversal**: Look for '../..', '/etc/passwd', or 'C:\Windows\System32'.
       - **Replay Attack**: Look for identical payloads (especially those containing authentication tokens, cookies, or sensitive commands) sent multiple times, potentially from different IPs or at different times. Check the "Duplicate Payloads" section for evidence.
    3. **LOOK FOR SPECIFIC PATTERNS**:
       - **Command Injection**: 'cmd.exe', '/bin/sh', 'whoami', 'powershell', 'nc -e', 'bash -i'.
       - **Suspicious User-Agents**: 'sqlmap', 'nikto', 'curl', 'python-requests', 'hydra', 'zgrab'.
       - **Cleartext Auth**: 'Authorization: Basic', 'password=', 'user=', 'cookie: session='.
    3. **CONTEXTUAL ANALYSIS**: If you see standard protocols (HTTP, DNS) behaving normally, mark them as safe. However, if you see binary data in DNS TXT records (Tunneling) or non-HTTP traffic on port 80, flag it.
    4. **SCORING RUBRIC**:
       - **0-10 (Clean)**: Standard traffic, no anomalies.
       - **11-40 (Low/Suspicious)**: Cleartext credentials, deprecated protocols (Telnet), or generic scanning noise.
       - **41-75 (High)**: Strong indicators of attack (SQLi patterns, XSS attempts, known malicious User-Agents).
       - **76-100 (Critical)**: Confirmed compromise indicators (Shell responses, successful data exfiltration signatures).

    If the capture appears clean, explicitly state "No significant threats detected in the provided sample."

    **FINAL WARNING**: Do not confuse Remote Code Execution (RCE) patterns (like shell commands or environment variable injection) with Prototype Pollution. Prototype Pollution specifically involves the modification of JavaScript object prototypes (e.g., __proto__). If you see shell commands, it is almost certainly an RCE or Command Injection attack.

    Return a structured JSON assessment. 
    - Include a 'forensicJustification' field where you explain the step-by-step reasoning for your classification. This should include specific references to the packet payloads you analyzed.
    - Include a 'classification' field that identifies the traffic type or malware family (e.g. "PlugX", "Emotet", "SQL Injection Attack", "Normal HTTP Traffic").
    - **CRITICAL**: If you can identify a specific attack name (e.g. "React2Shell", "Log4Shell", "EternalBlue", "WannaCry") or any associated CVE IDs (e.g. "CVE-2021-44228", "CVE-2017-0144"), you MUST include them in the 'attackName' and 'cveTags' fields respectively. 
    - If multiple CVEs are involved, list them all in 'cveTags'.
    - If no specific attack name is found, use the most descriptive classification as the 'attackName'.
  `;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      riskScore: { type: Type.INTEGER, description: "Risk score from 0 (safe) to 100 (critical)." },
      summary: { type: Type.STRING, description: "Executive summary of findings." },
      forensicJustification: { type: Type.STRING, description: "Step-by-step reasoning for the classification, referencing specific packet payloads." },
      classification: { type: Type.STRING, description: "Malware family or traffic classification (e.g. 'PlugX', 'Normal Traffic')." },
      attackName: { type: Type.STRING, description: "Specific attack name if identified (e.g. 'React2Shell')." },
      cveTags: { 
        type: Type.ARRAY, 
        items: { type: Type.STRING },
        description: "List of associated CVE IDs (e.g. ['CVE-2021-44228'])." 
      },
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
    required: ["riskScore", "summary", "classification", "iocs", "recommendations"]
  };

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
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
      intel.iocs = await enrichIocsWithGeoIp(intel.iocs);
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
