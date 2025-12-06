import { GoogleGenAI, Type, Schema } from '@google/genai';
import { PcapAnalysisResult, ThreatIntel } from '../types';

const getClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found");
  }
  return new GoogleGenAI({ apiKey });
};

export const generateThreatIntel = async (data: PcapAnalysisResult): Promise<ThreatIntel> => {
  const ai = getClient();
  
  const topProtocols = Object.entries(data.protocolCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 15);

  const connectionSample = data.connections.slice(0, 30);
  const hostsSample = data.uniqueHosts.slice(0, 50);

  const packetsWithPayload = data.rawSummary
    .filter(p => p.payload && p.payload.length > 2)
    .slice(0, 50);

  const packetPayloadSample = packetsWithPayload.map(p => ({
    src: p.srcIp,
    dst: p.dstIp,
    proto: p.protocol,
    dstPort: p.dstPort,
    payloadSnippet: p.payload
  }));

  const prompt = `
    Analyze the following network traffic summary from a PCAP file. Act as a senior IR analyst providing guidance to a Tier 1 SOC analyst.

    **CRITICAL INTEL**: The following IPs have been positively identified as known Command & Control (C2) servers: 
    ${JSON.stringify(data.flaggedC2Ips)}
    
    **This is a confirmed breach indicator. Your analysis must start from this premise.**

    Traffic Stats:
    - Total Packets: ${data.totalPackets}
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Unique Hosts Sample: ${JSON.stringify(hostsSample)}
    - Connections Sample: ${JSON.stringify(connectionSample)}
    
    Packet Payloads (Sample):
    ${JSON.stringify(packetPayloadSample)}
    
    Your objective is to:
    1.  **Prioritize C2 Activity**: Immediately focus on traffic to/from the flagged C2 IPs. This is the most critical part of the analysis.
    2.  **Reconstruct the Kill Chain**: Based on the C2 communication, infer the stages (e.g., beaconing, data staging, exfiltration).
    3.  **Identify the Compromised Host(s)**: Pinpoint which internal hosts are communicating with the C2 servers.
    4.  **Generate Actionable IOCs**: Create IOCs for the C2 IPs and any other related suspicious activity. All C2 IPs MUST be listed as IOCs with CRITICAL severity.
    5.  **Elevate Risk Score**: The risk score must be high (75-100) to reflect the confirmed C2 activity.
    6.  **Provide Tier 1 Actions**: Generate a list of clear, concise, and actionable recommendations for a Tier 1 SOC analyst. These should be immediate response actions.

    **Tier 1 Action Examples:**
    - "Isolate Host: Immediately isolate the affected host with IP <HOST_IP> from the network to prevent potential lateral movement."
    - "Block Indicator: Add the malicious IP address <MALICIOUS_IP> to the firewall blocklist."
    - "Investigate Traffic: Analyze historical network traffic from the affected host to the malicious IP to identify the extent of the compromise."
    - "Escalate: Escalate this incident to Tier 2 for further investigation and malware analysis."

    Return a structured JSON assessment.
  `;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      riskScore: { type: Type.INTEGER, description: "Risk score from 0 (safe) to 100 (critical)" },
      summary: { type: Type.STRING, description: "Executive summary focusing on the C2 activity, compromised hosts, and likely attacker objectives." },
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
        items: { type: Type.STRING, description: "Clear and actionable steps for a Tier 1 SOC analyst." }
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
        temperature: 0.1, // Lower temperature for more deterministic output based on the critical intel
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");
    
    return JSON.parse(text) as ThreatIntel;
  } catch (error) {
    console.error("Gemini Analysis Failed:", error);
    // Fallback if AI fails
    return {
      riskScore: 95, // High default score due to C2 being flagged by the parser
      summary: "AI Analysis unavailable. Critical Threat Detected: The PCAP analysis has identified traffic to known Command & Control (C2) servers. Immediate investigation is required.",
      iocs: data.flaggedC2Ips.map(ip => ({
        value: ip,
        type: 'IP',
        description: 'Connection to a known Command & Control (C2) server detected by internal threat intelligence.',
        severity: 'CRITICAL'
      })),
      recommendations: [
        "Immediately isolate any host(s) communicating with the flagged C2 IPs.",
        "Block the flagged C2 IPs at the network perimeter.",
        "Begin forensic analysis on the compromised host(s)."
      ]
    };
  }
};