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
  
  // Prepare a concise summary for the LLM to avoid token limits
  const topProtocols = Object.entries(data.protocolCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 15);

  const connectionSample = data.connections.slice(0, 30);
  const hostsSample = data.uniqueHosts.slice(0, 50);

  // Filter for packets that have payload data
  const packetsWithPayload = data.rawSummary
    .filter(p => p.payload && p.payload.length > 2) // >2 to ignore simple CRLFs or empties
    .slice(0, 50); // Sample first 50 packets with payloads

  const packetPayloadSample = packetsWithPayload.map(p => ({
    src: p.srcIp,
    dst: p.dstIp,
    proto: p.protocol,
    dstPort: p.dstPort,
    payloadSnippet: p.payload
  }));

  const prompt = `
    Analyze the following network traffic summary derived from a PCAP file captured during a potential security incident.
    Act as a senior Incident Response (IR) analyst conducting post-mortem forensic analysis.
    
    Traffic Stats:
    - Total Packets: ${data.totalPackets}
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Unique Hosts Sample: ${JSON.stringify(hostsSample)}
    - Connections Sample: ${JSON.stringify(connectionSample)}
    
    Packet Payloads (Sample):
    ${JSON.stringify(packetPayloadSample)}
    
    Your objective is to derive high-value security insights and reconstruct the narrative, not just flag data.
    
    Focus your analysis on:
    1. **Incident Reconstruction**: Infer the sequence of events (e.g., Reconnaissance -> Lateral Movement -> Exfiltration).
    2. **Intent & Attribution**: What is the likely intent (e.g., C2, credential harvesting, internal recon)? Are there patterns matching known tools?
    3. **Anomalous Behaviors**: Identify non-standard port usage, cleartext data leaks relative to the protocol, or suspicious beacons.
    4. **False Positive Evaluation**: Distinguish between likely malicious activity and potential benign administrative tasks.
    
    Return a structured JSON assessment.
  `;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      riskScore: { type: Type.INTEGER, description: "Risk score from 0 (safe) to 100 (critical)" },
      summary: { type: Type.STRING, description: "Executive summary focusing on the incident narrative, intent, and overall security posture." },
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
        temperature: 0.2, // Slightly increased to allow for interpretive reasoning
      }
    });

    const text = response.text;
    if (!text) throw new Error("No response from AI");
    
    return JSON.parse(text) as ThreatIntel;
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