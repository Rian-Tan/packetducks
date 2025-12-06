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

  const prompt = `
    Analyze the following network traffic summary derived from a PCAP file. 
    Act as a senior cybersecurity analyst.
    
    Traffic Stats:
    - Total Packets: ${data.totalPackets}
    - Top Protocols: ${JSON.stringify(topProtocols)}
    - Unique Hosts Sample: ${JSON.stringify(hostsSample)}
    - Connections Sample: ${JSON.stringify(connectionSample)}
    
    Identify potential threats, anomalies, or indicators of compromise (IOCs).
    Look for:
    - Cleartext protocols (Telnet, FTP, HTTP)
    - Suspicious high ports
    - Lateral movement patterns
    - Known bad IP ranges (if recognized)
    
    Return a structured JSON assessment.
  `;

  const schema: Schema = {
    type: Type.OBJECT,
    properties: {
      riskScore: { type: Type.INTEGER, description: "Risk score from 0 (safe) to 100 (critical)" },
      summary: { type: Type.STRING, description: "Executive summary of the traffic analysis" },
      iocs: {
        type: Type.ARRAY,
        items: {
          type: Type.OBJECT,
          properties: {
            value: { type: Type.STRING, description: "The IP, Port, or Protocol" },
            type: { type: Type.STRING, enum: ['IP', 'PORT', 'PATTERN'] },
            description: { type: Type.STRING, description: "Why this is suspicious" },
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
        temperature: 0.1, // Low temp for analytical precision
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