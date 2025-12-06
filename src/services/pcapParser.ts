import { PacketSummary, PcapAnalysisResult, PortUsage, ProtocolType } from '../types';
import { COMMON_PORTS, TCP_FLAGS } from '../constants';

// Helper to format IP addresses
const formatIPv4 = (view: DataView, offset: number): string => {
  return `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
};

const formatIPv6 = (view: DataView, offset: number): string => {
  const parts = [];
  for (let i = 0; i < 8; i++) {
    parts.push(view.getUint16(offset + (i * 2), false).toString(16));
  }
  return parts.join(':');
};

// Helper to extract printable ASCII from payload
const getPayloadASCII = (view: DataView, start: number, end: number, maxLength: number = 200): string => {
  if (start >= end) return '';
  const len = Math.min(end - start, maxLength);
  let str = '';
  for (let i = 0; i < len; i++) {
    const c = view.getUint8(start + i);
    // Printable ASCII: 32 (space) to 126 (~)
    str += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
  }
  return str;
};

export const parsePcap = async (file: File): Promise<PcapAnalysisResult> => {
  // Fetch the C2 IP set first. This will be fast if cached.

  const arrayBuffer = await file.arrayBuffer();
  const view = new DataView(arrayBuffer);

  // 1. Global Header Parsing (24 bytes)
  if (view.byteLength < 24) {
    throw new Error("File is too short to be a valid PCAP.");
  }

  const magicNumber = view.getUint32(0, true); 
  let littleEndian = true;
  let timePrecisionMultiplier = 1000; 

  if (magicNumber === 0xa1b2c3d4) {
    littleEndian = true;
    timePrecisionMultiplier = 1000;
  } else if (magicNumber === 0xd4c3b2a1) {
    littleEndian = false;
    timePrecisionMultiplier = 1000;
  } else if (magicNumber === 0xa1b23c4d) {
    littleEndian = true; // Nano LE
    timePrecisionMultiplier = 1000000;
  } else if (magicNumber === 0x4d3cb2a1) {
    littleEndian = false; // Nano BE
    timePrecisionMultiplier = 1000000;
  } else if (magicNumber === 0x0A0D0D0A) {
    throw new Error("PCAPNG format detected. Please convert to standard PCAP (Libpcap) format using Wireshark, editcap, or tcpdump.");
  } else {
    console.warn(`Unknown magic number 0x${magicNumber.toString(16)}, assuming Little Endian Microseconds.`);
    littleEndian = true;
  }

  const linkType = view.getUint32(20, littleEndian);
  
  let offset = 24;
  const packets: PacketSummary[] = [];
  const uniqueHosts = new Set<string>();
  const connections = new Set<string>();
  const protocolCounts: Record<string, number> = {};

  const tcpUsage: Record<number, PortUsage> = {};
  const udpUsage: Record<number, PortUsage> = {};

  const initUsage = (store: Record<number, PortUsage>, port: number) => {
    if (!store[port]) {
      store[port] = { sport: 0, dport: 0, syn_dst: 0, synack_src: 0 };
    }
  };

  while (offset < view.byteLength) {
    if (offset + 16 > view.byteLength) break;

    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    
    const timestamp = (tsSec * 1000) + Math.floor(tsUsec / (timePrecisionMultiplier / 1000));

    offset += 16;

    if (offset + inclLen > view.byteLength) {
      console.warn("Packet length exceeds file size, stopping parse.");
      break;
    }

    const packetStart = offset;
    const packetEnd = offset + inclLen;

    let l3Offset = 0;
    let l3Type = 0;
    let hasL3 = false;
    let handled = false;

    if (linkType === 1) { // Ethernet
      if (inclLen >= 14) {
        let etype = view.getUint16(packetStart + 12, false);
        let headerLen = 14;

        if (etype === 0x8100 && inclLen >= 18) {
          etype = view.getUint16(packetStart + 16, false);
          headerLen = 18;
        }
        
        l3Type = etype;
        l3Offset = packetStart + headerLen;
        hasL3 = true;
        handled = true;
        protocolCounts['Ethernet'] = (protocolCounts['Ethernet'] || 0) + 1;
      }
    } else if (linkType === 113) { // Linux SLL
      if (inclLen >= 16) {
        l3Type = view.getUint16(packetStart + 14, false);
        l3Offset = packetStart + 16;
        hasL3 = true;
        handled = true;
        protocolCounts['Linux SLL'] = (protocolCounts['Linux SLL'] || 0) + 1;
      }
    } else if (linkType === 0) { // Null/Loopback
      if (inclLen >= 4) {
        l3Offset = packetStart + 4;
        const firstByte = view.getUint8(l3Offset);
        const version = (firstByte >> 4) & 0xF;
        if (version === 4) l3Type = 0x0800;
        else if (version === 6) l3Type = 0x86DD;
        else l3Type = 0;

        hasL3 = true;
        handled = true;
        protocolCounts['Loopback'] = (protocolCounts['Loopback'] || 0) + 1;
      }
    } else if (linkType === 101 || linkType === 12) { // Raw IP
       l3Offset = packetStart;
       const firstByte = view.getUint8(l3Offset);
       const version = (firstByte >> 4) & 0xF;
       if (version === 4) l3Type = 0x0800;
       else if (version === 6) l3Type = 0x86DD;
       
       hasL3 = true;
       handled = true;
       protocolCounts['Raw IP'] = (protocolCounts['Raw IP'] || 0) + 1;
    }

    if (!handled) {
       protocolCounts[`Unknown L2 (Type ${linkType})`] = (protocolCounts[`Unknown L2 (Type ${linkType})`] || 0) + 1;
    }

    let srcIp = '';
    let dstIp = '';
    let nextProto = 0;
    let l4Offset = 0;
    let isIp = false;

    if (hasL3 && l3Offset < packetEnd) {
      if (l3Type === 0x0800) { // IPv4
        if (l3Offset + 20 <= packetEnd) {
          const verIhl = view.getUint8(l3Offset);
          const ihl = (verIhl & 0x0f) * 4;
          
          nextProto = view.getUint8(l3Offset + 9);
          srcIp = formatIPv4(view, l3Offset + 12);
          dstIp = formatIPv4(view, l3Offset + 16);
          
          l4Offset = l3Offset + ihl;
          isIp = true;
          protocolCounts['IPv4'] = (protocolCounts['IPv4'] || 0) + 1;
        }
      } else if (l3Type === 0x86DD) { // IPv6
        if (l3Offset + 40 <= packetEnd) {
          nextProto = view.getUint8(l3Offset + 6);
          srcIp = formatIPv6(view, l3Offset + 8);
          dstIp = formatIPv6(view, l3Offset + 24);
          
          l4Offset = l3Offset + 40;
          isIp = true;
          protocolCounts['IPv6'] = (protocolCounts['IPv6'] || 0) + 1;
        }
      } else if (l3Type === 0x0806) {
        protocolCounts['ARP'] = (protocolCounts['ARP'] || 0) + 1;
      }
    }

    if (isIp) {
      uniqueHosts.add(srcIp);
      uniqueHosts.add(dstIp);
      const connKey = [srcIp, dstIp].sort().join(' <-> ');
      connections.add(connKey);
    }

    let pSummary: PacketSummary = {
      timestamp: timestamp,
      srcIp: srcIp || '?',
      dstIp: dstIp || '?',
      protocol: ProtocolType.Other,
      length: inclLen
    };

    if (isIp && l4Offset > 0 && l4Offset < packetEnd) {
      if (nextProto === 6) { // TCP
        if (l4Offset + 20 <= packetEnd) {
          pSummary.protocol = ProtocolType.TCP;
          protocolCounts['TCP'] = (protocolCounts['TCP'] || 0) + 1;

          const srcPort = view.getUint16(l4Offset, false);
          const dstPort = view.getUint16(l4Offset + 2, false);
          
          const dataOffsetByte = view.getUint8(l4Offset + 12);
          const dataOffset = (dataOffsetByte >> 4) * 4;

          const flags = view.getUint8(l4Offset + 13);

          pSummary.srcPort = srcPort;
          pSummary.dstPort = dstPort;
          pSummary.flags = flags;

          const payloadStart = l4Offset + dataOffset;
          if (payloadStart < packetEnd) {
            pSummary.payload = getPayloadASCII(view, payloadStart, packetEnd);
          }

          initUsage(tcpUsage, srcPort);
          initUsage(tcpUsage, dstPort);
          tcpUsage[srcPort].sport++;
          tcpUsage[dstPort].dport++;

          if ((flags & TCP_FLAGS.SYN) && !(flags & TCP_FLAGS.ACK)) {
            tcpUsage[dstPort].syn_dst++;
          }
          if ((flags & TCP_FLAGS.SYN) && (flags & TCP_FLAGS.ACK)) {
            tcpUsage[srcPort].synack_src++;
          }

          if (COMMON_PORTS[dstPort]) {
            const label = `TCP/${COMMON_PORTS[dstPort]}`;
            protocolCounts[label] = (protocolCounts[label] || 0) + 1;
          }
        }
      } else if (nextProto === 17) { // UDP
        if (l4Offset + 8 <= packetEnd) {
          pSummary.protocol = ProtocolType.UDP;
          protocolCounts['UDP'] = (protocolCounts['UDP'] || 0) + 1;

          const srcPort = view.getUint16(l4Offset, false);
          const dstPort = view.getUint16(l4Offset + 2, false);

          pSummary.srcPort = srcPort;
          pSummary.dstPort = dstPort;

          const payloadStart = l4Offset + 8;
          if (payloadStart < packetEnd) {
            pSummary.payload = getPayloadASCII(view, payloadStart, packetEnd);
          }

          initUsage(udpUsage, srcPort);
          initUsage(udpUsage, dstPort);
          udpUsage[srcPort].sport++;
          udpUsage[dstPort].dport++;

          if (COMMON_PORTS[dstPort]) {
            const label = `UDP/${COMMON_PORTS[dstPort]}`;
            protocolCounts[label] = (protocolCounts[label] || 0) + 1;
          }
        }
      } else if (nextProto === 1) {
        pSummary.protocol = ProtocolType.ICMP;
        protocolCounts['ICMP'] = (protocolCounts['ICMP'] || 0) + 1;
      }
    }

    packets.push(pSummary);
    
    offset = packetEnd;
  }

  const significantTcp = new Set<number>();
  Object.entries(tcpUsage).forEach(([portStr, stats]) => {
    const port = parseInt(portStr);
    if (COMMON_PORTS[port]) return;

    const d = stats.dport;
    const s = stats.sport;
    const synHits = stats.syn_dst + stats.synack_src;

    if (d >= 5 && synHits >= 1 && d > s * 1.5) {
      significantTcp.add(port);
    }
  });

  const significantUdp = new Set<number>();
  Object.entries(udpUsage).forEach(([portStr, stats]) => {
    const port = parseInt(portStr);
    if (COMMON_PORTS[port]) return;

    const d = stats.dport;
    const s = stats.sport;
    if (d >= 5 && d > s * 1.5) {
      significantUdp.add(port);
    }
  });

  packets.forEach(p => {
    if (p.protocol === ProtocolType.TCP && p.dstPort) {
      if (significantTcp.has(p.dstPort)) {
        const pName = `TCP/${p.dstPort}`;
        protocolCounts[pName] = (protocolCounts[pName] || 0) + 1;
      }
    }
    if (p.protocol === ProtocolType.UDP && p.dstPort) {
      if (significantUdp.has(p.dstPort)) {
        const pName = `UDP/${p.dstPort}`;
        protocolCounts[pName] = (protocolCounts[pName] || 0) + 1;
      }
    }
  });

  packets.sort((a, b) => a.timestamp - b.timestamp);

  const startTime = packets.length > 0 ? new Date(packets[0].timestamp) : new Date();
  const endTime = packets.length > 0 ? new Date(packets[packets.length - 1].timestamp) : new Date();

  return {
    totalPackets: packets.length,
    protocolCounts,
    uniqueHosts: Array.from(uniqueHosts).sort(),
    connections: Array.from(connections).map(c => {
      const [a, b] = c.split(' <-> ');
      return { a, b };
    }),
    startTime,
    endTime,
    rawSummary: packets
  };
};
