
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

export const parsePcap = async (file: File): Promise<PcapAnalysisResult> => {
  const arrayBuffer = await file.arrayBuffer();
  const view = new DataView(arrayBuffer);

  // 1. Global Header Parsing (24 bytes)
  if (view.byteLength < 24) {
    throw new Error("File is too short to be a valid PCAP.");
  }

  const magicNumber = view.getUint32(0, true); // Read first 4 bytes as Little Endian for checking
  let littleEndian = true;
  let timePrecisionMultiplier = 1; // Default to microseconds

  /**
   * Magic Number Logic:
   * Standard PCAP Magic: 0xa1b2c3d4
   *
   * If we read it as LE and get 0xa1b2c3d4, the file IS Little Endian.
   * If we read it as LE and get 0xd4c3b2a1, the file IS Big Endian (bytes are swapped).
   */
  if (magicNumber === 0xa1b2c3d4) {
    littleEndian = true;
  } else if (magicNumber === 0xd4c3b2a1) {
    littleEndian = false;
  } else if (magicNumber === 0xa1b23c4d) {
    littleEndian = true; // Nano LE
    timePrecisionMultiplier = 1000;
  } else if (magicNumber === 0x4d3cb2a1) {
    littleEndian = false; // Nano BE
    timePrecisionMultiplier = 1000;
  } else if (magicNumber === 0x0A0D0D0A) {
    throw new Error("PCAPNG format detected. Please convert to standard PCAP (Libpcap) format using Wireshark, editcap, or tcpdump.");
  } else {
    console.warn(`Unknown magic number 0x${magicNumber.toString(16)}, assuming Little Endian.`);
    littleEndian = true;
  }

  // Link-Layer Header Type (Offset 20, 4 bytes)
  // 1 = Ethernet, 113 = Linux SLL, 0 = Null/Loopback, 101 = Raw IP
  const linkType = view.getUint32(20, littleEndian);
  
  // console.log(`PCAP Header: Endian=${littleEndian ? 'Little' : 'Big'}, LinkType=${linkType}`);

  let offset = 24; // Skip global header
  const packets: PacketSummary[] = [];
  const uniqueHosts = new Set<string>();
  const connections = new Set<string>();
  const protocolCounts: Record<string, number> = {};

  // Stats for "Significant Port" logic
  const tcpUsage: Record<number, PortUsage> = {};
  const udpUsage: Record<number, PortUsage> = {};

  const initUsage = (store: Record<number, PortUsage>, port: number) => {
    if (!store[port]) {
      store[port] = { sport: 0, dport: 0, syn_dst: 0, synack_src: 0 };
    }
  };

  // 2. Iterate Packets
  while (offset < view.byteLength) {
    // Packet Header (16 bytes)
    if (offset + 16 > view.byteLength) break;

    // Header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    const inclLen = view.getUint32(offset + 8, littleEndian);
    // const origLen = view.getUint32(offset + 12, littleEndian);
    
    offset += 16; // Move past packet header

    if (offset + inclLen > view.byteLength) {
      console.warn("Packet length exceeds file size, stopping parse.");
      break;
    }

    const packetStart = offset;
    const packetEnd = offset + inclLen;

    // --- Parse Layers ---
    let l3Offset = 0;
    let l3Type = 0; // EtherType or equivalent
    let hasL3 = false;
    let handled = false;

    // Layer 2: Link Layer
    if (linkType === 1) { 
      // Ethernet
      if (inclLen >= 14) {
        let etype = view.getUint16(packetStart + 12, false); // Ethernet is always Network Byte Order (Big Endian)
        let headerLen = 14;

        // Handle 802.1Q VLAN
        if (etype === 0x8100 && inclLen >= 18) {
          etype = view.getUint16(packetStart + 16, false);
          headerLen = 18; // 14 + 4 bytes VLAN tag
        }
        
        l3Type = etype;
        l3Offset = packetStart + headerLen;
        hasL3 = true;
        handled = true;
        protocolCounts['Ethernet'] = (protocolCounts['Ethernet'] || 0) + 1;
      }
    } else if (linkType === 113) { 
      // Linux SLL (Cooked Capture)
      // Header is 16 bytes. Protocol is at offset 14 (Network Byte Order).
      if (inclLen >= 16) {
        l3Type = view.getUint16(packetStart + 14, false);
        l3Offset = packetStart + 16;
        hasL3 = true;
        handled = true;
        protocolCounts['Linux SLL'] = (protocolCounts['Linux SLL'] || 0) + 1;
      }
    } else if (linkType === 0) {
      // Null / Loopback
      // 4 byte header. Contains protocol family in host byte order.
      // However, it's safer to just peek at the IP version in the payload.
      if (inclLen >= 4) {
        l3Offset = packetStart + 4;
        // Peek IP version
        const firstByte = view.getUint8(l3Offset);
        const version = (firstByte >> 4) & 0xF;
        if (version === 4) l3Type = 0x0800;
        else if (version === 6) l3Type = 0x86DD;
        else l3Type = 0; // Unknown

        hasL3 = true;
        handled = true;
        protocolCounts['Loopback'] = (protocolCounts['Loopback'] || 0) + 1;
      }
    } else if (linkType === 101 || linkType === 12) {
       // Raw IP
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

    // Layer 3: Network Layer
    let srcIp = '';
    let dstIp = '';
    let nextProto = 0; // TCP(6), UDP(17)
    let l4Offset = 0;
    let isIp = false;

    if (hasL3 && l3Offset < packetEnd) {
      if (l3Type === 0x0800) { // IPv4
        if (l3Offset + 20 <= packetEnd) {
          // Version & IHL
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
          nextProto = view.getUint8(l3Offset + 6); // Next Header
          srcIp = formatIPv6(view, l3Offset + 8);
          dstIp = formatIPv6(view, l3Offset + 24);
          
          // Simplified: We assume next header is L4. Real IPv6 has extension headers.
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

    // Layer 4: Transport Layer
    let pSummary: PacketSummary = {
      timestamp: Date.now(),
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

          const srcPort = view.getUint16(l4Offset, false); // Ports are Big Endian
          const dstPort = view.getUint16(l4Offset + 2, false);
          
          // TCP Data Offset (Header Length)
          const dataOffsetByte = view.getUint8(l4Offset + 12);
          // const dataOffset = (dataOffsetByte >> 4) * 4; // Unused for basic stats

          const flags = view.getUint8(l4Offset + 13);

          pSummary.srcPort = srcPort;
          pSummary.dstPort = dstPort;
          pSummary.flags = flags;

          // Stats tracking
          initUsage(tcpUsage, srcPort);
          initUsage(tcpUsage, dstPort);
          tcpUsage[srcPort].sport++;
          tcpUsage[dstPort].dport++;

          // Syn tracking
          // SYN set (0x02) AND ACK not set (0x10)
          if ((flags & TCP_FLAGS.SYN) && !(flags & TCP_FLAGS.ACK)) {
            tcpUsage[dstPort].syn_dst++;
          }
          // SYN set AND ACK set
          if ((flags & TCP_FLAGS.SYN) && (flags & TCP_FLAGS.ACK)) {
            tcpUsage[srcPort].synack_src++;
          }

          // Service ID
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
    
    // Prepare for next packet
    offset = packetEnd;
  }

  // 3. Post-Processing: Significant Numeric Ports (Logic ported from Python)
  const significantTcp = new Set<number>();
  Object.entries(tcpUsage).forEach(([portStr, stats]) => {
    const port = parseInt(portStr);
    if (COMMON_PORTS[port]) return;

    const d = stats.dport;
    const s = stats.sport;
    const synHits = stats.syn_dst + stats.synack_src;

    // Python: min_dport=5, min_syn=1, dominance_ratio=1.5
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
    // Python: min_dport=5, dominance_ratio=1.5
    if (d >= 5 && d > s * 1.5) {
      significantUdp.add(port);
    }
  });

  // Second pass count for significant numeric ports
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

  return {
    totalPackets: packets.length,
    protocolCounts,
    uniqueHosts: Array.from(uniqueHosts).sort(),
    connections: Array.from(connections).map(c => {
      const [a, b] = c.split(' <-> ');
      return { a, b };
    }),
    startTime: new Date(), // Placeholder
    endTime: new Date(),   // Placeholder
    rawSummary: packets
  };
};
