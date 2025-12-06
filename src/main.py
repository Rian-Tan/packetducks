import sys
from scapy.all import rdpcap
import socket
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

def analyze_packets(packets):
    """
    Analyze packets and return:
      - total_packets
      - protocol_counts (filtered: real protocols + likely service ports)
      - unique_hosts
      - connections (bidirectional pairs)
    """

    total_packets = len(packets)
    protocol_counts = {}

    # Port usage stats so we can decide which ports look like servers
    tcp_usage = defaultdict(lambda: {"sport": 0, "dport": 0, "syn_dst": 0, "synack_src": 0})
    udp_usage = defaultdict(lambda: {"sport": 0, "dport": 0})

    # Ports that we know map to named services via getservbyport
    tcp_service_ports: dict[int, str] = {}
    udp_service_ports: dict[int, str] = {}

    unique_hosts = set()
    connections = set()

    # ---------- First pass: base protocols, service names, port usage, hosts/conns ----------
    for packet in packets:
        identified_protocols_for_packet = set()

        # Basic layer names (Ether, IP, TCP, UDP, Raw, etc.)
        for layer_class in packet.layers():
            protocol_name = layer_class.__name__
            identified_protocols_for_packet.add(protocol_name)

        # TCP analysis
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            sport = tcp_layer.sport
            dport = tcp_layer.dport
            flags = int(tcp_layer.flags)

            tcp_usage[sport]["sport"] += 1
            tcp_usage[dport]["dport"] += 1

            # SYN without ACK: client initiating to server's dport
            if flags & 0x02 and not (flags & 0x10):
                tcp_usage[dport]["syn_dst"] += 1

            # SYN+ACK: server replying from its sport
            if (flags & 0x12) == 0x12:
                tcp_usage[sport]["synack_src"] += 1

            # Try to resolve well-known service on dport
            try:
                service_name = socket.getservbyport(dport, "tcp")
                service_name = service_name.upper()
                tcp_service_ports[dport] = service_name
                identified_protocols_for_packet.add(f"TCP/{service_name}")
            except OSError:
                # Unknown service, numeric port handled later
                pass

        # UDP analysis
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            sport = udp_layer.sport
            dport = udp_layer.dport

            udp_usage[sport]["sport"] += 1
            udp_usage[dport]["dport"] += 1

            try:
                service_name = socket.getservbyport(dport, "udp")
                service_name = service_name.upper()
                udp_service_ports[dport] = service_name
                identified_protocols_for_packet.add(f"UDP/{service_name}")
            except OSError:
                pass

        # Count base + named protocols
        for p_name in identified_protocols_for_packet:
            protocol_counts[p_name] = protocol_counts.get(p_name, 0) + 1

        # Host + connection info
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            unique_hosts.update([src_ip, dst_ip])
            connections.add(tuple(sorted((src_ip, dst_ip))))

        elif packet.haslayer(IPv6):
            ip6_layer = packet[IPv6]
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
            unique_hosts.update([src_ip, dst_ip])
            connections.add(tuple(sorted((src_ip, dst_ip))))

    # ---------- Decide which numeric ports are "likely services" ----------

    def pick_significant_tcp_ports(usage, service_ports, min_dport=5, min_syn=1, dominance_ratio=1.5):
        """
        Pick TCP ports that:
          - are not already mapped to a named service
          - have at least `min_syn` SYN-related activity
          - and are used more as dport than sport by `dominance_ratio`
          - and have at least `min_dport` dport hits
        """
        significant = set()
        for port, counts in usage.items():
            if port in service_ports:
                continue

            d = counts["dport"]
            s = counts["sport"]
            syn_hits = counts["syn_dst"] + counts["synack_src"]

            if d >= min_dport and syn_hits >= min_syn and d > s * dominance_ratio:
                significant.add(port)
        return significant

    def pick_significant_udp_ports(usage, service_ports, min_dport=5, dominance_ratio=1.5):
        """
        Similar idea for UDP, but no flags => rely on dport vs sport usage.
        """
        significant = set()
        for port, counts in usage.items():
            if port in service_ports:
                continue

            d = counts["dport"]
            s = counts["sport"]

            if d >= min_dport and d > s * dominance_ratio:
                significant.add(port)
        return significant

    significant_tcp_ports = pick_significant_tcp_ports(tcp_usage, tcp_service_ports)
    significant_udp_ports = pick_significant_udp_ports(udp_usage, udp_service_ports)

    # ---------- Second pass: count packets that hit those "service-like" numeric ports ----------
    for packet in packets:
        extra_protocols_for_packet = set()

        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in significant_tcp_ports and dport not in tcp_service_ports:
                extra_protocols_for_packet.add(f"TCP/{dport}")

        if packet.haslayer(UDP):
            dport = packet[UDP].dport
            if dport in significant_udp_ports and dport not in udp_service_ports:
                extra_protocols_for_packet.add(f"UDP/{dport}")

        for p_name in extra_protocols_for_packet:
            protocol_counts[p_name] = protocol_counts.get(p_name, 0) + 1

    return {
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "unique_hosts": sorted(unique_hosts),
        "connections": sorted(list(connections)),
    }

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading pcap: {e}")
        sys.exit(1)

    results = analyze_packets(packets)

    # you can swap this with JSON / UI / API later
    print("\n--- Packet Statistics Summary ---")
    print(f"Total packets: {results['total_packets']}")

    print("\n--- Protocol Statistics ---")
    for proto, count in sorted(results["protocol_counts"].items()):
        print(f"  {proto}: {count}")

    print("\n--- Connection Information ---")
    print("Unique Hosts:")
    if not results["unique_hosts"]:
        print("  No hosts found based on IP/IPv6 layers.")
    else:
        for host in results["unique_hosts"]:
            print(f"  {host}")

    print("\nHost Connection Relationships:")
    if not results["connections"]:
        print("  No IP-based connection relationships found.")
    else:
        for a, b in results["connections"]:
            print(f"  {a} <-> {b}")


if __name__ == "__main__":
    main()
