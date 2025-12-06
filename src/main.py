import sys
import socket
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

def load_pcap(file_path):
    try:
        packets = rdpcap(file_path)
        print(f"Successfully loaded {len(packets)} packets from {file_path}")
        return packets
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    packets = load_pcap(file_path)

    if not packets:
        return

    print("\n--- Packet Statistics Summary ---")
    print(f"Total packets: {len(packets)}")

    print("\n--- Protocol Statistics ---")
    protocol_counts = {}

    for packet in packets:
        # Track unique protocols per packet so we don't double-count
        identified_protocols_for_packet = set()

        for layer_class in packet.layers():
            protocol_name = layer_class.__name__

            # Generic layer name (e.g., 'Ether', 'IP', 'TCP', 'UDP')
            identified_protocols_for_packet.add(protocol_name)

            # TCP handling
            if protocol_name == "TCP":
                tcp_layer = packet.getlayer(TCP)
                if tcp_layer:
                    port = tcp_layer.dport
                    service_name = None
                    try:
                        service_name = socket.getservbyport(port, "tcp")
                    except OSError:
                        # Port not known, just ignore
                        pass

                    if service_name:
                        identified_protocols_for_packet.add(f"TCP/{service_name.upper()}")
                    else:
                        identified_protocols_for_packet.add(f"TCP/{port}")

            # UDP handling
            elif protocol_name == "UDP":
                udp_layer = packet.getlayer(UDP)
                if udp_layer:
                    port = udp_layer.dport
                    service_name = None
                    try:
                        service_name = socket.getservbyport(port, "udp")
                    except OSError:
                        pass

                    if service_name:
                        identified_protocols_for_packet.add(f"UDP/{service_name.upper()}")
                    else:
                        identified_protocols_for_packet.add(f"UDP/{port}")

        # Update counts
        for p_name in identified_protocols_for_packet:
            protocol_counts[p_name] = protocol_counts.get(p_name, 0) + 1

    # Print protocol stats
    for protocol, count in sorted(protocol_counts.items()):
        print(f"  {protocol}: {count}")

    print("\n--- Connection Information ---")
    unique_hosts = set()
    connections = set()  # Store unique bidirectional connections (host1, host2)

    for packet in packets:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            unique_hosts.add(src_ip)
            unique_hosts.add(dst_ip)
            connections.add(tuple(sorted((src_ip, dst_ip))))

        elif packet.haslayer(IPv6):
            ip6_layer = packet[IPv6]
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
            unique_hosts.add(src_ip)
            unique_hosts.add(dst_ip)
            connections.add(tuple(sorted((src_ip, dst_ip))))

    print("Unique Hosts:")
    if not unique_hosts:
        print("  No hosts found based on IP/IPv6 layers.")
    else:
        for host in sorted(unique_hosts):
            print(f"  {host}")

    print("\nHost Connection Relationships:")
    if not connections:
        print("  No IP-based connection relationships found.")
    else:
        for conn in sorted(connections):
            print(f"  {conn[0]} <-> {conn[1]}")


if __name__ == "__main__":
    main()
