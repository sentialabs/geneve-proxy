"""Main module."""

import select
import socket

import networking
from networking.geneve import GeneveHeader
from networking.ipv4 import Ipv4Header
from networking.udp import UdpHeader

from proxy.flow_stack import FlowStack
from proxy.packet_inspector import PacketInspector

UDP_IP = '0.0.0.0'
UDP_PORT = 6081
HEALTHCHECK_PORT = 80
IP_RECVERR = 11

def main():
    """Run main loop. Listens for new connections."""
    geneve_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_UDP
    )

    # Create a bind socket to let the outside world know
    # we're listening on `UDP_PORT`. Packets received on this
    # socket will be ignored.
    bind_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_sock.bind((UDP_IP, UDP_PORT))

    health_check_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    health_check_socket.bind((UDP_IP, HEALTHCHECK_PORT))
    health_check_socket.listen(100)

    # Create a raw socket to process the incoming packets,
    # including their IP headers.
    geneve_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    geneve_sock.bind((UDP_IP, UDP_PORT))

    flow_stack = FlowStack()
    packet_inspector = PacketInspector()

    print('Listening')
    while True:
        read_sockets, _, _ = select.select(
            [geneve_sock, bind_sock, health_check_socket], [], []
        )
        for selected_sock in read_sockets:
            if selected_sock == geneve_sock:
                data, addr = selected_sock.recvfrom(65565)
                # Only process messages on the geneve_sock.
                response = parse_udp_packet(data, flow_stack, packet_inspector)

                # If `response` is None the packet should be dropped.
                # If the reponse is not None, it should be returned to the GWLB.
                if response:
                    selected_sock.sendto(response, addr)
            if selected_sock == health_check_socket:
                conn, _ = selected_sock.accept()
                conn.recv(65565)
                conn.send(hc_response().encode('utf-8'))

def hc_response():
    """Generate a health check response."""
    response = 'HTTP/1.1 200 OK\n'
    response_body = 'Healthy'

    response_headers = {
        'Content-Type': 'text/html; encoding=utf8',
        'Content-Length': len(response_body),
        'Connection': 'close',
    }

    response += ''.join(f'{k}: {v}\n' for k, v in response_headers.items())
    response += f'\n{response_body}'
    return response


def parse_udp_packet(data, flow_stack, packet_inspector):
    """Read the data from the provided UDP packet."""
    # Outer IPv4 header
    outer_ipv4_header = Ipv4Header(data)
    if outer_ipv4_header.protocol != socket.IPPROTO_UDP:
        return None

    # Swap source and destination for response
    outer_ipv4_header.swap_source_dest()
    outer_ipv4_header.ttl -= 1
    outer_ipv4_header.update_checksum()

    # Pop the ipv4 header from the packet
    data = data[outer_ipv4_header.ihl * 4:]

    # Fetch the UDP header
    udp_header = UdpHeader(data)

    if udp_header.destination_port != UDP_PORT:
        # Only process port 6081 packets
        return None

    # Pop the udp header from the packet
    original_udp_header_bytes = data[:2 * 4] # UDP Header is always 8 bytes
    data = data[2 * 4:]

    geneve_header = GeneveHeader(data)

    # Pop the geneve header from the packet
    original_geneve_header_bytes = data[:geneve_header.length_bytes]
    data = data[geneve_header.length_bytes:]

    if geneve_header.protocol_type != networking.IPPROTO_IPV4:
        # Only IPv4 is supported
        return None

    # Prepare the reponse packet to return to the GWLB.
    response_packet = b''.join([
        outer_ipv4_header.as_bytes(),
        original_udp_header_bytes,
        original_geneve_header_bytes,
        data
    ])

    flow_cookie_tlv = geneve_header.get_tunnel_option(option_class=0x0108, option_type=3)
    if flow_cookie_tlv is None:
        raise ValueError('Flow Cookie TLV not found')

    flow_cookie = flow_cookie_tlv.data
    flow = flow_stack.get_flow(flow_cookie)

    if flow is None:
        flow = flow_stack.set_flow(flow_cookie)
        # New flow
    elif flow.is_allowed() is False:
        # This flow was rejected in the past,
        # no need to inspect it again.
        return None
    elif flow.is_allowed() is True:
        # This flow was previously allowed,
        # allow it through.
        return response_packet

    # At this point, `inner_packet` contains the contents of the inner IPv4 packet,
    # including the IPv4 header.
    inner_packet = data

    packet_allowed = packet_inspector.assess_packet(flow_stack, flow, inner_packet)
    if packet_allowed:
        return response_packet

    # Drop the packet
    return None

if __name__ == '__main__':
    main()
