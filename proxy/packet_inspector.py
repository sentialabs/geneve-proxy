"""PacketInspector module."""

import ipaddress

from networking.tcp import TcpHeader
from networking.udp import UdpHeader
from networking.ipv4 import Ipv4Header
from .proxy_config import ProxyConfig
from .flow_stack import Flow, FlowStack

class PacketInspector:
    """PacketInspector class."""

    def __init__(self) -> None:
        """Construct a new PacketInspector."""
        self._config = ProxyConfig()

    def assess_packet(self, flow_stack: FlowStack, flow: Flow, data: bytes) -> bool:
        """Assess whether a packet should be allowed."""
        inner_ipv4_header = self._assess_internet_layer(flow_stack, flow, data)
        if inner_ipv4_header is False:
            return False

        # Pop the inner ipv4 header from the packet
        data = data[inner_ipv4_header.ihl * 4:]

        return self._assess_transport_layer(flow_stack, flow, data, inner_ipv4_header)

    def _assess_internet_layer(self, flow_stack: FlowStack, flow: Flow, data: bytes) -> bool:
        """Assess the internet layer (IPv4)."""
        inner_ipv4_header = Ipv4Header(data)
        source_address = ipaddress.IPv4Address(inner_ipv4_header.source_ip)

        flow_cookie = flow.cookie

        if flow is None or flow.direction_allowed is None:
            direction = Flow.DIR_OUTBOUND if source_address.is_private else Flow.DIR_INBOUND

            if direction == Flow.DIR_OUTBOUND and self._config.outbound.get('drop_all_traffic'):
                print('Flow dropped because all outbound traffic is blocked')
                flow_stack.set_flow(flow_cookie, direction_allowed=False) # block this flow
                return False
            if direction == Flow.DIR_INBOUND and self._config.inbound.get('drop_all_traffic'):
                print('Flow dropped because all inbound traffic is blocked')
                flow_stack.set_flow(flow_cookie, direction_allowed=False) # block this flow
                return False

            flow = flow_stack.set_flow( # allow the direction of this flow
                flow_cookie,
                direction_allowed=True,
                direction=direction
            )

        if flow.direction == Flow.DIR_OUTBOUND:
            directional_config = self._config.outbound
        else:
            directional_config = self._config.inbound

        allowed_transport_protocols = directional_config.get('allowed_transport_protocols')
        blocked_transport_protocols = directional_config.get('blocked_transport_protocols')

        inner_ipv4_protocol = inner_ipv4_header.protocol
        if flow.transport_allowed is None:
            # If the transport protocol for this flow has not been determined yet
            if allowed_transport_protocols is not None:
                # An explicit allow_list has been set, validate this packet's
                # protocol is present in the list.
                if inner_ipv4_protocol not in allowed_transport_protocols:
                    print(
                        f'Dropped {flow.dir_string()} flow because protocol {inner_ipv4_protocol} '
                        'is not in the allow list'
                    )
                    flow_stack.set_flow(flow_cookie, transport_allowed=False) # block this flow
                    return False

            if blocked_transport_protocols is not None:
                if inner_ipv4_protocol in blocked_transport_protocols:
                    print(
                        f'Dropped {flow.dir_string()} flow because protocol {inner_ipv4_protocol} '
                        'is in the block list'
                    )
                    flow_stack.set_flow(flow_cookie, transport_allowed=False) # block this flow
                    return False

            flow = flow_stack.set_flow( # allow the transport protocol of this flow
                flow_cookie,
                transport_allowed=True
            )
            if inner_ipv4_protocol == 0x0001: # ICMP
                # Ping (ICMP), has no application layer,
                # so allow the 'application'.
                flow = flow_stack.set_flow(
                    flow_cookie,
                    application_allowed=True
                )

        return inner_ipv4_header

    def _assess_transport_layer(
        self,
        flow_stack: FlowStack,
        flow: Flow,
        data: bytes,
        inner_ipv4_header: Ipv4Header
    ) -> bool:
        """Assess the transport layer (TCP or UDP)."""
        if flow.application_allowed is True:
            return True

        # Get the transport header (TCP or UDP)
        if inner_ipv4_header.protocol == 0x0006: # TCP
            transport_header = TcpHeader(data)
        elif inner_ipv4_header.protocol == 0x0011: # UDP
            transport_header = UdpHeader(data)

        if flow.direction == Flow.DIR_OUTBOUND:
            directional_config = self._config.outbound
        else:
            directional_config = self._config.inbound

        allowed_application_ports = directional_config.get('allowed_application_ports')
        blocked_application_ports = directional_config.get('blocked_application_ports')

        dest_port = transport_header.destination_port
        if allowed_application_ports is not None:
            # An explicit allow_list has been set, validate this packet's
            # destination port is present in the list.
            if dest_port not in allowed_application_ports:
                print(
                    f'Dropped {flow.dir_string()} flow '
                    f'because port {dest_port} is not in the allow list'
                )
                flow_stack.set_flow(flow.cookie, application_allowed=False) # block this flow
                return False

        if blocked_application_ports is not None:
            if dest_port in blocked_application_ports:
                print(
                    f'Dropped {flow.dir_string()} flow '
                    f'because port {dest_port} is in the block list'
                )
                flow_stack.set_flow(flow.cookie, application_allowed=False) # block this flow
                return False

        flow = flow_stack.set_flow( # allow the transport protocol of this flow
            flow.cookie,
            application_allowed=True
        )

        return True
