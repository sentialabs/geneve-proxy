"""TCP module."""

from struct import unpack

class TcpHeader:
    """
    Class for a TCP header.

    Its structure is as follows:

    |1 2 3 4 5 6 7 8|9 0 1 2 3 4 5 6|7 8 9 0 1 2 3 4|5 6 7 8 9 0 1 2|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, header_bytes: bytes) -> None:
        """Initialize a TCP header."""
        tcp_header_first_word = unpack('!HH', header_bytes[:4])
        self.source_port = tcp_header_first_word[0]
        self.destination_port = tcp_header_first_word[1]

        self.sequence_number = header_bytes[4:8]
        self.acknowledgement_number = header_bytes[8:12]

        tcp_header_fourth_word = unpack('!HH', header_bytes[12:16])
        self.data_offset = tcp_header_fourth_word[0] >> 12
        self.reserved = (tcp_header_fourth_word[0] >> 9) & 0x7

        self.ns = bool(tcp_header_fourth_word[0] & 0x100) # pylint:disable=invalid-name
        self.cwr = bool(tcp_header_fourth_word[0] & 0x80)
        self.ece = bool(tcp_header_fourth_word[0] & 0x40)
        self.urg = bool(tcp_header_fourth_word[0] & 0x20)
        self.ack = bool(tcp_header_fourth_word[0] & 0x10)
        self.psh = bool(tcp_header_fourth_word[0] & 0x8)
        self.rst = bool(tcp_header_fourth_word[0] & 0x4)
        self.syn = bool(tcp_header_fourth_word[0] & 0x2)
        self.fin = bool(tcp_header_fourth_word[0] & 0x1)

        self.window = tcp_header_fourth_word[1]

        tcp_header_fifth_word = unpack('!HH', header_bytes[16:20])
        self.checksum = tcp_header_fifth_word[0]
        self.urgent_pointer = tcp_header_fifth_word[1]

        self.options = None
        option_word_count = self.data_offset - 5
        if option_word_count:
            self.options = header_bytes[20:(20 + option_word_count * 4)]

    def __repr__(self) -> str:
        """Generate a string representation for this IPv4 header."""
        return (
            f'TCP header with source port {self.source_port} and destination '
            f'port {self.destination_port}. Data Offset: {self.data_offset}, '
            f'Ack: {self.ack}, rst: {self.rst}, syn: {self.syn}, fin: {self.fin}'
        )
