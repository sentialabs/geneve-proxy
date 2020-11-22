"""UDP module."""

from struct import unpack, pack_into

class UdpHeader:
    """
    Class for a UDP header.

    Its structure is as follows:

    |1 2 3 4 5 6 7 8|9 0 1 2 3 4 5 6|7 8 9 0 1 2 3 4|5 6 7 8 9 0 1 2|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, header_bytes: bytes) -> None:
        """Initialize a UDP header."""
        udp_header_first_word = unpack('!HH', header_bytes[:4])
        self.source_port = udp_header_first_word[0]
        self.destination_port = udp_header_first_word[1]

        udp_header_second_word = unpack('!HH', header_bytes[4:8])
        self.length = udp_header_second_word[0]
        self.checksum = udp_header_second_word[1]

    def swap_source_dest(self):
        """Store the source port in the destination field and vice versa."""
        tmp = self.source_port
        self.source_port = self.destination_port
        self.destination_port = tmp

    def as_bytes(self, zero_checksum=False) -> bytes:
        """Return the byte representation of this IPv4 header."""
        byte_array = bytearray(2 * 4)
        pack_into('!HH', byte_array, 0,
            self.source_port,
            self.destination_port
        )
        pack_into('!HH', byte_array, 4,
            self.length,
            0 if zero_checksum else self.checksum
        )
        return byte_array

    def __repr__(self):
        """Generate a string representation for this IPv4 header."""
        return (
            f'UDP header with source port {self.source_port} and destination '
            f'port {self.destination_port}. Length: {self.length}, '
            f'Checksum: {self.checksum:#06x}.'
        )

    @classmethod
    def calculate_checksum_for_bytes(cls, header_bytes):
        """Calculate the checksum for the provided header."""
         # pylint:disable=invalid-name
        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        s = 0
        for i in range(0, len(header_bytes), 2):
            w = header_bytes[i+1] + (header_bytes[i] << 8)
            s = carry_around_add(s, w)
        return ~s & 0xffff
        # pylint:enable=invalid-name
