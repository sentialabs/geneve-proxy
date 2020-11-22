"""IPv4 module."""

import ipaddress
from struct import unpack, pack_into

class Ipv4Header:
    """
    Class for a IPv4 header.

    Its structure is as follows:

    |1 2 3 4 5 6 7 8|9 0 1 2 3 4 5 6|7 8 9 0 1 2 3 4|5 6 7 8 9 0 1 2|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |    DSCP   |ECN|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, header_bytes: bytes) -> None:
        """Initialize an IPv4 header."""
        ipv4_header_first_word = unpack('!BBH', header_bytes[:4])
        ipv4_header_second_word = unpack('!HH', header_bytes[4:8])
        ipv4_header_third_word = unpack('!BBH', header_bytes[8:12])

        self.version = ipv4_header_first_word[0] >> 4
        if self.version != 4: # IPv4
            raise ValueError(f'Incorrect protocol version: {self.version}')

        self.ihl = ipv4_header_first_word[0] & 0xF
        self.dscp = ipv4_header_first_word[1] >> 2
        self.ecn = ipv4_header_first_word[1] & 0x3
        self.total_length = ipv4_header_first_word[2]

        self.identification = ipv4_header_second_word[0]
        self.flags = ipv4_header_second_word[1] >> 13
        self.fragment_offset = ipv4_header_second_word[1] & 0x1FFF

        self.ttl = ipv4_header_third_word[0]
        self.protocol = ipv4_header_third_word[1]
        self.header_checksum = ipv4_header_third_word[2]

        self.source_ip = header_bytes[12:16]
        self.destination_ip = header_bytes[16:20]

        self.options = None
        option_word_count = self.ihl - 5
        if option_word_count:
            self.options = header_bytes[20:(20 + option_word_count * 4)]

    def swap_source_dest(self):
        """Store the source IP in the destination field and vice versa."""
        tmp = self.source_ip
        self.source_ip = self.destination_ip
        self.destination_ip = tmp

    def update_checksum(self) -> None:
        """Update the checksum field with a newly calculated checksum."""
        self.header_checksum = self.calculate_checksum()

    def calculate_checksum(self) -> bytes:
        """Calculate the checksum for this header."""
        header_bytes = self.as_bytes(zero_checksum=True)
        return self.calculate_checksum_for_bytes(header_bytes)

    def as_bytes(self, zero_checksum=False) -> bytes:
        """Return the byte representation of this IPv4 header."""
        byte_array = bytearray(self.ihl * 4)
        pack_into( '!BBH', byte_array, 0,
            (self.version << 4) + self.ihl,
            (self.dscp << 2) + self.ecn,
            self.total_length
        )
        pack_into('!HH', byte_array, 4,
            self.identification,
            self.flags << 13 + self.fragment_offset
        )
        pack_into('!BBH', byte_array, 8,
            self.ttl,
            self.protocol,
            0 if zero_checksum else self.header_checksum
        )
        byte_array[12:16] = self.source_ip
        byte_array[16:20] = self.destination_ip

        if self.options:
            byte_array.append(self.options)

        return byte_array

    def __repr__(self):
        """Generate a string representation for this IPv4 header."""
        human_source_ip = ipaddress.IPv4Address(self.source_ip)
        human_destination_ip = ipaddress.IPv4Address(self.destination_ip)
        return (
            f'IPv4 header with a header size of {self.ihl * 4} and a total length of '
            f'{self.total_length} bytes. Version: {self.version}, Flags: {self.flags:b}, '
            f'TTL: {self.ttl}, Protocol: {self.protocol:#06x}. Source IP: {human_source_ip}, '
            f'Destination IP: {human_destination_ip}, Checksum: {self.header_checksum:#06x}.'
        )

    @classmethod
    def verify_checksum(cls, header_bytes):
        """Verify the IPv4 checksum for the provided header."""
        return cls.calculate_checksum_for_bytes(header_bytes) == 0

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
