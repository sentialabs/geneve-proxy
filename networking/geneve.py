"""Geneve module."""

from struct import unpack

class GeneveTunnelOptions:
    """
    Class for Geneve tunnel options.

    Its structure is as follows:

    |0 1 2 3 4 5 6 7 8|9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Option Class         |      Type     |R|R|R| Length  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                  Variable-Length Option Data                  ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(
        self,
        option_class: int,
        option_type: int,
        reserved: int,
        length: int,
        data: bytes,
    ) -> None:
        """Initialize new Geneve Tunnel Options."""
        self.option_class = option_class
        self.option_type = option_type
        self.reserved = reserved
        self.length = length
        self.data = data

    def __repr__(self):
        """Generate a string representation for this Geneve tunnel option."""
        return (
            f'Geneve tunnel option with {self.length} words of data. '
            f'Option Class: {self.option_class:#06x}, '
            f'Option Type: {self.option_type:#06x}, '
            f'Data: {self.data}.'
        )

class GeneveHeader:
    """
    Class for a Geneve header.

    Its structure is as follows:

    |1 2 3 4 5 6 7 8|9 0 1 2 3 4 5 6|7 8 9 0 1 2 3 4|5 6 7 8 9 0 1 2|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Virtual Network Identifier (VNI)       |    Reserved   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                    Variable-Length Options                    ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, header_bytes: bytes) -> None:
        """Initialize a Geneve header."""
        # Unpack the first 8 bytes (64 bits) of the geneve header into
        # two bytes (2x 8 bit), one short (1x 16 bit) and one long (1x 32 bit)
        geneve_header = unpack('!BBHL', header_bytes[:8])

        self.version = geneve_header[0] >> 6 # first two bits
        if self.version != 0:
            raise ValueError(f'Incorrect version: {self.version}')

        self.opt_len = geneve_header[0] & 0x3F # next six bits

        # The total length in bytes is 2 * 4 bytes (static header)
        # plus self.opt_len * 4 (TLV fields)
        self.length_bytes = 2 * 4 + self.opt_len * 4

        self.control_packet = bool(geneve_header[1] >> 7)
        self.critical_options = bool(geneve_header[1] >> 6)
        self.reserved_1 = geneve_header[1] & 0x3F

        self.protocol_type = geneve_header[2]
        self.vni = geneve_header[3] >> 8

        self.reserved_2 = geneve_header[3] & 0xFF

        self.tunnel_options = []
        self.parse_tunnel_options(self.opt_len, header_bytes)

    def parse_tunnel_options(self, opt_len: int, header_bytes: bytes) -> None:
        """Parse the tunnel options in the Geneve header."""
        # Drop the static header fields (the first two words)
        header_bytes = header_bytes[8:]

        parsed_length = 0

        # Loop over the options until the amount of words processed matches
        # the length set in opt_len.
        while parsed_length != opt_len:
            # Unpack the first word (static header for this option)
            first_word = unpack('!HBB', header_bytes[:4])

            option_class = first_word[0]
            option_type = first_word[1]
            reserved = first_word[2] >> 5
            length = first_word[2] & 0x1f # in words (4 bytes)

            tunnel_options_length = (1 + length) # 1 word for the header + data length
            parsed_length += tunnel_options_length

            header_bytes = header_bytes[4:] # drop the 4 header bytes
            data = header_bytes[:length * 4]
            header_bytes = header_bytes[length * 4:] # drop the data bytes

            self.tunnel_options.append(GeneveTunnelOptions(
                option_class=option_class,
                option_type=option_type,
                reserved=reserved,
                length=length,
                data=data
            ))

    def get_tunnel_option(self, option_class, option_type):
        """Retrieve tunnel option by class and type."""
        for option in self.tunnel_options:
            if (
                option.option_class == option_class and
                option.option_type == option_type
            ):
                return option
        return None

    def __repr__(self):
        """Generate a string representation for this Geneve header."""
        return (
            f'Geneve header with {self.opt_len} words of options and a '
            f'total length of {self.length_bytes} bytes. Version: {self.version}, '
            f'Control Packet: {self.control_packet}, Critical Options: {self.critical_options}, '
            f'Protocol Type: {self.protocol_type:#06x}, VNI: {self.vni}.'
        )
