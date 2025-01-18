import struct
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
MESSAGE_TYPE_PAYLOAD = 0x4
MAGIC_COOKIE = 0xabcddcba


class UDP_Packet:
    """
    A flexible class for handling multiple types of UDP packets (Offer, Request, Payload).
    """

    def __init__(self, message_type, magic_cookie, **kwargs):
        """
        Initialize a UDP Packet with common fields and type-specific fields.
        :param message_type: int - The type of the message (e.g., OFFER, REQUEST, PAYLOAD).
        :param magic_cookie: int - The magic cookie for protocol validation.
        :param kwargs: dict - Flexible dictionary for additional fields. Can be empty or contain multiple values,
            such as IP address, name, message content, etc.
        """
        self.message_type = message_type
        self.magic_cookie = magic_cookie
        self.fields = kwargs

    def encode(self):
        """
        Encodes the UDP packet into bytes based on its type.

        Explanation:
        - For Offer (0x2):
          Encodes the magic cookie, message type, server IP (32 bytes), server name (32 bytes), and server port.
          Format: '!IB32s32sH' where:
            - 'I': Unsigned 32-bit integer (magic cookie).
            - 'B': Unsigned 8-bit integer (message type).
            - '32s': 32-byte string for IP and server name, padded with b'\x00' (null byte) to ensure fixed size.
            - 'H': Unsigned 16-bit integer (server port).

        - For Request (0x3):
          Encodes the magic cookie, message type, and file size (in bits).
          Format: '!IBQ' where:
            - 'I': Magic cookie.
            - 'B': Message type.
            - 'Q': Unsigned 64-bit integer (file size).

        - For Payload (0x4):
          Encodes the magic cookie, message type, total segments, current segment, and payload data.
          Format: '!IBQQ' where:
            - 'I': Magic cookie.
            - 'B': Message type.
            - 'Q': Total segments (64-bit).
            - 'Q': Current segment (64-bit).
            - Remaining bytes contain the payload data.

        Notes:
        - Padding with b'\x00' ensures consistent fixed-length fields for IP and server name.
        - Each packet type ensures proper structure for reliable network transmission.
        - `fields.get`: Retrieves the value of a key from the dictionary `fields`. If the key doesn't exist, it returns the default value provided (e.g., `0` or `b''`). This ensures robustness when optional fields are absent.

        """
        if self.message_type == MESSAGE_TYPE_OFFER:  # Offer
            return struct.pack(
                '!IB32s32sH',
                self.magic_cookie,
                self.message_type,
                self.fields.get('server_ip', '').encode().ljust(32, b'\x00'),
                self.fields.get('server_name', '').encode().ljust(32, b'\x00'),
                self.fields.get('server_port', 0)
            )
        elif self.message_type == MESSAGE_TYPE_REQUEST:  # Request
            return struct.pack(
                '!IBQ',
                self.magic_cookie,
                self.message_type,
                self.fields.get('file_size', 0)
            )
        elif self.message_type == MESSAGE_TYPE_PAYLOAD:  # Payload
            return struct.pack(
                '!IBQQ',
                self.magic_cookie,
                self.message_type,
                self.fields.get('total_segments', 0),
                self.fields.get('current_segment', 0)
            ) + self.fields.get('payload_data', b'')

    @staticmethod
    def decode(data):
        """
        Decodes a UDP packet into a `UDP_Packet` object based on its type.

        :param data: bytes - The raw data of the UDP packet to decode.
        :return: UDP_Packet or None - A structured packet object if decoding is successful, or `None` if an error occurs.

        Explanation:
        - `!IB`: Decodes the `magic_cookie` (unsigned 32-bit integer) and `message_type` (unsigned 8-bit integer).
        - `!32s32sH`: Decodes the server IP (32-byte string), server name (32-byte string), and server port (unsigned 16-bit integer) for Offer packets.
        - `!Q`: Decodes the file size (unsigned 64-bit integer) for Request packets.
        - `!QQ`: Decodes total segments (unsigned 64-bit integer) and current segment (unsigned 64-bit integer) for Payload packets, followed by raw payload data.

        Note:
        - `.strip(`\x00`)`: Removes null-byte padding (`\x00`) used to fix string lengths, ensuring clean and readable strings.
        """

        try:
            magic_cookie, message_type = struct.unpack('!IB', data[:5])
            if magic_cookie != MAGIC_COOKIE:
                raise ValueError("Invalid Magic Cookie")

            if message_type == MESSAGE_TYPE_OFFER:  # Offer
                server_ip, server_name, server_port = struct.unpack('!32s32sH', data[5:71])
                return UDP_Packet(
                    message_type,
                    magic_cookie,
                    server_ip=server_ip.decode().strip('\x00'),
                    server_name=server_name.decode().strip('\x00'),
                    server_port=server_port
                )
            elif message_type == MESSAGE_TYPE_REQUEST:  # Request
                file_size = struct.unpack('!Q', data[5:13])[0]
                return UDP_Packet(
                    message_type,
                    magic_cookie,
                    file_size=file_size
                )
            elif message_type == MESSAGE_TYPE_PAYLOAD:  # Payload
                total_segments, current_segment = struct.unpack('!QQ', data[5:21])
                payload_data = data[21:]
                return UDP_Packet(
                    message_type,
                    magic_cookie,
                    total_segments=total_segments,
                    current_segment=current_segment,
                    payload_data=payload_data
                )
            else:
                raise ValueError("Unknown Message Type")
        except Exception:
            return None

    def __getattr__(self, item):
        """
        Allow accessing fields as attributes for convenience.
        """
        if item in self.fields:
            return self.fields[item]
        raise AttributeError(f"'UDP_Packet' object has no attribute '{item}'")
