import socket
import time
import threading
from scapy.all import sniff
from scapy.layers.inet import UDP
from scapy.packet import Raw
from UDP_Packet import UDP_Packet

TEAM_NAME = "Lidor & Avi Team (Client)"
MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
MESSAGE_TYPE_PAYLOAD = 0x4
CHUNK_SIZE = 1024
SERVER_PORT = 64000
UDP_PAYLOAD_TIMEOUT = 1 #sec

## ANSI colors Codes :
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
PURPLE = "\033[35m"
CYAN = "\033[36m"
RESET = "\033[0m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_PURPLE = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"


class Client:
    def __init__(self,file_size,tcp_connections,udp_connections):
        """
            Initializes the Client object with necessary attributes.
        Attributes:
        - client_name: str - Identifies the client team.
        - server_ip: NoneType or str - Holds the IP address of the connected server, initially None.
        - server_port: NoneType or int - Holds the port number of the connected server, initially None.
        - running: bool - Indicates if the client is actively running, defaults to True.
        - file_size_in_bits: int - Stores the file size in bits for transfer calculations.
        - tcp_connections: int - Stores the configured number of TCP connections.
        - udp_connection: int - Stores the configured number of UDP connections.
        - previous_connected_servers: set - Tracks servers the client has already connected to.

        Why no UDP/TCP socket attributes:
        - The client creates sockets only when needed, unlike the server, which requires persistent sockets for listening and broadcasting.
              """
        self.client_name = TEAM_NAME
        self.server_ip = None
        self.server_port = None
        self.running = True
        self.file_size_in_bits = file_size
        self.tcp_connections = tcp_connections
        self.udp_connection = udp_connections
        self.previous_connected_servers = set()

    # def _receive_broadcast(self):
    #     """
    #     Listens for UDP broadcast messages from servers to receive connection offers.
    #
    #     Explanation:
    #     - `socket(socket.AF_INET, socket.SOCK_DGRAM)`:
    #       Creates a UDP socket using the IPv4 addressing scheme (`AF_INET`) and the UDP protocol (`SOCK_DGRAM`).
    #     - `setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)`:
    #       Configures the socket to allow broadcast messages by enabling the broadcast option.
    #     - `bind(('', SERVER_PORT))`:
    #       Binds the socket to the specified port (`SERVER_PORT`), allowing it to listen for messages on this port.
    #       The empty string (`''`) means it will listen on all available network interfaces.
    #
    #     Operation:
    #     - `recvfrom(CHUNK_SIZE)`:
    #       Waits in a blocking state until a UDP message is received. The received message is processed to extract server details.
    #     - Broadcast messages are decoded using the `UDP_Packet.decode` method to ensure they conform to the expected structure.
    #
    #     Behavior:
    #     - The method keeps listening until a valid offer (`MESSAGE_TYPE_OFFER`) is received from a server.
    #     - If the client has already connected to the server (checked using `previous_connected_servers`), it skips the offer.
    #     - Once a new server offer is accepted, the server details are stored for further connection.
    #
    #     Notes:
    #     - Once a new server offer is accepted, the server details are stored for further connection (Request).
    #     - After a valid server is found, the socket is explicitly closed because the purpose of this socket is limited to discovering servers via broadcast.
    #     - The subsequent `Request` operation involves creating a separate socket, ensuring clean handling of different stages of communication.
    #     - If the client has already connected to the server (checked using `previous_connected_servers`), it skips the offer.
    #
    #     """
    #     udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #     udp_socket.bind(('', SERVER_PORT))
    #
    #     print(f"{self.client_name} Started, listening for offer requests...")
    #
    #     while self.running:
    #         try:
    #             message, address = udp_socket.recvfrom(CHUNK_SIZE)
    #
    #             # דיקוד ההודעה באמצעות מחלקת UDP_Packet
    #             decoded_message = UDP_Packet.decode(message)
    #
    #             if decoded_message and decoded_message.message_type == MESSAGE_TYPE_OFFER and decoded_message.magic_cookie == MAGIC_COOKIE:  # Offer
    #                 self.server_ip = decoded_message.server_ip
    #                 self.server_port = decoded_message.server_port
    #                 server_name = decoded_message.server_name
    #                 server_identifier = (self.server_ip, self.server_port)
    #
    #                 # בדיקה אם כבר התחברנו לשרת הזה
    #                 if server_identifier in self.previous_connected_servers:
    #                     # print(
    #                     #     f"Already connected to server '{server_name}' at {self.server_ip}:{self.server_port}. Skipping...")
    #                     continue
    #
    #                 print(
    #                     f"Received offer from server '{server_name}' at IP {self.server_ip} and port {self.server_port}")
    #                 self.previous_connected_servers.add(server_identifier)  # הוספה לרשימת השרתים
    #                 break
    #         except Exception as e:
    #             print(f"Error receiving broadcast: {e}")
    #
    #     udp_socket.close()
    #     self._connect_to_server()

    def _receive_broadcast(self):
        """
        Listens for UDP broadcast messages using the `scapy` library's `sniff` function.

        Explanation:
        - `sniff`: A Scapy function that captures packets on the network.
            - Parameters:
                - `filter="udp"`: Captures only UDP packets.
                - `prn=process_packet`: Specifies a callback function (`process_packet`) that is executed for each captured packet.
                - `stop_filter=process_packet`: Determines whether to stop sniffing based on the result of `process_packet`.
                - `store=0`: Prevents storing captured packets in memory to save resources.
                - `quiet=True`: Suppresses Scapy's verbose output.
        - Behavior:
            - Each packet that matches the filter (`udp`) is passed to the `process_packet` function.
            - If `process_packet` returns `True`, the sniffing process stops, and the client moves to the next step.
            - If `process_packet` returns `False`, sniffing continues, and more packets are processed.

        Notes:
        - The `process_packet` function validates whether the packet is a valid UDP offer. If valid, it extracts the server details, stores them, and signals to stop the sniffing process.
        """

        print(f"\n{BOLD}{BRIGHT_GREEN}####################################################################################{RESET}")
        print(f"\t\t{BOLD}{BRIGHT_GREEN}{self.client_name} Started, listening for offer requests...{RESET}")
        print(f"{BOLD}{BRIGHT_GREEN}####################################################################################{RESET}")
        try:
            sniff(
                filter="udp",
                prn=lambda packet: None,
                stop_filter=lambda packet: self._process_packet_and_stop(packet),
                quiet=True,
                store=False
            )
            self._connect_to_server()
        except Exception as e:
            print(f"{BOLD}{RED}Error in broadcast reception: {e}{RESET}")

    def _process_packet_and_stop(self, packet):
        """
        Processes each captured UDP packet to determine if it is a valid server offer.

        Parameters:
        - `packet`: The packet object captured by Scapy's `sniff` function.

        Explanation:
        - Checks whether the packet contains UDP and Raw layers:
            - `if UDP in packet and Raw in packet`: Ensures the packet is a UDP message and contains raw data.
            - `bytes(packet[Raw])`: Extracts the raw payload from the packet and converts it to bytes for decoding.
        - Decodes the packet using the custom `UDP_Packet.decode` method.
            - Verifies the packet type (`MESSAGE_TYPE_OFFER`) and its magic cookie (`MAGIC_COOKIE`) for validity.
        - Behavior:
            - If the packet is valid:
                - Extracts server details (IP, port, and name).
                - Ensures the server is not already processed.
                - Prints server details and stops further sniffing by returning `True`.
            - If the packet is invalid:
                - Returns `False`, allowing the sniffing process to continue capturing more packets.

        Notes:
        - The `bytes(packet[Raw])` conversion ensures the raw payload is processed as a byte array, compatible with `UDP_Packet.decode`.
        - Returning `True` stops the sniffing process, while `False` keeps it running to capture more packets.
        """

        try:
            if UDP in packet and Raw in packet:
                message = bytes(packet[Raw])
                try:
                    decoded_message = UDP_Packet.decode(message)

                    if (decoded_message and
                            decoded_message.message_type == MESSAGE_TYPE_OFFER and
                            decoded_message.magic_cookie == MAGIC_COOKIE):

                        self.server_ip = decoded_message.server_ip
                        self.server_port = decoded_message.server_port
                        server_name = decoded_message.server_name
                        server_identifier = (self.server_ip, self.server_port)

                        if server_identifier not in self.previous_connected_servers:
                            print(
                                f"\n\n{BOLD}{BRIGHT_BLUE}Received offer from server '{server_name}' at IP {self.server_ip} and port {self.server_port}{RESET}\n\n")
                            self.previous_connected_servers.add(server_identifier)
                            return True
                except:
                    # Silent handling of decode errors
                    pass
        except Exception:
            # Silent exception handling
            pass
        return False


    def _connect_to_server(self):
        """
        Establishes connections to the server by creating threads for both TCP and UDP communications.

        Explanation:
        - For TCP:
          - Creates a thread for each TCP connection specified by `self.tcp_connections` (Input).
          - Each thread runs the `_send_tcp_message` method.
        - For UDP:
          - Creates a thread for each UDP connection specified by `self.udp_connection`(Input).
          - Each thread runs the `_send_udp_message` method.

        Operation:
        - Threads are stored in separate lists (`tcp_threads` and `udp_threads`) and started immediately.
        - The `join` method ensures the main program waits for all threads to finish before proceeding.
        """

        tcp_threads = []
        for thread_index in range(int(self.tcp_connections)):
            thread_TCP = threading.Thread(target=self._send_tcp_message,args=((thread_index+1),))
            tcp_threads.append(thread_TCP)
            thread_TCP.start()

        udp_threads = []
        for thread_index in range(int(self.udp_connection)):
            thread_UDP = threading.Thread(target=self._send_udp_message,args=((thread_index+1),))
            udp_threads.append(thread_UDP)
            thread_UDP.start()


        for thread in tcp_threads + udp_threads:
            thread.join()

    def _send_tcp_message(self, thread_index):
        """
        Sends a TCP message to the server, measures the transfer duration, and calculates transfer speed.

        Parameters:
        - thread_index (int): The index of the thread performing the transfer, used for logging.

        Explanation:
        - Establishes a TCP connection using `socket.create_connection`.
        - Sends the file size (in bits) to the server, encoded as a UTF-8 string ending with `\n` (default encoding).
        - Receives server responses in a loop (ignoring content but ensuring all data is read).
        - Measures elapsed time and calculates transfer speed in bits per second.
        - Prints transfer statistics, including thread index, total time, and speed.

        Notes:
        - The `with` block ensures automatic resource management: the TCP connection is closed once the block is exited, even in case of an exception.
        - Handles exceptions gracefully, logging errors if the transfer fails.
        """

        try:
            with socket.create_connection((self.server_ip, self.server_port)) as tcp_socket:
                start_time = time.time()  # Start timing
                tcp_socket.send(f"{self.file_size_in_bits}\n".encode())  # Send the file size

                # Receive the response (but we don't care about the content)
                while tcp_socket.recv(CHUNK_SIZE):
                    pass

                elapsed_time = time.time() - start_time  # Calculate elapsed time

                if elapsed_time > 0:
                    speed = self.file_size_in_bits / elapsed_time
                else:
                    speed = float('inf')  # Handle edge case where time is too small

                print(
                    f"\n\n{BOLD}{BRIGHT_PURPLE}###############################################################################\n"
                    f"\t\t\t\t\tTCP transfer #{thread_index} finished\n"
                    f"\t\t\t\t\tTotal time: {elapsed_time:.2f} seconds\n"
                    f"\t\t\t\t\tTotal speed: {speed:.2f} bits/sec\n"
                    f"###############################################################################\n\n{RESET}"
                )
        except Exception as e:
            print(f"\n\n{BOLD}{RED}TCP message failed for transfer #{thread_index}: {e}{RESET}")

    def _send_udp_message(self, thread_index):
        """
        Sends a UDP message to the server as a request and receives PAYLOAD responses.

        Parameters:
        - thread_index (int): The index of the thread performing the transfer, used for logging.

        Explanation:
        - Creates a UDP socket with appropriate buffer size and timeout
        - Sends initial request with desired file size
        - Receives and tracks payload segments from server
        - Updates progress in-place on single line
        - Shows final results when transfer completes

        Notes:
        - Uses \r to update the progress on the same line
        - Progress shows segments received vs total expected
        - Final summary printed on new line after completion
        """
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(UDP_PAYLOAD_TIMEOUT)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

            request_packet = UDP_Packet(
                message_type=MESSAGE_TYPE_REQUEST,
                magic_cookie=MAGIC_COOKIE,
                file_size=self.file_size_in_bits
            )

            udp_socket.sendto(request_packet.encode(), (self.server_ip, self.server_port))

            if (self.file_size_in_bits // CHUNK_SIZE) != (self.file_size_in_bits / CHUNK_SIZE):
                total_segments_expected = (self.file_size_in_bits // CHUNK_SIZE) + 1
            else:
                total_segments_expected = (self.file_size_in_bits / CHUNK_SIZE)
            total_segments_expected = int(total_segments_expected)

            start_time = time.time()
            total_received_bits = 0
            received_segments = set()
            last_packet_time = time.time()

            while time.time() - last_packet_time < UDP_PAYLOAD_TIMEOUT:
                try:
                    data, address = udp_socket.recvfrom(CHUNK_SIZE)
                    last_packet_time = time.time()

                    packet = UDP_Packet.decode(data)
                    if packet and packet.message_type == MESSAGE_TYPE_PAYLOAD:
                        if packet.current_segment not in received_segments:
                            payload_size_bits = len(packet.payload_data) * 8
                            total_received_bits += payload_size_bits
                            received_segments.add(packet.current_segment)

                            print(
                                f"\r{BOLD}{BRIGHT_YELLOW}Receiving from {self.server_ip}: Progress {len(received_segments)}/{total_segments_expected} segments{RESET}",
                                end="", flush=True)

                        if len(received_segments) == total_segments_expected:
                            print()  # מעבר שורה בסיום
                            break

                except socket.timeout:
                    break
                except Exception as e:
                    print(f"{BOLD}{RED}Error processing packet: {e}{RESET}")
                    continue

            elapsed_time = time.time() - start_time
            if elapsed_time > 0:
                success_rate = (total_received_bits / self.file_size_in_bits) * 100
                speed = total_received_bits / elapsed_time
            else:
                success_rate = 0
                speed = 0

            print(
                f"\n\n{BOLD}{BRIGHT_CYAN}###############################################################################\n"
                f"\t\t\t\t\tUDP transfer #{thread_index} finished\n"
                f"\t\t\t\t\tTotal time: {elapsed_time:.2f} seconds\n"
                f"\t\t\t\t\tTotal speed: {speed:.2f} bits/sec\n"
                f"\t\t\t\t\tPercentage Of Packets Received Successfully: {success_rate:.2f}%\n"
                f"###############################################################################\n\n{RESET}"
            )

            udp_socket.close()

        except Exception as e:
            print(f"{BOLD}{RED}UDP Thread {thread_index} failed: {e}{RESET}")


    def run(self):
        """
        Runs the client, listening for broadcasts and connecting to the server.
        """
        while True:
            try:
                self._receive_broadcast()
            except Exception as e:
                print(f"{BOLD}{RESET}Client {self.client_name} failed to receive : {e}{RESET}")
                print(f"{BOLD}{RESET}Disconnect Now{RESET}")







def parse_file_size(size_input: str) -> int:
    """
    Parses a file size input string and converts it to bits.

    :param size_input: str
        The file size input string (e.g., "5GB", "1024Kb", "2Gb").
    :return: int
        The equivalent file size in bits.
    :raises ValueError:
        If the input format is invalid or the unit is unsupported.
    """
    size_input = size_input.strip().replace(" ", "")  # Normalize input
    units_map = {
        "b": 1,              # bits
        "Kb": 2**10,         # kilobits
        "Mb": 2**20,         # megabits
        "Gb": 2**30,         # gigabits
        "Byte": 8,           # bytes
        "B": 8,
        "KB": 8 * 2**10,     # kilobytes
        "MB": 8 * 2**20,     # megabytes
        "GB": 8 * 2**30
    }

    # Extract numeric value and unit
    for i, char in enumerate(size_input):
        if not char.isdigit() and char != ".":
            break
    else:
        i = len(size_input)  # Handle pure numeric input

    try:
        number_part = float(size_input[:i])  # Allow decimal values
    except ValueError:
        raise ValueError(f"{BOLD}{RED}Invalid numeric value in file size: {size_input}{RESET}")

    unit_part = size_input[i:]          # Unit

    # Default to bits if no unit is specified
    if not unit_part:
        unit_part = "b"

    # Convert to bits using the units map
    if unit_part in units_map:
        return round(number_part * units_map[unit_part])  # Use round to properly handle decimal bits
    else:
        raise ValueError(f"{BOLD}{RED}Unsupported unit: {unit_part}{RESET}")


if __name__ == "__main__":
    while True:
        try:
            file_size = input(f"{BOLD}{BRIGHT_YELLOW}Please enter the File Size.\nSupported units are: b, Kb, Mb, Gb, B, KB, MB, GB.\nEnter your answer here - {RESET}")
            size_in_bits = parse_file_size(file_size)
            print(f"\n{BOLD}{BRIGHT_YELLOW}File size in bits: {size_in_bits}{RESET}")
            break
        except Exception as e:
            print(f"{BOLD}{RED}Invalid input: {e}.\n{BOLD}{RED}Please try again.{RESET}\n")

    while True:
        try:
            tcp_connections = int(input(f"\n{BOLD}{BRIGHT_PURPLE}Please enter the amount of TCP Connections - {RESET}"))
            if tcp_connections < 0:
                raise ValueError(f"{BOLD}{RED}Connections must be a non-negative integer.{RESET}")
            break
        except Exception:
            print(f"{BOLD}{RED}Invalid input for TCP Connections. Please enter a positive integer.{RESET}")

    while True:
        try:
            udp_connections = int(input(f"\n{BOLD}{BRIGHT_CYAN}Please enter the amount of UDP Connections - {RESET}"))
            if udp_connections < 0:
                raise ValueError(f"{BOLD}{RED}Connections must be a non-negative integer.{RESET}")
            break
        except Exception:
            print(f"{BOLD}{RED}Invalid input for UDP Connections. Please enter a positive integer.{RESET}")

    client = Client(file_size=size_in_bits, tcp_connections=tcp_connections, udp_connections=udp_connections)
    client.run()
