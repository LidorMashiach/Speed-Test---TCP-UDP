import socket
import threading
import time
import atexit

from UDP_Packet import UDP_Packet

#Imports for the second get_ip_address() function
#import subprocess
#import re


# Settings - Global Parameters
SERVER_NAME = "Lidor & Avi Team (Server)"
MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
MESSAGE_TYPE_PAYLOAD = 0x4
SERVER_PORT = 64000
BROADCAST_INTERVAL = 1  # seconds
CHUNK_SIZE = 1024  # Size of each segment in bytes

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



def get_ip_address() -> str:
    """
    Gets the IP address of the server using socket.gethostbyname.
    :return: The IP address of the server.

    Explanation:
    - socket.gethostbyname(socket.gethostname()):
        Resolves the local hostname to its corresponding IP address.
    - ip_address.startswith("127."):
        This check is necessary because an IP address starting with "127." indicates a loopback address.
        Loopback addresses are used for internal communication within the same machine.
        This can happen if `socket.gethostbyname(socket.gethostname())` fails to resolve a valid external IP address,
        and returns the loopback address as a default.
    - Lookup:
        The process of resolving a hostname (like "localhost") to an IP address (like "127.0.0.1").
    """
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        if ip_address.startswith("127."):
            raise Exception(
                f"The hostname resolved to a loopback address. Ensure the network is configured correctly.")
        print(f"{BOLD}{RED}The server IP was found automatically: {ip_address}{RESET}")
        return ip_address
    except Exception as e:
        print(f"{BOLD}{RED}Failed to determine IP address automatically. Error: {e}{RESET}")
        ip_address = input(f'{BOLD}{BRIGHT_YELLOW}Enter the server IP address manually: {RESET}')
        return ip_address
#
# def get_ip_address() -> str:
#     """
#     Tries to get the IP address of the server automatically using ipconfig.
#     :return: The IP address of the server.
#
#     Explanation:
#     - This function is more dynamic compared to socket.gethostbyname(socket.gethostname()),
#       as it directly retrieves all IP addresses from the system using the `ipconfig` command.
#     - It filters the IP addresses to ensure they belong to private ranges:
#         - "192.168.x.x": Common in home and office LANs.
#         - "10.x.x.x": Used by large organizations or VPNs.
#         - "172.16.x.x - 172.31.x.x": Used in larger internal networks.
#     - This function is especially useful in dynamic environments with multiple networks.
#
#     Why we currently don't use this:
#     - The simpler method (socket.gethostbyname) is sufficient for a static environment like yours.
#     - This function adds complexity that isn't necessary unless the network environment changes frequently.
#     """
#     try:
#         # Executes the ipconfig command to get network details.
#         ipconfig_output = subprocess.check_output(
#             "ipconfig", shell=True, universal_newlines=True, errors='ignore'
#         )
#
#         # Extracts all IPv4 addresses using regex.
#         ip_addresses = re.findall(r"IPv4 Address[. ]+: ([\d.]+)", ipconfig_output)
#         valid_ips = []
#
#         for ip_address in ip_addresses:
#             # Filters IP addresses based on private network ranges.
#             if ip_address.startswith("192.168"):
#                 # 192.168.x.x: Common in home and office LANs.
#                 valid_ips.append(ip_address)
#             elif ip_address.startswith("10."):
#                 # 10.x.x.x: Used by large organizations or VPNs.
#                 valid_ips.append(ip_address)
#             elif ip_address.startswith("172."):
#                 # 172.16.x.x - 172.31.x.x: Used in larger internal networks.
#                 valid_ips.append(ip_address)
#
#         if len(valid_ips) == 1:
#             print(f"The server IP was found automatically: {valid_ips[0]}")
#             return valid_ips[0]
#         elif len(valid_ips) > 1:
#             print('Found multiple IP addresses:')
#             for i, ip in enumerate(valid_ips):
#                 print(f'{i + 1}. {ip}')
#             choice = input('Enter the number of the IP address to use: ')
#             return valid_ips[int(choice) - 1]
#         else:
#             raise Exception("Could not find a valid IP address in the expected ranges.")
#
#     except Exception as e:
#         print(f"Failed to get IP address automatically. Error: {e}")
#         ip_address = input('Enter the server IP address manually: ')
#         return ip_address




class Server:
    def __init__(self, ip):
        """
        Initializes the Server object with the given IP address and sets up necessary sockets.

        :param ip: str
            The valid server IP address returned by get_ip_address function.

        Explanation:
        - udp_socket: A UDP socket configured for broadcasting messages across the network (Type = Offer, Broadcast).
        - tcp_socket: A TCP socket used for reliable, connection-based communication with clients (Type = Payload).
        - clients: A list to track connected clients dynamically.
        - running: A flag to indicate if the server is operational, initialized to True.
        - atexit.register(self.cleanup): Ensures proper cleanup of resources like sockets when the program exits.
        """
        self.ip = ip
        self.name = SERVER_NAME
        self.port = SERVER_PORT
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.running = True


        atexit.register(self.cleanup)

    def _start_broadcast(self):
        """
        Private method to continuously broadcast an Offer message to the network.

        Purpose:
        - Sends a broadcast message at regular intervals (defined by BROADCAST_INTERVAL) to notify clients about the server's presence.
        - The broadcast message is of type Offer.

        Explanation:
        - broadcast_address = ('<broadcast>', self.port):
            Specifies the broadcast target address and port.
            The message will be received only by devices on the network that are actively listening to the specified port.
        - self.udp_socket.sendto(broadcast_message, broadcast_address):
            Sends the encoded broadcast message using UDP to devices listening on the given port.

        Additional Notes:
        - Messages are sent every BROADCAST_INTERVAL seconds as long as the server is running.
        - The method uses the UDP socket to transmit the broadcast message, as there is no direct connection between the client and the server at this stage.
        """
        broadcast_packet = UDP_Packet(
            message_type=MESSAGE_TYPE_OFFER,  # Offer
            magic_cookie=MAGIC_COOKIE,
            server_ip=self.ip,
            server_name=self.name,
            server_port=self.port
        )
        broadcast_message = broadcast_packet.encode()
        broadcast_address = ('<broadcast>', self.port)
        print(f"{BOLD}{BRIGHT_GREEN}Server Started, Listening on IP Address: {self.ip}{RESET}")
        while self.running:
            try:
                self.udp_socket.sendto(broadcast_message, broadcast_address)
                time.sleep(BROADCAST_INTERVAL)
            except Exception as e:
                print(f"\n{BOLD}{RED}Failed to send broadcast message: {e}{RESET}")



    def _searching_after_TCP_Request(self):
        """
        Listens for incoming TCP requests from clients, accepts them, and spawns a thread to handle each connection.

        Explanation:
        - `bind`: Binds the TCP socket to a specific IP address (`self.ip`) and port (`self.port`).
        - `listen`: Prepares the socket to listen for incoming TCP connection requests.
                    By default, without a parameter, the OS determines the maximum number of pending connections in the queue.
        - `accept`: Blocks execution until a client connects to the socket.
                    Returns a new socket (`client_socket`) for communication with the client and the client's address (`client_address`).

        Notes:
        - Each accepted connection is passed to a new thread targeting `_handle_TCP`, allowing the server to handle multiple clients concurrently without blocking further incoming connections.
        """

        self.tcp_socket.bind((self.ip, self.port))
        self.tcp_socket.listen()

        while self.running:
            try:
                client_socket, client_address = self.tcp_socket.accept()
                print(f"\n\n{BOLD}{BRIGHT_PURPLE}TCP connection received from {client_address}{RESET}")
                threading.Thread(target=self._handle_TCP, args=(client_socket,client_address,)).start()
            except Exception as e:
                print(f"\n\n{BOLD}{RED}Error accepting TCP connection: {e}{RESET}")

    def _handle_TCP(self, client_socket,client_address):
        """
        Handles a TCP connection from a client, receives the file size request, and sends data back in chunks.

        Explanation:
        - `client_socket.recv(CHUNK_SIZE)`:
            - Receives data from the client with a maximum size defined by `CHUNK_SIZE`.
            - This size limits the buffer(Waiting Queue) for incoming data, ensuring memory efficiency and preventing oversized packets.
            - The operation blocks temporarily, pausing the thread until data is received.

        - `.decode()`:
            - Decodes the received bytes into a string using Python's default UTF-8 encoding.

        - `.endswith('\n')`:
            - Validates that the received data ends with `\n` to ensure it's correctly formatted, as expected from the client.

        - `.strip()`:
            - Removes whitespace characters (including `\n`) from the beginning and end of the string.
            - This ensures clean parsing of the file size value from the received string.

        - `remaining_bits` and `bytes_to_send`:
            - `remaining_bits`: Calculates the number of bits yet to be sent by subtracting the total bits already sent (`total_sent`) from the requested file size.
            - `bytes_to_send`: Determines the number of bytes to send in the next iteration, ensuring the data size does not exceed `CHUNK_SIZE`.

        Notes:
        - The division (`remaining_bits // 8`) converts bits to bytes
        - The multiplication (`total_sent * 8`) converts bytes back to bits for accurate tracking of sent data.
        - The use of `min(CHUNK_SIZE, remaining_bits // 8)` ensures that the server does not send more data than requested or exceed the allowed chunk size.

        """

        try:
            data = client_socket.recv(CHUNK_SIZE).decode()

            if not data.endswith('\n'):
                raise ValueError("Invalid TCP message format. Expected '\\n' at the end.")
            file_size_in_bits = int(data.strip())


            message = "A" * CHUNK_SIZE  # הודעה בגודל CHUNK_SIZE

            total_sent = 0
            while total_sent < file_size_in_bits:
                remaining_bits = file_size_in_bits - total_sent
                bytes_to_send = min(CHUNK_SIZE, remaining_bits // 8)  # המרנו לבתים

                if bytes_to_send > 0:
                    client_socket.send(message[:bytes_to_send].encode())
                    total_sent += bytes_to_send * 8

            print(f"\n\n\n{BOLD}{BRIGHT_PURPLE}###########################################################################################################\n"
                  f"\t\t\tTCP Connection Update - Finished sending all {total_sent} bits to {client_address}\n"
                  f"###########################################################################################################\n\n{RESET}")
        except Exception as e:
            print(f"\n{BOLD}{RED}Error handling TCP request: {e}{RESET}")

        finally:
            client_socket.close()

    def _searching_after_UDP_Request(self):
        """
        Listens for incoming UDP requests from clients and spawns a thread to handle each request.

        Explanation:
        - `socket(AF_INET, SOCK_DGRAM)`:
            - Creates a UDP socket to handle connectionless datagram-based communication(UDP).
        - `bind`: Binds the UDP socket to a specific IP address (`self.ip`) and port (`self.port`).
                  Ensures the server listens for UDP datagrams sent to this address and port.
        - `recvfrom(CHUNK_SIZE)`:
            - Blocks execution temporarily until a UDP datagram is received.
            - Returns the received data and the address of the client that sent the datagram.
            - The size of the received datagram is limited to `CHUNK_SIZE` bytes.

        Notes:
        - Each incoming UDP request is handled in its own thread, ensuring concurrent processing of multiple clients.
        - Unlike TCP, UDP does not require a connection or handshake, enabling faster communication but without guaranteed delivery or order.
        - UDP uses `sendto` and `recvfrom` for direct packet transmission, unlike TCP's persistent `accept` and `connect`.
        - Each UDP packet is independent, while TCP maintains a continuous, reliable connection for data transmission.
        """

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.ip, self.port))

        while self.running:
            try:
                data, client_address = udp_socket.recvfrom(CHUNK_SIZE)
                threading.Thread(target=self._handle_UDP, args=(data, client_address, udp_socket)).start()
            except Exception as e:
                print(f"\n{BOLD}{RED}Error receiving UDP request: {e}{RESET}")

    def _handle_UDP(self, data, client_address, udp_socket):
        """
        Handles an incoming UDP request, decodes it, and transmits Payload packets to the client.

        Parameters:
        - data: The raw UDP packet data received from the client.
        - client_address: Tuple of (ip, port) - The address of the client that sent the request.
        - udp_socket: The server's UDP socket used to send response packets.

        Explanation:
        - Decodes the incoming request to get file size and calculate total segments
        - Sends segments one by one with a small delay between them
        - Updates progress in-place on a single line
        - Shows final success/failure message when transfer completes

        Notes:
        - Uses \r to update the progress on the same line
        - Progress shows segments sent vs total for current client IP
        - Final summary printed on new line after transfer completes
        """
        try:
            packet = UDP_Packet.decode(data)
            if packet.message_type != MESSAGE_TYPE_REQUEST:
                return

            print(f"\n\n{BOLD}{BRIGHT_CYAN}Received UDP request from {client_address}{RESET}")

            file_size_in_bits = int(packet.fields.get('file_size', 0))
            max_payload_size = 512
            segment_size = max_payload_size * 8
            total_segments = (file_size_in_bits + segment_size - 1) // segment_size

            print(f"\n\n{BOLD}{BRIGHT_CYAN}Starting UDP transmission to {client_address}{RESET}")
            successful_segments = 0

            for current_segment in range(1, total_segments + 1):
                remaining_bits = file_size_in_bits - ((current_segment - 1) * segment_size)
                current_payload_size = min(max_payload_size, (remaining_bits + 7) // 8)

                payload_data = b'A' * current_payload_size
                payload_packet = UDP_Packet(
                    message_type=MESSAGE_TYPE_PAYLOAD,
                    magic_cookie=MAGIC_COOKIE,
                    total_segments=total_segments,
                    current_segment=current_segment,
                    payload_data=payload_data
                )

                try:
                    encoded_packet = payload_packet.encode()
                    udp_socket.sendto(encoded_packet, client_address)
                    successful_segments += 1

                    print(
                        f"\r{BOLD}{BRIGHT_YELLOW}Sending to {client_address[0]}: Progress {current_segment}/{total_segments} segments{RESET}",
                        end="", flush=True)

                    time.sleep(0.001)

                except Exception as e:
                    print(f"{BOLD}{RED}Failed to send segment {current_segment}: {e}{RESET}")
                    continue

            print()  # מעבר שורה אחרי סיום העדכונים

            if successful_segments == total_segments:
                print(
                    f"\n\n{BOLD}{BRIGHT_CYAN}###########################################################################################################{RESET}\n"
                    f"\t\t\t{BOLD}{BRIGHT_CYAN}UDP Connection Update - Finished sending all {total_segments} segments to {client_address}{RESET}"
                    f"\n{BOLD}{BRIGHT_CYAN}###########################################################################################################{RESET}\n")
            else:
                print(
                    f"\n{BOLD}{RED}Warning: Only {successful_segments}/{total_segments} segments were sent successfully to {client_address}{RESET}\n")

        except Exception as e:
            print(f"{BOLD}{RED}Error handling UDP request from {client_address}: {e}{RESET}")


    def run(self):
        """
        Starts the server's main execution loop by initializing and running the broadcasting, TCP, and UDP threads.

        Explanation:
        - `broadcast_thread`: A thread responsible for continuously broadcasting UDP offer messages to clients.
        - `tcp_thread`: Handles incoming TCP requests, creating a new thread for each client connection.
        - `udp_thread`: Listens for UDP requests and processes them using the `_handle_UDP` method.

        Notes:
        - Threads are used to ensure the server can handle multiple tasks (broadcasting, TCP, UDP) concurrently without blocking.
        - `KeyboardInterrupt`: Catches manual interruption (e.g., Ctrl+C) to shut down the server gracefully.
        - `cleanup`: Ensures proper release of resources such as sockets upon server shutdown.
        """

        try:

            broadcast_thread = threading.Thread(target=self._start_broadcast)
            tcp_thread = threading.Thread(target=self._searching_after_TCP_Request)
            udp_thread = threading.Thread(target=self._searching_after_UDP_Request)

            broadcast_thread.start()
            tcp_thread.start()
            udp_thread.start()
        except KeyboardInterrupt:
            print(f"{BOLD}{RED}Shutting down server...{RESET}")
            self.cleanup()

    def cleanup(self):
        """
           Releases server resources and shuts down the server.

           Explanation:
           - Closes the UDP and TCP sockets to ensure no resources are left open.
           - This method can be safely called multiple times without causing errors.

           Note:
           - Registered with `atexit` to ensure it's called when the program exits.
           """
        if  self.running:
            print(f"{BOLD}{BRIGHT_BLUE}Cleaning up resources...{RESET}")
            self.udp_socket.close()
            self.tcp_socket.close()
            self.running = False





if __name__ == "__main__":
    server_ip = get_ip_address()
    server = Server(server_ip)
    server.run()
