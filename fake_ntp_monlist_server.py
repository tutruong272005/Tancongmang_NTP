# import socket
# import struct
# import time

# HOST = "0.0.0.0"
# PORT = 123  # NTP port

# # Fake MONLIST response payload (mode 7)
# # This is NOT a real NTP response, but enough for detector to classify monlist packets.
# fake_monlist_data = b"\x17\x02\x00\x2c" + b"A" * 40

# def start_server():
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((HOST, PORT))

#     print(f"[+] Fake NTP MONLIST server running on UDP {PORT}")
#     print("[+] Waiting for packets...\n")

#     while True:
#         data, addr = sock.recvfrom(1024)

#         print(f"[REQ] {addr[0]}:{addr[1]} -> received {len(data)} bytes")

#         # Check if mode7 MONLIST request
#         if len(data) > 0 and data[0] == 0x17:  # NTP mode 7 op
#             print(f"[MONLIST] Sending fake response to {addr[0]}")
#             sock.sendto(fake_monlist_data, addr)
#         else:
#             print("[INFO] Non-monlist packet ignored")

# if __name__ == "__main__":
#     start_server()

import socket
import signal
import sys

HOST = "0.0.0.0"
PORT = 123  # NTP port

# REALISTIC FAKE MONLIST PAYLOAD (NTP mode 7 response)
fake_monlist_reply = (
    b"\x17"              # LI, VN, Mode = 7
    b"\x02"              # Response opcode
    b"\x00\x2c"          # Sequence + status
    + b"A" * 40          # Fake data
)

running = True

def stop_server(sig, frame):
    global running
    print("\n[+] Stopping fake NTP MONLIST server...")
    running = False

signal.signal(signal.SIGINT, stop_server)

def start_server():
    global running

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    sock.settimeout(1)

    print(f"[+] Fake NTP Server (MONLIST) running on port {PORT}")
    print("[+] Waiting for NTP packets...\n")

    while running:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue

        print(f"[REQ] From {addr[0]}:{addr[1]} ({len(data)} bytes)")

        # Detect monlist request "17 00 03 2a"
        if len(data) > 3 and data[:4] == b"\x17\x00\x03\x2a":
            print(f"[MONLIST] Sending response to {addr[0]}")
            sock.sendto(fake_monlist_reply, addr)
        else:
            print("[INFO] Not a MONLIST request")

    sock.close()

if __name__ == "__main__":
    start_server()
