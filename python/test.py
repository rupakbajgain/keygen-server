import socket
import struct
import cbor2
import os

SOCKET_PATH = f"/run/user/{os.getuid()}/mfs/keyserver.socket"
RECV_TIMEOUT = 5.0  # seconds


def connect_socket():
    """Create a new Unix socket connection with a timeout."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCKET_PATH)
    sock.settimeout(RECV_TIMEOUT)
    return sock


def send(sock, req: dict):
    """
    Send a request as CBOR with a 4-byte length prefix.
    All data is sent in a single sendall() call to avoid partial frame issues.
    """
    payload = cbor2.dumps(req)
    frame = struct.pack(">I", len(payload)) + payload
    sock.sendall(frame)


def recv(sock):
    """
    Receive a CBOR response safely.
    Reads exactly 4-byte length prefix, then payload.
    Handles timeout and connection closure gracefully.
    """
    try:
        # Read 4-byte length prefix
        raw_size = sock.recv(4)
        if len(raw_size) < 4:
            print("Connection closed while reading size")
            return None
        size = struct.unpack(">I", raw_size)[0]

        # Read payload in chunks until full size is received
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                print("Connection closed while reading payload")
                return None
            data += chunk

        return cbor2.loads(data)

    except socket.timeout:
        print("Timeout: no data received")
        return None
    except Exception as e:
        print(f"Recv error: {e}")
        return None


def main():
    # Connect once and reuse the socket
    sock = connect_socket()

    try:
        # 1️⃣ Ping
        send(sock, {"v": 1, "cmd": "ping"})
        resp = recv(sock)
        print("Ping response:", resp)

        # 2️⃣ Unlock with password (as string)
        send(sock, {"v": 1, "cmd": "unlock", "data": "password"})
        resp = recv(sock)
        print("Unlock response:", resp)

        # 3️⃣ Additional requests can go here
        # send(sock, {"v": 1, "cmd": "status"})
        # resp = recv(sock)
        # print("Status response:", resp)

    finally:
        sock.close()


if __name__ == "__main__":
    main()
