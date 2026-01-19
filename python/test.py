import socket
import struct
import os

SOCKET_PATH = f"/run/user/{os.getuid()}/mfs/keyserver.sock"
RECV_TIMEOUT = 5.0  # seconds

def encode_req_res(fields: dict):
    """
    Serializes a dictionary into the custom binary ReqRes format.
    Format: [KeyLen(4)][Key][ValLen(4)][Val] ...
    """
    payload = b""
    for key, value in fields.items():
        key_bytes = key.encode('utf-8')
        # Value might be string or bytes
        val_bytes = value.encode('utf-8') if isinstance(value, str) else value

        payload += struct.pack(">I", len(key_bytes)) + key_bytes
        payload += struct.pack(">I", len(val_bytes)) + val_bytes
    return payload

def decode_req_res(data: b""):
    """
    Deserializes the custom binary ReqRes format into a dictionary.
    """
    fields = {}
    offset = 0
    while offset < len(data):
        # Read Key
        k_len = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        key = data[offset:offset + k_len].decode('utf-8')
        offset += k_len

        # Read Value
        v_len = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        val = data[offset:offset + v_len]
        offset += v_len

        fields[key] = val
    return fields

def connect_socket():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCKET_PATH)
    sock.settimeout(RECV_TIMEOUT)
    return sock

def send(sock, fields: dict):
    """Sends request with a 4-byte total length prefix."""
    payload = encode_req_res(fields)
    frame = struct.pack(">I", len(payload)) + payload
    sock.sendall(frame)

def recv(sock):
    """Receives response with a 4-byte total length prefix."""
    try:
        raw_size = sock.recv(4)
        if len(raw_size) < 4: return None
        size = struct.unpack(">I", raw_size)[0]

        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk: break
            data += chunk

        return decode_req_res(data)
    except Exception as e:
        print(f"Recv error: {e}")
        return None

def main():
    sock = connect_socket()
    try:
        # 1️⃣ Ping
        send(sock, {"command": "ping"})
        print("Ping response:", recv(sock))

        # 2️⃣ Pass (Unlock)
        send(sock, {
            "command": "pass",
            "password": "my_secure_password"
        })
        print("Unlock response:", recv(sock))

        # 3️⃣ Derived Key Example
        # Note: archive_id must be exactly 16 bytes
        send(sock, {
            "command": "derived.key",
            "archive_id": b"\x00" * 16,
            "purpose": "signing",
            "path": "m/0/1"
        })
        print("Derived Key response:", recv(sock))

    finally:
        sock.close()

if __name__ == "__main__":
    main()
