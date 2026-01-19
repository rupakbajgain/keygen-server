import socket
import struct
import os
from dataclasses import dataclass
from typing import Union

# --- Sensible Data Objects ---

@dataclass
class Ok:
    msg: str  # e.g., "pong"

@dataclass
class Archive:
    wrapped_key: bytes
    nonce: bytes
    archive_id: bytes

@dataclass
class Key:
    key: bytes

@dataclass
class Data:
    data: bytes

@dataclass
class Error:
    msg: str  # The actual error description

# Type alias for easier hinting
MfsResponse = Union[Ok, Archive, Key, Data, Error]

class KeyserverClient:
    def __init__(self, socket_path=None, timeout=5.0):
        if socket_path is None:
            self.socket_path = f"/run/user/{os.getuid()}/mfs/keyserver.sock"
        else:
            self.socket_path = socket_path
        self.timeout = timeout
        self.sock = None

    def _encode_req_res(self, fields: dict) -> bytes:
        payload = b""
        for key, value in fields.items():
            k_bytes = key.encode('utf-8')
            v_bytes = value.encode('utf-8') if isinstance(value, str) else value
            payload += struct.pack(">I", len(k_bytes)) + k_bytes
            payload += struct.pack(">I", len(v_bytes)) + v_bytes
        return payload

    def _decode_req_res(self, data: bytes) -> dict:
        fields = {}
        offset = 0
        while offset < len(data):
            k_len = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            key = data[offset:offset + k_len].decode('utf-8')
            offset += k_len
            v_len = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            val = data[offset:offset + v_len]
            offset += v_len
            fields[key] = val
        return fields

    def _execute(self, fields: dict) -> MfsResponse:
        if not self.sock:
            raise ConnectionError("Socket not connected.")

        # Binary framing: [TotalLen][Payload]
        payload = self._encode_req_res(fields)
        self.sock.sendall(struct.pack(">I", len(payload)) + payload)

        raw_size = self.sock.recv(4)
        if len(raw_size) < 4: return Error("Connection closed or empty size")
        size = struct.unpack(">I", raw_size)[0]

        body = b""
        while len(body) < size:
            chunk = self.sock.recv(size - len(body))
            if not chunk: break
            body += chunk

        raw = self._decode_req_res(body)
        status = raw.get("status", b"").decode('utf-8')

        # Logic Mapping
        if status == "ok":
            return Ok(msg=raw.get("msg", b"").decode('utf-8'))
        elif status == "error":
            return Error(msg=raw.get("msg", b"").decode('utf-8'))
        elif status == "data":
            return Data(data=raw.get("data", b""))
        elif status == "key":
            return Key(key=raw.get("key", b""))
        elif status == "ArchiveFields":
            return Archive(
                wrapped_key=raw.get("wrapped_key", b""),
                nonce=raw.get("nonce", b""),
                archive_id=raw.get("archive_id", b"")
            )
        return Error(f"Unknown status code: {status}")

    # --- API Methods ---

    def ping(self) -> MfsResponse:
        return self._execute({"command": "ping"})

    def unlock(self, password: str) -> MfsResponse:
        return self._execute({"command": "pass", "password": password})

    def get_master_id(self) -> MfsResponse:
        return self._execute({"command": "master.get_id"})

    def archive_generate(self) -> MfsResponse:
        return self._execute({"command": "archive.generate"})

    def archive_load(self, archive: Archive) -> MfsResponse:
        return self._execute({
            "command": "archive.load",
            "wrapped_key": archive.wrapped_key,
            "nonce": archive.nonce,
            "archive_id": archive.archive_id
        })

    def get_derived_key(self, archive_id: bytes, path: str, purpose: str = "signing") -> MfsResponse:
        return self._execute({
            "command": "derived.key",
            "archive_id": archive_id,
            "purpose": purpose,
            "path": path
        })

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        self.sock.settimeout(self.timeout)
        return self

    def close(self):
        if self.sock: self.sock.close()

    def __enter__(self): return self.connect()
    def __exit__(self, *args): self.close()
