"""Small public WebSocket relay for the two-client check session.

The service is intentionally dependency-free so it can run on a free Python web
service. It forwards only the protocol fields used by NetworkSessionClient.
Render terminates TLS in front of this process, so clients connect with wss://.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import threading
from dataclasses import dataclass, field


HOST = os.environ.get("RELAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "17890"))
MAX_FRAME = 4 * 1024 * 1024
FORWARDED_FIELDS = ("msg", "raw", "inv", "invAck", "start", "stop", "pass", "quit")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed the socket")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock: socket.socket, payload: bytes, opcode: int = 0x1) -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length <= 125:
        header.append(length)
    elif length <= 0xFFFF:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    sock.sendall(bytes(header) + payload)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    opcode = first & 0x0F
    masked = (second & 0x80) != 0
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    mask = recv_exact(sock, 4) if masked else b"\0\0\0\0"
    payload = bytearray(recv_exact(sock, length))
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)


@dataclass(eq=False)
class Client:
    sock: socket.socket
    address: tuple[str, int]
    channel: str = ""
    nick: str = ""
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def send_json(self, value: dict) -> None:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        with self.send_lock:
            send_frame(self.sock, payload)


clients: set[Client] = set()
clients_lock = threading.RLock()


def channel_clients(channel: str) -> list[Client]:
    with clients_lock:
        return [client for client in clients if client.channel == channel]


def notify_peers(channel: str) -> None:
    peers = channel_clients(channel)
    for client in peers:
        try:
            client.send_json({"peers": len(peers)})
        except OSError:
            pass


def relay(client: Client, message: dict) -> None:
    if "join" in message:
        old_channel = client.channel
        client.channel = str(message.get("join") or "")[:128]
        client.nick = str(message.get("nick") or "user")[:64]
        if old_channel and old_channel != client.channel:
            notify_peers(old_channel)
        notify_peers(client.channel)
        return

    if not client.channel:
        return
    outgoing = {key: message[key] for key in FORWARDED_FIELDS if key in message}
    if not outgoing:
        return
    for target in channel_clients(client.channel):
        if target is client:
            continue
        try:
            target.send_json(outgoing)
        except OSError:
            pass


def http_response(client: Client, request_line: str) -> None:
    path = request_line.split()[1] if len(request_line.split()) > 1 else "/"
    if path == "/health":
        body = b'{"status":"ok","service":"mod-relay"}\n'
        status = "200 OK"
        content_type = "application/json"
    else:
        body = b"WebSocket relay\n"
        status = "200 OK"
        content_type = "text/plain; charset=utf-8"
    response = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    client.sock.sendall(response)


def client_loop(client: Client) -> None:
    try:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 16384:
            chunk = client.sock.recv(4096)
            if not chunk:
                return
            request += chunk
        header_text = request.decode("latin-1")
        headers = header_text.split("\r\n")
        key = next(
            (line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("sec-websocket-key:")),
            None,
        )
        if key is None:
            http_response(client, headers[0] if headers else "GET / HTTP/1.1")
            return
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        client.sock.sendall(response.encode("ascii"))

        while True:
            opcode, payload = recv_frame(client.sock)
            if opcode == 0x8:
                return
            if opcode == 0x9:
                with client.send_lock:
                    send_frame(client.sock, payload, opcode=0xA)
                continue
            if opcode not in (0x1, 0x2):
                continue
            relay(client, json.loads(payload.decode("utf-8")))
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError, UnicodeError):
        pass
    finally:
        with clients_lock:
            clients.discard(client)
        try:
            client.sock.close()
        except OSError:
            pass
        if client.channel:
            notify_peers(client.channel)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"Relay listening on {HOST}:{PORT}; health=/health", flush=True)
        while True:
            sock, address = server.accept()
            client = Client(sock=sock, address=address)
            with clients_lock:
                clients.add(client)
            threading.Thread(target=client_loop, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
