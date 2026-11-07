"""Bounded test payloads inside the LAN namespaces."""

import hashlib
import json
import socket
import struct
import sys

LIMIT = 16384


def receive(sock, length):
    payload = bytearray()
    while len(payload) < length:
        part = sock.recv(length - len(payload))
        if not part:
            raise RuntimeError("Unexpected EOF")
        payload.extend(part)
    return bytes(payload)


def read_frame(sock):
    size = struct.unpack("!H", receive(sock, 2))[0]
    if size > LIMIT:
        raise RuntimeError("Payload exceeds the fixture limit.")
    return receive(sock, size)


def write_frame(sock, payload):
    sock.sendall(struct.pack("!H", len(payload)) + payload)


def serve(protocol, address, port, count):
    with socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    ) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(5)
        listener.bind((address, port))
        if protocol == "tcp":
            listener.listen(1)
        print("READY", flush=True)
        rows = []
        if protocol == "udp":
            for _ in range(count):
                payload, source = listener.recvfrom(LIMIT)
                listener.sendto(payload, source)
                rows.append(receipt(source, payload))
        else:
            conn, source = listener.accept()
            with conn:
                conn.settimeout(5)
                for _ in range(count):
                    payload = read_frame(conn)
                    write_frame(conn, payload)
                    rows.append(receipt(source, payload))
                assert conn.recv(1) == b""
        print(json.dumps(rows), flush=True)


def receipt(address, payload):
    return {
        "source": list(address),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def client(protocol, source, sport, target, port, count, size, nonce, pmtu, mss):
    with socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    ) as sock:
        sock.settimeout(3)
        if pmtu != "default":
            sock.setsockopt(socket.IPPROTO_IP, 10, 2 if pmtu == "df" else 0)
        if mss:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        sock.bind((source, sport))
        sock.connect((target, port))
        rows = []
        for seq in range(count):
            prefix = f"{nonce}/{seq}/".encode()
            payload = prefix + b"x" * (size - len(prefix))
            if protocol == "udp":
                sock.send(payload)
                echo = sock.recv(LIMIT)
            else:
                write_frame(sock, payload)
                echo = read_frame(sock)
            if echo != payload:
                raise RuntimeError("Payload or sequence mismatch.")
            rows.append(receipt(sock.getsockname(), payload))
        if protocol == "tcp":
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(1) == b""
        print(json.dumps(rows), flush=True)


if __name__ == "__main__":
    mode, protocol, *args = sys.argv[1:]
    if mode == "server":
        address, port, count = args
        serve(protocol, address, int(port), int(count))
    elif mode == "client":
        source, sport, target, port, count, size, nonce, pmtu, mss = args
        try:
            client(
                protocol,
                source,
                int(sport),
                target,
                int(port),
                int(count),
                int(size),
                nonce,
                pmtu,
                int(mss),
            )
        except OSError as exc:
            print(json.dumps({"errno": exc.errno, "timeout": isinstance(exc, TimeoutError)}))
            sys.exit(1)
    else:
        raise ValueError("Invalid test traffic mode")
