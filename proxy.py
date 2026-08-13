import socket
import threading
from datetime import datetime
import os

# === WAF INTEGRATION ===
from waf import WAF
waf = WAF()

HOST = "127.0.0.1"
PORT = 8080

# ===== SCOPE CONFIG =====
IN_SCOPE_HOST = "192.168.1.102"
IN_SCOPE_PORT = 80

# ===== CONNECTION CONFIG =====
# Prevents a slow/stalled client or backend from tying up a thread
# forever - without this, a client that connects and sends nothing
# blocks that thread indefinitely.
SOCKET_TIMEOUT = 30

# Refuse to buffer an unbounded header block (basic guard against a
# client that never sends the header terminator).
MAX_HEADER_SIZE = 64 * 1024

RECV_CHUNK = 65536

# ===== LOG CONFIG =====
LOG_DIR = "logs"
PROXY_LOG_FILE = os.path.join(LOG_DIR, "proxy.log")
os.makedirs(LOG_DIR, exist_ok=True)


def log(msg):
    with open(PROXY_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


# ============================================================
# HTTP PARSING HELPERS
# ============================================================

def recv_until_headers_end(sock):
    """Read from the socket until the header/body separator
    (\\r\\n\\r\\n) has been seen. Returns everything read so far,
    which may include some body bytes that arrived in the same
    read as the tail of the headers.
    """

    buffer = b""

    while b"\r\n\r\n" not in buffer:

        if len(buffer) > MAX_HEADER_SIZE:
            raise ValueError("Header block too large")

        chunk = sock.recv(RECV_CHUNK)

        if not chunk:
            break

        buffer += chunk

    return buffer


def parse_headers(headers_text):
    """Parse a raw HTTP header block (request line / status line +
    header lines) into (first_line, headers) where headers is a
    list of (name, value) tuples.

    A list (not a dict) is used deliberately: raw HTTP allows
    duplicate header names, and the WAF has rules that depend on
    seeing every occurrence (e.g. duplicate Content-Length /
    request-smuggling checks). Collapsing to a dict here would
    silently defeat those rules before the WAF ever sees the
    request.
    """

    lines = headers_text.split("\r\n")
    first_line = lines[0]

    headers = []

    for line in lines[1:]:

        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))

    return first_line, headers


def read_body(sock, already_read, headers):
    """Read the full message body based on Content-Length or a
    simple chunked read, instead of relying on whatever happened to
    arrive in a single recv(). Without this, bodies over ~64KB (or
    just split across TCP packets) get silently truncated before
    the WAF ever inspects them.

    If neither Content-Length nor Transfer-Encoding is present,
    there is nothing more to read for a request (a bodyless GET,
    for example) - returning immediately here matters because
    reading "until the connection closes" would hang against a
    keep-alive client that has nothing more to send.
    """

    content_length = waf.get_header(headers, "Content-Length", "").strip()
    transfer_encoding = waf.get_header(
        headers, "Transfer-Encoding", ""
    ).lower()

    if content_length.isdigit():

        needed = int(content_length)
        body = already_read

        while len(body) < needed:

            chunk = sock.recv(RECV_CHUNK)

            if not chunk:
                break

            body += chunk

        return body[:needed]

    if "chunked" in transfer_encoding:

        # Phase-1 handling: read raw chunked bytes through to the
        # terminating "0\r\n\r\n" marker so the WAF sees the whole
        # body instead of a truncated first fragment. This does NOT
        # decode chunk framing into the real payload - full chunked
        # decoding is a reasonable phase-2 addition.
        body = already_read

        while not body.endswith(b"0\r\n\r\n"):

            chunk = sock.recv(RECV_CHUNK)

            if not chunk:
                break

            body += chunk

        return body

    return already_read


def relay_response(server_socket, client_socket):
    """Read the backend's response and forward it to the client,
    using Content-Length when present so the proxy doesn't wait on
    a keep-alive backend that never closes the connection. Falls
    back to relaying bytes until the backend closes when no
    Content-Length/chunked framing is present, which matches how a
    close-delimited HTTP/1.0-style response is meant to be read.
    """

    raw = recv_until_headers_end(server_socket)

    if not raw:
        return

    headers_part, sep, body_start = raw.partition(b"\r\n\r\n")

    if not sep:
        # Backend didn't send a full header block - relay whatever
        # arrived and stop.
        client_socket.sendall(raw)
        return

    _, resp_headers = parse_headers(headers_part.decode(errors="ignore"))

    content_length = waf.get_header(
        resp_headers, "Content-Length", ""
    ).strip()

    transfer_encoding = waf.get_header(
        resp_headers, "Transfer-Encoding", ""
    ).lower()

    client_socket.sendall(headers_part + b"\r\n\r\n")

    if content_length.isdigit():

        needed = int(content_length)
        body = body_start

        while len(body) < needed:

            chunk = server_socket.recv(RECV_CHUNK)

            if not chunk:
                break

            body += chunk

        client_socket.sendall(body[:needed])
        return

    if "chunked" in transfer_encoding:

        body = body_start

        while not body.endswith(b"0\r\n\r\n"):

            chunk = server_socket.recv(RECV_CHUNK)

            if not chunk:
                break

            body += chunk

        client_socket.sendall(body)
        return

    # No explicit length - stream until the backend closes.
    if body_start:
        client_socket.sendall(body_start)

    while True:

        chunk = server_socket.recv(RECV_CHUNK)

        if not chunk:
            break

        client_socket.sendall(chunk)


# ============================================================
# CLIENT HANDLING
# ============================================================

def handle_client(client_socket, client_address):
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        raw = recv_until_headers_end(client_socket)

        if not raw:
            client_socket.close()
            return

        headers_part, sep, body_start = raw.partition(b"\r\n\r\n")

        if not sep:
            # Never got a full header block (client sent nothing
            # useful, or dropped mid-headers).
            client_socket.close()
            return

        headers_text = headers_part.decode(errors="ignore")

        try:
            request_line, headers = parse_headers(headers_text)
            method, path, version = request_line.split()
        except (ValueError, IndexError):
            log(f"[MALFORMED REQUEST] Client: {client_address[0]}")
            client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            client_socket.close()
            return

        body_bytes = read_body(client_socket, body_start, headers)
        body = body_bytes.decode(errors="ignore")

        full_request_text = headers_text + "\r\n\r\n" + body

        # ===== LOG RAW REQUEST (ALWAYS) =====
        log(
            f"\n[RAW REQUEST]\n"
            f"Client: {client_address[0]}\n"
            f"{full_request_text}\n"
            f"{'='*70}"
        )

        host = waf.get_header(headers, "Host", "")
        host_only = host.split(":")[0]

        # ===== BLOCK CONNECT =====
        if method.upper() == "CONNECT":
            log(f"[BLOCKED] CONNECT method from {client_address[0]}")
            client_socket.sendall(
                b"HTTP/1.1 403 Forbidden\r\n\r\nCONNECT not allowed\n"
            )
            client_socket.close()
            return

        # ===== BLOCK OUT OF SCOPE =====
        if host_only != IN_SCOPE_HOST:
            log(
                f"[OUT OF SCOPE]\n"
                f"Client: {client_address[0]}\n"
                f"Host: {host_only}\n"
                f"{'='*70}"
            )
            client_socket.sendall(
                b"HTTP/1.1 403 Forbidden\r\n\r\nOut of scope\n"
            )
            client_socket.close()
            return

        # ===== WAF INSPECTION =====
        allowed, reason = waf.inspect_request(
            method=method,
            path=path,
            headers=headers,
            body=body,
            client_ip=client_address[0]
        )

        if not allowed:
            log(
                f"[WAF BLOCKED]\n"
                f"Client: {client_address[0]}\n"
                f"Reason: {reason}\n"
                f"{full_request_text}\n"
                f"{'='*70}"
            )

            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                f"WAF BLOCKED REQUEST\n{reason}\n"
            )
            client_socket.sendall(response.encode())
            client_socket.close()
            return

        # ===== ALLOWED REQUEST LOG =====
        timestamp = datetime.utcnow().isoformat()

        entry = (
            f"\n[ALLOWED REQUEST]\n"
            f"Time   : {timestamp}\n"
            f"Client : {client_address[0]}\n"
            f"Method : {method}\n"
            f"Path   : {path}\n"
            f"Host   : {host}\n"
            f"\n--- HEADERS ---\n"
        )

        for k, v in headers:
            entry += f"{k}: {v}\n"

        entry += "\n--- BODY ---\n"
        entry += body.strip() if body else "None"
        entry += "\n" + "=" * 70

        log(entry)

        # ===== FORWARD REQUEST =====
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(SOCKET_TIMEOUT)

        try:
            server_socket.connect((IN_SCOPE_HOST, IN_SCOPE_PORT))
            server_socket.sendall(headers_part + b"\r\n\r\n" + body_bytes)

            # ===== RELAY RESPONSE =====
            relay_response(server_socket, client_socket)

        finally:
            server_socket.close()

        client_socket.close()

    except Exception as e:
        log(f"[ERROR] {e}")
        try:
            client_socket.close()
        except Exception:
            pass


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)

    print(f"[+] HTTP Proxy running on {HOST}:{PORT}")
    print(f"[+] Proxy log : {PROXY_LOG_FILE}")
    print(f"[+] Scope     : {IN_SCOPE_HOST}:{IN_SCOPE_PORT}")
    print("[+] WAF       : Enabled\n")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(
            target=handle_client,
            args=(client_socket, addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    start_proxy()