#!/usr/bin/env python3
"""Send one ordinary OPTIONS request to a loopback lab endpoint."""
import argparse
import socket
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", type=int, default=17000)
parser.add_argument("--wait", type=float, default=0,
                    help="retry until ready, for at most this many seconds")
args = parser.parse_args()
deadline = time.monotonic() + max(0, args.wait)
while True:
    timeout = min(3, max(0.1, deadline - time.monotonic())) if args.wait > 0 else 3
    data = bytearray()
    error_text = ""
    try:
        with socket.create_connection(("127.0.0.1", args.port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            request_end = time.monotonic() + timeout
            while b"\r\n\r\n" not in data and len(data) < 16384:
                conn.settimeout(max(0.1, request_end - time.monotonic()))
                block = conn.recv(min(4096, 16384 - len(data)))
                if not block:
                    break
                data.extend(block)
                if time.monotonic() >= request_end:
                    break
        if data.startswith(b"RTSP/1.0 200"):
            print(data.decode("utf-8", errors="replace"))
            break
    except OSError as error:
        error_text = str(error)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        print(data.decode("utf-8", errors="replace"))
        parser.exit(1, f"probe failed: {error_text or 'no RTSP 200 response'}\n")
    time.sleep(min(0.5, remaining))
