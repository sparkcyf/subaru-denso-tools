#!/usr/bin/env python3
"""Run one lab console command and wait for its exit-code marker."""
import argparse
import re
import secrets
import socket
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", type=int, default=17001)
parser.add_argument("--socket", dest="unix_socket")
parser.add_argument("--timeout", type=float, default=20)
parser.add_argument("command")
args = parser.parse_args()
marker = "BLOG_" + secrets.token_hex(8)
pattern = re.compile((marker + r"_RC_(\d+)").encode())
if args.unix_socket:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(3)
    conn.connect(args.unix_socket)
else:
    conn = socket.create_connection(("127.0.0.1", args.port), timeout=3)
with conn:
    conn.settimeout(0.2)
    # First discard boot output already waiting on this connection.
    end = time.monotonic() + 0.3
    while time.monotonic() < end:
        try:
            if not conn.recv(65536):
                parser.exit(1, "serial connection closed\n")
        except socket.timeout:
            break
    # echo is a builtin even in the small QNX host shell, where printf
    # need not exist. The echoed input still contains literal '$?'.
    payload = "\n" + args.command + "\necho " + marker + "_RC_$?\n"
    conn.sendall(payload.encode())
    data = bytearray()
    end = time.monotonic() + args.timeout
    while time.monotonic() < end:
        try:
            block = conn.recv(65536)
        except socket.timeout:
            continue
        if not block:
            break
        data.extend(block)
        match = pattern.search(data)
        if match:
            sys.stdout.write(data[:match.start()].decode(errors="replace"))
            raise SystemExit(int(match.group(1)))
    sys.stdout.write(data.decode(errors="replace"))
    parser.exit(124, "\nserial command timed out; no completion marker\n")
