#!/usr/bin/env python3
"""Launch preflight, NOT persistent isolation: require all external links DOWN."""
import fcntl
import socket
import struct
import sys


def active_links():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        result = []
        for _, name in socket.if_nameindex():
            data = fcntl.ioctl(control.fileno(), 0x8913, struct.pack("256s", name.encode()))
            flags = struct.unpack_from("H", data, 16)[0]
            if flags & 1 and not flags & 8:  # IFF_UP, IFF_LOOPBACK
                result.append(name)
        return result


if __name__ == "__main__":
    try:
        links = active_links()
    except OSError as error:
        sys.exit(f"Cannot verify offline network state: {error}")
    if links:
        sys.exit("Disable external network links before this test: " + ", ".join(links) +
                 ". Keep them disabled until the game exits; this is only a preflight check.")
