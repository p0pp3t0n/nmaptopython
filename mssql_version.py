#!/usr/bin/env python3␍
import socket␍
␍
# TDS Pre-Login packet (from Nmap's probe)␍
# This is the exact packet the script sends␍
prelogin_packet = bytes([␍
    0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,␍
    0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,␍
    0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,␍
    0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,␍
    0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51,␍
    0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00␍
])␍
␍
 ␍
␍
def get_sql_version(host, port=1433):␍
    try:␍
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)␍
        sock.settimeout(5)␍
        sock.connect((host, port))␍
        sock.send(prelogin_packet)␍
        response = sock.recv(1024)␍
        sock.close()␍
␍
        # Parse version from response (bytes 44-48 typically contain version)␍
        if len(response) > 48:␍
            # Version is usually at offset 44-48␍
            version_bytes = response[44:48]␍
            major = version_bytes[0]␍
            minor = version_bytes[1]␍
            build = (version_bytes[2] << 8) | version_bytes[3]␍
            print(f"Version: {major}.{minor}.{build}")␍
            return f"{major}.{minor}.{build}"␍
    except Exception as e:␍
        print(f"Error: {e}")␍
    return None␍
␍
 ␍
␍
# Usage␍
get_sql_version("10.65.54.22")
