#!/usr/bin/env python3
import socket
import ssl
import sys


def get_mssql_version_tls(ip, port=1433):
    print(f"[*] Initiating TLS wrapped handshake to {ip}:{port}...")

    # 1. Standard TDS Prelogin header
    pkt = b"\x12\x01\x00\x1d\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\xff\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"

    # 2. Setup an unverified SSL Context to tolerate self-signed database certificates
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    base_socket.settimeout(5.0)

    try:
        base_socket.connect((ip, port))

        # Wrap the socket directly in TLS to avoid the firewall/server drop
        with ctx.wrap_socket(base_socket, server_hostname=ip) as tls_socket:
            tls_socket.sendall(pkt)
            res = tls_socket.recv(1024)

            if res:
                print(f"\n[+] Connected! Raw Response Hex: {res.hex()}")
                # Extracting version bytes relative to the termination token
                idx = res.find(b"\xff")
                if idx != -1 and len(res) >= idx + 5:
                    major = res[idx + 1]
                    minor = res[idx + 2]
                    build = (res[idx + 3] << 8) + res[idx + 4]
                    print(f"[+] Decoded Exact Build: {major}.{minor}.{build}")
                    return
            print("[-] Connected, but the server returned an empty payload stream.")

    except Exception as e:
        print(f"\n[-] Connection failed over TLS layer: {e}")
    finally:
        base_socket.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <Target_IP> [Port]")
        sys.exit(1)
    get_mssql_version_tls(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1433)
