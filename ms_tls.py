#!/usr/bin/env python3
import socket
import sys
import struct


def get_tls_mssql_version(ip, port=1433):
    print(f"[*] Connecting to {ip}:{port} with TLS capability...")

    # Authoritative TDS PRELOGIN structure packet
    pkt = (
        b"\x12\x01\x00\x2f\x00\x00\x01\x00"  # TDS Header
        b"\x00\x00\x1a\x00\x06"  # Token 0: Version offset
        b"\x01\x00\x20\x00\x01"  # Token 1: Encryption offset
        b"\x02\x00\x21\x00\x06"  # Token 2: Instopt offset
        b"\x03\x00\x27\x00\x04"  # Token 3: ThreadID offset
        b"\xff"  # Token Terminator
        b"\x00\x00\x00\x00\x00\x00"  # Client placeholder version
        b"\x01"  # Encryption Flag: ENCRYPT_REQ (Forces handshake response)
        b"\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)

    try:
        s.connect((ip, port))
        s.sendall(pkt)
        res = s.recv(4096)

        # Validate minimal TDS response header length
        if len(res) > 8 and res[0] == 0x04:
            # Locate the exact position of the Version option (Token Type 0x00)
            # The structure details the offset value starting at byte index 10
            version_offset = struct.unpack(">H", res[10:12])[0]

            # The version block payload is placed at the calculated offset index relative to header start
            v_data = res[version_offset : version_offset + 6]

            if len(v_data) >= 4:
                major = v_data[0]
                minor = v_data[1]
                build = struct.unpack(">H", v_data[2:4])[0]

                marketing_names = {
                    16: "SQL Server 2022",
                    15: "SQL Server 2019",
                    14: "SQL Server 2017",
                    13: "SQL Server 2016",
                    12: "SQL Server 2014",
                    11: "SQL Server 2012",
                    10: "SQL Server 2008 / 2008 R2",
                }
                product = marketing_names.get(major, "Unknown MSSQL Release")

                print("\n[+] Discovery Successful!")
                print("---------------------------------------")
                print(f"Product Release : {product}")
                print(f"Exact Build     : {major}.{minor}.{build}")
                print("---------------------------------------")
                return

        print("\n[-] Handshake succeeded but version block data was unexpected.")
        print(f"Raw hex response: {res.hex()}")

    except socket.timeout:
        print("\n[-] Connection timed out. Ensure target port is listening.")
    except Exception as e:
        print(f"\n[-] Connection failed: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <Target_IP> [Port]")
        print(f"Example: python3 {sys.argv[0]} 10.10.10.1")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433

    get_mssql_version(
        target_ip, target_port
    ) if "get_mssql_version" in locals() else get_tls_mssql_version(
        target_ip, target_port
    )
