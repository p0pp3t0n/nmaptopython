#!/usr/bin/env python3
import sys
import socket
import struct


def get_mssql_version(ip, port=1433):
    print(f"[*] Connecting to {ip}:{port} via raw TCP socket...")

    # 1. Craft a reliable, standard TDS PRELOGIN packet frame
    # This specific structure includes the correct offsets for Version, Encryption, and Instopt tokens
    payload = (
        b"\x12\x01\x00\x2f\x00\x00\x01\x00"  # TDS Header (Type: Pre-login, Status: EOM)
        b"\x00\x00\x1a\x00\x06"  # Token 0: Version offset 26, length 6
        b"\x01\x00\x20\x00\x01"  # Token 1: Encryption offset 32, length 1
        b"\x02\x00\x21\x00\x06"  # Token 2: Instopt offset 33, length 6
        b"\x03\x00\x27\x00\x04"  # Token 3: ThreadID offset 39, length 4
        b"\xff"  # Token Terminator
        b"\x00\x00\x00\x00\x00\x00"  # Dummy client version values
        b"\x00"  # Encryption: Not encrypted / option support
        b"\x00\x00\x00\x00\x00\x00"  # Instance option payload
        b"\x00\x00\x00\x00"  # Thread ID data
    )

    # 2. Establish connection and handle network timeouts
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)

    try:
        s.connect((ip, port))
        s.sendall(payload)
        response = s.recv(4096)
    except socket.timeout:
        print(
            "[-] Error: Connection timed out. Target port might be firewalled or dropped the packet."
        )
        return
    except Exception as e:
        print(f"[-] Network connection error: {e}")
        return
    finally:
        s.close()

    if not response:
        print("[-] Error: Received empty response from the server.")
        return

    # 3. Locate the version block mapping inside the response payload
    # In a TDS PRELOGIN response, the version position is indicated by Option Token 0x00
    if response[8] == 0x00:
        # Extract the offset where the version block data actually starts
        version_offset = struct.unpack(">H", response[9:11])[0]
        version_length = struct.unpack(">H", response[11:13])[0]

        # Pull the raw bytes out of the stream payload using the offset index
        v_bytes = response[version_offset : version_offset + version_length]

        if len(v_bytes) >= 4:
            major = v_bytes[0]
            minor = v_bytes[1]
            build = struct.unpack(">H", v_bytes[2:4])[0]

            # Map Major version integer to the commercial marketing build name
            marketing_names = {
                16: "SQL Server 2022",
                15: "SQL Server 2019",
                14: "SQL Server 2017",
                13: "SQL Server 2016",
                12: "SQL Server 2014",
                11: "SQL Server 2012",
                10: "SQL Server 2008 / 2008 R2",
                9: "SQL Server 2005",
            }
            product = marketing_names.get(major, "Unknown MSSQL Release")

            print("\n[+] Discovery Successful!")
            print("---------------------------------------")
            print(f"Product Release : {product}")
            print(f"Exact Build     : {major}.{minor}.{build}")
            print("---------------------------------------")
            return

    # Fallback debug print if parsing fails due to unexpected network frame formats
    print("\n[-] Error: Received unexpected or abnormal response sequence.")
    print(f"Raw Response Hex: {response.hex()}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <Target_IP> [Port]")
        print("Example: python3 mssql_check.py 10.65.54.24")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433

    get_mssql_version(target_ip, target_port)
