#!/usr/bin/env python3
import sys
import re

try:
    import pymssql
except ImportError:
    print("[-] Error: pymssql library missing. Install it using: pip install pymssql")
    sys.exit(1)


def discover_version(ip, port=1433):
    print(f"[*] Initiating formal TDS connection to {ip}:{port}...")

    # We deliberately use fake credentials.
    # The TDS protocol requires the server to negotiate and declare its version
    # inside the connection handshake BEFORE it validates credentials.
    try:
        conn = pymssql.connect(
            server=ip,
            port=port,
            user="UnauthenticatedDiscoveryUser",
            password="FakePassword123!",
            database="master",
            timeout=5,
        )
        conn.close()
    except pymssql.OperationalError as e:
        error_msg = str(e)

        # Look for the classic SQL Server error frame containing the version numbers
        # Typically looks like: "Adaptive Server ... (16.0.4021)" or similar patterns
        version_match = re.search(r"\((\d+)\.(\d+)\.(\d+)\)", error_msg)

        if version_match:
            major = int(version_match.group(1))
            minor = version_match.group(2)
            build = version_match.group(3)

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

            print("\n[+] Discovery Successful via Driver Handshake!")
            print("---------------------------------------")
            print(f"Product Release : {product}")
            print(f"Exact Build     : {major}.{minor}.{build}")
            print("---------------------------------------")
            return

        # If the driver didn't parse out the version, inspect the raw error string
        print("\n[-] Connection rejected, but no version parsed from standard string.")
        print(f"Raw Driver Error: {error_msg}")

    except Exception as e:
        print(f"\n[-] Unexpected network error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <Target_IP> [Port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433

    discover_version(target_ip, target_port)
