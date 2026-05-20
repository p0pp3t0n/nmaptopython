#!/bin/bash

# Check arguments
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <IP> [PORT]"
    echo "Default port is 1433"
    exit 1
fi

TARGET_IP="$1"
TARGET_PORT="${2:-1433}"

echo "[*] Querying MSSQL on $TARGET_IP:$TARGET_PORT via raw TDS handshake..."

# Fixed: Keep the payload strictly as a hex string to avoid Bash null-byte corruption
PRELOGIN_HEX="1201003200000000000015000601001b000102001c000c0300280004ff0b0002320000020000000000000000000000000000"

# Convert and pipe directly to Netcat in one stream
RESPONSE_HEX=$(echo "$PRELOGIN_HEX" | xxd -r -p | nc -N -w 3 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null | xxd -p | tr -d '\n')

# Fallback for older Netcat versions (-q 2 instead of -N)
if [ -z "$RESPONSE_HEX" ]; then
    RESPONSE_HEX=$(echo "$PRELOGIN_HEX" | xxd -r -p | nc -q 2 -w 3 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null | xxd -p | tr -d '\n')
fi

# Check if we got a response
if [ -z "$RESPONSE_HEX" ]; then
    echo "[-] Error: No response received from $TARGET_IP:$TARGET_PORT"
    echo "[-] Ensure no firewalls are dropping the payload packet."
    exit 1
fi

# Find the 'ff' delimiter that precedes the version payload
if [[ "$RESPONSE_HEX" =~ ff([0-9a-f]{12}) ]]; then
    # Strip everything except the 12 hex digits following 'ff'
    VERSION_BYTES="${BASH_REMATCH[1]}"
else
    echo "[-] Error: Could not find version block token in server response."
    echo "[-] Raw Response Hex: $RESPONSE_HEX"
    exit 1
fi

# Extract hex components
HEX_MAJOR="${VERSION_BYTES:0:2}"
HEX_MINOR="${VERSION_BYTES:2:2}"
HEX_BUILD_HIGH="${VERSION_BYTES:4:2}"
HEX_BUILD_LOW="${VERSION_BYTES:6:2}"

# Convert from Hex to Decimal
DEC_MAJOR=$((16#$HEX_MAJOR))
DEC_MINOR=$((16#$HEX_MINOR))
DEC_BUILD=$((16#$HEX_BUILD_HIGH * 256 + 16#$HEX_BUILD_LOW))

# Map Major Version to Marketing Name
case $DEC_MAJOR in
16) MARKETING="SQL Server 2022" ;;
15) MARKETING="SQL Server 2019" ;;
14) MARKETING="SQL Server 2017" ;;
13) MARKETING="SQL Server 2016" ;;
12) MARKETING="SQL Server 2014" ;;
11) MARKETING="SQL Server 2012" ;;
10) MARKETING="SQL Server 2008 / 2008 R2" ;;
9) MARKETING="SQL Server 2005" ;;
*) MARKETING="Unknown Version" ;;
esac

# Output the authoritative results
echo -e "\n[+] Discovery Successful!"
echo "-----------------------------------"
echo "Raw Version Bytes : $VERSION_BYTES"
echo "Marketing Name    : $MARKETING"
echo "Exact Build       : $DEC_MAJOR.$DEC_MINOR.$DEC_BUILD"
echo "-----------------------------------"
