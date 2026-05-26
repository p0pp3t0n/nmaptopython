#!/usr/bin/env bash
# infra-recon.sh — Parse nmap XML, run port-specific [UNAUTH] recon per the
# Infrastructure Internal Pentest Checklist (Phase 2).
#
# Single-file, no external dependencies beyond the recon tools themselves.
# Wordlists are embedded and extracted to a temp dir at runtime.
#
# Modes:
#   default   Banner grabs, version detection, null/anonymous checks, basic vuln scans
#   -D        Deep — adds nikto, nuclei, feroxbuster, testssl, enum4linux-ng
#   -B        Brute — adds hydra/netexec default-credential checks
#   -C        Tool check — verify all required/optional tools are installed, then exit
#
# Traffic: scales with number of hosts × open ports. Every command hits the wire.
set -uo pipefail

ORIGINAL_ARGS="$*"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# Logging — colored to terminal, plain-text to $LOG_FILE
LOG_FILE=""  # set after OUTDIR is known

_log_to_file() {
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"
}

log()  { echo -e "${CYAN}[*]${NC} $*";   _log_to_file "[*] $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*";  _log_to_file "[+] $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; _log_to_file "[!] $*"; }
err()  { echo -e "${RED}[-]${NC} $*";    _log_to_file "[-] $*"; }

usage() {
    cat <<'EOF'
Usage: infra-recon.sh -n <nmap.xml> [-o output_dir] [options]
       infra-recon.sh -C [-D] [-B]

Required (unless -C):
  -n FILE       Nmap XML (-oX) file

Modes:
  -C            Tool check — list all tools and their install status, then exit
  -D            Deep mode — slow tools: nikto, nuclei, feroxbuster, testssl, enum4linux-ng
  -B            Brute mode — default-credential checks (hydra, netexec)

Options:
  -o DIR        Output directory (default: recon_YYYYMMDD_HHMMSS)
  -d DOMAIN     Domain name for DNS/LDAP/Kerberos checks
  -H HOSTS      Comma-separated host filter
  -P PORTS      Comma-separated port filter
  -t SECS       Per-command timeout (default: 300)
  -T NUM        Max parallel tasks per host (default: 5)

Examples:
  infra-recon.sh -C                              # check tools
  infra-recon.sh -C -D -B                        # check all tools including deep + brute
  infra-recon.sh -n full_tcp.xml -o ./recon
  infra-recon.sh -n full_tcp.xml -o ./recon -D -B -d corp.local
  infra-recon.sh -n full_tcp.xml -o ./recon -P 80,443,445 -H 10.0.0.5
EOF
    exit 1
}

# ---------------------------------------------------------------------------
# Embedded wordlists — written to $OUTDIR/.wordlists/ at runtime
# ---------------------------------------------------------------------------
extract_wordlists() {
WL_DIR="$OUTDIR/.wordlists"
mkdir -p "$WL_DIR"

cat > "$WL_DIR/default-creds.txt" <<'WORDLIST'
admin:admin
admin:password
admin:Password
admin:Password1
admin:admin123
admin:123456
admin:1234
admin:12345
admin:
administrator:administrator
administrator:password
administrator:Password1
administrator:
root:root
root:toor
root:password
root:Password1
root:123456
root:
user:user
user:password
guest:guest
guest:
test:test
oracle:oracle
postgres:postgres
postgres:
ftp:ftp
anonymous:anonymous
anonymous:
cisco:cisco
cisco:
admin:cisco
enable:
admin:changeme
admin:default
admin:nas
admin:letmein
admin:admin1
admin:public
manager:manager
monitor:monitor
operator:operator
support:support
ubnt:ubnt
pi:raspberry
root:calvin
Administrator:password
Administrator:
ADMIN:ADMIN
tomcat:tomcat
tomcat:s3cret
tomcat:password
role1:role1
admin:tomcat
admin:jenkins
admin:changeme
sa:sa
sa:password
sa:Password1
sa:
dbadmin:dbadmin
mysql:mysql
root:mysql
admin:1234
admin:0000
admin:9999
admin:pfsense
admin:sophos
admin:fortinet
admin:Admin123
netscreen:netscreen
admin:amp111
admin:freepbx
WORDLIST

cat > "$WL_DIR/usernames.txt" <<'WORDLIST'
admin
administrator
root
user
test
guest
info
support
postmaster
webmaster
www
mail
ftp
backup
operator
monitor
nagios
zabbix
oracle
postgres
mysql
tomcat
jenkins
deploy
svc
service
www-data
nobody
daemon
WORDLIST

cat > "$WL_DIR/snmp-communities.txt" <<'WORDLIST'
public
private
community
snmp
mngt
cisco
cable-docsis
manager
admin
default
password
pass
secret
tivoli
openview
monitor
agent
ILMI
rmon
rmon_admin
hp_admin
security
internal
system
write
read
all
solaris
sun
freebsd
linux
router
switch
access
net
network
snmpd
test
guest
WORDLIST

cat > "$WL_DIR/infra-web.txt" <<'WORDLIST'
admin
admin/
administrator
administrator/
manager
manager/html
management
console
console/
dashboard
dashboard/
portal
portal/
cpanel
webadmin
sysadmin
admin/login
admin/index
admin-console
admin-panel
_admin
~admin
manager/html
manager/status
manager/text
host-manager
host-manager/html
tomcat
docs/
examples/
examples/servlets
examples/jsp
script
manage
login
asynchPeople
computer
systemInfo
log
pluginManager
configureSecurity
cli
api
api/json
api/xml
jmx-console
jmx-console/
web-console
web-console/
invoker/JMXInvokerServlet
invoker/EJBInvokerServlet
jbossws
jbossws/services
admin-console/
status
console/login/LoginForm.jsp
wls-wsat/CoordinatorPortType
wls-wsat/CoordinatorPortType11
_async/AsyncResponseService
bea_wls_deployment_internal
iisstart.htm
web.config
Web.config
aspnet_client
aspnet_client/
trace.axd
elmah.axd
elmah
phpinfo.php
info.php
php-info.php
test.php
debug.php
adminer.php
phpmyadmin
phpmyadmin/
pma
pma/
phpMyAdmin
phpMyAdmin/
mysql/
mysqladmin
wp-admin
wp-admin/
wp-login.php
wp-content
wp-content/
wp-content/uploads
wp-content/debug.log
wp-includes
wp-config.php
wp-config.php.bak
wp-config.php.old
wp-config.bak
wp-json
wp-json/wp/v2/users
xmlrpc.php
readme.html
CHANGELOG.txt
INSTALL.txt
user/login
admin/content
core/install.php
sites/default/settings.php
sites/default/files
configuration.php
configuration.php.bak
.env
.env.bak
.env.local
.env.production
.env.development
.env.old
.env.example
.htaccess
.htpasswd
.npmrc
.dockerenv
config.php
config.php.bak
config.inc.php
config.yml
config.yaml
config.json
config.xml
config.ini
database.yml
settings.php
settings.py
settings.ini
local.xml
app.config
appsettings.json
appsettings.Development.json
application.properties
application.yml
web.xml
server.xml
context.xml
crossdomain.xml
clientaccesspolicy.xml
.git
.git/
.git/HEAD
.git/config
.gitignore
.svn
.svn/
.svn/entries
.svn/wc.db
.hg
.hg/
.bzr
.DS_Store
backup
backup/
backups
backups/
bak
db.sql
dump.sql
database.sql
backup.sql
backup.tar.gz
backup.zip
site.zip
www.zip
web.zip
htdocs.zip
public.zip
old/
old
archive
archive/
temp
temp/
tmp
tmp/
server-status
server-info
server-status/
server-info/
nginx_status
stub_status
status
status/
health
health/
healthcheck
healthz
readyz
livez
ping
metrics
prometheus
monitoring
api
api/
api/v1
api/v2
api/docs
api/swagger
api/swagger-ui
api/swagger.json
api/swagger.yaml
swagger
swagger/
swagger-ui
swagger-ui/
swagger.json
swagger.yaml
openapi.json
openapi.yaml
graphql
graphiql
graphql/console
docs
docs/
doc
doc/
login
login/
signin
sign-in
auth
auth/
authenticate
logout
register
signup
sign-up
forgot-password
reset-password
sso
saml
oauth
oauth2
oauth/token
.well-known/openid-configuration
robots.txt
sitemap.xml
sitemap_index.xml
humans.txt
security.txt
.well-known/security.txt
favicon.ico
debug
debug/
test
test/
testing
cgi-bin
cgi-bin/
bin
bin/
shell
cmd
command
exec
remote
upload
upload/
uploads
uploads/
files
files/
download
downloads
static
assets
images
img
css
js
fonts
nagios
nagios/
cacti
cacti/
zabbix
zabbix/
munin
munin/
grafana
grafana/
kibana
kibana/
prometheus/
splunk
splunk/
graylog
elastic
elasticsearch
solr
solr/
actuator
actuator/health
actuator/env
actuator/info
actuator/beans
actuator/mappings
actuator/configprops
WORDLIST
}

# ---------------------------------------------------------------------------
# Tool check
# ---------------------------------------------------------------------------

TOOLS_CORE=(
    "nmap:port scanning and NSE scripts"
    "curl:HTTP probing, banner grabs"
    "nc:banner grabs, memcached, raw TCP"
    "netexec:SMB/FTP/RDP/WinRM/MSSQL checks"
    "sslscan:quick SSL/TLS cipher scan"
    "openssl:certificate inspection"
    "whatweb:web technology fingerprinting"
    "wafw00f:WAF detection"
    "ssh-audit:SSH config audit"
    "dig:DNS queries and zone transfers"
    "ldapsearch:LDAP anonymous bind tests"
    "showmount:NFS share enumeration"
    "rpcinfo:RPC service listing"
    "nbtscan:NetBIOS name scanning"
    "onesixtyone:SNMP community brute-force"
    "snmpwalk:SNMP enumeration"
    "snmp-check:SNMP formatted enumeration"
    "ipmitool:IPMI checks"
    "redis-cli:Redis no-auth checks"
    "mongosh:MongoDB no-auth check"
)

TOOLS_DEEP=(
    "nikto:web vulnerability scanner"
    "nuclei:template-based vuln scanner"
    "feroxbuster:directory brute-force"
    "testssl.sh:thorough SSL/TLS analysis"
    "enum4linux-ng:SMB/RPC full enumeration"
    "dnsrecon:DNS enumeration and brute-force"
    "kerbrute:Kerberos user enumeration"
    "odat:Oracle database attack tool"
)

TOOLS_BRUTE=(
    "hydra:multi-protocol credential brute-force"
    "smtp-user-enum:SMTP user enumeration"
    "mysql:MySQL client for default login test"
    "psql:PostgreSQL client for default login test"
)

# Tool name → Kali apt package name
declare -A APT_PKG=(
    [nmap]="nmap"
    [curl]="curl"
    [nc]="netcat-openbsd"
    [netexec]="netexec"
    [sslscan]="sslscan"
    [openssl]="openssl"
    [whatweb]="whatweb"
    [wafw00f]="wafw00f"
    [ssh-audit]="ssh-audit"
    [dig]="dnsutils"
    [ldapsearch]="ldap-utils"
    [showmount]="nfs-common"
    [rpcinfo]="rpcbind"
    [nbtscan]="nbtscan"
    [onesixtyone]="onesixtyone"
    [snmpwalk]="snmp"
    [snmp-check]="snmpcheck"
    [ipmitool]="ipmitool"
    [redis-cli]="redis-tools"
    [mongosh]="mongosh"
    [nikto]="nikto"
    [nuclei]="nuclei"
    [feroxbuster]="feroxbuster"
    [testssl.sh]="testssl.sh"
    [enum4linux-ng]="enum4linux"
    [dnsrecon]="dnsrecon"
    [odat]="odat"
    [hydra]="hydra"
    [smtp-user-enum]="smtp-user-enum"
    [mysql]="default-mysql-client"
    [psql]="postgresql-client"
)

check_tools() {
    local missing=0 total=0 found=0
    local missing_pkgs=()
    local missing_manual=()

    echo ""
    echo -e "${BOLD}=== Tool Check ===${NC}"
    echo ""

    _check_list() {
        local label="$1"; shift
        local entries=("$@")
        echo -e "${BOLD}${label}:${NC}"
        for entry in "${entries[@]}"; do
            local tool="${entry%%:*}" desc="${entry#*:}"
            total=$((total + 1))
            if command -v "$tool" &>/dev/null; then
                ok "$tool — $desc"
                found=$((found + 1))
            else
                err "$tool — $desc"
                missing=$((missing + 1))
                if [[ "$tool" == "kerbrute" ]]; then
                    missing_manual+=("kerbrute — https://github.com/ropnop/kerbrute/releases")
                elif [[ -n "${APT_PKG[$tool]:-}" ]]; then
                    missing_pkgs+=("${APT_PKG[$tool]}")
                else
                    missing_manual+=("$tool")
                fi
            fi
        done
    }

    _check_list "Core tools (quick mode)" "${TOOLS_CORE[@]}"

    if [[ $DEEP -eq 1 ]]; then
        echo ""
        _check_list "Deep mode tools (-D)" "${TOOLS_DEEP[@]}"
    fi

    if [[ $BRUTE -eq 1 ]]; then
        echo ""
        _check_list "Brute mode tools (-B)" "${TOOLS_BRUTE[@]}"
    fi

    echo ""
    if [[ $missing -eq 0 ]]; then
        ok "All $total tools installed"
    else
        warn "$found/$total tools installed, $missing missing"
        if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
            echo ""
            log "Install missing tools:"
            log "  sudo apt install ${missing_pkgs[*]}"
        fi
        if [[ ${#missing_manual[@]} -gt 0 ]]; then
            echo ""
            log "Manual install:"
            for item in "${missing_manual[@]}"; do
                log "  $item"
            done
        fi
    fi

    return $missing
}

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NMAP_FILE="" OUTDIR="" DEEP=0 BRUTE=0 DOMAIN="" HOST_FILTER="" PORT_FILTER=""
CMD_TIMEOUT=300 MAX_PARALLEL=5 CHECK_ONLY=0

while getopts "n:o:DBCd:H:P:t:T:h" opt; do
    case $opt in
        n) NMAP_FILE="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        D) DEEP=1 ;;
        B) BRUTE=1 ;;
        C) CHECK_ONLY=1 ;;
        d) DOMAIN="$OPTARG" ;;
        H) HOST_FILTER="$OPTARG" ;;
        P) PORT_FILTER="$OPTARG" ;;
        t) CMD_TIMEOUT="$OPTARG" ;;
        T) MAX_PARALLEL="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# Tool check mode
if [[ $CHECK_ONLY -eq 1 ]]; then
    check_tools
    exit $?
fi

[[ -z "$NMAP_FILE" ]] && usage
[[ ! -f "$NMAP_FILE" ]] && { err "File not found: $NMAP_FILE"; exit 1; }
[[ -z "$OUTDIR" ]] && OUTDIR="recon_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTDIR"
extract_wordlists

# Initialize log file
LOG_FILE="$OUTDIR/infra-recon.log"
{
    echo "================================================================"
    echo "infra-recon.sh — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Command: $0 $ORIGINAL_ARGS"
    echo "Working directory: $(pwd)"
    echo "================================================================"
    echo ""
} > "$LOG_FILE"

# ---------------------------------------------------------------------------
# Parse nmap XML — pure awk, no external deps
# ---------------------------------------------------------------------------
# Emit lines: HOST|HOSTNAME|PORT|PROTO|SERVICE|PRODUCT|VERSION
parse_nmap() {
    awk '
    /<host[> ]/ { in_host=1; addr=""; hostname=""; host_up=0 }
    /<\/host>/ { in_host=0 }

    in_host && /status.*state="up"/ { host_up=1 }

    in_host && /address.*addrtype="ipv4"/ {
        match($0, /addr="([^"]*)"/, m)
        addr = m[1]
    }

    in_host && /<hostname / {
        match($0, /name="([^"]*)"/, m)
        hostname = m[1]
    }

    in_host && host_up && /<port / {
        match($0, /protocol="([^"]*)"/, m); proto = m[1]
        match($0, /portid="([^"]*)"/, m); portid = m[1]
        port_open = 0; svc_name = ""; svc_product = ""; svc_version = ""
    }

    in_host && /state="open"/ { port_open = 1 }

    in_host && /<service / {
        if (match($0, /name="([^"]*)"/, m)) svc_name = m[1]
        if (match($0, /product="([^"]*)"/, m)) svc_product = m[1]
        if (match($0, /version="([^"]*)"/, m)) svc_version = m[1]
    }

    in_host && /<\/port>/ {
        if (host_up && port_open && addr != "" && portid != "") {
            print addr "|" hostname "|" portid "|" proto "|" svc_name "|" svc_product "|" svc_version
        }
    }
    ' "$1"
}

declare -A HOST_PORTS  # host -> "port:service ..."
declare -A HOST_NAMES  # host -> hostname

while IFS='|' read -r addr hostname port proto svc product version; do
    [[ -z "$addr" || -z "$port" ]] && continue

    # Apply filters
    if [[ -n "$HOST_FILTER" ]]; then
        echo ",$HOST_FILTER," | grep -q ",$addr," || continue
    fi
    if [[ -n "$PORT_FILTER" ]]; then
        echo ",$PORT_FILTER," | grep -q ",$port," || continue
    fi

    HOST_PORTS["$addr"]+="$port:$svc:$product:$version "
    [[ -n "$hostname" ]] && HOST_NAMES["$addr"]="$hostname"
done < <(parse_nmap "$NMAP_FILE")

if [[ ${#HOST_PORTS[@]} -eq 0 ]]; then
    err "No hosts with open ports found (after filters)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Service classifier
# ---------------------------------------------------------------------------
classify_port() {
    local port="$1" svc="$2"
    case "$port" in
        21)                     echo "ftp" ;;
        22)                     echo "ssh" ;;
        23)                     echo "telnet" ;;
        25|465|587)             echo "smtp" ;;
        53)                     echo "dns" ;;
        69)                     echo "tftp" ;;
        80|8080|8888)
            case "$svc" in *https*|*ssl*) echo "https" ;; *) echo "http" ;; esac ;;
        443|8443)               echo "https" ;;
        88)                     echo "kerberos" ;;
        110|995)                echo "pop3" ;;
        143|993)                echo "imap" ;;
        111)                    echo "rpc" ;;
        2049)                   echo "nfs" ;;
        135|445)                echo "smb" ;;
        139)                    echo "netbios" ;;
        161|162)                echo "snmp" ;;
        389)                    echo "ldap" ;;
        636)                    echo "ldaps" ;;
        623)                    echo "ipmi" ;;
        1433)                   echo "mssql" ;;
        1521)                   echo "oracle" ;;
        3306)                   echo "mysql" ;;
        3389)                   echo "rdp" ;;
        5432)                   echo "postgres" ;;
        5900|5901)              echo "vnc" ;;
        5985|5986)              echo "winrm" ;;
        6379)                   echo "redis" ;;
        11211)                  echo "memcached" ;;
        27017)                  echo "mongodb" ;;
        *)
            case "$svc" in
                ftp)                    echo "ftp" ;;
                ssh)                    echo "ssh" ;;
                telnet)                 echo "telnet" ;;
                smtp|smtps|submission)  echo "smtp" ;;
                domain|dns)             echo "dns" ;;
                tftp)                   echo "tftp" ;;
                http|http-proxy|http-alt) echo "http" ;;
                https|https-alt|ssl/http) echo "https" ;;
                kerberos*)              echo "kerberos" ;;
                pop3*)                  echo "pop3" ;;
                imap*)                  echo "imap" ;;
                rpcbind|sunrpc)         echo "rpc" ;;
                nfs)                    echo "nfs" ;;
                microsoft-ds|msrpc)     echo "smb" ;;
                netbios-ssn)            echo "netbios" ;;
                snmp)                   echo "snmp" ;;
                ldap)                   echo "ldap" ;;
                ldaps)                  echo "ldaps" ;;
                asf-rmcp)               echo "ipmi" ;;
                ms-sql*)                echo "mssql" ;;
                oracle*)                echo "oracle" ;;
                mysql|mariadb)          echo "mysql" ;;
                ms-wbt-server)          echo "rdp" ;;
                postgresql)             echo "postgres" ;;
                vnc*)                   echo "vnc" ;;
                wsman*)                 echo "winrm" ;;
                redis)                  echo "redis" ;;
                memcache*)              echo "memcached" ;;
                mongod*)                echo "mongodb" ;;
                *)                      echo "" ;;
            esac
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Task runner with parallelism + timeout
# ---------------------------------------------------------------------------
RESULTS_LOG="$OUTDIR/results.csv"
echo "STATUS|HOST|PORT|SERVICE|TASK|SUMMARY" > "$RESULTS_LOG"
PARALLEL_PIDS=()

has_tool() { command -v "$1" &>/dev/null; }

run_task() {
    local host="$1" port="$2" svc="$3" name="$4" outfile="$5"
    shift 5
    local cmd="$*"
    local tool="${cmd%% *}"

    if ! has_tool "$tool"; then
        echo "# [SKIP] tool not found: $tool" > "$outfile"
        echo -e "  ${YELLOW}~${NC} ${host}:${port}/${svc} — ${name}: tool not found: ${tool}"
        echo "SKIP|$host|$port|$svc|$name|tool not found: $tool" >> "$RESULTS_LOG"
        _log_to_file "  [~] ${host}:${port}/${svc} — ${name}: SKIP tool not found: ${tool}"
        return
    fi

    _log_to_file "  [>] ${host}:${port}/${svc} — ${name}: STARTED  cmd=${cmd}"

    {
        echo "# Command: $cmd"
        echo "# Timestamp: $(date -Iseconds)"
        echo ""
        timeout "$CMD_TIMEOUT" bash -c "$cmd" 2>&1
        local rc=$?
        echo ""
        echo "# Exit code: $rc"
    } > "$outfile" 2>&1

    local rc
    rc=$(tail -1 "$outfile" | grep -oP '(?<=Exit code: )\d+' || echo "1")
    local summary
    summary=$(grep -v '^#' "$outfile" | grep -v '^\s*$' | head -1 | cut -c1-120)
    [[ -z "$summary" ]] && summary="(empty output)"

    if [[ "$rc" == "0" ]]; then
        echo -e "  ${GREEN}+${NC} ${host}:${port}/${svc} — ${name}: ${summary}"
        echo "OK|$host|$port|$svc|$name|$summary" >> "$RESULTS_LOG"
        _log_to_file "  [+] ${host}:${port}/${svc} — ${name}: OK  ${summary}"
    elif [[ "$rc" == "124" ]]; then
        echo -e "  ${RED}-${NC} ${host}:${port}/${svc} — ${name}: timeout after ${CMD_TIMEOUT}s"
        echo "FAIL|$host|$port|$svc|$name|timeout after ${CMD_TIMEOUT}s" >> "$RESULTS_LOG"
        _log_to_file "  [-] ${host}:${port}/${svc} — ${name}: TIMEOUT after ${CMD_TIMEOUT}s"
    else
        echo -e "  ${RED}-${NC} ${host}:${port}/${svc} — ${name}: ${summary}"
        echo "FAIL|$host|$port|$svc|$name|$summary" >> "$RESULTS_LOG"
        _log_to_file "  [-] ${host}:${port}/${svc} — ${name}: FAIL rc=${rc}  ${summary}"
    fi

    # Append full tool output to main log
    if [[ -n "$LOG_FILE" ]]; then
        {
            echo "--- [$(date '+%H:%M:%S')] ${host}:${port}/${svc}/${name} ---"
            cat "$outfile"
            echo "--- END ${name} ---"
            echo ""
        } >> "$LOG_FILE"
    fi
}

run_bg() {
    while [[ ${#PARALLEL_PIDS[@]} -ge $MAX_PARALLEL ]]; do
        local new_pids=()
        for pid in "${PARALLEL_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                new_pids+=("$pid")
            fi
        done
        PARALLEL_PIDS=("${new_pids[@]}")
        [[ ${#PARALLEL_PIDS[@]} -ge $MAX_PARALLEL ]] && sleep 0.5
    done
    run_task "$@" &
    PARALLEL_PIDS+=($!)
}

wait_all() {
    for pid in "${PARALLEL_PIDS[@]}"; do
        wait "$pid" 2>/dev/null
    done
    PARALLEL_PIDS=()
}

# ---------------------------------------------------------------------------
# Recon modules
# ---------------------------------------------------------------------------

recon_ftp() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" ftp nmap-ftp "$d/nmap_ftp.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    run_bg "$host" "$port" ftp ftp-anon "$d/ftp_anon.txt" \
        "netexec ftp $host -p $port -u 'anonymous' -p ''"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" ftp ftp-default-creds "$d/ftp_defaults.txt" \
            "hydra -C $WL_DIR/default-creds.txt -s $port $host ftp -t 4"
    fi
}

recon_ssh() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" ssh nmap-ssh "$d/nmap_ssh.txt" \
        "nmap -Pn -sV -p $port $host"
    run_bg "$host" "$port" ssh ssh-audit "$d/ssh_audit.txt" \
        "ssh-audit -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" ssh ssh-default-creds "$d/ssh_defaults.txt" \
            "hydra -C $WL_DIR/default-creds.txt -s $port $host ssh -t 4"
    fi
}

recon_telnet() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" telnet nmap-telnet "$d/nmap_telnet.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    run_bg "$host" "$port" telnet banner-grab "$d/banner.txt" \
        "echo '' | nc -w 5 -nv $host $port 2>&1 || true"
}

recon_smtp() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" smtp nmap-smtp "$d/nmap_smtp.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    run_bg "$host" "$port" smtp smtp-open-relay "$d/smtp_relay.txt" \
        "nmap -Pn --script smtp-open-relay -p $port $host"
    run_bg "$host" "$port" smtp smtp-ntlm-info "$d/smtp_ntlm.txt" \
        "nmap -Pn --script smtp-ntlm-info -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" smtp smtp-user-enum "$d/smtp_users.txt" \
            "smtp-user-enum -M VRFY -U $WL_DIR/usernames.txt -t $host -p $port"
    fi
}

recon_dns() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" dns nmap-dns "$d/nmap_dns.txt" \
        "nmap -Pn -sV -p $port $host"
    run_bg "$host" "$port" dns dns-version "$d/dns_version.txt" \
        "dig @$host version.bind chaos txt +short"
    if [[ -n "$DOMAIN" ]]; then
        run_bg "$host" "$port" dns zone-transfer "$d/zone_transfer.txt" \
            "dig axfr $DOMAIN @$host"
        run_bg "$host" "$port" dns reverse-dns "$d/reverse_dns.txt" \
            "dnsrecon -r $host/24 -n $host 2>&1 | head -100"
    fi
    if [[ $DEEP -eq 1 ]]; then
        run_bg "$host" "$port" dns dns-cache-snoop "$d/dns_cache.txt" \
            "nmap -Pn --script dns-cache-snoop -p $port $host"
        if [[ -n "$DOMAIN" ]]; then
            run_bg "$host" "$port" dns dns-enum "$d/dns_enum.txt" \
                "dnsrecon -d $DOMAIN -n $host -t std,brt,axfr 2>&1 | head -200"
        fi
    fi
}

recon_tftp() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" tftp nmap-tftp "$d/nmap_tftp.txt" \
        "nmap -Pn -sU -p $port --script tftp-enum $host"
}

recon_http() {
    local host="$1" port="$2" d="$3" scheme="$4"
    local url="${scheme}://${host}:${port}"

    run_bg "$host" "$port" "$scheme" nmap-http "$d/nmap_http.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    run_bg "$host" "$port" "$scheme" http-headers "$d/http_headers.txt" \
        "curl -skI -m 10 $url"
    run_bg "$host" "$port" "$scheme" robots-txt "$d/robots_txt.txt" \
        "curl -sk -m 10 $url/robots.txt"
    run_bg "$host" "$port" "$scheme" sitemap-xml "$d/sitemap_xml.txt" \
        "curl -sk -m 10 $url/sitemap.xml"
    run_bg "$host" "$port" "$scheme" http-methods "$d/http_methods.txt" \
        "nmap -Pn --script http-methods -p $port $host"
    run_bg "$host" "$port" "$scheme" whatweb "$d/whatweb.txt" \
        "whatweb -a 3 --color=never $url"
    run_bg "$host" "$port" "$scheme" wafw00f "$d/wafw00f.txt" \
        "wafw00f $url"
    run_bg "$host" "$port" "$scheme" sensitive-files "$d/sensitive_files.txt" \
        "for path in .env .git/HEAD web.config phpinfo.php server-status server-info wp-config.php .htaccess; do code=\$(curl -sk -o /dev/null -w '%{http_code}' -m 5 $url/\$path); echo \"\$code \$path\"; done"

    if [[ "$scheme" == "https" ]]; then
        run_bg "$host" "$port" https ssl-scan "$d/sslscan.txt" \
            "sslscan --no-colour ${host}:${port}"
        run_bg "$host" "$port" https ssl-cert "$d/ssl_cert.txt" \
            "echo | openssl s_client -connect ${host}:${port} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"
        if [[ $DEEP -eq 1 ]]; then
            run_bg "$host" "$port" https testssl "$d/testssl.txt" \
                "testssl.sh --quiet --color 0 ${host}:${port}"
        fi
    fi

    if [[ $DEEP -eq 1 ]]; then
        run_bg "$host" "$port" "$scheme" nikto "$d/nikto.txt" \
            "nikto -h $url -o $d/nikto_raw.txt -Format txt -maxtime 300"
        run_bg "$host" "$port" "$scheme" nuclei "$d/nuclei.txt" \
            "nuclei -u $url -as -rl 50 -nc -o $d/nuclei_raw.txt"
        run_bg "$host" "$port" "$scheme" feroxbuster "$d/feroxbuster.txt" \
            "feroxbuster -u $url -w $WL_DIR/infra-web.txt -k --no-state -q -o $d/feroxbuster_raw.txt"
    fi
}

recon_kerberos() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" kerberos nmap-kerberos "$d/nmap_kerberos.txt" \
        "nmap -Pn -sV -p $port $host"
    if [[ -n "$DOMAIN" && $DEEP -eq 1 ]]; then
        run_bg "$host" "$port" kerberos kerbrute-enum "$d/kerbrute.txt" \
            "kerbrute userenum -d $DOMAIN --dc $host $WL_DIR/usernames.txt --output $d/kerbrute_valid.txt 2>&1 | tail -30"
    fi
}

recon_pop3() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" pop3 nmap-pop3 "$d/nmap_pop3.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" pop3 pop3-brute "$d/pop3_brute.txt" \
            "hydra -C $WL_DIR/default-creds.txt -s $port $host pop3 -t 4"
    fi
}

recon_imap() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" imap nmap-imap "$d/nmap_imap.txt" \
        "nmap -Pn -sV -sC -p $port $host"
    run_bg "$host" "$port" imap imap-ntlm-info "$d/imap_ntlm.txt" \
        "nmap -Pn --script imap-ntlm-info -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" imap imap-brute "$d/imap_brute.txt" \
            "hydra -C $WL_DIR/default-creds.txt -s $port $host imap -t 4"
    fi
}

recon_rpc() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" rpc rpcinfo "$d/rpcinfo.txt" \
        "rpcinfo -p $host"
    run_bg "$host" "$port" rpc nmap-rpc "$d/nmap_rpc.txt" \
        "nmap -Pn -sV -p $port --script rpcinfo $host"
}

recon_nfs() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" nfs showmount "$d/showmount.txt" \
        "showmount -e $host"
    run_bg "$host" "$port" nfs nmap-nfs "$d/nmap_nfs.txt" \
        "nmap -Pn -sV -p $port --script nfs-ls,nfs-showmount,nfs-statfs $host"
}

recon_smb() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" smb smb-protocols "$d/smb_protocols.txt" \
        "nmap -Pn -sV -p 445 --script smb-protocols $host"
    run_bg "$host" "$port" smb smb-null-session "$d/smb_null.txt" \
        "netexec smb $host -u '' -p '' --shares --users --groups"
    run_bg "$host" "$port" smb smb-guest-session "$d/smb_guest.txt" \
        "netexec smb $host -u 'guest' -p '' --shares"
    run_bg "$host" "$port" smb smb-signing "$d/smb_signing.txt" \
        "netexec smb $host --gen-relay-list $d/nosigning.txt"
    run_bg "$host" "$port" smb ms17-010 "$d/ms17_010.txt" \
        "nmap -Pn --script smb-vuln-ms17-010 -p 445 $host"
    run_bg "$host" "$port" smb smbghost "$d/smbghost.txt" \
        "nmap -Pn --script smb-vuln-cve-2020-0796 -p 445 $host"
    if [[ $DEEP -eq 1 ]]; then
        run_bg "$host" "$port" smb enum4linux-ng "$d/enum4linux.txt" \
            "enum4linux-ng -A $host 2>&1 | head -300"
    fi
}

recon_netbios() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" netbios nbtscan "$d/nbtscan.txt" \
        "nbtscan $host"
}

recon_snmp() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" snmp community-brute "$d/community_brute.txt" \
        "onesixtyone -c $WL_DIR/snmp-communities.txt $host"
    run_bg "$host" "$port" snmp snmpwalk-public "$d/snmpwalk_public.txt" \
        "snmpwalk -v2c -c public $host 2>&1 | head -200"
    run_bg "$host" "$port" snmp snmp-check "$d/snmp_check.txt" \
        "snmp-check $host 2>&1 | head -300"
}

recon_ldap() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" ldap ldap-rootdse "$d/ldap_rootdse.txt" \
        "nmap -Pn -p $port --script ldap-rootdse $host"
    run_bg "$host" "$port" ldap ldap-anon-bind "$d/ldap_anon.txt" \
        "ldapsearch -H ldap://${host}:${port} -x -s base namingcontexts"
    if [[ -n "$DOMAIN" && $DEEP -eq 1 ]]; then
        local basedn
        basedn=$(echo "$DOMAIN" | sed 's/\./,DC=/g; s/^/DC=/')
        run_bg "$host" "$port" ldap ldap-anon-dump "$d/ldap_dump.txt" \
            "ldapsearch -H ldap://${host}:${port} -x -b '$basedn' '(objectClass=*)' cn 2>&1 | head -200"
    fi
}

recon_ldaps() {
    local host="$1" port="$2" d="$3"
    recon_ldap "$host" "$port" "$d"
    run_bg "$host" "$port" ldaps ldaps-cert "$d/ldaps_cert.txt" \
        "echo | openssl s_client -connect ${host}:${port} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"
}

recon_ipmi() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" ipmi nmap-ipmi "$d/nmap_ipmi.txt" \
        "nmap -Pn -sU -p $port --script ipmi-version $host"
    run_bg "$host" "$port" ipmi cipher-zero "$d/cipher_zero.txt" \
        "ipmitool -I lanplus -C 0 -H $host -U '' -P '' user list 2>&1"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" ipmi ipmi-dell "$d/ipmi_dell.txt" \
            "ipmitool -I lanplus -H $host -U root -P calvin user list 2>&1"
        run_bg "$host" "$port" ipmi ipmi-hp "$d/ipmi_hp.txt" \
            "ipmitool -I lanplus -H $host -U Administrator -P password user list 2>&1"
        run_bg "$host" "$port" ipmi ipmi-sm "$d/ipmi_sm.txt" \
            "ipmitool -I lanplus -H $host -U ADMIN -P ADMIN user list 2>&1"
    fi
}

recon_mssql() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" mssql nmap-mssql "$d/nmap_mssql.txt" \
        "nmap -Pn -sV -p $port --script ms-sql-info $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" mssql mssql-default-sa "$d/mssql_defaults.txt" \
            "netexec mssql $host -p $port -u sa -p 'sa' 2>&1; netexec mssql $host -p $port -u sa -p 'password' 2>&1; netexec mssql $host -p $port -u sa -p '' 2>&1"
    fi
}

recon_oracle() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" oracle nmap-oracle "$d/nmap_oracle.txt" \
        "nmap -Pn -sV -p $port --script oracle-tns-version $host"
    if [[ $BRUTE -eq 1 && $DEEP -eq 1 ]]; then
        run_bg "$host" "$port" oracle odat-sid "$d/odat_sid.txt" \
            "odat sidguesser -s $host -p $port 2>&1 | head -50"
    fi
}

recon_mysql() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" mysql nmap-mysql "$d/nmap_mysql.txt" \
        "nmap -Pn -sV -p $port --script mysql-info $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" mysql mysql-anon-root "$d/mysql_anon.txt" \
            "mysql -h $host -P $port -u root --connect-timeout=5 -e 'SELECT VERSION();' 2>&1"
    fi
}

recon_rdp() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" rdp nmap-rdp "$d/nmap_rdp.txt" \
        "nmap -Pn -sV -p $port --script rdp-enum-encryption,rdp-ntlm-info $host"
    run_bg "$host" "$port" rdp bluekeep "$d/bluekeep.txt" \
        "nmap -Pn -p $port --script rdp-vuln-ms12-020 $host"
}

recon_postgres() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" postgres nmap-postgres "$d/nmap_postgres.txt" \
        "nmap -Pn -sV -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" postgres pg-default "$d/pg_default.txt" \
            "PGCONNECT_TIMEOUT=5 psql -h $host -p $port -U postgres -c 'SELECT version();' 2>&1"
    fi
}

recon_vnc() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" vnc nmap-vnc "$d/nmap_vnc.txt" \
        "nmap -Pn -sV -p $port $host"
    run_bg "$host" "$port" vnc vnc-info "$d/vnc_info.txt" \
        "nmap -Pn --script vnc-info -p $port $host"
    if [[ $BRUTE -eq 1 ]]; then
        run_bg "$host" "$port" vnc vnc-brute "$d/vnc_brute.txt" \
            "hydra -C $WL_DIR/default-creds.txt -s $port $host vnc -t 4"
    fi
}

recon_winrm() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" winrm nmap-winrm "$d/nmap_winrm.txt" \
        "nmap -Pn -sV -p $port $host"
}

recon_redis() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" redis redis-ping "$d/redis_ping.txt" \
        "redis-cli -h $host -p $port ping"
    run_bg "$host" "$port" redis redis-info "$d/redis_info.txt" \
        "redis-cli -h $host -p $port info 2>&1 | head -80"
    run_bg "$host" "$port" redis redis-keys "$d/redis_keys.txt" \
        "redis-cli -h $host -p $port --no-auth-warning KEYS '*' 2>&1 | head -50"
}

recon_memcached() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" memcached memcached-stats "$d/memcached_stats.txt" \
        "echo 'stats' | nc -w 3 $host $port"
    run_bg "$host" "$port" memcached memcached-items "$d/memcached_items.txt" \
        "echo 'stats items' | nc -w 3 $host $port"
}

recon_mongodb() {
    local host="$1" port="$2" d="$3"
    run_bg "$host" "$port" mongodb nmap-mongodb "$d/nmap_mongodb.txt" \
        "nmap -Pn -sV -p $port --script mongodb-info $host"
    run_bg "$host" "$port" mongodb mongodb-noauth "$d/mongodb_noauth.txt" \
        "mongosh --host $host --port $port --eval 'db.adminCommand({listDatabases:1})' --quiet 2>&1 || mongo --host $host --port $port --eval 'db.adminCommand({listDatabases:1})' --quiet 2>&1"
}

# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------
dispatch_service() {
    local svc="$1" host="$2" port="$3" d="$4"
    case "$svc" in
        ftp)        recon_ftp       "$host" "$port" "$d" ;;
        ssh)        recon_ssh       "$host" "$port" "$d" ;;
        telnet)     recon_telnet    "$host" "$port" "$d" ;;
        smtp)       recon_smtp      "$host" "$port" "$d" ;;
        dns)        recon_dns       "$host" "$port" "$d" ;;
        tftp)       recon_tftp      "$host" "$port" "$d" ;;
        http)       recon_http      "$host" "$port" "$d" http ;;
        https)      recon_http      "$host" "$port" "$d" https ;;
        kerberos)   recon_kerberos  "$host" "$port" "$d" ;;
        pop3)       recon_pop3      "$host" "$port" "$d" ;;
        imap)       recon_imap      "$host" "$port" "$d" ;;
        rpc)        recon_rpc       "$host" "$port" "$d" ;;
        nfs)        recon_nfs       "$host" "$port" "$d" ;;
        smb)        recon_smb       "$host" "$port" "$d" ;;
        netbios)    recon_netbios   "$host" "$port" "$d" ;;
        snmp)       recon_snmp      "$host" "$port" "$d" ;;
        ldap)       recon_ldap      "$host" "$port" "$d" ;;
        ldaps)      recon_ldaps     "$host" "$port" "$d" ;;
        ipmi)       recon_ipmi      "$host" "$port" "$d" ;;
        mssql)      recon_mssql     "$host" "$port" "$d" ;;
        oracle)     recon_oracle    "$host" "$port" "$d" ;;
        mysql)      recon_mysql     "$host" "$port" "$d" ;;
        rdp)        recon_rdp       "$host" "$port" "$d" ;;
        postgres)   recon_postgres  "$host" "$port" "$d" ;;
        vnc)        recon_vnc       "$host" "$port" "$d" ;;
        winrm)      recon_winrm     "$host" "$port" "$d" ;;
        redis)      recon_redis     "$host" "$port" "$d" ;;
        memcached)  recon_memcached "$host" "$port" "$d" ;;
        mongodb)    recon_mongodb   "$host" "$port" "$d" ;;
        *)          warn "No recon module for service: $svc" ;;
    esac
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------
generate_report() {
    local report="$OUTDIR/summary.md"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$report" <<EOF
# Infrastructure Recon Summary

- **Generated**: $ts
- **Nmap input**: \`$NMAP_FILE\`
- **Mode**: $([ $DEEP -eq 1 ] && echo "deep" || echo "quick")$([ $BRUTE -eq 1 ] && echo " + brute" || echo "")
$([ -n "$DOMAIN" ] && echo "- **Domain**: \`$DOMAIN\`")
- **Hosts scanned**: ${#HOST_PORTS[@]}

## Host / Service Matrix

| Host | Hostname | Open Ports | Services |
|------|----------|------------|----------|
EOF

    for host in $(echo "${!HOST_PORTS[@]}" | tr ' ' '\n' | sort); do
        local hn="${HOST_NAMES[$host]:-}"
        local ports_raw="${HOST_PORTS[$host]}"
        local port_nums="" svcs=""
        for entry in $ports_raw; do
            local p="${entry%%:*}"
            local rest="${entry#*:}"
            local s="${rest%%:*}"
            local svc_key
            svc_key=$(classify_port "$p" "$s")
            port_nums+="$p, "
            [[ -n "$svc_key" ]] && svcs+="${p}/${svc_key}, "
        done
        port_nums="${port_nums%, }"
        svcs="${svcs%, }"
        echo "| $host | $hn | $port_nums | $svcs |" >> "$report"
    done

    local interesting
    interesting=$(grep '^OK|' "$RESULTS_LOG" | grep -iE 'anonymous|vulnerable|open relay|no auth|PONG|cipher.0|no_root_squash|Pwn3d|guest|null session|signing not required|listdatabases|200 \.env|200 \.git' || true)
    if [[ -n "$interesting" ]]; then
        echo "" >> "$report"
        echo "## Interesting Findings" >> "$report"
        echo "" >> "$report"
        echo "These deserve immediate manual follow-up:" >> "$report"
        echo "" >> "$report"
        while IFS='|' read -r status host port svc task summary; do
            echo "- **${host}:${port}/${svc}** — \`${task}\`: ${summary}" >> "$report"
        done <<< "$interesting"
    fi

    local missing
    missing=$(grep '^SKIP|' "$RESULTS_LOG" | sed 's/.*tool not found: //' | sort -u || true)
    if [[ -n "$missing" ]]; then
        echo "" >> "$report"
        echo "## Missing Tools" >> "$report"
        echo "" >> "$report"
        echo "Install these for full coverage:" >> "$report"
        echo "" >> "$report"
        while read -r tool; do
            echo "- \`$tool\`" >> "$report"
        done <<< "$missing"
    fi

    local fail_count
    fail_count=$(grep -c '^FAIL|' "$RESULTS_LOG" 2>/dev/null || echo "0")
    if [[ "$fail_count" -gt 0 ]]; then
        echo "" >> "$report"
        echo "## Failed Tasks ($fail_count)" >> "$report"
        echo "" >> "$report"
        grep '^FAIL|' "$RESULTS_LOG" | while IFS='|' read -r status host port svc task summary; do
            echo "- ${host}:${port}/${svc} — \`${task}\`: ${summary}" >> "$report"
        done
    fi

    echo "" >> "$report"
    echo "---" >> "$report"
    echo "*Generated by infra-recon.sh*" >> "$report"

    echo "$report"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

mode_label="quick"
[[ $DEEP -eq 1 ]] && mode_label="deep"
[[ $BRUTE -eq 1 ]] && mode_label="$mode_label + brute"

echo ""
echo -e "${BOLD}=== Infrastructure Recon ===${NC}"
log "Nmap input: $NMAP_FILE"
log "Output:     $OUTDIR"
log "Mode:       $mode_label"
log "Timeout:    ${CMD_TIMEOUT}s per command"
log "Parallel:   $MAX_PARALLEL tasks per host"
[[ -n "$DOMAIN" ]] && log "Domain:     $DOMAIN"
echo ""

total_ports=0
for host in $(echo "${!HOST_PORTS[@]}" | tr ' ' '\n' | sort); do
    count=$(echo "${HOST_PORTS[$host]}" | wc -w)
    total_ports=$((total_ports + count))
done
log "Targets: ${#HOST_PORTS[@]} host(s), $total_ports open port(s)"

declare -A SVC_COUNTS
for host in "${!HOST_PORTS[@]}"; do
    for entry in ${HOST_PORTS[$host]}; do
        local_port="${entry%%:*}"
        local_rest="${entry#*:}"
        local_svc="${local_rest%%:*}"
        svc_key=$(classify_port "$local_port" "$local_svc")
        [[ -z "$svc_key" ]] && svc_key="unknown"
        SVC_COUNTS["$svc_key"]=$(( ${SVC_COUNTS["$svc_key"]:-0} + 1 ))
    done
done
breakdown=""
for key in $(echo "${!SVC_COUNTS[@]}" | tr ' ' '\n' | sort); do
    breakdown+="${key}=${SVC_COUNTS[$key]}, "
done
log "Services:   ${breakdown%, }"
echo ""

for host in $(echo "${!HOST_PORTS[@]}" | tr ' ' '\n' | sort); do
    hn="${HOST_NAMES[$host]:-}"
    label="$host"
    [[ -n "$hn" ]] && label="$host ($hn)"
    port_count=$(echo "${HOST_PORTS[$host]}" | wc -w)

    log "Starting recon on $label — $port_count open port(s)"

    seen_services=""
    for entry in ${HOST_PORTS[$host]}; do
        port="${entry%%:*}"
        rest="${entry#*:}"
        svc_name="${rest%%:*}"
        svc_key=$(classify_port "$port" "$svc_name")

        if [[ -z "$svc_key" ]]; then
            warn "  ${host}:${port} ($svc_name) — no matching checklist module, skipping"
            continue
        fi

        dedup="${svc_key}_${port}"
        echo "$seen_services" | grep -q "$dedup" && continue
        seen_services+=" $dedup"

        svc_dir="$OUTDIR/$host/${port}_${svc_key}"
        mkdir -p "$svc_dir"

        dispatch_service "$svc_key" "$host" "$port" "$svc_dir"
    done

    wait_all
    echo ""
done

report_path=$(generate_report)
ok_count=$(grep -c '^OK|' "$RESULTS_LOG" 2>/dev/null || echo "0")
fail_count=$(grep -c '^FAIL|' "$RESULTS_LOG" 2>/dev/null || echo "0")
skip_count=$(grep -c '^SKIP|' "$RESULTS_LOG" 2>/dev/null || echo "0")

echo -e "${BOLD}=== Done ===${NC}"
ok "Tasks: $ok_count succeeded, $fail_count failed, $skip_count skipped (missing tools)"
ok "Report:  $report_path"
ok "Results: $RESULTS_LOG"
ok "Log:     $LOG_FILE"
ok "Output:  $OUTDIR/"
