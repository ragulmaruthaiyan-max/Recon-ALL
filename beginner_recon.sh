#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#   recon_all.sh — All-in-One Reconnaissance Script
#   Covers: nmap, whois, dig, theHarvester, subdomain enum, OSINT
#   Usage  : ./recon_all.sh <target> [options]
#   Example: ./recon_all.sh example.com
#            ./recon_all.sh 192.168.1.1
# ══════════════════════════════════════════════════════════════════════════════

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ── Globals ───────────────────────────────────────────────────────────────────
TARGET=""
OUTPUT_DIR=""
LOGFILE=""
START_TIME=$SECONDS
SKIP_ACTIVE=false        # set true to skip nmap (passive only)
THREADS=10               # for subdomain brute force

# ══════════════════════════════════════════════════════════════════════════════
#   HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# Print a section header
section() {
    local TITLE="$1"
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  $TITLE${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}  Time: $(date '+%H:%M:%S')${NC}\n"
    # Also write to log
    echo "" >> "$LOGFILE"
    echo "══════════════════════════════════════════" >> "$LOGFILE"
    echo "  $TITLE — $(date '+%H:%M:%S')" >> "$LOGFILE"
    echo "══════════════════════════════════════════" >> "$LOGFILE"
}

# Print status messages
info()    { echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOGFILE"; }
success() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOGFILE"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOGFILE"; }
error()   { echo -e "${RED}[x]${NC} $1" | tee -a "$LOGFILE"; }
result()  { echo -e "    ${MAGENTA}$1${NC}" | tee -a "$LOGFILE"; }

# Check if a tool is installed; warn if missing
tool_check() {
    local TOOL="$1"
    if command -v "$TOOL" &>/dev/null; then
        success "$TOOL is available"
        return 0
    else
        warn "$TOOL is NOT installed — skipping that check"
        warn "  Install: sudo apt install $TOOL"
        return 1
    fi
}

# Run a command and tee output to logfile + terminal
run() {
    local CMD="$*"
    echo -e "${YELLOW}  >> $CMD${NC}"
    eval "$CMD" 2>&1 | tee -a "$LOGFILE"
    echo "" | tee -a "$LOGFILE"
}

# Detect if target is IP or domain
is_ip() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]
}

# ══════════════════════════════════════════════════════════════════════════════
#   BANNER
# ══════════════════════════════════════════════════════════════════════════════

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "  ${YELLOW}All-in-One Reconnaissance Script${NC}"
    echo -e "  ${MAGENTA}nmap · whois · dig · theHarvester · subdomains · OSINT${NC}"
    echo -e "  ${BLUE}$(date '+%Y-%m-%d %H:%M:%S')${NC}\n"
}

# ══════════════════════════════════════════════════════════════════════════════
#   SETUP — validate input, create output dir
# ══════════════════════════════════════════════════════════════════════════════

setup() {
    # Require a target
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] No target specified!${NC}"
        echo ""
        echo -e "  Usage : ${BOLD}./recon_all.sh <target>${NC}"
        echo -e "  Domain: ${BOLD}./recon_all.sh example.com${NC}"
        echo -e "  IP    : ${BOLD}./recon_all.sh 192.168.1.1${NC}"
        echo -e "  Flags : ${BOLD}./recon_all.sh example.com --passive${NC}  (skip nmap)"
        exit 1
    fi

    # Sanitise target for use as a directory name
    local SAFE_TARGET="${TARGET//\//_}"
    OUTPUT_DIR="./recon_${SAFE_TARGET}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    LOGFILE="${OUTPUT_DIR}/full_recon.log"

    echo -e "${GREEN}[+] Output directory : ${BOLD}${OUTPUT_DIR}/${NC}"
    echo -e "${GREEN}[+] Log file         : ${BOLD}${LOGFILE}${NC}"
    echo -e "${GREEN}[+] Target           : ${BOLD}${TARGET}${NC}"
    [[ "$SKIP_ACTIVE" == true ]] && echo -e "${YELLOW}[!] Passive-only mode (nmap skipped)${NC}"
    echo ""

    # Write header to log
    {
        echo "═══════════════════════════════════════════════════"
        echo "  RECON REPORT"
        echo "  Target  : $TARGET"
        echo "  Date    : $(date)"
        echo "  Mode    : $([ "$SKIP_ACTIVE" == true ] && echo 'Passive' || echo 'Active+Passive')"
        echo "═══════════════════════════════════════════════════"
    } > "$LOGFILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 1 — WHOIS
# ══════════════════════════════════════════════════════════════════════════════

module_whois() {
    section "MODULE 1 — WHOIS LOOKUP"

    if ! tool_check "whois"; then return; fi

    info "Running whois on $TARGET ..."
    whois "$TARGET" 2>/dev/null | tee "${OUTPUT_DIR}/whois.txt" | tee -a "$LOGFILE"

    # Extract key fields and highlight them
    echo ""
    info "Key whois fields:"
    grep -iE "registrar|registrant|country|creation date|expiry|name server|org:|email:" \
        "${OUTPUT_DIR}/whois.txt" 2>/dev/null | sort -u | while read -r LINE; do
        result "$LINE"
    done

    success "Whois saved → ${OUTPUT_DIR}/whois.txt"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 2 — DNS ENUMERATION (dig)
# ══════════════════════════════════════════════════════════════════════════════

module_dns() {
    section "MODULE 2 — DNS ENUMERATION (dig)"

    if ! tool_check "dig"; then return; fi

    local OUTFILE="${OUTPUT_DIR}/dns.txt"
    : > "$OUTFILE"   # create/clear file

    # Only run DNS enum on domain targets, not bare IPs
    if is_ip "$TARGET"; then
        info "Target is an IP — running reverse DNS lookup..."
        run "dig -x $TARGET +short" | tee -a "$OUTFILE"
        return
    fi

    # A record — IPv4 address
    info "A record (IPv4)..."
    run "dig $TARGET A +short" | tee -a "$OUTFILE"

    # AAAA record — IPv6
    info "AAAA record (IPv6)..."
    run "dig $TARGET AAAA +short" | tee -a "$OUTFILE"

    # MX — mail servers
    info "MX records (mail servers)..."
    run "dig $TARGET MX +short" | tee -a "$OUTFILE"

    # NS — name servers
    info "NS records (name servers)..."
    run "dig $TARGET NS +short" | tee -a "$OUTFILE"

    # TXT — SPF, DMARC, verification tokens
    info "TXT records (SPF, DMARC, etc.)..."
    run "dig $TARGET TXT +short" | tee -a "$OUTFILE"

    # SOA — start of authority
    info "SOA record..."
    run "dig $TARGET SOA +short" | tee -a "$OUTFILE"

    # CNAME
    info "CNAME record..."
    run "dig $TARGET CNAME +short" | tee -a "$OUTFILE"

    # Attempt zone transfer (usually blocked, but worth trying)
    info "Attempting DNS zone transfer (usually blocked)..."
    local NS
    NS=$(dig "$TARGET" NS +short | head -1)
    if [[ -n "$NS" ]]; then
        run "dig axfr $TARGET @$NS" | tee -a "$OUTFILE"
    fi

    # DNSSEC check
    info "DNSSEC check..."
    run "dig $TARGET DNSKEY +short" | tee -a "$OUTFILE"

    success "DNS results saved → $OUTFILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 3 — SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

module_subdomains() {
    section "MODULE 3 — SUBDOMAIN ENUMERATION"

    if is_ip "$TARGET"; then
        warn "Target is an IP — skipping subdomain enumeration"
        return
    fi

    local OUTFILE="${OUTPUT_DIR}/subdomains.txt"
    : > "$OUTFILE"

    # ── Method 1: dig brute force with a wordlist ──────────────────────────
    info "Method 1: Brute force common subdomains with dig..."

    # Built-in wordlist of common subdomains (no file needed!)
    local SUBS=(
        www mail ftp ssh vpn remote admin portal api
        dev staging test prod beta app mobile cdn static
        assets images blog shop store support helpdesk
        ns1 ns2 smtp pop imap webmail calendar wiki
        gitlab jenkins ci jira confluence grafana
        monitor dashboard login auth sso internal
    )

    local FOUND=0
    for SUB in "${SUBS[@]}"; do
        local RESULT
        RESULT=$(dig "${SUB}.${TARGET}" A +short 2>/dev/null | grep -v "^;")
        if [[ -n "$RESULT" ]]; then
            success "FOUND: ${SUB}.${TARGET} → $RESULT"
            echo "${SUB}.${TARGET}  →  $RESULT" >> "$OUTFILE"
            ((FOUND++))
        fi
    done
    info "Brute force found $FOUND subdomain(s)"

    # ── Method 2: Certificate Transparency (crt.sh) — passive OSINT ────────
    info "Method 2: Certificate Transparency logs (crt.sh)..."
    if tool_check "curl"; then
        # Query crt.sh API (passive, no direct contact with target)
        local CRT_DATA
        CRT_DATA=$(curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null)
        if [[ -n "$CRT_DATA" ]]; then
            echo "$CRT_DATA" | grep -oP '"name_value":"[^"]*"' | \
                grep -oP '(?<=")[^"]+(?=")' | \
                sed 's/\\n/\n/g' | \
                grep -v "^\*" | \
                sort -u | \
                grep "\.${TARGET}$" | tee -a "$OUTFILE"
            success "crt.sh results appended to $OUTFILE"
        else
            warn "Could not reach crt.sh (check internet)"
        fi
    fi

    # ── Method 3: subfinder (if installed) ─────────────────────────────────
    if command -v subfinder &>/dev/null; then
        info "Method 3: subfinder (passive)..."
        run "subfinder -d $TARGET -silent" | tee -a "$OUTFILE"
    else
        warn "subfinder not installed (optional). Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    fi

    # ── Method 4: amass (if installed) ─────────────────────────────────────
    if command -v amass &>/dev/null; then
        info "Method 4: amass enum (passive)..."
        run "amass enum -passive -d $TARGET -o ${OUTPUT_DIR}/amass_subs.txt"
        cat "${OUTPUT_DIR}/amass_subs.txt" >> "$OUTFILE" 2>/dev/null
    fi

    # Deduplicate and count
    sort -u "$OUTFILE" -o "$OUTFILE"
    local COUNT
    COUNT=$(wc -l < "$OUTFILE")
    success "$COUNT unique subdomain(s) found → $OUTFILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 4 — NMAP SCANNING (active)
# ══════════════════════════════════════════════════════════════════════════════

module_nmap() {
    section "MODULE 4 — NMAP PORT & SERVICE SCAN"

    if [[ "$SKIP_ACTIVE" == true ]]; then
        warn "Active scanning skipped (--passive flag)"
        return
    fi

    if ! tool_check "nmap"; then return; fi

    # Step 1: Quick ping sweep / host check
    info "Step 1: Host discovery..."
    run "nmap -sn $TARGET -oN ${OUTPUT_DIR}/nmap_discovery.txt"

    # Step 2: Top 1000 ports, service version
    info "Step 2: Top 1000 ports + service version detection..."
    run "nmap -sV -T4 --open --top-ports 1000 -oN ${OUTPUT_DIR}/nmap_top1000.txt -oX ${OUTPUT_DIR}/nmap_top1000.xml $TARGET"

    # Step 3: Full port scan
    info "Step 3: Full port scan (1-65535) — this may take a while..."
    run "nmap -p- -T4 --min-rate 1000 --open -oN ${OUTPUT_DIR}/nmap_fullports.txt $TARGET"

    # Step 4: OS detection + scripts (needs root)
    if [[ $EUID -eq 0 ]]; then
        info "Step 4: OS detection + default scripts (running as root)..."
        run "nmap -A -T4 --open -oN ${OUTPUT_DIR}/nmap_aggressive.txt -oX ${OUTPUT_DIR}/nmap_aggressive.xml $TARGET"
    else
        warn "Step 4: OS detection skipped (requires sudo/root)"
        info "  Run: sudo ./recon_all.sh $TARGET for OS detection"
    fi

    # Step 5: Vuln scripts on common ports
    info "Step 5: Vulnerability scripts on common ports..."
    run "nmap --script vuln -p 21,22,23,25,80,110,139,143,443,445,3306,3389,8080 \
        -oN ${OUTPUT_DIR}/nmap_vuln.txt $TARGET"

    # Extract open ports summary
    echo "" | tee -a "$LOGFILE"
    info "Open ports summary:"
    grep "^[0-9]" "${OUTPUT_DIR}/nmap_top1000.txt" 2>/dev/null | while read -r LINE; do
        result "$LINE"
    done

    success "All nmap results saved → ${OUTPUT_DIR}/nmap_*.txt / *.xml"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 5 — theHarvester (email, IP, host OSINT)
# ══════════════════════════════════════════════════════════════════════════════

module_harvester() {
    section "MODULE 5 — theHarvester (OSINT: emails, hosts, IPs)"

    if is_ip "$TARGET"; then
        warn "theHarvester works best with domain targets — skipping for IP"
        return
    fi

    if ! tool_check "theHarvester"; then
        warn "Install: sudo apt install theharvester  OR  pip3 install theHarvester"
        return
    fi

    local OUTFILE="${OUTPUT_DIR}/harvester"

    # Run across multiple data sources
    info "Querying: Google, Bing, DuckDuckGo, Crtsh, HackerTarget..."
    run "theHarvester -d $TARGET -b google,bing,duckduckgo,crtsh,hackertarget \
        -l 500 -f ${OUTFILE}"

    # Additional sources if available
    info "Querying: LinkedIn (host discovery only)..."
    run "theHarvester -d $TARGET -b linkedin -l 200 >> ${OUTFILE}.txt 2>&1"

    success "theHarvester results → ${OUTFILE}.html / ${OUTFILE}.txt"

    # Extract and display emails found
    if [[ -f "${OUTFILE}.txt" ]]; then
        echo ""
        info "Emails found:"
        grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
            "${OUTFILE}.txt" 2>/dev/null | sort -u | while read -r EMAIL; do
            result "$EMAIL"
        done | tee -a "$LOGFILE"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 6 — OSINT (passive, no direct contact)
# ══════════════════════════════════════════════════════════════════════════════

module_osint() {
    section "MODULE 6 — OSINT (Passive Intelligence Gathering)"

    local OUTFILE="${OUTPUT_DIR}/osint.txt"
    : > "$OUTFILE"

    # ── 6a: Shodan CLI (if installed + API key configured) ─────────────────
    if command -v shodan &>/dev/null; then
        info "Shodan lookup..."
        if is_ip "$TARGET"; then
            run "shodan host $TARGET" | tee -a "$OUTFILE"
        else
            run "shodan search hostname:$TARGET" | tee -a "$OUTFILE"
        fi
    else
        warn "shodan CLI not installed. Install: pip3 install shodan"
        info "  Manual check: https://www.shodan.io/search?query=$TARGET"
        echo "  Shodan URL: https://www.shodan.io/search?query=$TARGET" >> "$OUTFILE"
    fi

    # ── 6b: Reverse IP lookup (find other domains on same IP) ──────────────
    if ! is_ip "$TARGET"; then
        info "Getting IP address of domain..."
        local IP
        IP=$(dig "$TARGET" A +short | head -1)
        if [[ -n "$IP" ]]; then
            success "IP address: $IP"
            echo "IP: $IP" >> "$OUTFILE"

            # Check if IP is private
            if [[ "$IP" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
                warn "IP is private — skipping public OSINT lookups"
            else
                info "Checking VirusTotal for IP reputation (manual)..."
                echo "  VirusTotal: https://www.virustotal.com/gui/ip-address/$IP" | tee -a "$OUTFILE"
                info "Checking AbuseIPDB (manual)..."
                echo "  AbuseIPDB: https://www.abuseipdb.com/check/$IP" | tee -a "$OUTFILE"
            fi
        fi
    fi

    # ── 6c: HTTP headers (what tech is the server running?) ────────────────
    if command -v curl &>/dev/null; then
        info "Fetching HTTP headers (tech fingerprinting)..."
        {
            echo ""
            echo "── HTTP Headers ──"
            curl -sI "http://${TARGET}" --max-time 5 2>/dev/null
            echo ""
            echo "── HTTPS Headers ──"
            curl -sI "https://${TARGET}" --max-time 5 -k 2>/dev/null
        } | tee -a "$OUTFILE" | tee -a "$LOGFILE"
    fi

    # ── 6d: robots.txt and sitemap ─────────────────────────────────────────
    if command -v curl &>/dev/null && ! is_ip "$TARGET"; then
        info "Fetching robots.txt..."
        curl -s "https://${TARGET}/robots.txt" --max-time 5 -k 2>/dev/null | \
            tee "${OUTPUT_DIR}/robots.txt" | tee -a "$LOGFILE"

        info "Fetching sitemap.xml..."
        curl -s "https://${TARGET}/sitemap.xml" --max-time 5 -k 2>/dev/null | \
            grep -oP 'https?://[^ <>"]+' | head -30 | \
            tee "${OUTPUT_DIR}/sitemap_urls.txt" | tee -a "$LOGFILE"
    fi

    # ── 6e: Google dork links (manual follow-up) ───────────────────────────
    if ! is_ip "$TARGET"; then
        info "Google dork search links (open manually):"
        {
            echo ""
            echo "── Google Dorks for $TARGET ──"
            echo "  Site search      : https://www.google.com/search?q=site:$TARGET"
            echo "  Subdomains       : https://www.google.com/search?q=site:*.$TARGET"
            echo "  Login pages      : https://www.google.com/search?q=site:$TARGET+inurl:login"
            echo "  Config files     : https://www.google.com/search?q=site:$TARGET+ext:xml+OR+ext:conf+OR+ext:cnf"
            echo "  Exposed files    : https://www.google.com/search?q=site:$TARGET+ext:log+OR+ext:sql+OR+ext:bak"
            echo "  Admin panels     : https://www.google.com/search?q=site:$TARGET+inurl:admin"
            echo "  Pastes (Pastebin): https://www.google.com/search?q=site:pastebin.com+$TARGET"
        } | tee -a "$OUTFILE" | tee -a "$LOGFILE"
    fi

    # ── 6f: Wayback Machine (archived pages) ───────────────────────────────
    if command -v curl &>/dev/null && ! is_ip "$TARGET"; then
        info "Checking Wayback Machine for archived URLs..."
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=30" \
            --max-time 10 2>/dev/null | \
            tee "${OUTPUT_DIR}/wayback_urls.txt" | tee -a "$LOGFILE"
        local WB_COUNT
        WB_COUNT=$(wc -l < "${OUTPUT_DIR}/wayback_urls.txt" 2>/dev/null)
        success "$WB_COUNT archived URLs found → ${OUTPUT_DIR}/wayback_urls.txt"
    fi

    success "OSINT results saved → $OUTFILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#   MODULE 7 — SSL/TLS CERTIFICATE INSPECTION
# ══════════════════════════════════════════════════════════════════════════════

module_ssl() {
    section "MODULE 7 — SSL/TLS CERTIFICATE INSPECTION"

    if is_ip "$TARGET"; then
        local HOST="$TARGET"
    else
        local HOST="$TARGET"
    fi

    local OUTFILE="${OUTPUT_DIR}/ssl_cert.txt"

    if command -v openssl &>/dev/null; then
        info "Fetching SSL certificate from $HOST:443 ..."
        echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null | \
            openssl x509 -noout -text 2>/dev/null | \
            tee "$OUTFILE" | tee -a "$LOGFILE"

        # Extract key fields
        echo ""
        info "Certificate summary:"
        grep -E "Subject:|Issuer:|Not Before:|Not After:|DNS:" "$OUTFILE" 2>/dev/null | \
            while read -r LINE; do result "$LINE"; done | tee -a "$LOGFILE"

        success "Full SSL cert → $OUTFILE"
    else
        warn "openssl not installed"
    fi

    # Also check with nmap ssl scripts if available
    if command -v nmap &>/dev/null && [[ "$SKIP_ACTIVE" != true ]]; then
        info "Running nmap ssl-enum-ciphers..."
        run "nmap --script ssl-enum-ciphers -p 443 $TARGET \
            -oN ${OUTPUT_DIR}/nmap_ssl.txt"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#   FINAL SUMMARY REPORT
# ══════════════════════════════════════════════════════════════════════════════

print_summary() {
    local DURATION=$(( SECONDS - START_TIME ))
    local MINS=$(( DURATION / 60 ))
    local SECS=$(( DURATION % 60 ))

    section "RECON COMPLETE — SUMMARY REPORT"

    echo -e "${GREEN}${BOLD}"
    echo "  ╔════════════════════════════════════════════════╗"
    echo "  ║            RECONNAISSANCE COMPLETE             ║"
    echo "  ╚════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "  ${BOLD}Target      :${NC} $TARGET"
    echo -e "  ${BOLD}Duration    :${NC} ${MINS}m ${SECS}s"
    echo -e "  ${BOLD}Output Dir  :${NC} $OUTPUT_DIR/"
    echo ""
    echo -e "  ${BOLD}Files generated:${NC}"
    ls -lh "$OUTPUT_DIR" 2>/dev/null | awk 'NR>1 {printf "    %-40s %s\n", $NF, $5}'

    echo ""
    echo -e "  ${CYAN}${BOLD}Recommended next steps:${NC}"
    echo -e "  ${CYAN}  1. Review subdomains.txt — attack surface expansion${NC}"
    echo -e "  ${CYAN}  2. Open nmap_vuln.txt — check for CVEs${NC}"
    echo -e "  ${CYAN}  3. Follow Google dork links in osint.txt${NC}"
    echo -e "  ${CYAN}  4. Import nmap XML into Metasploit:${NC}"
    echo -e "  ${CYAN}       msf> db_import ${OUTPUT_DIR}/nmap_top1000.xml${NC}"
    echo -e "  ${CYAN}  5. Run nikto for web vuln scan:${NC}"
    echo -e "  ${CYAN}       nikto -h http://$TARGET${NC}"
    echo -e "  ${CYAN}  6. Run gobuster for directory brute force:${NC}"
    echo -e "  ${CYAN}       gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt${NC}"
    echo ""

    # Append summary to log
    {
        echo ""
        echo "══════════════════════════════════════════"
        echo "  SUMMARY"
        echo "  Target   : $TARGET"
        echo "  Duration : ${MINS}m ${SECS}s"
        echo "  Finished : $(date)"
        echo "══════════════════════════════════════════"
    } >> "$LOGFILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#   ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════════════════

parse_args() {
    if [[ $# -eq 0 ]]; then
        # No args — ask interactively
        banner
        echo -e "${BOLD}[?] Enter target (domain or IP):${NC}"
        echo "    e.g. example.com | 192.168.1.1 | scanme.nmap.org"
        read -rp "    Target: " TARGET

        echo ""
        echo -e "${BOLD}[?] Scan mode:${NC}"
        echo "    1) Full scan  (active + passive — includes nmap)"
        echo "    2) Passive only (no nmap — whois, DNS, OSINT only)"
        read -rp "    Choice [1/2]: " MODE_CHOICE
        [[ "$MODE_CHOICE" == "2" ]] && SKIP_ACTIVE=true
    else
        TARGET="$1"
        shift
        for ARG in "$@"; do
            case "$ARG" in
                --passive|-p) SKIP_ACTIVE=true ;;
                --help|-h)
                    echo "Usage: ./recon_all.sh <target> [--passive]"
                    echo "  --passive   Skip nmap (DNS, OSINT, whois only)"
                    exit 0 ;;
            esac
        done
    fi

    # Validate target isn't empty
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] No target provided. Exiting.${NC}"
        exit 1
    fi

    # Public IP warning
    if ! is_ip "$TARGET"; then
        local RESOLVED_IP
        RESOLVED_IP=$(dig "$TARGET" A +short 2>/dev/null | head -1)
        if [[ -n "$RESOLVED_IP" ]]; then
            local FIRST_OCTET="${RESOLVED_IP%%.*}"
            if [[ $FIRST_OCTET -ne 10 && $FIRST_OCTET -ne 192 && $FIRST_OCTET -ne 172 ]]; then
                echo -e "\n${RED}  ⚠  WARNING: $TARGET resolves to a PUBLIC IP ($RESOLVED_IP)${NC}"
                echo -e "${YELLOW}     Only scan targets you own or have written permission to test!${NC}"
                read -rp "     Type 'AGREE' to confirm permission: " PERM
                [[ "$PERM" != "AGREE" ]] && echo "Aborted." && exit 0
            fi
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#   MAIN — run all modules in order
# ══════════════════════════════════════════════════════════════════════════════

main() {
    banner
    parse_args "$@"
    setup

    echo -e "${GREEN}${BOLD}[*] Starting full reconnaissance on: $TARGET${NC}\n"

    module_whois          # 1. Whois registration info
    module_dns            # 2. DNS records (A, MX, NS, TXT, zone transfer)
    module_subdomains     # 3. Subdomain enumeration (brute + crt.sh + tools)
    module_nmap           # 4. Port scanning & service detection (active)
    module_harvester      # 5. theHarvester — emails, IPs, hosts
    module_osint          # 6. Passive OSINT (Shodan, headers, dorks, Wayback)
    module_ssl            # 7. SSL/TLS certificate inspection

    print_summary         # Final report
}

# Entry point
main "$@"
