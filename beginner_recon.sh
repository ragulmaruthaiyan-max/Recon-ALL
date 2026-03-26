#!/bin/bash
# ============================================================
#  beginner_recon.sh — Your First Pentest Recon Script
#  For: Beginners learning bash + pentesting together
#  Safe to run on your own lab network
# ============================================================

# === COLORS ===
# These are escape codes that make terminal text colorful
GREEN='\033[0;32m'   # Green text
RED='\033[0;31m'     # Red text
YELLOW='\033[1;33m'  # Yellow text
CYAN='\033[0;36m'    # Cyan text
NC='\033[0m'         # NC = No Color (resets color back to normal)

# ============================================================
# FUNCTIONS — reusable blocks of code
# Think of them like tools in a toolbox
# ============================================================

# Function: print a nice banner at the start
banner() {
  echo -e "${CYAN}"
  echo "  =================================="
  echo "    My First Recon Script v1.0"
  echo "  =================================="
  echo -e "${NC}"
}

# Function: check if a host is alive (responds to ping)
# $1 = the first argument passed to this function (the IP)
ping_host() {
  local IP="$1"   # 'local' means this variable only lives inside this function

  echo -e "${YELLOW}[*] Pinging $IP ...${NC}"

  # ping -c 1 = send only 1 packet
  # ping -W 1 = wait max 1 second for reply
  # &>/dev/null = hide all output (we only care about exit code)
  ping -c 1 -W 1 "$IP" &>/dev/null

  # $? = exit code of the LAST command (0 = success, anything else = fail)
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] $IP is ALIVE${NC}"
  else
    echo -e "${RED}[-] $IP is DOWN or not reachable${NC}"
  fi
}

# Function: check if a specific port is open on a host
# $1 = IP address, $2 = port number
check_port() {
  local IP="$1"
  local PORT="$2"
  local SERVICE="$3"   # optional: name of the service

  # nc = netcat, a network tool
  # -z = just scan (don't send data)
  # -w1 = timeout after 1 second
  # 2>/dev/null = hide error messages
  nc -z -w1 "$IP" "$PORT" 2>/dev/null

  if [ $? -eq 0 ]; then
    echo -e "${GREEN}  [OPEN]   Port $PORT  ($SERVICE)${NC}"
  else
    echo "  [closed] Port $PORT  ($SERVICE)"
  fi
}

# Function: do a basic whois lookup
whois_lookup() {
  local TARGET="$1"

  # Check if whois is installed first
  if command -v whois &>/dev/null; then
    echo -e "\n${YELLOW}[*] Whois lookup for $TARGET ...${NC}"
    whois "$TARGET" 2>/dev/null | grep -E "Registrar:|Country:|Creation Date:|Expiry Date:" | head -10
  else
    echo -e "${RED}[!] whois not installed. Skipping.${NC}"
  fi
}

# Function: DNS lookup
dns_lookup() {
  local TARGET="$1"

  echo -e "\n${YELLOW}[*] DNS lookup for $TARGET ...${NC}"

  # nslookup gives us IP from domain name
  if command -v nslookup &>/dev/null; then
    nslookup "$TARGET" 2>/dev/null | grep "Address:" | tail -n +2
  else
    # fallback: use host command
    host "$TARGET" 2>/dev/null | head -5
  fi
}

# ============================================================
# MAIN SCRIPT — this is where everything runs
# ============================================================

banner   # Call the banner function

# === STEP 1: Get target from the user ===
echo -e "${CYAN}Enter a target to scan.${NC}"
echo "  Examples: 192.168.1.1  |  scanme.nmap.org  |  192.168.101.1"
read -rp "  Target: " TARGET

# Check that user actually typed something
# -z means "is this string empty?"
if [ -z "$TARGET" ]; then
  echo -e "${RED}[!] No target entered. Exiting.${NC}"
  exit 1   # exit 1 = exit with an error code
fi

echo ""
echo -e "${CYAN}[+] Target set to: $TARGET${NC}"
echo ""

# === STEP 2: Ping check — is the host alive? ===
ping_host "$TARGET"

# === STEP 3: DNS lookup (only if target looks like a hostname) ===
# =~ checks if variable matches a pattern
# This pattern checks if it does NOT start with a number (i.e., it's a hostname)
if [[ ! "$TARGET" =~ ^[0-9] ]]; then
  dns_lookup "$TARGET"
fi

# === STEP 4: Port scanning with a loop ===
echo -e "\n${YELLOW}[*] Checking common ports on $TARGET ...${NC}"
echo "    (This uses netcat — no root needed)"
echo ""

# Associative array — stores port:service pairs
declare -A PORTS
PORTS[21]="FTP"
PORTS[22]="SSH"
PORTS[23]="Telnet"
PORTS[25]="SMTP"
PORTS[80]="HTTP"
PORTS[110]="POP3"
PORTS[139]="NetBIOS"
PORTS[443]="HTTPS"
PORTS[445]="SMB"
PORTS[3306]="MySQL"
PORTS[3389]="RDP"
PORTS[8080]="HTTP-Alt"

# Loop through all ports in our array
for PORT in "${!PORTS[@]}"; do
  SERVICE="${PORTS[$PORT]}"
  check_port "$TARGET" "$PORT" "$SERVICE"
done

# === STEP 5: Whois lookup ===
whois_lookup "$TARGET"

# === STEP 6: Offer to run nmap if installed ===
echo ""
if command -v nmap &>/dev/null; then
  echo -e "${CYAN}[*] nmap is available for deeper scanning.${NC}"
  read -rp "    Run a quick nmap scan? (yes/no): " RUN_NMAP
  if [ "$RUN_NMAP" = "yes" ]; then
    echo -e "\n${YELLOW}[*] Running: nmap -sV --top-ports 20 $TARGET${NC}\n"
    nmap -sV --top-ports 20 "$TARGET"
  fi
else
  echo -e "${YELLOW}[!] nmap not installed. Install it for deeper scans: sudo apt install nmap${NC}"
fi

# === DONE ===
echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Recon complete for: $TARGET${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo "  Next steps:"
echo "  - Use nmap for port/service/vuln scanning"
echo "  - Use gobuster/dirb for web directory brute force"
echo "  - Use nikto for web vulnerability scanning"
echo ""
