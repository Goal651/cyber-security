#!/bin/bash

# ----- SUDO/ROOT CHECK -----
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[91m[!] This script must be run as root (using sudo). Exiting...\e[0m"
    exit 1
fi

# ----- ANSI COLOR CODES -----
RED='\e[91m'
GREEN='\e[92m'
CYAN='\e[96m'
YELLOW='\e[93m'
BLUE='\e[94m'
BOLD='\e[1m'
RESET='\e[0m'

# ----- CONSTANTS -----
INSECURE_PORTS="21:FTP (unencrypted) 23:Telnet (unencrypted) 25:SMTP (unencrypted) 110:POP3 (unencrypted) 143:IMAP (unencrypted) 445:SMB (unencrypted) 3389:RDP (unencrypted)"

# ----- FUNCTIONS -----

# Print a Metasploit-style header
print_header() {
    clear
    echo -e "${RED}${BOLD}============================================================${RESET}"
    echo -e "${GREEN}${BOLD}       CyberGuard Toolkit - Security Scanning Suite        ${RESET}"
    echo -e "${RED}${BOLD}============================================================${RESET}"
    echo -e "${CYAN}Developed by: Wilson && Chael | Date: $(date +"%Y-%m-%d %H:%M:%S")${RESET}"
    echo
}

# Save findings to a report file
save_report() {
    local scan_type="$1"
    local details="$2"
    local actions="$3"
    local timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    local filename="${scan_type}_report_${timestamp}.txt"
    {
        echo "Scan Type: $scan_type"
        echo "Date: $timestamp"
        echo "Details:"
        echo "$details"
        if [ -n "$actions" ]; then
            echo "Actions Taken:"
            echo "$actions"
        fi
    } >"$filename"
    echo -e "${GREEN}[+] Report saved as $filename${RESET}"
}

# Exploit vulnerabilities with user consent
exploit_vulnerability() {
    local ip="$1"
    local port="$2"
    local service="$3"
    echo -e "${YELLOW}[*] Potential vulnerability found on $ip:$port ($service)${RESET}"
    read -p "$(echo -e ${CYAN}'[*] Attempt to exploit? (y/n): '${RESET})" answer
    if [ "$answer" != "y" ]; then
        return
    fi

    local actions=""
    if echo "$service" | grep -qi "ssh"; then
        echo -e "${BLUE}[*] Attempting SSH brute-force with Hydra...${RESET}"
        hydra -l admin -P /usr/share/wordlists/rockyou.txt "$ip" ssh -t 4 2>/dev/null
        actions="SSH brute-force attempted on $ip:$port - Check terminal for results"
    elif echo "$service" | grep -qi "http"; then
        echo -e "${BLUE}[*] Checking if $ip:$port is responsive...${RESET}"
        if ! echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc "$ip" "$port" >/dev/null 2>&1; then
            echo -e "${RED}[!] $ip:$port is not responsive, skipping Metasploit.${RESET}"
            actions="HTTP scan skipped on $ip:$port - Port not responsive"
        else
            echo -e "${BLUE}[*] Launching Metasploit for HTTP exploit on $ip:$port...${RESET}"
            echo -e "${BLUE}[*] This may take a moment, please wait...${RESET}"
            echo -e "use auxiliary/scanner/http/http_version\nset RHOSTS $ip\nset RPORT $port\nrun\nexit" >msf.rc
            msfconsole -r msf.rc >/dev/null 2>&1
            actions="HTTP scan attempted on $ip:$port - Check terminal for results"
            rm -f msf.rc
        fi
    fi
    echo "$actions"
}

# Scan for vulnerabilities using Nmap
scan_vulnerabilities() {
    local live_hosts="$1"
    local vulnerabilities=""
    for ip in $live_hosts; do
        echo -e "${BLUE}[*] Scanning $ip for vulnerabilities with Nmap...${RESET}"
        nmap_output=$(nmap -p- --script vuln "$ip" 2>/dev/null)
        echo "$nmap_output" | grep -E "[0-9]+/tcp.*open.*" | while read -r line; do
            if echo "$nmap_output" | grep -q "VULNERABLE"; then
                port=$(echo "$line" | cut -d'/' -f1)
                service="$line"
                vulnerabilities="$vulnerabilities $ip:$port:$service"
            fi
        done
    done
    echo "$vulnerabilities"
}

# Scan a remote network with Nmap for live hosts
network_scan() {
    local ip_range="$1"
    echo -e "${BLUE}[*] Scanning network with Nmap to find live hosts: $ip_range${RESET}"
    nmap_output=$(nmap -sn "$ip_range" 2>/dev/null)
    if [ -z "$nmap_output" ]; then
        echo -e "${RED}[!] No live hosts found${RESET}"
        return 1
    fi
    echo -e "${GREEN}[+] Nmap Findings (Live Hosts):${RESET}"
    echo "$nmap_output"
    live_hosts=$(echo "$nmap_output" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u)
    if [ -n "$live_hosts" ]; then
        echo -e "${GREEN}[+] Found $(echo "$live_hosts" | wc -w) live host(s):${RESET}"
        echo "$live_hosts" | sed "s/^/${YELLOW}  - /"
        echo "$live_hosts"
        return 0
    else
        echo -e "${RED}[!] No live hosts found.${RESET}"
        return 1
    fi
}

# Scan the local PC for vulnerabilities
local_pc_scan() {
    echo -e "${BLUE}[*] Scanning local PC for vulnerabilities...${RESET}"
    local findings=""

    if [ -r "/etc/shadow" ]; then
        findings="$findings\n${RED}File permissions: /etc/shadow is world-readable (Severity: Critical)${RESET}"
    fi

    echo -e "${BLUE}[*] Checking open ports...${RESET}"
    ss_output=$(ss -tuln -p 2>/dev/null | tail -n +2)
    if [ -n "$ss_output" ]; then
        open_ports_info=""
        while read -r line; do
            port=$(echo "$line" | awk '{print $5}' | cut -d':' -f2)
            pid=$(echo "$line" | grep -o 'pid=[0-9]*' | cut -d'=' -f2)
            if [ -n "$pid" ]; then
                process_info=$(ps -p "$pid" -o comm,user --no-headers 2>/dev/null)
                if [ -n "$process_info" ]; then
                    process_name=$(echo "$process_info" | awk '{print $1}')
                    owner=$(echo "$process_info" | awk '{print $2}')
                    open_ports_info="$open_ports_info\n  - Port: $port, Process: $process_name, Owner: $owner, PID: $pid"
                else
                    open_ports_info="$open_ports_info\n  - Port: $port, PID: $pid (Process info unavailable)"
                fi
            else
                open_ports_info="$open_ports_info\n  - Port: $port (No PID available)"
            fi
        done <<<"$ss_output"
        if [ -n "$open_ports_info" ]; then
            findings="$findings\n${YELLOW}Open ports:${open_ports_info} (Severity: Medium)${RESET}"
        fi
    fi

    if [ -n "$findings" ]; then
        echo -e "${GREEN}[+] Local PC Scan Findings:${RESET}"
        echo -e "$findings" | sed "s/^/${YELLOW}  - /"
        read -p "$(echo -e ${CYAN}'[*] Would you like to block any open ports? (y/n): '${RESET})" block_answer
        if [ "$block_answer" = "y" ]; then
            echo -e "${CYAN}Open ports detected:${open_ports_info}${RESET}"
            read -p "$(echo -e ${CYAN}'[*] Enter port number to block: '${RESET})" port_to_block
            iptables -A INPUT -p tcp --dport "$port_to_block" -j DROP
            iptables -A OUTPUT -p tcp --sport "$port_to_block" -j DROP
            echo -e "${GREEN}[+] Port $port_to_block has been blocked.${RESET}"
            actions="Blocked port $port_to_block"
        fi
        save_report "local_pc" "$(echo -e "$findings")" "$actions"
    else
        echo -e "${GREEN}[+] No issues found on local PC.${RESET}"
        save_report "local_pc" "No issues found."
    fi
}

# Scan security logs for suspicious activity
scan_security_logs() {
    echo -e "${BLUE}[*] Scanning security logs for potential issues...${RESET}"
    local findings=""

    if [ -f "/var/log/auth.log" ]; then
        failed_logins=$(grep "Failed password" /var/log/auth.log | awk '{print $9 " from " $11}' | sort | uniq -c | awk '$1 > 5 {print $2 " " $3 " (" $1 " attempts)"}')
        if [ -n "$failed_logins" ]; then
            findings="$findings\n${YELLOW}Failed logins: Multiple failed logins: $failed_logins (Severity: High)${RESET}"
        fi
    fi

    if [ -f "/var/log/syslog" ]; then
        suspicious_commands=$(grep "sudo:.*COMMAND=" /var/log/syslog | grep -E "rm -rf|shutdown" | awk -F"COMMAND=" '{print $2}')
        if [ -n "$suspicious_commands" ]; then
            findings="$findings\n${RED}Suspicious command: Suspicious sudo command: $suspicious_commands (Severity: Critical)${RESET}"
        fi
    fi

    if [ -n "$findings" ]; then
        echo -e "${GREEN}[+] Security Log Findings:${RESET}"
        echo -e "$findings" | sed "s/^/${YELLOW}  - /"
        save_report "security_logs" "$(echo -e "$findings")"
    else
        echo -e "${GREEN}[+] No security issues found in logs.${RESET}"
        save_report "security_logs" "No security issues found."
    fi
}

# New System Info Functions
public_ip() {
    echo -e "${GREEN}[+] Public IP Address: $(curl -s ifconfig.me)${RESET}"
}

private_ip() {
    echo -e "${GREEN}[+] Private IP Address: $(ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d'/' -f1 | head -n 1)${RESET}"
}

get_mac() {
    echo -e "${GREEN}[+] MAC Address: $(ip link show | grep ether | awk '{print $2}' | head -n 1)${RESET}"
}

get_cpu() {
    echo -e "${GREEN}[+] Top 5 CPU Usage (Percentage, User):${RESET}"
    ps aux | awk '{print $3 " " $1}' | sort -nr | head -n 5 | while read -r line; do
        echo -e "${YELLOW}  - $line${RESET}"
    done
}

get_mem_usage() {
    echo -e "${GREEN}[+] Memory Usage:${RESET}"
    free -h | sed "s/^/${YELLOW}  /"
}

get_active() {
    echo -e "${GREEN}[+] Active Services:${RESET}"
    service --status-all | grep -F '[ + ]' | sed "s/^/${YELLOW}  /"
}

get_top_ten() {
    echo -e "${GREEN}[+] Top 10 Largest Files in /home:${RESET}"
    du -ah /home/ 2>/dev/null | sort -rh | head -n 10 | sed "s/^/${YELLOW}  /"
}

get_all() {
    private_ip
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    public_ip
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    get_mac
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    get_cpu
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    get_mem_usage
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    get_active
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
    get_top_ten
    echo -e "${BLUE}------------------------------------------------------------${RESET}"
}

# ----- MAIN MENU -----
main_menu() {
    while true; do
        print_header
        echo -e "${BLUE}${BOLD}Available Commands:${RESET}"
        echo -e "${YELLOW}  1) Network Scan          - Scan a network range for live hosts${RESET}"
        echo -e "${YELLOW}  2) Local PC Scan        - Check local system for vulnerabilities${RESET}"
        echo -e "${YELLOW}  3) Security Logs Scan   - Analyze logs for suspicious activity${RESET}"
        echo -e "${YELLOW} 4) All System Info     - Display all system information${RESET}"
        echo -e "${YELLOW} 5) Exit                - Terminate the toolkit${RESET}"
        echo -e "${RED}${BOLD}------------------------------------------------------------${RESET}"
        read -p "$(echo -e ${CYAN}'cg > '${RESET})" choice

        case $choice in
        1)
            print_header
            read -p "$(echo -e ${CYAN}'[*] Enter IP range (e.g., 192.168.1.0/24): '${RESET})" ip_range

            if network_scan "$ip_range"; then
                live_hosts=$(network_scan "$ip_range" | tail -n +6)
                read -p "$(echo -e ${CYAN}'[*] Scan for vulnerabilities? (y/n): '${RESET})" vuln_answer
                if [ "$vuln_answer" = "y" ]; then
                    vulnerabilities=$(scan_vulnerabilities "$live_hosts")
                    if [ -n "$vulnerabilities" ]; then
                        echo -e "${GREEN}[+] Vulnerabilities Detected:${RESET}"
                        actions=""
                        for vuln in $vulnerabilities; do
                            ip=$(echo "$vuln" | cut -d':' -f1)
                            port=$(echo "$vuln" | cut -d':' -f2)
                            service=$(echo "$vuln" | cut -d':' -f3-)
                            echo -e "${YELLOW}  - $ip:$port - $service${RESET}"
                            action=$(exploit_vulnerability "$ip" "$port" "$service")
                            if [ -n "$action" ]; then
                                actions="$actions\n$action"
                            fi
                        done
                        save_report "network" "Live hosts:\n$live_hosts\n\nVulnerabilities:\n$vulnerabilities" "$actions"
                    else
                        echo -e "${GREEN}[+] No vulnerabilities found.${RESET}"
                        save_report "network" "Live hosts:\n$live_hosts\n\nNo vulnerabilities found."
                    fi
                fi
            fi
            ;;
        2)
            print_header
            local_pc_scan
            ;;
        3)
            print_header
            scan_security_logs
            ;;

        4)
            print_header
            get_all
            ;;
        5)
            echo -e "${RED}[!] Exiting CyberGuard Toolkit...${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid command. Please try again.${RESET}"
            ;;
        esac
        echo
        read -p "$(echo -e ${CYAN}'[*] Press Enter to continue... '${RESET})"
    done
}

# ----- RUN MAIN MENU -----
main_menu
