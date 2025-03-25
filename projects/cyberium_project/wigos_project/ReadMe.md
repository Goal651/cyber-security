How to Run the Python Vulnerability and Security Scan Script
Overview

This script performs several vulnerability scans on a system or remote network. It includes:

    Root Privileges Check: Ensures the script is run with root privileges.

    Vulnerability Scanning: Scans for vulnerable services running on local or remote systems.

    Exploit Attempt: With user consent, the script attempts to exploit vulnerabilities using tools like Hydra (for SSH brute-force) or Metasploit (for HTTP exploits).

    Local PC Security Check: Scans the local system for open ports, outdated packages, and file permissions.

    Security Logs Check: Scans security logs for suspicious activities such as multiple failed logins or dangerous sudo commands.

The script uses Nmap for scanning, Metasploit for HTTP exploit attempts, and Hydra for SSH brute-force.
Requirements

    Python 3.x

    Root (sudo) privileges to run the script

    Nmap, Metasploit, and Hydra installed on your system

    Tkinter for the graphical user interface (GUI)

    psutil and subprocess modules (used for scanning and executing commands)

Installation

    Install Python 3.x: Ensure that Python 3 is installed on your system.

        Ubuntu/Debian: sudo apt install python3 python3-pip

        Fedora: sudo dnf install python3

    Install required packages:

    pip3 install psutil tkinter

    Install required tools:

        Nmap: sudo apt install nmap

        Metasploit: Follow installation instructions from Metasploit website

        Hydra: sudo apt install hydra

    Ensure sudo access: The script needs root privileges to perform vulnerability scans and exploits.

Running the Script
1. Make the script executable

If the script is named vuln_scan.py, you need to make it executable.

chmod +x vuln_scan.py

2. Run the script with root privileges

sudo python3 vuln_scan.py

The script will begin executing, scanning for vulnerabilities, checking for insecure services, and optionally attempting exploits if permitted by the user.
3. GUI Interface

The script uses a Tkinter GUI to show findings, especially the Localhost Open Ports table, and prompts for user input when action is needed (e.g., confirming exploit attempts or closing open ports).
Scan Options

    Network Scan: You can scan a range of IPs to find live hosts. The script will attempt to scan services and check for known vulnerabilities.

    Example: Scanning an IP range:

    network_scan("192.168.1.0/24", output_callback)

    Local PC Scan: The script will scan the local machine for open ports, outdated packages, and potential security risks (e.g., world-readable /etc/shadow file).

    Security Log Scan: The script also scans /var/log/auth.log and /var/log/syslog for suspicious activities like multiple failed login attempts.

Saving Reports

After each scan or exploit attempt, the script will save a report with a timestamp. These reports are stored in the current directory with a filename pattern:

scan_type_report_YYYY-MM-DD_HH-MM-SS.txt

For example, a report for local PC scans will be named like:

local_pc_report_2025-03-25_12-30-45.txt

Example of User Prompts

    Exploit: If a vulnerability is found, the user will be asked if they wish to attempt an exploit.

        "Do you want to attempt SSH brute-force with Hydra?"

    Close Ports: If open ports are detected, the user will be prompted to confirm whether to close those ports.

Troubleshooting

    Permission Issues: Ensure that you run the script with root privileges (sudo).

    Missing Tools: Ensure that Nmap, Metasploit, and Hydra are installed and properly configured.

    Firewall Issues: Some exploits might be blocked by local or network firewalls. Check if relevant ports are accessible.

License

This script is for educational purposes only. Use responsibly and with permission on systems you own or have explicit consent to scan and exploit.
