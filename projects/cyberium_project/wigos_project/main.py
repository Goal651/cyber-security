#!/usr/bin/env python3
import os
import re
import subprocess
import psutil
from datetime import datetime
from threading import Thread
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ----- SUDO/ROOT CHECK -----
if os.name == "posix" and os.geteuid() != 0:
    print("This script must be run as root (using sudo). Exiting...")
    exit(1)

# ----- ORIGINAL FUNCTIONS AND CONSTANTS -----

# List of commonly unencrypted/insecure ports
INSECURE_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    25: "SMTP (unencrypted)",
    110: "POP3 (unencrypted)",
    143: "IMAP (unencrypted)",
    445: "SMB (unencrypted)",
    3389: "RDP (unencrypted)",
}


# Save findings to a report file
def save_report(scan_type, details, actions=None):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{scan_type}_report_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(f"Scan Type: {scan_type}\n")
        f.write(f"Date: {timestamp}\n")
        f.write(f"Details:\n{details}\n")
        if actions:
            f.write(f"Actions Taken:\n{actions}\n")
    return filename


# Exploit vulnerabilities with user consent
def exploit_vulnerability(ip, port, service, output_callback):
    output_callback(f"Potential vulnerability found on {ip}:{port} ({service})\n")
    if not messagebox.askyesno(
        "Exploit", f"Attempt to exploit {ip}:{port} ({service})?"
    ):
        return None

    actions = []
    if "ssh" in service.lower():
        output_callback("Attempting SSH brute-force with Hydra...\n")
        try:
            hydra_cmd = (
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {ip} ssh -t 4"
            )
            subprocess.run(hydra_cmd, shell=True)
            actions.append(
                f"SSH brute-force attempted on {ip}:{port} - Check terminal for results"
            )
        except Exception as e:
            actions.append(f"Error during Hydra exploit: {str(e)}")
    elif "http" in service.lower() or "https" in service.lower():
        output_callback(f"Checking if {ip}:{port} is responsive...\n")
        try:
            # Note: the double backslashes are needed to escape properly inside the f-string.
            nc_cmd = f"echo -e 'HEAD / HTTP/1.0\\r\\n\\r\\n' | nc {ip} {port}"
            result = subprocess.run(nc_cmd, shell=True, capture_output=True, text=True)
            if not result.stdout or "Connection refused" in result.stderr:
                output_callback(
                    f"{ip}:{port} is not responsive, skipping Metasploit.\n"
                )
                actions.append(
                    f"HTTP scan skipped on {ip}:{port} - Port not responsive"
                )
                return "\n".join(actions) if actions else None
        except Exception as e:
            output_callback(f"Error checking {ip}:{port}: {str(e)}\n")
            actions.append(
                f"HTTP scan skipped on {ip}:{port} - Error checking responsiveness"
            )
            return "\n".join(actions) if actions else None

        output_callback(f"Launching Metasploit for HTTP exploit on {ip}:{port}...\n")
        output_callback("This may take a moment, please wait...\n")
        try:
            msf_script = f"use auxiliary/scanner/http/http_version; set RHOSTS {ip}; set RPORT {port}; run; exit"
            with open("msf.rc", "w") as f:
                f.write(msf_script)
            subprocess.run("msfconsole -r msf.rc", shell=True)
            actions.append(
                f"HTTP scan attempted on {ip}:{port} - Check terminal for results"
            )
        except Exception as e:
            actions.append(f"Error during Metasploit exploit: {str(e)}")
        finally:
            if os.path.exists("msf.rc"):
                os.remove("msf.rc")
    return "\n".join(actions) if actions else None


# Scan for vulnerabilities using Nmap
def scan_vulnerabilities(live_hosts, output_callback):
    vulnerabilities = []
    for ip in live_hosts:
        output_callback(f"Scanning {ip} for vulnerabilities with Nmap...\n")
        try:
            nmap_cmd = f"nmap -p- --script vuln {ip}"
            subprocess.run(nmap_cmd, shell=True)
            nmap_result = subprocess.run(
                nmap_cmd, shell=True, capture_output=True, text=True
            )
            if nmap_result.stdout:
                for line in nmap_result.stdout.splitlines():
                    service_match = re.search(r"(\d+/tcp.*open.*)", line)
                    if service_match and "VULNERABLE" in nmap_result.stdout:
                        port = service_match.group(1).split("/")[0]
                        service = service_match.group(1)
                        vulnerabilities.append((ip, port, service))
        except Exception as e:
            output_callback(f"Error scanning {ip} with Nmap: {str(e)}\n")
    return vulnerabilities


# Scan a remote network with Nmap for live hosts
def network_scan(ip_range, output_callback):
    output_callback(f"Scanning network with Nmap to find live hosts: {ip_range}\n")
    try:
        nmap_cmd = f"nmap -sn {ip_range}"
        result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)
        output = result.stdout or "No live hosts found"
        output_callback("Nmap Findings (Live Hosts):\n")
        output_callback(output + "\n")
        live_hosts = []
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match and ip_match.group(1) not in live_hosts:
                    live_hosts.append(ip_match.group(1))
        if live_hosts:
            output_callback(f"Found {len(live_hosts)} live host(s):\n")
            for host in live_hosts:
                output_callback(f"- {host}\n")
            return live_hosts, output
        else:
            output_callback("No live hosts found.\n")
            return None, output
    except Exception as e:
        output_callback(f"Error during network scan: {str(e)}\n")
        return None, f"Error: {str(e)}"


# Scan the local PC for vulnerabilities
def local_pc_scan(output_callback):
    output_callback("Scanning local PC for vulnerabilities...\n")
    findings = []
    try:
        output_callback("Checking for outdated packages...\n")
        subprocess.run("apt update", shell=True)
        subprocess.run("apt list --upgradable", shell=True)
        apt_result = subprocess.run(
            "apt list --upgradable", shell=True, capture_output=True, text=True
        )
        if apt_result.returncode == 0:
            outdated = len(
                [
                    line
                    for line in apt_result.stdout.splitlines()
                    if line.strip() and not line.startswith("Listing")
                ]
            )
            if outdated > 0:
                findings.append(
                    {
                        "check": "Outdated packages",
                        "issue": f"{outdated} packages need updating",
                        "severity": "High",
                    }
                )
    except Exception as e:
        findings.append(
            {
                "check": "Outdated packages",
                "issue": f"Unable to check: {str(e)}",
                "severity": "Unknown",
            }
        )

    if os.name == "posix" and os.access("/etc/shadow", os.R_OK):
        findings.append(
            {
                "check": "File permissions",
                "issue": "/etc/shadow is world-readable",
                "severity": "Critical",
            }
        )

    try:
        output_callback("Checking open ports...\n")
        subprocess.run("ss -tuln", shell=True)
        ss_result = subprocess.run(
            "ss -tuln", shell=True, capture_output=True, text=True
        )
        if ss_result.returncode == 0:
            open_ports = [
                line.split()[4].split(":")[-1]
                for line in ss_result.stdout.splitlines()[1:]
                if line.strip()
            ]
            if open_ports:
                findings.append(
                    {
                        "check": "Open ports",
                        "issue": f"Open ports: {', '.join(open_ports)}",
                        "severity": "Medium",
                    }
                )
    except Exception as e:
        findings.append(
            {
                "check": "Open ports",
                "issue": f"Unable to check: {str(e)}",
                "severity": "Unknown",
            }
        )

    if findings:
        output_callback("Local PC Scan Findings:\n")
        details = []
        for f in findings:
            output_callback(
                f"- {f['check']}: {f['issue']} (Severity: {f['severity']})\n"
            )
            details.append(f"{f['check']}: {f['issue']} (Severity: {f['severity']})")
        open_ports_finding = next(
            (f for f in findings if f["check"] == "Open ports"), None
        )
        if open_ports_finding and messagebox.askyesno(
            "Action", "Do you want to close any open ports?"
        ):
            actions = []
            open_ports = (
                open_ports_finding["issue"].replace("Open ports: ", "").split(", ")
            )
            for port in open_ports:
                if messagebox.askyesno("Confirm", f"Close port {port}?"):
                    try:
                        output_callback(f"Checking processes on port {port}...\n")
                        subprocess.run(f"lsof -i :{port}", shell=True)
                        lsof_result = subprocess.run(
                            f"lsof -i :{port}",
                            shell=True,
                            capture_output=True,
                            text=True,
                        )
                        if lsof_result.returncode == 0 and lsof_result.stdout:
                            lines = lsof_result.stdout.splitlines()
                            if len(lines) > 1:
                                pid = lines[1].split()[1]
                                service = lines[1].split()[0]
                                if messagebox.askyesno(
                                    "Confirm",
                                    f"Stop {service} (PID: {pid}) on port {port}?",
                                ):
                                    subprocess.run(
                                        f"kill {pid}", shell=True, check=True
                                    )
                                    actions.append(
                                        f"Closed port {port} (stopped {service}, PID: {pid})"
                                    )
                    except Exception as e:
                        output_callback(f"Error closing port {port}: {str(e)}\n")
            if actions:
                filename = save_report(
                    "local_pc", "\n".join(details), "\n".join(actions)
                )
                output_callback(f"Report saved as {filename}\n")
            else:
                filename = save_report("local_pc", "\n".join(details))
                output_callback(f"Report saved as {filename}\n")
        else:
            filename = save_report("local_pc", "\n".join(details))
            output_callback(f"Report saved as {filename}\n")
    else:
        output_callback("No issues found on local PC.\n")
        filename = save_report("local_pc", "No issues found.")
        output_callback(f"Report saved as {filename}\n")


# Scan security logs for suspicious activity
def scan_security_logs(output_callback):
    output_callback("Scanning security logs for potential issues...\n")
    findings = []
    if os.name == "posix":
        try:
            with open("/var/log/auth.log", "r") as f:
                auth_log = f.read()
            failed_logins = re.findall(
                r"Failed password for (\\w+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)", auth_log
            )
            failed_login_counts = defaultdict(int)
            for user, ip in failed_logins:
                failed_login_counts[(user, ip)] += 1
            for (user, ip), count in failed_login_counts.items():
                if count > 5:
                    findings.append(
                        {
                            "check": "Failed logins",
                            "issue": f"Multiple failed logins for {user} from {ip} ({count} attempts)",
                            "severity": "High",
                        }
                    )
        except Exception as e:
            output_callback(f"Error reading auth.log: {str(e)}\n")
        try:
            with open("/var/log/syslog", "r") as f:
                syslog = f.read()
            sudo_usages = re.findall(
                r"sudo: .*? : TTY=.* ; PWD=.* ; USER=.* ; COMMAND=(.*)", syslog
            )
            for command in sudo_usages:
                if "rm -rf" in command or "shutdown" in command:
                    findings.append(
                        {
                            "check": "Suspicious command",
                            "issue": f"Suspicious sudo command: {command}",
                            "severity": "Critical",
                        }
                    )
        except Exception as e:
            output_callback(f"Error reading syslog: {str(e)}\n")
    if findings:
        output_callback("Security Log Findings:\n")
        for f in findings:
            output_callback(
                f"- {f['check']}: {f['issue']} (Severity: {f['severity']})\n"
            )
        filename = save_report(
            "security_logs",
            "\n".join(
                [
                    f"{f['check']}: {f['issue']} (Severity: {f['severity']})"
                    for f in findings
                ]
            ),
        )
        output_callback(f"Report saved as {filename}\n")
    else:
        output_callback("No security issues found in logs.\n")
        filename = save_report("security_logs", "No security issues found.")
        output_callback(f"Report saved as {filename}\n")


# ----- NEW FUNCTIONALITY: Localhost Open Ports Table -----
class OpenPortsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Localhost Open Ports")
        self.geometry("500x300")
        self.configure(bg="#1a1a1a")

        self.tree = ttk.Treeview(
            self, columns=("Port", "Process", "PID"), show="headings"
        )
        self.tree.heading("Port", text="Port")
        self.tree.heading("Process", text="Process")
        self.tree.heading("PID", text="PID")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_table).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(
            btn_frame, text="Block Selected Port", command=self.block_selected
        ).pack(side=tk.LEFT, padx=5)

        self.refresh_table()

    def refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                port = conn.laddr.port
                pid = conn.pid if conn.pid else "N/A"
                process = "N/A"
                if pid and pid != "N/A":
                    try:
                        process = psutil.Process(pid).name()
                    except Exception:
                        process = "Unknown"
                self.tree.insert("", "end", values=(port, process, pid))

    def block_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No selection", "Please select a port to block.")
            return
        item = self.tree.item(selected_item)
        port = item["values"][0]
        try:
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    "DROP",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--sport",
                    str(port),
                    "-j",
                    "DROP",
                ],
                check=True,
            )
            messagebox.showinfo("Blocked", f"Port {port} has been blocked.")
            self.refresh_table()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block port {port}: {e}")


# ----- MAIN GUI APPLICATION -----
class CyberGuardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberGuard Toolkit")
        self.geometry("900x800")
        self.configure(bg="#1a1a1a")

        header = tk.Label(
            self,
            text="CyberGuard Toolkit",
            font=("Arial", 20, "bold"),
            bg="#1a1a1a",
            fg="#00ff00",
        )
        header.pack(pady=10)

        scan_frame = tk.Frame(self, bg="#1a1a1a")
        scan_frame.pack(pady=10)
        tk.Label(
            scan_frame, text="Scan Type:", font=("Arial", 12), bg="#1a1a1a", fg="white"
        ).pack(side=tk.LEFT, padx=5)
        self.scan_var = tk.StringVar()
        self.scan_combobox = ttk.Combobox(
            scan_frame,
            textvariable=self.scan_var,
            values=["Network Scan", "Local PC Scan", "Security Logs Scan"],
            state="readonly",
            width=20,
        )
        self.scan_combobox.set("Network Scan")
        self.scan_combobox.pack(side=tk.LEFT, padx=5)

        self.ip_frame = tk.Frame(self, bg="#1a1a1a")
        self.ip_frame.pack(pady=10)
        tk.Label(
            self.ip_frame,
            text="IP Range (Network Scan only):",
            font=("Arial", 12),
            bg="#1a1a1a",
            fg="white",
        ).pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(
            self.ip_frame,
            width=30,
            font=("Arial", 12),
            bg="#2e2e2e",
            fg="white",
            insertbackground="white",
        )
        self.ip_entry.pack(side=tk.LEFT)

        self.output_text = scrolledtext.ScrolledText(
            self,
            width=100,
            height=30,
            font=("Consolas", 10),
            bg="#2e2e2e",
            fg="#00ff00",
            wrap=tk.WORD,
        )
        self.output_text.pack(pady=10, padx=10)

        btn_frame = tk.Frame(self, bg="#1a1a1a")
        btn_frame.pack(pady=10)
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=10)
        self.scan_btn = ttk.Button(
            btn_frame, text="Start Scan", command=self.start_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Output", command=self.clear_output).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(
            btn_frame, text="Open Ports Table", command=self.open_ports_window
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.quit).pack(side=tk.LEFT, padx=5)

    def log(self, message):
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.update()

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def start_scan(self):
        scan_type = self.scan_var.get()
        self.scan_btn.config(state="disabled")
        if scan_type == "Network Scan":
            ip_range = self.ip_entry.get()
            if not ip_range:
                messagebox.showerror(
                    "Error", "Please enter an IP range for Network Scan"
                )
                self.scan_btn.config(state="normal")
                return
            Thread(target=self.network_scan_thread, args=(ip_range,)).start()
        elif scan_type == "Local PC Scan":
            Thread(target=self.local_pc_scan_thread).start()
        elif scan_type == "Security Logs Scan":
            Thread(target=self.scan_security_logs_thread).start()

    def network_scan_thread(self, ip_range):
        def output_callback(message):
            self.log(message)

        live_hosts, output = network_scan(ip_range, output_callback)
        if live_hosts and messagebox.askyesno("Proceed", "Scan for vulnerabilities?"):
            vulnerabilities = scan_vulnerabilities(live_hosts, output_callback)
            if vulnerabilities:
                self.log("Vulnerabilities Detected:\n")
                actions = []
                for ip, port, service in vulnerabilities:
                    self.log(f"- {ip}:{port} - {service}\n")
                    exploit_result = exploit_vulnerability(
                        ip, port, service, output_callback
                    )
                    if exploit_result:
                        actions.append(exploit_result)
                if actions:
                    filename = save_report(
                        "network",
                        output
                        + "\n\nVulnerabilities:\n"
                        + "\n".join(
                            [
                                f"{ip}:{port} - {service}"
                                for ip, port, service in vulnerabilities
                            ]
                        ),
                        "\n".join(actions),
                    )
                    self.log(f"Report saved as {filename}\n")
            else:
                self.log("No vulnerabilities found.\n")
                filename = save_report(
                    "network", output + "\n\nNo vulnerabilities found."
                )
                self.log(f"Report saved as {filename}\n")
        self.scan_btn.config(state="normal")

    def local_pc_scan_thread(self):
        def output_callback(message):
            self.log(message)

        local_pc_scan(output_callback)
        self.scan_btn.config(state="normal")

    def scan_security_logs_thread(self):
        def output_callback(message):
            self.log(message)

        scan_security_logs(output_callback)
        self.scan_btn.config(state="normal")

    def open_ports_window(self):
        OpenPortsWindow(self)


if __name__ == "__main__":
    try:
        app = CyberGuardGUI()
        app.mainloop()
    except PermissionError:
        print("Error: Permission Denied. Please run as root.")
    except Exception as e:
        print(f"Error: {str(e)}")
