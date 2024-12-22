# categorize_subnet.py

import argparse
import subprocess
import re
import threading
from queue import Queue
from colorama import init, Fore, Style
import json
import csv
import os

init()  # Enable color

def discover_hosts(subnet):
    """
    Basic Nmap ping sweep to find live hosts.
    """
    cmd = ["nmap", "-n", "-sn", subnet]
    output = subprocess.check_output(cmd).decode()
    pattern = re.compile(r"Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    hosts = pattern.findall(output)
    return hosts

def scan_host(host):
    """
    Runs an aggressive scan on one host:
    - -p- : all TCP ports
    - -sV : version detection
    - -O  : OS detection
    - -sC : default scripts
    - --script=vuln : basic vulnerability checks
    - -T4 : faster
    """
    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-p-",
        "-sV",
        "-O",
        "-sC",
        "--script=vuln",
        "-T4",
        host
    ]
    try:
        output = subprocess.check_output(cmd).decode()
    except subprocess.CalledProcessError:
        output = ""
    return output

def parse_scan_output(scan_output):
    """
    Extracts OS, open ports, services, potential vulnerabilities from nmap output.
    """
    data = {
        "os": "Unknown",
        "ports": [],
        "vulnerabilities": [],
        "roles": []
    }

    lines = scan_output.split("\n")

    # Regexes
    os_regex = re.compile(r"Running:\s*(.*)")
    port_regex = re.compile(r"^(\d+/tcp)\s+open\s+([^\s]+)\s?(.*)?")
    script_regex = re.compile(r"\|\s*(.*)")

    for line in lines:
        # OS
        match_os = os_regex.search(line)
        if match_os:
            data["os"] = match_os.group(1).strip()

        # Ports
        match_port = port_regex.match(line.strip())
        if match_port:
            port_id = match_port.group(1)
            service_name = match_port.group(2)
            version_info = match_port.group(3).strip() if match_port.group(3) else ""
            data["ports"].append({
                "port": port_id,
                "service": service_name,
                "version": version_info
            })

        # Potential vulnerabilities
        match_script = script_regex.search(line)
        if match_script:
            text = match_script.group(1).strip()
            if "CVE" in text or "Vulnerable" in text or "vuln" in text.lower():
                data["vulnerabilities"].append(text)

    # Determine roles
    data["roles"] = categorize_host(data["ports"], data["os"])

    return data

def categorize_host(ports, os_info):
    """
    Identifies likely roles based on open ports, OS, service names.
    You can expand or customize as needed.
    """
    roles = []

    # Common triggers
    port_services = {p["service"].lower() for p in ports}

    # Web server detection
    # Common web ports: 80, 443, 8080, 8443, etc.
    if any(s in port_services for s in ["http", "ssl/http"]):
        roles.append("Web Server")

    # SMB detection
    if any(s in port_services for s in ["microsoft-ds", "netbios-ssn", "smb"]):
        roles.append("File Server (SMB)")

    # FTP detection
    if "ftp" in port_services:
        roles.append("File Server (FTP)")

    # NFS detection
    if "rpcbind" in port_services or "nfs" in port_services:
        roles.append("File Server (NFS)")

    # SSH detection
    if "ssh" in port_services:
        roles.append("SSH Server")

    # Database detection (common DB ports: 3306, 1433, 5432, etc.)
    # We check known service names or port numbers
    for p in ports:
        if p["service"].lower() in ["mysql", "mssql", "postgresql", "oracle", "mongodb", "redis"]:
            roles.append("Database Server")

    # Domain controller / AD
    # Often on Windows OS with SMB/LDAP/Kerberos (port 88, 389, 445, 53 if DNS)
    # This is approximate
    if "windows" in os_info.lower():
        if any(p["port"] in ["88/tcp", "389/tcp", "445/tcp", "53/tcp"] for p in ports):
            roles.append("Windows AD Domain Controller?")

    return roles

def worker(q, results):
    while not q.empty():
        host = q.get()
        raw_output = scan_host(host)
        parsed_data = parse_scan_output(raw_output)
        results[host] = parsed_data
        q.task_done()

def export_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def export_csv(results, filename):
    """
    Writes rows: Host, OS, Roles, Port, Service, Version, Vulnerabilities
    Each vulnerability on a separate line or joined.
    """
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "OS", "Roles", "Port", "Service", "Version", "Vulnerabilities"])
        for host, data in results.items():
            roles_joined = "; ".join(data["roles"]) if data["roles"] else "None"
            vulns_joined = "; ".join(data["vulnerabilities"]) if data["vulnerabilities"] else "None"
            if data["ports"]:
                for p in data["ports"]:
                    writer.writerow([
                        host,
                        data["os"],
                        roles_joined,
                        p["port"],
                        p["service"],
                        p["version"],
                        vulns_joined
                    ])
            else:
                writer.writerow([host, data["os"], roles_joined, "None", "None", "None", vulns_joined])

def main():
    parser = argparse.ArgumentParser(description="Subnet Scan & Categorization")
    parser.add_argument("subnet", help="e.g. 192.168.1.0/24")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel scans")
    parser.add_argument("--json", default="categorized_results.json", help="JSON output file")
    parser.add_argument("--csv", default="categorized_results.csv", help="CSV output file")
    args = parser.parse_args()

    print(Fore.YELLOW + f"Discovering hosts in {args.subnet}..." + Style.RESET_ALL)
    hosts = discover_hosts(args.subnet)
    if not hosts:
        print(Fore.RED + "No live hosts found." + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"Found {len(hosts)} hosts. Scanning and categorizing..." + Style.RESET_ALL)
    q = Queue()
    results = {}

    for h in hosts:
        q.put(h)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(Fore.CYAN + "\n=== Categorized Results ===" + Style.RESET_ALL)
    for host, data in results.items():
        print(Fore.YELLOW + f"Host: {host}" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"  OS: {data['os']}" + Style.RESET_ALL)
        print("  Roles:", ", ".join(data["roles"]) if data["roles"] else "None")

        if data["ports"]:
            print("  Ports:")
            for p in data["ports"]:
                port_info = f"{p['port']} -> {p['service']} {p['version']}"
                print(Fore.GREEN + f"    {port_info}" + Style.RESET_ALL)
        else:
            print("  No open ports found.")

        if data["vulnerabilities"]:
            print(Fore.RED + "  Potential Vulnerabilities:" + Style.RESET_ALL)
            for v in data["vulnerabilities"]:
                print("    " + v)
        else:
            print("  No vulnerabilities noted.")
        print()

    # Export
    export_json(results, args.json)
    export_csv(results, args.csv)
    print(Fore.GREEN + f"Results saved to {args.json} and {args.csv}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
