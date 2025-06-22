#!/usr/bin/env python3

import argparse
import subprocess
import re
import threading
from queue import Queue
from colorama import init, Fore, Style
import json
import csv

# Initialize colorama
init(autoreset=True)

# ASCII Banner
banner = r"""
   _____ _____ ____     _____                
  |__  // ___// __ \   / ___/_________ _____ 
   /_ </ __ \/ / / /   \__ \/ ___/ __ `/ __ \
 ___/ / /_/ / /_/ /   ___/ / /__/ /_/ / / / /
/____/\____/\____/   /____/\___/\__,_/_/ /_/ 

 360 Scan - Comprehensive Network Scanner v3.0
      Author: Khafagy
"""

def print_banner():
    print(Fore.CYAN + banner + Style.RESET_ALL)

def discover_hosts(subnet):
    """
    Perform a ping sweep to discover live hosts in the subnet.
    """
    cmd = ["nmap", "-n", "-sn", subnet]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        output = ""
    pattern = re.compile(r"Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    hosts = pattern.findall(output)
    return hosts

def scan_host(host):
    """
    Perform an aggressive Nmap scan on the host:
    - Includes OS detection, version detection, and vulnerability scanning.
    """
    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-p-",
        "-sV",
        "-O",
        "--osscan-guess",
        "--max-os-tries", "5",
        "-T4",
        "--script=vuln",
        host
    ]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        output = ""
    return output

def detect_os(lines):
    """
    Enhanced OS detection:
    - Parse OS, device type, MAC address, and TTL from Nmap output.
    """
    os_info = "Unknown"
    device_type = None
    mac_address = None
    vendor = None

    # Regex patterns
    os_regex = re.compile(r"Running:\s*(.*)")
    device_type_regex = re.compile(r"Device type:\s*(.*)")
    mac_regex = re.compile(r"MAC Address:\s*([0-9A-F:]+)\s+\((.*?)\)")
    ttl_regex = re.compile(r"TTL=(\d+)")

    for line in lines:
        # Match OS
        match_os = os_regex.search(line)
        if match_os and os_info == "Unknown":
            os_info = match_os.group(1).strip()

        # Match device type
        match_device = device_type_regex.search(line)
        if match_device:
            device_type = match_device.group(1).strip()

        # Match MAC address and vendor
        match_mac = mac_regex.search(line)
        if match_mac:
            mac_address = match_mac.group(1)
            vendor = match_mac.group(2)

    # TTL-based heuristic fallback
    ttl_match = ttl_regex.search("\n".join(lines))
    if ttl_match and os_info == "Unknown":
        ttl = int(ttl_match.group(1))
        if ttl <= 64:
            os_info = "Linux/Unix (TTL 64)"
        elif ttl <= 128:
            os_info = "Windows (TTL 128)"
        elif ttl <= 255:
            os_info = "Network Device (TTL 255)"

    # Combine all data
    if device_type:
        os_info += f" | Device: {device_type}"
    if mac_address:
        os_info += f" | MAC: {mac_address} ({vendor})"

    return os_info

def parse_scan_output(scan_output):
    """
    Extract OS, open ports, services, and vulnerabilities from the scan output.
    """
    data = {
        "os": "Unknown",
        "ports": [],
        "vulnerabilities": [],
        "roles": []
    }

    lines = scan_output.split("\n")

    # Detect OS
    data["os"] = detect_os(lines)

    # Regex for ports and vulnerabilities
    port_regex = re.compile(r"^(\d+/tcp)\s+open\s+([^\s]+)\s?(.*)?")
    script_regex = re.compile(r"\|\s*(.*)")

    for line in lines:
        # Parse open ports
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

        # Parse potential vulnerabilities
        match_script = script_regex.search(line)
        if match_script:
            text = match_script.group(1).strip()
            if "CVE" in text or "Vulnerable" in text or "vuln" in text.lower():
                data["vulnerabilities"].append(text)

    # Determine roles based on services and OS
    data["roles"] = categorize_host(data["ports"], data["os"])

    return data

def categorize_host(ports, os_info):
    """
    Categorize the host based on detected services and OS information.
    """
    roles = []
    port_services = {p["service"].lower() for p in ports}

    # Identify roles
    if any(s in port_services for s in ["http", "ssl/http"]):
        roles.append("Web Server")
    if any(s in port_services for s in ["microsoft-ds", "netbios-ssn", "smb"]):
        roles.append("File Server (SMB)")
    if "ftp" in port_services:
        roles.append("File Server (FTP)")
    if "rpcbind" in port_services or "nfs" in port_services:
        roles.append("File Server (NFS)")
    if "ssh" in port_services:
        roles.append("SSH Server")
    for p in ports:
        if p["service"].lower() in ["mysql", "mssql", "postgresql", "oracle", "mongodb", "redis"]:
            roles.append("Database Server")
    if "windows" in os_info.lower() and any(p["port"] in ["88/tcp", "389/tcp", "445/tcp", "53/tcp"] for p in ports):
        roles.append("Windows AD Domain Controller")

    return roles

def worker(q, results):
    """
    Worker thread function to process each host.
    """
    while not q.empty():
        host = q.get()
        raw_output = scan_host(host)
        parsed_data = parse_scan_output(raw_output)
        results[host] = parsed_data
        q.task_done()

def export_json(results, filename):
    """
    Export results to a JSON file.
    """
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def export_csv(results, filename):
    """
    Export results to a CSV file.
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
    print_banner()

    parser = argparse.ArgumentParser(description="360 Scan - Comprehensive Network Scanner")
    parser.add_argument("subnet", help="Target subnet, e.g., 192.168.1.0/24")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel scans")
    parser.add_argument("--json", default="scan_results.json", help="JSON output file")
    parser.add_argument("--csv", default="scan_results.csv", help="CSV output file")
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

    print(Fore.CYAN + "\n=== Scan Results ===" + Style.RESET_ALL)
    for host, data in results.items():
        print(Fore.YELLOW + f"Host: {host}" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"  OS: {data['os']}" + Style.RESET_ALL)
        print("  Roles:", ", ".join(data["roles"]) if data["roles"] else "None")

        if data["ports"]:
            print("  Ports:")
            for p in data["ports"]:
                print(Fore.GREEN + f"    {p['port']} -> {p['service']} {p['version']}" + Style.RESET_ALL)
        else:
            print("  No open ports found.")

        if data["vulnerabilities"]:
            print(Fore.RED + "  Potential Vulnerabilities:" + Style.RESET_ALL)
            for v in data["vulnerabilities"]:
                print("    " + v)
        else:
            print("  No vulnerabilities noted.")
        print()

    export_json(results, args.json)
    export_csv(results, args.csv)
    print(Fore.GREEN + f"Results saved to {args.json} and {args.csv}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
