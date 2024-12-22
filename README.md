# 360-Scan

I want to build a penetration testing tool focused on file-sharing misconfigurations and brute-forcing for SMB, FTP, NFS, and HTTP services. This tool should take a **subnet as input** and follow these steps systematically:

1. **Subnet Scanning and Host Discovery**:
   - Perform a ping sweep to discover live hosts in the subnet.
   - Alternatively, perform port scanning on key file-sharing service ports (21, 80, 139, 445, 443, 2049).

2. **Service Detection**:
   - Identify active services on the discovered hosts, focusing on:
     - SMB (ports 139, 445).
     - FTP (port 21).
     - NFS (port 2049).
     - HTTP/HTTPS (ports 80, 443).

3. **Misconfiguration Checks**:
   - **SMB**:
     - List shared folders and check if they are accessible anonymously.
     - Check for world-readable or writable shares.
   - **FTP**:
     - Test for anonymous login.
     - Enumerate files and directories.
     - Identify writable directories.
   - **NFS**:
     - List exported shares.
     - Test if the shares can be mounted without authentication.
     - Enumerate files in mounted shares.
   - **HTTP**:
     - Search for sensitive files and directories using brute-forcing techniques.
     - Check for exposed backups, configuration files, and logs.

4. **Brute-Forcing**:
   - If no misconfigurations are detected, automatically brute-force credentials:
     - SMB and FTP using Hydra.
     - HTTP authentication forms using wordlists.
   - Allow integration with custom username/password wordlists.

5. **Sensitive Data Detection**:
   - Search for sensitive information in accessible files using pattern matching (e.g., passwords, API keys, secrets).

6. **Reporting**:
   - Generate a structured report summarizing:
     - Discovered hosts and their services.
     - Misconfigurations and vulnerabilities.
     - Brute-forcing results.
   - Export the report in JSON and CSV formats.

7. **Performance**:
   - Include parallel processing to handle multiple hosts efficiently.
   - Allow options to limit testing to specific protocols or skip brute-forcing.

8. **Future-Proofing**:
   - Build the tool in a modular way, so new protocols (e.g., cloud-based file-sharing) can be added easily.
   - Provide a clean command-line interface for flexibility.

**Technical Notes**:
- Use **Python** as the primary programming language.
- Leverage libraries like scapy for network scanning, pysmb or Impacket for SMB, ftplib for FTP, and requests for HTTP.
- Incorporate tools like Nmap for service detection and Hydra for brute-forcing.

I want the tool to be simple, aggressive, and efficient, targeting real-world file-sharing misconfigurations. Start coding this tool. Begin with a modular design, and provide explanations for each module.
