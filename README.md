# 360-Scan

**360-Scan** is a fast, modular penetration testing tool focused on discovering and exploiting file-sharing misconfigurations across **SMB**, **FTP**, **NFS**, and **HTTP(S)**. It automates host discovery, service enumeration, brute-forcing, and sensitive-data detection—then outputs clean reports in JSON and CSV.

---

## 🔍 Features

- **Host Discovery:** Ping sweep or TCP port scan (21, 80, 139, 445, 443, 2049)  
- **Service Detection:** Identifies SMB, FTP, NFS, and HTTP(S)  
- **Misconfiguration Checks:**  
  - **SMB:** list shares, check anonymous and writeable access  
  - **FTP:** test for anonymous login, find writeable dirs  
  - **NFS:** list exports, test unauthenticated mounts  
  - **HTTP:** brute-force paths, find exposed configs/backups  
- **Brute-Forcing:**  
  - SMB/FTP/HTTP login brute-force using Hydra  
  - Supports custom wordlists  
- **Sensitive Data Search:** Detects secrets, passwords, tokens in discovered files  
- **Reporting:** Exports full scan results to structured **JSON** and **CSV**  
- **Performance:** Parallel scanning with optional brute-force skipping  
- **Modular Design:** Easy to extend with new protocols or scanning modules  

---

## ⚙️ Quickstart

1. **Clone & install**  
   ```bash
   git clone https://github.com/your-org/360-Scan.git
   cd 360-Scan
   pip3 install -r requirements.txt

2.  **Run a basic scan**
   ```bash
   sudo python3 360scan.py \
  --subnet 192.168.1.0/24 \
  --threads 10 \
  --output-json results.json \
  --output-csv results.csv
```


> 💡 Use `--skip-brute` to avoid brute-force attempts, or `--smb-user/pass` for credentialed share access.

## 🤝 Contributing

Pull requests welcome! Fork the project, create a feature branch, and open a PR with clear commits.

---

## 📄 License

360-Scan is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
