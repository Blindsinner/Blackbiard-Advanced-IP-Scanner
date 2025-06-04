# Blackbird IP and Vulnerability Scanner

**Author**: MD Faysal Mahmud

## Description

Blackbird IP and Vulnerability Scanner is a Python-based tool designed for network reconnaissance and vulnerability assessment. It scans IP addresses or CIDR ranges to gather detailed information, including WHOIS data, geolocation, open ports, services, vulnerabilities, and potential attack vectors. The tool leverages libraries like `nmap`, `ipwhois`, and `geocoder` to provide comprehensive network insights and generates HTML reports for easy analysis. It is designed to run on Kali Linux, Ubuntu, and macOS.

**Key Features**:
- Scans single IPs or CIDR ranges for network and device information.
- Retrieves WHOIS data, geolocation, open ports, services, and vulnerabilities.
- Suggests potential attack vectors based on identified vulnerabilities.
- Generates HTML reports with responsive design for scan results.
- Utilizes multithreading for efficient scanning.
- Caches WHOIS and geolocation data to optimize performance.

## Requirements

To run Blackbird, ensure the following dependencies are installed:

### Software
- **Python 3.8+**
- **Nmap** (Network exploration tool and security/port scanner)
- **Kali Linux**, **Ubuntu**, or **macOS**

### Python Libraries
- `ipwhois`
- `geocoder`
- `python-nmap`
- `colorama`

## Installation

### Kali Linux
1. **Update the system**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. **Install Nmap**:
   ```bash
   sudo apt install nmap -y
   ```
3. **Install Python dependencies**:
   ```bash
   pip3 install ipwhois geocoder python-nmap colorama
   ```
4. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/Blackbiard-Advanced-IP-Scanner.git
   cd Blackbiard-Advanced-IP-Scanner
   ```

### Ubuntu
1. **Update the system**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. **Install Nmap**:
   ```bash
   sudo apt install nmap -y
   ```
3. **Install Python dependencies**:
   ```bash
   pip3 install ipwhois geocoder python-nmap colorama
   ```
4. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/Blackbiard-Advanced-IP-Scanner.git
   cd Blackbiard-Advanced-IP-Scanner
   ```

### macOS
1. **Install Homebrew** (if not installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. **Install Nmap**:
   ```bash
   brew install nmap
   ```
3. **Install Python dependencies**:
   ```bash
   pip3 install ipwhois geocoder python-nmap colorama
   ```
4. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/Blackbiard-Advanced-IP-Scanner.git
   cd Blackbiard-Advanced-IP-Scanner
   ```

## How to Use

1. **Run the script**:
   ```bash
   python3 blackbird.py
   ```
2. **Main Menu Options**:
   - **Option 1**: Scan a single IP address (e.g., `192.168.1.1`).
   - **Option 2**: Scan a CIDR range (e.g., `192.168.1.0/24`).
   - **Option 3**: Generate an HTML report for the last scan.
   - **Option 4**: Exit the program.

3. **Output**:
   - Scan results are displayed in the console with colored output.
   - HTML reports are saved in the `Ipreport` folder with a timestamped filename.

### Sample Input and Output

#### Sample Input
```
Menu:
1. Scan a single IP
2. Scan a CIDR range
3. Generate report for last scan
4. Exit
Enter your choice: 1
Enter the IP address: 192.168.1.1
```

#### Sample Output (Console)
```
Scanning IP: 192.168.1.1
IP Version: IPv4
IP Class: C
Hostname: router.local
Open Ports: 80, 443
Services:
  Port 80: http Apache httpd 2.4.41
  Port 443: https Apache httpd 2.4.41
Vulnerabilities:
  Port 80 (http Apache httpd 2.4.41): http-vuln-CVE-2020-3542 - Vulnerable to DoS
Attack Suggestions:
  HTTP exploit for web application attacks
Responsive Protocols:
  Protocol tcp
MAC Address: 00:14:22:01:23:45
OS Details: Linux 3.X
Traceroute: N/A
Network ID: 192.168.1.0
Subnet Mask: 255.255.255.0
Network Class: Classless
Possible Subnet Count: 256
ASN: 12345
ISP: Example ISP
Country: US
Registration Date: 2020-01-01
Registrant Name: John Doe
Registrant Address: 123 Main St, CA
Registrant Email: john@example.com
Latitude: 37.7749
Longitude: -122.4194
City: San Francisco
State: California
Postal Code: 94103
Local Default Gateway: 192.168.1.1
Local Network Interfaces:
  eth0: 192.168.1.100/24
Scan Time: 12.34 seconds
```

#### Sample HTML Report
- Generated in the `Ipreport` folder, e.g., `report_192_168_1_1_router_local_20250604_233221.html`.
- Contains a formatted table with all scan details, responsive for mobile and desktop viewing.

## Troubleshooting

### Common Issues
1. **Nmap not found**:
   - Ensure Nmap is installed (`nmap --version`).
   - Verify the Nmap path in the script (`/usr/bin/nmap` for Kali Linux).
   - On macOS, ensure Nmap is in your PATH after installing via Homebrew.

2. **Permission errors**:
   - Run the script with `sudo` if scanning privileged ports or using certain Nmap features:
     ```bash
     sudo python3 blackbird.py
     ```

3. **Module not found**:
   - Ensure all Python dependencies are installed using `pip3 install -r requirements.txt` (create a `requirements.txt` with `ipwhois`, `geocoder`, `python-nmap`, `colorama`).
   - Example `requirements.txt`:
     ```text
     ipwhois
     geocoder
     python-nmap
     colorama
     ```

4. **Timeout or network errors**:
   - Check your internet connection for WHOIS and geolocation queries.
   - Increase the timeout in the script (e.g., `timeout=30` in `get_whois_info` or `get_open_ports`).
   - Reduce the number of concurrent scans by adjusting `max_workers` in `ThreadPoolExecutor`.

5. **No vulnerabilities found**:
   - Ensure Nmap’s vulnerability scripts are installed (`/usr/share/nmap/scripts/` on Kali Linux).
   - Update Nmap to the latest version:
     ```bash
     sudo apt install nmap -y
     ```

6. **Report not generating**:
   - Check if the `Ipreport` folder has write permissions:
     ```bash
     chmod -R 755 Ipreport
     ```

### Debugging
- Run the script with verbose output by adding print statements or using a debugger like `pdb`.
- Check Nmap scan logs for errors:
  ```bash
  nmap -d 192.168.1.1
  ```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer
This tool is for educational and ethical use only. Unauthorized scanning of networks or systems is illegal and prohibited. Always obtain explicit permission before scanning any network or device.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.

## Contact
For questions or feedback, contact MD Faysal Mahmud via [GitHub Issues](https://github.com/<your-username>/blackbird-ip-scanner/issues).
