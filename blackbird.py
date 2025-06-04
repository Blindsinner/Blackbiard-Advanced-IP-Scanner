import socket
import ipaddress
from ipwhois import IPWhois
import geocoder
import nmap
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
import time
import os
from datetime import datetime
import colorama
import sys

# Initialize colorama for colored console output
colorama.init()

# Set the nmap path for Kali Linux
nmap.nmap.PortScanner().nmap_path = "/usr/bin/nmap"

# Cache for WHOIS and geolocation data
whois_cache = {}
geo_cache = {}

# Folder for reports
REPORT_FOLDER = "Ipreport"

# Vulnerability to attack suggestions mapping
VULN_TO_ATTACK = {
    "heartbleed": "Heartbleed attack to extract sensitive data",
    "smb-vuln": "SMB exploit for remote code execution",
    "ftp-vuln": "FTP exploit for unauthorized access",
    "ssh-vuln": "SSH brute-force or exploit for unauthorized access",
    "http-vuln": "HTTP exploit for web application attacks",
    "ssl-vuln": "SSL/TLS exploit for man-in-the-middle attacks",
    "mysql-vuln": "MySQL exploit for database access",
}

def get_default_gateway():
    """Retrieve the default gateway of the local system."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if 'default via' in line:
                return line.split()[2]
        return "N/A"
    except:
        return "N/A"

def get_local_network_info():
    """Retrieve local network interfaces and IPs."""
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
        interfaces = {}
        for line in result.stdout.splitlines():
            if 'inet ' in line and 'scope global' in line:
                parts = line.split()
                interface = parts[-1]
                ip_cidr = parts[1]
                interfaces[interface] = ip_cidr
        return interfaces
    except:
        return {"N/A": "N/A"}

def get_device_details(ip):
    """Retrieve device details (MAC address, OS, traceroute) using nmap."""
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O -sT --traceroute -T4 --min-rate 1000 -Pn', timeout=30)
        details = {}
        if ip in nm.all_hosts():
            details['mac'] = nm[ip].get('addresses', {}).get('mac', 'N/A')
            os_info = nm[ip].get('osmatch', [])
            details['os'] = os_info[0]['name'] if os_info else 'N/A'
            details['traceroute'] = nm[ip].get('traceroute', 'N/A')
        else:
            details['mac'] = 'N/A'
            details['os'] = 'N/A'
            details['traceroute'] = 'N/A'
        return details
    except:
        return {'mac': 'N/A', 'os': 'N/A', 'traceroute': 'N/A'}

def get_protocol_info(ip):
    """Check for responsive protocols using nmap protocol scan."""
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sO -T4 --min-rate 1000 -Pn', timeout=30)
        protocols = []
        if ip in nm.all_hosts():
            for proto in nm[ip].get('ip', {}):
                if nm[ip]['ip'][proto]['state'] == 'open':
                    protocols.append(f"Protocol {proto}")
        return protocols
    except:
        return []

def get_open_ports(ip):
    """Retrieve open ports, service versions, and vulnerabilities using nmap."""
    nm = nmap.PortScanner()
    for _ in range(2):  # Retry once
        try:
            nm.scan(ip, arguments='--top-ports 1000 -sT -sV --script "(vuln* or http-vuln* or ssl-vuln* or smb-vuln* or ftp-vuln* or mysql-vuln* or ssh-vuln*)" -T4 --min-rate 1000 -Pn', timeout=30)
            services = []
            vulnerabilities = []
            if ip in nm.all_hosts():
                open_ports = [port for port in nm[ip].get('tcp', {}) if nm[ip]['tcp'][port]['state'] == 'open']
                for port in open_ports:
                    service = nm[ip]['tcp'][port].get('name', 'N/A')
                    version = nm[ip]['tcp'][port].get('product', '') + ' ' + nm[ip]['tcp'][port].get('version', '')
                    services.append(f"Port {port}: {service} {version}".strip())
                    script_output = nm[ip]['tcp'][port].get('script', {})
                    for script_id, output in script_output.items():
                        vulnerabilities.append(f"Port {port} ({service} {version}): {script_id} - {output}")
                if open_ports:
                    return open_ports, services, vulnerabilities
            break
        except:
            continue
    return [], [], []

def get_whois_info(ip):
    """Retrieve WHOIS information with caching."""
    if ip in whois_cache:
        return whois_cache[ip]
    try:
        whois = IPWhois(ip, timeout=10)
        whois_info = whois.lookup_rdap()
        result = {}
        network_cidr = whois_info.get('network', {}).get('cidr', 'N/A')
        network_obj = ipaddress.ip_network(network_cidr, strict=False) if network_cidr != 'N/A' else None
        result['Network ID'] = str(network_obj.network_address) if network_obj else 'N/A'
        result['Subnet Mask'] = str(network_obj.netmask) if network_obj else 'N/A'
        result['Network Class'] = 'Classless' if network_obj and network_obj.is_private else 'Classful' if network_obj else 'N/A'
        result['Possible Subnet Count'] = 2 ** (32 - network_obj.prefixlen) if network_obj else 'N/A'
        result['ASN'] = whois_info.get('asn', 'N/A')
        result['ISP'] = whois_info.get('asn_description', 'N/A')
        result['Country'] = whois_info.get('network', {}).get('country', 'N/A')
        result['Registration Date'] = whois_info.get('network', {}).get('start_date', 'N/A')
        result['Network'] = network_cidr

        # Owner and Contact Information
        entities = whois_info.get('entities', {})
        for role in ['registrant', 'administrative', 'technical', 'abuse']:
            entity = None
            if isinstance(entities, dict):
                entity = entities.get(role, {})
            elif isinstance(entities, list):
                for e in entities:
                    if isinstance(e, dict) and role in e.get('roles', []):
                        entity = e
                        break
            if entity:
                vcard = entity.get('vcardArray', [None, []])[1]
                owner_name = 'N/A'
                owner_address = 'N/A'
                owner_email = 'N/A'
                for entry in vcard:
                    if isinstance(entry, list) and entry[0] == 'fn':
                        owner_name = entry[3]
                    elif isinstance(entry, list) and entry[0] == 'adr':
                        owner_address = ', '.join(entry[3]) if isinstance(entry[3], list) else entry[3]
                    elif isinstance(entry, list) and entry[0] == 'email':
                        owner_email = entry[3]
                result[f"{role.capitalize()} Name"] = owner_name
                result[f"{role.capitalize()} Address"] = owner_address
                result[f"{role.capitalize()} Email"] = owner_email
            else:
                result[f"{role.capitalize()} Name"] = 'N/A'
                result[f"{role.capitalize()} Address"] = 'N/A'
                result[f"{role.capitalize()} Email"] = 'N/A'
        whois_cache[ip] = result
        return result
    except:
        return {
            'Network ID': 'N/A', 'Subnet Mask': 'N/A', 'Network Class': 'N/A',
            'Possible Subnet Count': 'N/A', 'ASN': 'N/A', 'ISP': 'N/A',
            'Country': 'N/A', 'Registration Date': 'N/A', 'Network': 'N/A',
            'Registrant Name': 'N/A', 'Registrant Address': 'N/A', 'Registrant Email': 'N/A',
            'Administrative Name': 'N/A', 'Administrative Address': 'N/A', 'Administrative Email': 'N/A',
            'Technical Name': 'N/A', 'Technical Address': 'N/A', 'Technical Email': 'N/A',
            'Abuse Name': 'N/A', 'Abuse Address': 'N/A', 'Abuse Email': 'N/A'
        }

def get_geo_info(ip):
    """Retrieve geolocation information with caching."""
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        geo_info = geocoder.ip(ip)
        if geo_info.ok:
            result = {
                'Latitude': geo_info.lat,
                'Longitude': geo_info.lng,
                'City': geo_info.city or 'N/A',
                'State': geo_info.state or 'N/A',
                'Postal Code': geo_info.postal or 'N/A'
            }
        else:
            result = {
                'Latitude': 'N/A',
                'Longitude': 'N/A',
                'City': 'N/A',
                'State': 'N/A',
                'Postal Code': 'N/A'
            }
        geo_cache[ip] = result
        return result
    except:
        return {
            'Latitude': 'N/A',
            'Longitude': 'N/A',
            'City': 'N/A',
            'State': 'N/A',
            'Postal Code': 'N/A'
        }

def suggest_attacks(vulnerabilities):
    """Suggest possible attacks based on vulnerabilities."""
    suggestions = []
    for vuln in vulnerabilities:
        for key, suggestion in VULN_TO_ATTACK.items():
            if key in vuln.lower():
                suggestions.append(suggestion)
                break
    return suggestions

def get_ip_info_single(ip):
    """Gather detailed info for a single IP."""
    print(colorama.Fore.CYAN + f"\nScanning IP: {ip}" + colorama.Style.RESET_ALL, flush=True)
    start_time = time.time()
    result = {'IP': ip}
    try:
        ip_obj = ipaddress.ip_address(ip)
        result['IP Version'] = 'IPv6' if ip_obj.version == 6 else 'IPv4'
        print(f"IP Version: {result['IP Version']}", flush=True)
        if ip_obj.version == 4:
            ip_class = None
            if ip_obj.is_multicast:
                ip_class = 'D'
            elif ip_obj.is_private:
                ip_class = 'C' if ip_obj in ipaddress.ip_network('192.168.0.0/16') else 'B' if ip_obj in ipaddress.ip_network('172.16.0.0/12') else 'A'
            result['IP Class'] = ip_class or 'N/A'
            print(f"IP Class: {result['IP Class']}", flush=True)

        # Parallel execution for reverse DNS, port scanning, device details, WHOIS, and protocol scan
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_dns = executor.submit(lambda: socket.gethostbyaddr(ip) if ip else None)
            future_ports = executor.submit(get_open_ports, ip)
            future_device = executor.submit(get_device_details, ip)
            future_whois = executor.submit(get_whois_info, ip)
            future_protocols = executor.submit(get_protocol_info, ip)
            future_geo = executor.submit(get_geo_info, ip)

            # Reverse DNS
            try:
                hostname = future_dns.result()
                result['Hostname'] = hostname[0] if hostname else 'Not found'
                print(f"Hostname: {result['Hostname']}", flush=True)
            except:
                result['Hostname'] = 'Not found'
                print("Hostname: Not found", flush=True)

            # Open Ports, Services, and Vulnerabilities
            open_ports, services, vulnerabilities = future_ports.result()
            result['Open Ports'] = open_ports
            result['Services'] = services
            result['Vulnerabilities'] = vulnerabilities
            print(f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}", flush=True)
            print("Services:", flush=True)
            for service in services:
                print(f"  {service}", flush=True)
            print("Vulnerabilities:", flush=True)
            for vuln in vulnerabilities:
                print(f"  {vuln}", flush=True)

            # Suggest attacks based on vulnerabilities
            attack_suggestions = suggest_attacks(vulnerabilities)
            result['Attack Suggestions'] = attack_suggestions
            print("Attack Suggestions:", flush=True)
            for suggestion in attack_suggestions:
                print(colorama.Fore.RED + f"  {suggestion}" + colorama.Style.RESET_ALL, flush=True)

            # Protocol Scan
            protocols = future_protocols.result()
            result['Protocols'] = protocols
            print("Responsive Protocols:", flush=True)
            for proto in protocols:
                print(f"  {proto}", flush=True)

            # Device Details
            device_details = future_device.result()
            result['MAC Address'] = device_details['mac']
            result['OS Details'] = device_details['os']
            result['Traceroute'] = device_details['traceroute']
            print(f"MAC Address: {device_details['mac']}", flush=True)
            print(f"OS Details: {device_details['os']}", flush=True)
            print(f"Traceroute: {device_details['traceroute']}", flush=True)

            # WHOIS Information
            whois_result = future_whois.result()
            result.update(whois_result)
            for key, value in whois_result.items():
                print(f"{key}: {value}", flush=True)

            # Geolocation
            geo_result = future_geo.result()
            result.update(geo_result)
            for key, value in geo_result.items():
                print(f"{key}: {value}", flush=True)

        # Local Network Info
        result['Local Default Gateway'] = get_default_gateway()
        print(f"Local Default Gateway: {result['Local Default Gateway']}", flush=True)
        result['Local Network Interfaces'] = get_local_network_info()
        print("Local Network Interfaces:", flush=True)
        for iface, ip_cidr in result['Local Network Interfaces'].items():
            print(f"  {iface}: {ip_cidr}", flush=True)

        print(f"Scan Time: {(time.time() - start_time):.2f} seconds", flush=True)
        return result
    except ValueError:
        print("Invalid IP address", flush=True)
    except:
        print("An error occurred, continuing with available data", flush=True)
    return result

def get_ip_info(target):
    """Gather detailed info for a single IP or subnet."""
    start_time = time.time()
    results = []
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            print(f"Scanning subnet: {network}", flush=True)
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(get_ip_info_single, str(ip)) for ip in network.hosts()[:10]]  # Limit to 10 IPs
                for future in futures:
                    results.append(future.result())
        else:
            results.append(get_ip_info_single(str(network.network_address)))
    except ValueError:
        results.append(get_ip_info_single(target))
    print(f"Total Scan Time: {(time.time() - start_time):.2f} seconds", flush=True)
    return results

def sanitize_filename(s):
    """Sanitize a string to be safe for filenames."""
    return re.sub(r'\W+', '_', s)

def generate_html_report(results, filename):
    """Generate an HTML report from the scan results."""
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)
    filepath = os.path.join(REPORT_FOLDER, filename)
    with open(filepath, 'w') as f:
        f.write("<html><head><title>IP Scan Report</title><style>body {font-family: Arial, sans-serif;} table {border-collapse: collapse; width: 100%;} th, td {border: 1px solid #ddd; padding: 8px; text-align: left;} th {background-color: #f2f2f2;} @media (max-width: 600px) {table, th, td {display: block; width: 100%;}}</style></head><body>")
        f.write("<h1>IP Scan Report</h1>")
        for result in results:
            f.write(f"<h2>IP: {result['IP']}</h2>")
            f.write("<table>")
            for key, value in result.items():
                if isinstance(value, list):
                    value = "<br>".join(map(str, value))
                f.write(f"<tr><th>{key}</th><td>{value}</td></tr>")
            f.write("</table>")
        f.write("</body></html>")
    print(f"Report generated: {filepath}", flush=True)

def main_menu():
    """Present the main menu to the user."""
    last_scan_results = []
    last_target = None  # To track whether it was a single IP or CIDR

    while True:
        print(colorama.Fore.YELLOW + "\nMenu:" + colorama.Style.RESET_ALL, flush=True)
        print("1. Scan a single IP", flush=True)
        print("2. Scan a CIDR range", flush=True)
        print("3. Generate report for last scan", flush=True)
        print("4. Exit", flush=True)
        sys.stdout.flush()  # Ensure menu is displayed before input
        choice = input("Enter your choice: ")

        if choice == '1':
            print("Enter the IP address: ", end="", flush=True)
            ip = input()
            last_scan_results = get_ip_info(ip)
            last_target = ip  # Store the target as a single IP

        elif choice == '2':
            print("Enter the CIDR range: ", end="", flush=True)
            cidr = input()
            last_scan_results = get_ip_info(cidr)
            last_target = cidr  # Store the target as a CIDR range

        elif choice == '3':
            if last_scan_results:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if len(last_scan_results) == 1:  # Single IP scan
                    ip = last_scan_results[0]['IP']
                    hostname = last_scan_results[0].get('Hostname', 'Not found')
                    if hostname != 'Not found':
                        filename_part = f"{ip}_{sanitize_filename(hostname)}"
                    else:
                        filename_part = ip
                else:  # CIDR range scan
                    filename_part = sanitize_filename(last_target)  # Use sanitized CIDR notation
                filename = f"report_{filename_part}_{timestamp}.html"
                generate_html_report(last_scan_results, filename)
            else:
                print("No scan has been performed yet.", flush=True)

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please try again.", flush=True)

if __name__ == "__main__":
    main_menu()
