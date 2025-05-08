import socket
import nmap
from scapy.all import *
import requests
from concurrent.futures import ThreadPoolExecutor

def stealth_scan(host, port, open_ports):
    try:
        syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
        syn_ack = sr1(syn_packet, timeout=0.5, verbose=False)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == "SA":
            print(f"Port {port} is open on {host} (SYN scan)")
            open_ports.append(port)
    except Exception:
        pass

def threaded_stealth_scan(host, start_port, end_port, open_ports):
    print(f"Scanning open ports on {host} from {start_port} to {end_port}")
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(stealth_scan, host, port, open_ports)

def is_external_ip(ip):
    parts = ip.split('.')
    first = int(parts[0])
    second = int(parts[1])
    return not (
        (first == 10) or
        (first == 172 and 16 <= second <= 31) or
        (first == 192 and second == 168)
    )

def os_service_detection(host, open_ports, banners):
    nm = nmap.PortScanner()
    if len(open_ports) < 2:
        print("Skipping OS detection (not enough open ports)")
        return {"os": "Unknown", "version": "Unknown"}

    print(f"[*] Running OS and service detection on {host}. Please wait...")
    try:
        if is_external_ip(host):
            print("[!] Skipping deep OS detection due to external IP. Falling back to banner analysis.")
            raise Exception("External host")
        nm.scan(host, arguments='-O --version-light')
        os_data = nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else "Unknown"

        if os_data == "Unknown":
            for port, banner in banners.items():
                os_guess = detect_os_from_banner(banner)
                if os_guess != "Unknown":
                    os_data = os_guess
                    break

        print(f"Detected OS: {os_data}")
        return {"os": os_data, "version": "Nmap"}
    except Exception:
        for port, banner in banners.items():
            os_guess = detect_os_from_banner(banner)
            if os_guess != "Unknown":
                print(f"Guessed OS from banner: {os_guess}")
                return {"os": os_guess, "version": "Banner Analysis"}
        return {"os": "Unknown", "version": "Fallback"}

def detect_os_from_banner(banner):
    if "Ubuntu" in banner:
        return "Ubuntu"
    elif "Debian" in banner:
        return "Debian"
    elif "Windows" in banner:
        return "Windows"
    return "Unknown"

def banner_grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        banner = s.recv(1024).decode().strip()
        print(f"Banner on port {port} of {host}: {banner}")
        s.close()
        return banner
    except Exception:
        return "No banner"

def suggest_exploits(service_banner):
    print(f"\n🔎 Analyzing banner for vulnerabilities: {service_banner}")
    
    try:
        service = "Unknown"
        version = ""
        
        if "SSH" in service_banner:
            service = "OpenSSH"
            parts = service_banner.split()
            for part in parts:
                if part.startswith("OpenSSH_"):
                    version = part.split("_")[1]
                    break
                elif part.count(".") >= 1 and any(c.isdigit() for c in part):
                    version = part
        
        elif "HTTP" in service_banner or "Apache" in service_banner:
            service = "Apache"
            if "Apache/" in service_banner:
                version = service_banner.split("Apache/")[1].split()[0]
            elif "Server:" in service_banner:
                version = service_banner.split("Server:")[1].split()[0]
        
        elif "ftp" in service_banner.lower():
            service = "FTP"
            if "vsFTPd" in service_banner:
                service = "vsFTPd"
                version = service_banner.split("vsFTPd")[1].split()[0]
        
        if service != "Unknown" and version:
            search_term = f"{service} {version.split('-')[0].split('+')[0].split('~')[0]}"
            search_term = search_term.strip()
            print(f"\n💡 Found service: {service} version: {version}")
            print("🔗 Possible exploit sources:")
            
            exploitdb_url = f"https://www.exploit-db.com/search?q={search_term.replace(' ', '+')}"
            print(f"- ExploitDB: {exploitdb_url}")
            
            nvd_url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={search_term.replace(' ', '+')}&search_type=all"
            print(f"- NVD Database: {nvd_url}")
            
            rapid7_url = f"https://www.rapid7.com/db/?q={search_term.replace(' ', '+')}"
            print(f"- Rapid7 DB: {rapid7_url}")
            
            return {
                "service": service,
                "version": version,
                "exploitdb": exploitdb_url,
                "nvd": nvd_url,
                "rapid7": rapid7_url
            }
        else:
            print("⚠️ Could not extract specific version information")
            print(f"🔗 General search: https://www.exploit-db.com/search?q={service_banner[:30].replace(' ', '+')}")
            return None
            
    except Exception as e:
        print(f"Error analyzing banner: {e}")
        return None
