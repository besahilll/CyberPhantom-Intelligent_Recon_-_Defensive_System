import socket
import os
from urllib.parse import urlparse

def resolve_domain(target):
    try:
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else target
        ip = socket.gethostbyname(domain)
        print(f"Resolved {domain} to {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Could not resolve domain {target}")
        return None

def host_discovery(network, hosts):
    print(f"Scanning network: {network}")
    try:
        response = os.system(f"ping -c 1 -W 1 {network} > /dev/null 2>&1")
        if response == 0:
            print(f"Host {network} is active")
            hosts.append(str(network))
    except Exception as e:
        print(f"Error scanning host {network}: {e}")
