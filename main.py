from logo import print_logo
from network import resolve_domain, host_discovery
from scanner import threaded_stealth_scan, os_service_detection, banner_grab, suggest_exploits
from nids import live_nids
from results import save_results_json, save_results_csv

def main():
    print_logo()
    
    results = []
    hosts = []
    open_ports = []
    
    print("\nChoose an option:")
    print("1. Full Scan (Port Scan, OS Detection, Banner Grabbing, Exploit Suggestion)")
    print("2. Port Scan Only")
    print("3. OS Detection Only")
    print("4. Banner Grabbing Only")
    print("5. Live Network Intrusion Detection (NIDS)")

    choice = input("\nEnter your choice (1-5): ")

    if choice != "5":
        target = input("Enter target (IP or Domain): ")
        if not target.replace(".", "").isdigit():
            target = resolve_domain(target)
        if not target:
            print("Invalid target. Exiting.")
            return

    if choice == "1":
        host_discovery(target, hosts)
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        threaded_stealth_scan(target, start_port, end_port, open_ports)
        banners = {port: banner_grab(target, port) for port in open_ports}
        os_info = os_service_detection(target, open_ports, banners)
        
        exploits = {}
        for port, banner in banners.items():
            if banner != "No banner":
                exploit_info = suggest_exploits(banner)
                if exploit_info:
                    exploits[port] = exploit_info
        
        results.append({
            "host": target,
            "open_ports": open_ports.copy(),
            "os": os_info['os'],
            "version": os_info['version'],
            "banners": banners,
            "exploits": exploits
        })
        save_results_json(results)
        save_results_csv(results)

    elif choice == "2":
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        threaded_stealth_scan(target, start_port, end_port, open_ports)

    elif choice == "3":
        start_port = 1
        end_port = 1000
        print("\nPerforming quick port scan for OS detection...")
        threaded_stealth_scan(target, start_port, end_port, open_ports)
        os_service_detection(target, open_ports, {})

    elif choice == "4":
        port = int(input("Enter port to grab banner from: "))
        banner = banner_grab(target, port)
        if banner != "No banner":
            suggest_exploits(banner)

    elif choice == "5":
        live_nids()

    else:
        print("Invalid option. Exiting.")

if __name__ == "__main__":
    main()
