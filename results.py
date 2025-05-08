import json
import csv

def save_results_json(results):
    try:
        with open('scan_results.json', 'w') as f:
            json.dump(results, f, indent=4)
        print("Results saved to scan_results.json")
    except Exception as e:
        print(f"Error saving results: {e}")

def save_results_csv(results):
    try:
        with open('scan_results.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Open Ports", "OS", "Version", "Banners", "Exploits"])
            for result in results:
                writer.writerow([
                    result['host'],
                    result['open_ports'],
                    result['os'],
                    result['version'],
                    str(result['banners']),
                    str(result['exploits'])
                ])
        print("Results saved to scan_results.csv")
    except Exception as e:
        print(f"Error saving results: {e}")
