import nmap
import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {
    "User-Agent": "MiniVulnScanner"
}

# ---------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------

def get_severity(cvss_score):
    if cvss_score is None:
        return "Unknown"
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0:
        return "Low"
    else:
        return "Unknown"

# ---------------------------------------------------------
# Fetch CVEs
# ---------------------------------------------------------

def fetch_cves(product, version):
    vulnerabilities = []

    if not product:
        return vulnerabilities

    keyword = f"{product} {version}" if version else product

    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }

        response = requests.get(NVD_API_URL, headers=HEADERS, params=params, timeout=15)

        if response.status_code != 200:
            return vulnerabilities

        data = response.json()

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})

            cve_id = cve_data.get("id")

            # Description
            description = None
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            # CVSS Score
            metrics = cve_data.get("metrics", {})
            cvss_score = None

            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            vulnerabilities.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "description": description,
                "severity": get_severity(cvss_score)
            })

        time.sleep(1)

    except Exception as e:
        print("CVE fetch error:", e)

    return vulnerabilities

# ---------------------------------------------------------
# Main Scan Logic
# ---------------------------------------------------------

def run_scan_logic(target, progress_callback=None):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sV")

    results = []

    total_ports = 0
    scanned_ports = 0

    # Count total ports
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            total_ports += len(scanner[host][proto].keys())

    if total_ports == 0:
        return results

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():

                scanned_ports += 1
                port_data = scanner[host][proto][port]

                service = port_data.get("name", "")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                vulnerabilities = fetch_cves(product, version)

                results.append({
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "service": service,
                    "product": product,
                    "version": version,
                    "vulnerabilities": vulnerabilities
                })

                if progress_callback:
                    percent = int((scanned_ports / total_ports) * 100)
                    progress_callback(percent)

    return results
