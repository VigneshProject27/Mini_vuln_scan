import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_severity_from_score(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Unknown"


def fetch_cves(product, version):
    """
    Queries NVD API and returns:
    [
        {
            "cve_id": str,
            "cvss_score": float,
            "severity": str,
            "description": str
        }
    ]
    """

    query = f"{product} {version}".strip()

    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            description = ""
            descriptions = cve.get("descriptions", [])
            if descriptions:
                description = descriptions[0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss_score = None

            # Check CVSS v3.1
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            # Check CVSS v3.0
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

            # Check CVSS v2
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            severity = get_severity_from_score(cvss_score)

            vulnerabilities.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description
            })

        return vulnerabilities

    except Exception as e:
        print(f"[!] CVE lookup failed: {e}")
        return []
