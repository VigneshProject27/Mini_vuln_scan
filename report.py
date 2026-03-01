import json


def calculate_summary(findings):
    total_ports = len(findings)
    total_vulnerabilities = 0

    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    for finding in findings:
        vulns = finding.get("vulnerabilities", [])
        total_vulnerabilities += len(vulns)

        for vuln in vulns:
            severity = vuln.get("severity", "Unknown")
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count["Unknown"] += 1

    summary = {
        "total_open_ports": total_ports,
        "total_vulnerabilities": total_vulnerabilities,
        "severity_breakdown": severity_count
    }

    return summary


def generate_report(report_data):
    """
    Expects:
    {
        "target": str,
        "scan_time": str,
        "findings": list
    }
    """

    findings = report_data.get("findings", [])

    # Add summary section
    report_data["summary"] = calculate_summary(findings)

    # Save to JSON file
    with open("report.json", "w") as file:
        json.dump(report_data, file, indent=4)

    return report_data
