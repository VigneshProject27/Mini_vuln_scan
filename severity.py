def classify_severity(score):
    if score is None:
        return "Unknown"
    elif score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "Informational"
