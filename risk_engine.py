def calculate_risk(findings):

    critical = sum(
        1 for f in findings
        if f["Severity"] == "CRITICAL"
    )

    high = sum(
        1 for f in findings
        if f["Severity"] == "HIGH"
    )

    if critical > 0:
        return "CRITICAL"

    if high >= 5:
        return "HIGH"

    if high > 0:
        return "MEDIUM"

    return "LOW"
