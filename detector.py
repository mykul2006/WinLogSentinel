from detections import DETECTIONS

def detect_events(events):

    findings = []
    failed_logons = 0

    for event in events:

        try:
            event_id = int(event["EventID"])

            if event_id == 4625:
                failed_logons += 1

            if event_id in DETECTIONS:

                detection = DETECTIONS[event_id]

                findings.append({
                    "Timestamp": event["Timestamp"],
                    "EventID": event_id,
                    "Detection": detection["name"],
                    "Severity": detection["severity"],
                    "Technique": detection["technique"],
                    "MITRE": detection.get("mitre_id", "N/A")
                })

        except Exception:
            continue

    if failed_logons >= 10:

        findings.append({
            "Timestamp": "Multiple Events",
            "EventID": 4625,
            "Detection": "Possible Brute Force Attack",
            "Severity": "CRITICAL",
            "Technique": "Credential Access",
            "MITRE": "T1110"
        })

    return findings, failed_logons