# evtx_parser.py

# evtx_parser.py

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

# Windows EVTX XML uses this namespace
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

def parse_evtx(file_path):
    events = []

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = ET.fromstring(xml)

                # Use namespace-aware search
                event_id = root.find(f".//{{{NS}}}EventID")
                timestamp = root.find(f".//{{{NS}}}TimeCreated")

                # Fallback: try without namespace if not found
                if event_id is None:
                    event_id = root.find(".//EventID")
                if timestamp is None:
                    timestamp = root.find(".//TimeCreated")

                events.append({
                    "EventID": event_id.text.strip() if event_id is not None and event_id.text else "",
                    "Timestamp": timestamp.attrib.get("SystemTime", "") if timestamp is not None else "",
                    "RawXML": xml
                })

            except Exception:
                continue

    return events