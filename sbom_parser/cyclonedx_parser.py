import json
import xml.etree.ElementTree as ET
from typing import Union
def _parse_cyclonedx_json(content: str) -> dict:
    """Parse CycloneDX JSON format"""
    data = json.loads(content)
    
    # basic validation
    if not isinstance(data, dict):
        raise ValueError("Invalid CycloneDX JSON format")
    if "bomFormat" not in data or data["bomFormat"] != "CycloneDX":
        raise ValueError("Not a CycloneDX JSON file")
    
    components = []
    for component in data.get("components", []):
        components.append({
            "name": component.get("name", "unknown"),
            "version": component.get("version", "unknown"),
            "license": component.get("license", {}).get("name", "unknown"),
            "purl": component.get("purl", "unknown")
        })
    
    return {
        "format": "CycloneDX",
        "components": components,
        "creation_date": data.get("metadata", {}).get("timestamp", "unknown")
    }

def _parse_cyclonedx_xml(content: str) -> dict:
    """Parse CycloneDX XML format"""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {str(e)}")
    
    # Namespace handling
    ns = {"cdx": "http://cyclonedx.org/schema/bom/1.4"}
    
    # Basic validation
    if root.tag != "{http://cyclonedx.org/schema/bom/1.4}bom":
        raise ValueError("Not a CycloneDX XML file")
    
    components = []
    for component in root.findall(".//cdx:component", ns):
        components.append({
            "name": component.find("cdx:name", ns).text if component.find("cdx:name", ns) is not None else "unknown",
            "version": component.find("cdx:version", ns).text if component.find("cdx:version", ns) is not None else "unknown",
            "license": component.find("cdx:license/cdx:name", ns).text if component.find("cdx:license/cdx:name", ns) is not None else "unknown",
            "purl": component.find("cdx:purl", ns).text if component.find("cdx:purl", ns) is not None else "unknown"
        })
    
    return {
        "format": "CycloneDX",
        "components": components,
        "creation_date": root.find("cdx:metadata/cdx:timestamp", ns).text if root.find("cdx:metadata/cdx:timestamp", ns) is not None else "unknown"
    }