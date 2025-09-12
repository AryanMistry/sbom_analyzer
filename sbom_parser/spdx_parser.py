import json

def parse_spdx(content: bytes) -> dict:
    """Parse SPDX file"""
    data = json.loads(content)
    components = []
    for package in data.get("packages", []):
        components.append({
            "name": package.get("name"),
            "version": package.get("versionInfo", "unknown"),
            "license": package.get("licenseConcluded"),
            "purl": None  # SPDX doesn't use PURLs
        })
    return {
        "format": "SPDX",
        "components": components,
        "creation_date": data.get("creationInfo", {}).get("created", "unknown")
    }