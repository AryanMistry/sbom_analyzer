"""
CycloneDX SBOM Parser
Supports both JSON and XML formats
"""
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional


# CycloneDX XML namespaces for different versions
CYCLONEDX_NAMESPACES = {
    "1.4": "http://cyclonedx.org/schema/bom/1.4",
    "1.5": "http://cyclonedx.org/schema/bom/1.5",
    "1.6": "http://cyclonedx.org/schema/bom/1.6",
}


def parse_cyclonedx_json(content: str) -> Dict[str, Any]:
    """
    Parse CycloneDX JSON format.
    
    Args:
        content: JSON string content of the SBOM file
        
    Returns:
        Normalized SBOM analysis dictionary
    """
    data = json.loads(content)
    
    # Validate format
    if not isinstance(data, dict):
        raise ValueError("Invalid CycloneDX JSON format: expected object")
    
    bom_format = data.get("bomFormat", "").lower()
    if bom_format != "cyclonedx":
        raise ValueError(f"Not a CycloneDX file: bomFormat is '{bom_format}'")
    
    # Extract metadata
    metadata = data.get("metadata", {})
    spec_version = data.get("specVersion", "unknown")
    serial_number = data.get("serialNumber")
    timestamp = metadata.get("timestamp", "unknown")
    
    # Extract tool info
    tools = metadata.get("tools", [])
    tool_name = None
    if tools:
        if isinstance(tools, list) and tools:
            tool_name = tools[0].get("name") if isinstance(tools[0], dict) else str(tools[0])
        elif isinstance(tools, dict):
            tool_name = tools.get("name")
    
    # Extract creator/manufacturer
    creator_org = None
    component_meta = metadata.get("component", {})
    if component_meta:
        supplier = component_meta.get("supplier", {})
        creator_org = supplier.get("name") if supplier else None
    
    # Parse components
    components = []
    for comp in data.get("components", []):
        component = _parse_json_component(comp)
        components.append(component)
    
    return {
        "format": "CycloneDX",
        "spec_version": spec_version,
        "serial_number": serial_number,
        "creation_date": timestamp,
        "creator_tool": tool_name,
        "creator_organization": creator_org,
        "components": components,
        "document_name": component_meta.get("name")
    }


def _parse_json_component(comp: Dict) -> Dict[str, Any]:
    """Parse a single component from CycloneDX JSON"""
    name = comp.get("name", "unknown")
    version = comp.get("version", "unknown")
    purl = comp.get("purl")
    
    # Extract license - can be in different formats
    license_str = None
    licenses = comp.get("licenses", [])
    if licenses:
        first_license = licenses[0]
        if isinstance(first_license, dict):
            # Could be {"license": {"id": "MIT"}} or {"license": {"name": "MIT"}}
            license_obj = first_license.get("license", {})
            license_str = license_obj.get("id") or license_obj.get("name")
            if not license_str:
                # Direct format {"id": "MIT"}
                license_str = first_license.get("id") or first_license.get("name")
    
    # Extract ecosystem from purl
    ecosystem = None
    if purl:
        try:
            purl_type = purl.split(":")[1].split("/")[0]
            ecosystem = purl_type.upper()
        except:
            pass
    
    return {
        "name": name,
        "version": version,
        "purl": purl,
        "license": license_str,
        "ecosystem": ecosystem,
        "description": comp.get("description"),
        "type": comp.get("type"),
        "group": comp.get("group"),
        "vulnerabilities": []
    }


def parse_cyclonedx_xml(content: str) -> Dict[str, Any]:
    """
    Parse CycloneDX XML format.
    Supports versions 1.4, 1.5, and 1.6.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {str(e)}")
    
    # Detect namespace version
    ns_uri = None
    spec_version = None
    
    for version, uri in CYCLONEDX_NAMESPACES.items():
        if uri in root.tag:
            ns_uri = uri
            spec_version = version
            break
    
    if not ns_uri:
        # Try without namespace
        if "bom" in root.tag.lower():
            ns_uri = ""
            spec_version = "unknown"
        else:
            raise ValueError("Not a CycloneDX XML file")
    
    ns = {"cdx": ns_uri} if ns_uri else {}
    prefix = "cdx:" if ns_uri else ""
    
    def find(element, path):
        """Helper to find element with or without namespace"""
        if ns:
            return element.find(path, ns)
        return element.find(path.replace("cdx:", ""))
    
    def findall(element, path):
        """Helper to find all elements with or without namespace"""
        if ns:
            return element.findall(path, ns)
        return element.findall(path.replace("cdx:", ""))
    
    def get_text(element, path, default="unknown"):
        """Helper to get text from element"""
        el = find(element, path)
        return el.text if el is not None and el.text else default
    
    # Extract metadata
    metadata_el = find(root, f"{prefix}metadata")
    timestamp = "unknown"
    tool_name = None
    creator_org = None
    doc_name = None
    
    if metadata_el is not None:
        timestamp = get_text(metadata_el, f"{prefix}timestamp")
        
        # Get tool
        tools_el = find(metadata_el, f"{prefix}tools")
        if tools_el is not None:
            tool_el = find(tools_el, f"{prefix}tool")
            if tool_el is not None:
                tool_name = get_text(tool_el, f"{prefix}name", None)
        
        # Get component metadata
        comp_el = find(metadata_el, f"{prefix}component")
        if comp_el is not None:
            doc_name = get_text(comp_el, f"{prefix}name", None)
            supplier_el = find(comp_el, f"{prefix}supplier")
            if supplier_el is not None:
                creator_org = get_text(supplier_el, f"{prefix}name", None)
    
    # Parse components
    components = []
    components_el = find(root, f"{prefix}components")
    if components_el is not None:
        for comp_el in findall(components_el, f"{prefix}component"):
            component = _parse_xml_component(comp_el, prefix, ns)
            components.append(component)
    
    # Also check for components at root level (some formats)
    for comp_el in findall(root, f".//{prefix}component"):
        if comp_el not in (findall(components_el, f"{prefix}component") if components_el is not None else []):
            component = _parse_xml_component(comp_el, prefix, ns)
            if component not in components:
                components.append(component)
    
    return {
        "format": "CycloneDX",
        "spec_version": spec_version,
        "serial_number": root.get("serialNumber"),
        "creation_date": timestamp,
        "creator_tool": tool_name,
        "creator_organization": creator_org,
        "components": components,
        "document_name": doc_name
    }


def _parse_xml_component(comp_el: ET.Element, prefix: str, ns: Dict) -> Dict[str, Any]:
    """Parse a single component from CycloneDX XML"""
    
    def find(element, path):
        if ns:
            return element.find(path, ns)
        return element.find(path.replace("cdx:", ""))
    
    def get_text(element, path, default=None):
        el = find(element, path)
        return el.text if el is not None and el.text else default
    
    name = get_text(comp_el, f"{prefix}name", "unknown")
    version = get_text(comp_el, f"{prefix}version", "unknown")
    purl = get_text(comp_el, f"{prefix}purl")
    description = get_text(comp_el, f"{prefix}description")
    
    # Extract license
    license_str = None
    licenses_el = find(comp_el, f"{prefix}licenses")
    if licenses_el is not None:
        license_el = find(licenses_el, f"{prefix}license")
        if license_el is not None:
            license_str = get_text(license_el, f"{prefix}id") or get_text(license_el, f"{prefix}name")
    
    # Extract ecosystem from purl
    ecosystem = None
    if purl:
        try:
            purl_type = purl.split(":")[1].split("/")[0]
            ecosystem = purl_type.upper()
        except:
            pass
    
    return {
        "name": name,
        "version": version,
        "purl": purl,
        "license": license_str,
        "ecosystem": ecosystem,
        "description": description,
        "type": comp_el.get("type"),
        "vulnerabilities": []
    }