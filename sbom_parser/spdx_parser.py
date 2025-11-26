import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import re


# SPDX RDF namespaces
SPDX_NAMESPACES = {
    "spdx": "http://spdx.org/rdf/terms#",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "doap": "http://usefulinc.com/ns/doap#",
}


def parse_spdx(content: str) -> Dict[str, Any]:
    """
    Parse SPDX file (auto-detect JSON or RDF/XML format).
    
    Args:
        content: String content of the SBOM file
        
    Returns:
        Normalized SBOM analysis dictionary
    """
    content = content.strip()
    
    # Try JSON first
    if content.startswith("{"):
        return parse_spdx_json(content)
    elif content.startswith("<"):
        return parse_spdx_rdf(content)
    else:
        try:
            return parse_spdx_json(content)
        except:
            raise ValueError("Unable to determine SPDX format (not JSON or XML)")


def parse_spdx_json(content: str) -> Dict[str, Any]:
    """
    Parse SPDX JSON format.
    """
    data = json.loads(content)
    
    # Validate SPDX format
    spdx_version = data.get("spdxVersion", "")
    if not spdx_version.startswith("SPDX"):
 
        if "SPDXID" not in data and "packages" not in data:
            raise ValueError("Not a valid SPDX JSON file")
    
    # Extract metadata
    creation_info = data.get("creationInfo", {})
    created = creation_info.get("created", "unknown")
    
    # Get creator info
    creators = creation_info.get("creators", [])
    tool_name = None
    creator_org = None
    for creator in creators:
        if isinstance(creator, str):
            if creator.startswith("Tool:"):
                tool_name = creator.replace("Tool:", "").strip()
            elif creator.startswith("Organization:"):
                creator_org = creator.replace("Organization:", "").strip()
    
    # Parse packages/components
    components = []
    for package in data.get("packages", []):
        component = _parse_spdx_json_package(package)
        components.append(component)
    
    return {
        "format": "SPDX",
        "spec_version": spdx_version,
        "serial_number": data.get("SPDXID"),
        "creation_date": created,
        "creator_tool": tool_name,
        "creator_organization": creator_org,
        "components": components,
        "document_name": data.get("name")
    }


def _parse_spdx_json_package(package: Dict) -> Dict[str, Any]:
    """Parse a single package from SPDX JSON"""
    name = package.get("name", "unknown")
    version = package.get("versionInfo", "unknown")
    
    # Extract license (SPDX has multiple license fields)
    license_str = (
        package.get("licenseConcluded") or 
        package.get("licenseDeclared") or
        None
    )
    
    if license_str and license_str.upper() == "NOASSERTION":
        license_str = None
    
    purl = None
    for ext_ref in package.get("externalRefs", []):
        if ext_ref.get("referenceType") == "purl":
            purl = ext_ref.get("referenceLocator")
            break
    
    # Extract ecosystem from PURL
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
        "description": package.get("description"),
        "supplier": package.get("supplier"),
        "download_location": package.get("downloadLocation"),
        "vulnerabilities": []
    }


def parse_spdx_rdf(content: str) -> Dict[str, Any]:
    """
    Parse SPDX RDF/XML format.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid SPDX RDF/XML: {str(e)}")
    
    ns = SPDX_NAMESPACES
    
    # Find SpdxDocument
    doc = root.find(".//spdx:SpdxDocument", ns)
    if doc is None:
        # Try without namespace
        doc = root.find(".//SpdxDocument")
        if doc is None:
            # Try root
            doc = root
    
    # Extract metadata
    spec_version = _get_rdf_text(doc, ".//spdx:specVersion", ns) or "SPDX-2.3"
    creation_date = _get_rdf_text(doc, ".//spdx:created", ns) or "unknown"
    doc_name = _get_rdf_text(doc, ".//spdx:name", ns)
    
    # Get creator info
    tool_name = None
    creator_org = None
    creation_info = doc.find(".//spdx:CreationInfo", ns)
    if creation_info is not None:
        for creator in creation_info.findall(".//spdx:creator", ns):
            text = creator.text or ""
            if text.startswith("Tool:"):
                tool_name = text.replace("Tool:", "").strip()
            elif text.startswith("Organization:"):
                creator_org = text.replace("Organization:", "").strip()
    
    # Parse packages
    components = []
    for package in root.findall(".//spdx:Package", ns):
        component = _parse_spdx_rdf_package(package, ns)
        components.append(component)
    
    # Also try without namespace
    if not components:
        for package in root.findall(".//Package"):
            component = _parse_spdx_rdf_package(package, {})
            components.append(component)
    
    return {
        "format": "SPDX",
        "spec_version": spec_version,
        "serial_number": doc.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about"),
        "creation_date": creation_date,
        "creator_tool": tool_name,
        "creator_organization": creator_org,
        "components": components,
        "document_name": doc_name
    }


def _parse_spdx_rdf_package(package: ET.Element, ns: Dict) -> Dict[str, Any]:
    """Parse a single package from SPDX RDF"""
    name = _get_rdf_text(package, ".//spdx:name", ns) or "unknown"
    version = _get_rdf_text(package, ".//spdx:versionInfo", ns) or "unknown"
    
    # Get license
    license_str = (
        _get_rdf_text(package, ".//spdx:licenseConcluded", ns) or
        _get_rdf_text(package, ".//spdx:licenseDeclared", ns)
    )
    
    if license_str:
        license_str = re.sub(r'http://spdx.org/licenses/', '', license_str)
        if license_str.upper() == "NOASSERTION":
            license_str = None
    
    # Get PURL from external refs
    purl = None
    for ext_ref in package.findall(".//spdx:externalRef", ns) or package.findall(".//externalRef"):
        ref_type = _get_rdf_text(ext_ref, ".//spdx:referenceType", ns)
        if ref_type and "purl" in ref_type.lower():
            purl = _get_rdf_text(ext_ref, ".//spdx:referenceLocator", ns)
            break
    
    # Extract ecosystem
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
        "description": _get_rdf_text(package, ".//spdx:description", ns),
        "download_location": _get_rdf_text(package, ".//spdx:downloadLocation", ns),
        "vulnerabilities": []
    }


def _get_rdf_text(element: ET.Element, path: str, ns: Dict, default: str = None) -> Optional[str]:
    """Helper to get text from RDF element"""
    if element is None:
        return default
    
    if ns:
        el = element.find(path, ns)
    else:
        # Try without namespace
        el = element.find(path.replace("spdx:", "").replace("rdf:", "").replace("rdfs:", ""))
    
    if el is not None:
        # Check for rdf:resource attribute
        resource = el.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource")
        if resource:
            return resource
        return el.text
    
    return default
