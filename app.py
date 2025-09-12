import argparse
from sbom_parser.spdx_parser import parse_spdx
from sbom_parser.cyclonedx_parser import parse_cyclonedx
from utils.vulnerability_lookup import check_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="SBOM Parser MVP")
    parser.add_argument("file", help="Path to SBOM file")
    args = parser.parse_args()
    
    if "spdx" in args.file.lower():
        result = parse_spdx(args.file)
    elif "cyclonedx" in args.file.lower():
        result = parse_cyclonedx(args.file)
    else:
        raise ValueError("Unsupported SBOM format")
    
    # Enrich with vulnerabilities
    for component in result["components"]:
        component["vulnerabilities"] = check_vulnerabilities(
            component["name"], 
            component["version"]
        )
    
    print(format_result(result))

def format_result(result: dict) -> str:
    """Generate human-readable report"""
    report = []
    report.append(f"SBOM Format: {result['format']}")
    report.append(f"Creation Date: {result['creation_date']}")
    report.append("\nComponents:")
    
    for idx, component in enumerate(result["components"], 1):
        report.append(
            f"{idx}. {component['name']}@{component['version']} | "
            f"License: {component['license']} | "
            f"Vulnerabilities: {len(component['vulnerabilities'])}"
        )
    
    return "\n".join(report)

if __name__ == "__main__":
    main()