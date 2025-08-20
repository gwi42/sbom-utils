#!/usr/bin/env python3
import json
import sys
import os
import glob
from typing import Set, Tuple

def normalize_license(license_str: str) -> str:
    lower = license_str.lower()
    if "lesser general public licen" in lower:
        return "GNU Lesser General Public License"
    return license_str

def extract_licenses(sbom_file: str) -> Tuple[Set[str], str, str, Set[str]]:
    try:
        encodings = ['utf-8', 'utf-8-sig', 'latin1']
        sbom_data = None
        for encoding in encodings:
            try:
                with open(sbom_file, 'r', encoding=encoding) as file:
                    sbom_data = json.load(file)
                break
            except UnicodeDecodeError:
                continue
        if sbom_data is None:
            print(f"Error: Unable to decode '{sbom_file}'")
            return set(), "Unknown SBOM", "Unknown Version", set()

        licenses: Set[str] = set()
        component_licenses: Set[str] = set()
        sbom_name = "Unknown SBOM"
        sbom_version = "Unknown Version"

        if sbom_data.get("bomFormat") == "CycloneDX":
            metadata = sbom_data.get("metadata", {}).get("component", {})
            for license_entry in metadata.get("licenses", []):
                license_obj = license_entry.get("license", {})
                value = license_obj.get("name") or license_obj.get("id") or license_obj.get("expression")
                if value:
                    component_licenses.add(normalize_license(value))

            for component in sbom_data.get("components", []):
                for license_entry in component.get("licenses", []):
                    license_obj = license_entry.get("license", {})
                    value = license_obj.get("name") or license_obj.get("id") or license_obj.get("expression")
                    if value:
                        licenses.add(normalize_license(value))

            sbom_name = metadata.get("name", sbom_name)
            sbom_version = metadata.get("version", sbom_version)

        elif "spdxVersion" in sbom_data:
            for package in sbom_data.get("packages", []):
                license_concluded = package.get("licenseConcluded")
                license_declared = package.get("licenseDeclared")
                if license_concluded and license_concluded != "NOASSERTION":
                    licenses.add(normalize_license(license_concluded))
                if license_declared and license_declared != "NOASSERTION":
                    licenses.add(normalize_license(license_declared))

            sbom_name = sbom_data.get("name", sbom_name)
            metadata = sbom_data.get("metadata", {})
            sbom_name = metadata.get("name", sbom_name)
            sbom_version = metadata.get("versionInfo", sbom_version)

        else:
            print(f"Unsupported SBOM format in {sbom_file}. Expected CycloneDX or SPDX.")
            return set(), sbom_name, sbom_version, set()

        return licenses, sbom_name, sbom_version, component_licenses

    except FileNotFoundError:
        print(f"Error: File '{sbom_file}' not found")
    except json.JSONDecodeError as e:
        print(f"Error: '{sbom_file}' is not valid JSON: {str(e)}")
    except Exception as e:
        print(f"Error processing '{sbom_file}': {str(e)}")

    return set(), "Unknown SBOM", "Unknown Version", set()

def process_file(sbom_file: str):
    licenses, sbom_name, sbom_version, component_licenses = extract_licenses(sbom_file)

    output_file = os.path.splitext(sbom_file)[0] + ".md"
    markdown = f"# {sbom_name} {sbom_version}\n\n"

    markdown += "## License of this component\n\n"
    if component_licenses:
        for license in sorted(component_licenses):
            markdown += f"- {license}\n"
    else:
        markdown += "No license found for this component.\n"

    markdown += "\n## Licenses of used 3rd party libraries\n\n"
    if licenses:
        for license in sorted(licenses):
            markdown += f"- {license}\n"
    else:
        markdown += "No dependencies found, no licenses used.\n"

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(markdown)
        print(f"Licenses saved to {output_file}")
    except Exception as e:
        print(f"Error writing to {output_file}: {str(e)}")

def main():
    if len(sys.argv) == 1:
        json_files = glob.glob("*.json")
        if not json_files:
            print("No JSON files found in the current directory")
            sys.exit(1)
        for file in json_files:
            process_file(file)

    elif len(sys.argv) == 2 and sys.argv[1] in ("--all", "-a"):
        json_files = glob.glob("*.json")
        if not json_files:
            print("No JSON files found in the current directory")
            sys.exit(1)
        for file in json_files:
            process_file(file)

    elif len(sys.argv) == 3 and sys.argv[1] in ("--file", "-f"):
        sbom_file = sys.argv[2]
        if not os.path.isfile(sbom_file):
            print(f"Error: File '{sbom_file}' does not exist")
            sys.exit(1)
        process_file(sbom_file)

    else:
        print("Usage: python extract_licenses.py [--all|-a | --file|-f <filename>]")
        sys.exit(1)

if __name__ == "__main__":
    main()
