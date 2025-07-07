import json
import sys
import os
import glob
from typing import Set, Tuple

def extract_licenses(sbom_file: str, debug: bool = False) -> Tuple[Set[str], str, str]:
    try:
        # Try opening with UTF-8 first, then fall back to utf-8-sig or latin1
        encodings = ['utf-8', 'utf-8-sig', 'latin1']
        sbom_data = None
        for encoding in encodings:
            try:
                with open(sbom_file, 'r', encoding=encoding) as file:
                    sbom_data = json.load(file)
                if debug:
                    print(f"Successfully read {sbom_file} with encoding: {encoding}")
                break
            except UnicodeDecodeError:
                continue
        if sbom_data is None:
            print(f"Error: Unable to decode '{sbom_file}' with supported encodings (utf-8, utf-8-sig, latin1)")
            return set(), "Unknown SBOM", "Unknown Version"

        licenses: Set[str] = set()
        sbom_name = "Unknown SBOM"
        sbom_version = "Unknown Version"
        component_count = 0
        
        # Check if it's CycloneDX format
        if "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX":
            components = sbom_data.get("components", [])
            if not components and debug:
                print(f"No components found in {sbom_file} (CycloneDX format)")
            for component in components:
                component_count += 1
                component_name = component.get("name", "unnamed")
                if debug:
                    print(f"Processing component {component_count}: {component_name}")
                if "licenses" in component:
                    if debug:
                        print(f"Found licenses field in component {component_name}: {component['licenses']}")
                    for license_entry in component["licenses"]:
                        if "license" in license_entry:
                            license_data = license_entry["license"]
                            license_name = license_data.get("name")
                            license_id = license_data.get("id")
                            license_expression = license_data.get("expression")
                            if license_name:
                                if debug:
                                    print(f"Adding license (name): {license_name} from {component_name}")
                                licenses.add(license_name)
                            elif license_id:
                                if debug:
                                    print(f"Adding license (id): {license_id} from {component_name}")
                                licenses.add(license_id)
                            elif license_expression:
                                if debug:
                                    print(f"Adding license (expression): {license_expression} from {component_name}")
                                licenses.add(license_expression)
                            elif debug:
                                print(f"No valid license name, id, or expression in component {component_name}: {license_data}")
                        elif debug:
                            print(f"Invalid license entry format in component {component_name}: {license_entry}")
                elif debug:
                    print(f"No licenses field in component {component_name}")
            if debug:
                print(f"Processed {component_count} components in {sbom_file}")
            if not licenses:
                print(f"No valid licenses found in components of {sbom_file}")
            # Get name and version from metadata.component
            if "metadata" in sbom_data and "component" in sbom_data["metadata"]:
                sbom_name = sbom_data["metadata"]["component"].get("name", "Unknown SBOM")
                sbom_version = sbom_data["metadata"]["component"].get("version", "Unknown Version")
        
        # Check if it's SPDX format
        elif "spdxVersion" in sbom_data:
            packages = sbom_data.get("packages", [])
            if not packages and debug:
                print(f"No packages found in {sbom_file} (SPDX format)")
            for package in packages:
                component_count += 1
                package_name = package.get("name", "unnamed")
                if debug:
                    print(f"Processing package {component_count}: {package_name}")
                license_concluded = package.get("licenseConcluded")
                license_declared = package.get("licenseDeclared")
                if license_concluded and license_concluded != "NOASSERTION":
                    if debug:
                        print(f"Adding license (concluded): {license_concluded} from {package_name}")
                    licenses.add(license_concluded)
                if license_declared and license_declared != "NOASSERTION":
                    if debug:
                        print(f"Adding license (declared): {license_declared} from {package_name}")
                    licenses.add(license_declared)
                if not (license_concluded and license_concluded != "NOASSERTION") and \
                   not (license_declared and license_declared != "NOASSERTION") and debug:
                    print(f"No valid licenses in package {package_name}: "
                          f"licenseConcluded={license_concluded}, licenseDeclared={license_declared}")
            if debug:
                print(f"Processed {component_count} packages in {sbom_file}")
            if not licenses:
                print(f"No valid licenses found in packages of {sbom_file}")
            # Get name and version from metadata or top-level
            sbom_name = sbom_data.get("name", "Unknown SBOM")
            if "metadata" in sbom_data:
                sbom_name = sbom_data["metadata"].get("name", sbom_name)
                sbom_version = sbom_data["metadata"].get("versionInfo", "Unknown Version")
        
        else:
            print(f"Unsupported SBOM format in {sbom_file}. Expected CycloneDX or SPDX.")
            return set(), sbom_name, sbom_version
        
        return licenses, sbom_name, sbom_version
    
    except FileNotFoundError:
        print(f"Error: File '{sbom_file}' not found")
        return set(), "Unknown SBOM", "Unknown Version"
    except json.JSONDecodeError as e:
        print(f"Error: '{sbom_file}' is not a valid JSON file: {str(e)}")
        return set(), "Unknown SBOM", "Unknown Version"
    except Exception as e:
        print(f"Error processing SBOM file {sbom_file}: {str(e)}")
        return set(), "Unknown SBOM", "Unknown Version"

def process_file(sbom_file: str, debug: bool = False):
    licenses, sbom_name, sbom_version = extract_licenses(sbom_file, debug)
    
    if licenses:
        output_file = os.path.splitext(sbom_file)[0] + ".md"
        
        markdown_content = f"# {sbom_name} {sbom_version}\n\n"
        markdown_content += "## Licenses of used 3rd party libraries\n\n"
        for license in sorted(licenses):
            markdown_content += f"- {license}\n"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(markdown_content)
            print(f"Licenses saved to {output_file}")
        except Exception as e:
            print(f"Error writing to {output_file}: {str(e)}")
    else:
        print(f"No licenses found or error occurred for {sbom_file}")

def main():
    debug = False
    if "--debug" in sys.argv:
        debug = True
        sys.argv.remove("--debug")

    if len(sys.argv) == 1:
        # Default: process all JSON files in the current directory
        json_files = glob.glob("*.json")
        if not json_files:
            print("No JSON files found in the current directory")
            sys.exit(1)
        for sbom_file in json_files:
            process_file(sbom_file, debug)
    
    elif len(sys.argv) == 2 and sys.argv[1] in ["--all", "-a"]:
        json_files = glob.glob("*.json")
        if not json_files:
            print("No JSON files found in the current directory")
            sys.exit(1)
        for sbom_file in json_files:
            process_file(sbom_file, debug)
    
    elif len(sys.argv) == 3 and sys.argv[1] in ["--file", "-f"]:
        sbom_file = sys.argv[2]
        if not os.path.isfile(sbom_file):
            print(f"Error: File '{sbom_file}' does not exist")
            sys.exit(1)
        process_file(sbom_file, debug)
    
    else:
        print("Usage: python extract_licenses.py [--debug] [--all|-a | --file|-f <filename>]")
        sys.exit(1)

if __name__ == "__main__":
    main()