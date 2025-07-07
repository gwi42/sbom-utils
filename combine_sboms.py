import json
import sys
import os
import uuid
from datetime import datetime
from typing import List, Dict, Set, Tuple

def read_sbom(sbom_file: str, debug: bool = False) -> Tuple[Dict, str]:
    try:
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
            return {}, "unknown"
        
        if "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX":
            sbom_format = "CycloneDX"
        elif "spdxVersion" in sbom_data:
            sbom_format = "SPDX"
        else:
            print(f"Unsupported SBOM format in {sbom_file}. Expected CycloneDX or SPDX.")
            return {}, "unknown"
        
        return sbom_data, sbom_format
    
    except FileNotFoundError:
        print(f"Error: File '{sbom_file}' not found")
        return {}, "unknown"
    except json.JSONDecodeError as e:
        print(f"Error: '{sbom_file}' is not a valid JSON file: {str(e)}")
        return {}, "unknown"
    except Exception as e:
        print(f"Error processing SBOM file {sbom_file}: {str(e)}")
        return {}, "unknown"

def get_metadata_from_sbom(sbom_data: Dict, sbom_format: str, debug: bool = False) -> Tuple[str, str]:
    name = "Combined Project"
    version = "1.0.0"
    
    if sbom_format == "CycloneDX":
        if "metadata" in sbom_data and "component" in sbom_data["metadata"]:
            name = sbom_data["metadata"]["component"].get("name", name)
            version = sbom_data["metadata"]["component"].get("version", version)
            if debug:
                print(f"Extracted metadata from CycloneDX: name={name}, version={version}")
    elif sbom_format == "SPDX":
        name = sbom_data.get("name", name)
        if "metadata" in sbom_data:
            name = sbom_data["metadata"].get("name", name)
            version = sbom_data["metadata"].get("versionInfo", version)
        if debug:
            print(f"Extracted metadata from SPDX: name={name}, version={version}")
    
    return name, version

def convert_spdx_to_cyclonedx_package(package: Dict, debug: bool = False) -> Dict:
    component = {
        "type": "library",  # Default type, as SPDX doesn't always specify
        "name": package.get("name", "unnamed"),
        "version": package.get("versionInfo", "unknown"),
        "bom-ref": package.get("SPDXID", str(uuid.uuid4())),
    }
    licenses = []
    license_concluded = package.get("licenseConcluded")
    license_declared = package.get("licenseDeclared")
    if license_concluded and license_concluded != "NOASSERTION":
        licenses.append({"license": {"id": license_concluded}})
        if debug:
            print(f"Converted SPDX licenseConcluded {license_concluded} to CycloneDX format for {component['name']}")
    if license_declared and license_declared != "NOASSERTION":
        licenses.append({"license": {"id": license_declared}})
        if debug:
            print(f"Converted SPDX licenseDeclared {license_declared} to CycloneDX format for {component['name']}")
    if licenses:
        component["licenses"] = licenses
    return component

def combine_sboms(sbom_files: List[str], project_name: str, project_version: str, debug: bool = False) -> Tuple[Dict, str, str]:
    combined_components: Dict[Tuple[str, str], Dict] = {}
    metadata_name = project_name
    metadata_version = project_version
    
    # Extract metadata from the first valid SBOM if not provided
    if not project_name or not project_version:
        for sbom_file in sbom_files:
            sbom_data, sbom_format = read_sbom(sbom_file, debug)
            if sbom_data:
                name, version = get_metadata_from_sbom(sbom_data, sbom_format, debug)
                if not project_name:
                    metadata_name = name
                if not project_version:
                    metadata_version = version
                break
        else:
            print("Warning: No valid SBOMs found to extract metadata. Using defaults.")
    
    # Combine components
    for sbom_file in sbom_files:
        sbom_data, sbom_format = read_sbom(sbom_file, debug)
        if not sbom_data:
            continue
        
        if sbom_format == "CycloneDX":
            components = sbom_data.get("components", [])
            for component in components:
                name = component.get("name", "unnamed")
                version = component.get("version", "unknown")
                key = (name, version)
                if key not in combined_components:
                    combined_components[key] = component
                    if debug:
                        print(f"Added CycloneDX component: {name} {version} from {sbom_file}")
                elif debug:
                    print(f"Skipped duplicate component: {name} {version} from {sbom_file}")
        
        elif sbom_format == "SPDX":
            packages = sbom_data.get("packages", [])
            for package in packages:
                component = convert_spdx_to_cyclonedx_package(package, debug)
                name = component["name"]
                version = component["version"]
                key = (name, version)
                if key not in combined_components:
                    combined_components[key] = component
                    if debug:
                        print(f"Added converted SPDX package: {name} {version} from {sbom_file}")
                elif debug:
                    print(f"Skipped duplicate package: {name} {version} from {sbom_file}")
    
    # Create combined CycloneDX SBOM
    combined_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": metadata_name,
                "version": metadata_version
            }
        },
        "components": list(combined_components.values())
    }
    
    if debug:
        print(f"Combined {len(combined_components)} unique components into SBOM")
    
    return combined_sbom, metadata_name, metadata_version

def main():
    debug = False
    project_name = ""
    project_version = ""
    
    args = sys.argv[1:]
    if "--debug" in args:
        debug = True
        args.remove("--debug")
    
    if "--name" in args:
        name_index = args.index("--name")
        if name_index + 1 < len(args):
            project_name = args[name_index + 1]
            args = args[:name_index] + args[name_index + 2:]
        else:
            print("Error: --name requires a project name")
            sys.exit(1)
    
    if "--version" in args:
        version_index = args.index("--version")
        if version_index + 1 < len(args):
            project_version = args[version_index + 1]
            args = args[:version_index] + args[version_index + 2:]
        else:
            print("Error: --version requires a version")
            sys.exit(1)
    
    if not args:
        print("Usage: python combine_sboms.py [--debug] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...")
        sys.exit(1)
    
    sbom_files = args
    for sbom_file in sbom_files:
        if not os.path.isfile(sbom_file):
            print(f"Error: File '{sbom_file}' does not exist")
            sys.exit(1)
    
    # Combine SBOMs
    combined_sbom, metadata_name, metadata_version = combine_sboms(sbom_files, project_name, project_version, debug)
    
    # Save combined SBOM
    output_file = "combined_sbom.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump(combined_sbom, file, indent=2)
        print(f"Combined SBOM saved to {output_file} (name: {metadata_name}, version: {metadata_version})")
    except Exception as e:
        print(f"Error writing to {output_file}: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()