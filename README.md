# SBOM Tools

This repository contains two Python scripts for working with Software Bill of Materials (SBOM) files in CycloneDX or SPDX JSON formats:

1. **`extract_licenses.py`**: Extracts a unique list of licenses from one or more SBOM files and saves them as Markdown files.
2. **`combine_sboms.py`**: Combines multiple SBOM files into a single CycloneDX JSON SBOM, merging components and deduplicating based on name and version.

Both scripts support UTF-8, UTF-8 with BOM, and Latin-1 encodings for input files and include error handling for invalid JSON or unsupported SBOM formats.

## Requirements

- Python 3.6 or later
- Input SBOM files must be in valid CycloneDX or SPDX JSON format

## Installation

1. Save both scripts (`extract_licenses.py` and `combine_sboms.py`) in your working directory (e.g., `C:\sbom\`).
2. Ensure Python is installed and accessible from your command line.

## `extract_licenses.py`

### Purpose

Extracts a unique list of licenses from one or more SBOM files and saves them as Markdown files. Each output file includes the SBOM's name and version (from `metadata.component` for CycloneDX or `metadata.name`/`name` and `metadata.versionInfo` for SPDX) and a bulleted list of licenses.

### Usage

Run the script from the command line in the directory containing your SBOM files.

#### Syntax

```bash
python extract_licenses.py [--debug] [--all|-a | --file|-f <filename>]
```

#### Options

- `--debug`: Enable detailed logging (e.g., component/package processing, license fields).
- `--all` or `-a`: Process all `.json` files in the current directory.
- `--file <filename>` or `-f <filename>`: Process a single specified SBOM file.
- _Default_: If no arguments are provided, processes all `.json` files in the current directory.

#### Examples

1. **Process all JSON SBOMs in the current directory**:

   ```bash
   python extract_licenses.py
   ```

   Output: Creates a `.md` file for each `.json` file (e.g., `sbom.json` → `sbom.md`).

2. **Process a single SBOM file**:
   ```bash
   python extract_licenses.py --file "Application - 1.0 - sbom.json"
   ```
   Output: Creates `Application - 1.0 - sbom.md`.

#### Output Format

For an SBOM file `Application - 1.0 - sbom.json`, the output `Application - 1.0 - sbom.md` will look like:

```markdown
# Application 1.0

## Used Licenses

- Apache-2.0
- MIT
- BSD-3-Clause
```

#### Notes

- Supports CycloneDX (extracts licenses from `components[].licenses[].license.name|id|expression`) and SPDX (extracts `packages[].licenseConcluded|licenseDeclared`, excluding `NOASSERTION`).
- Outputs one Markdown file per input SBOM, named `<input_filename>.md`.
- If no licenses are found, an error message is printed (with details if `--debug` is used).

## `combine_sboms.py`

### Purpose

Combines multiple SBOM files (CycloneDX or SPDX JSON) into a single CycloneDX JSON SBOM. Components/packages are deduplicated based on `name` and `version`, and the first occurrence is kept. The combined SBOM's metadata uses a specified project name and version or defaults to values from the first valid SBOM.

### Usage

Run the script from the command line, providing the SBOM files to combine.

#### Syntax

```bash
python combine_sboms.py [--debug] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...
```

#### Options

- `--debug`: Enable detailed logging (e.g., file reading, component additions, duplicates).
- `--name <project_name>`: Set the project name in the combined SBOM's metadata (default: `Combined Project` or first SBOM's metadata name).
- `--version <version>`: Set the version in the combined SBOM's metadata (default: `1.0.0` or first SBOM's metadata version).
- `<sbom_file1> <sbom_file2> ...`: List of SBOM files to combine (at least one required).

#### Examples

1. **Combine multiple SBOMs with default metadata**:

   ```bash
   python combine_sboms.py react1.sbom.json react2.sbom.json java.sbom.json
   ```

   Output: Creates `combined_sbom.json` with metadata from `react1.sbom.json` (e.g., `metadata.component.name` for CycloneDX or `metadata.name`/`name` for SPDX).

2. **Combine with custom name and version**:

   ```bash
   python combine_sboms.py --name "MyProject" --version "1.0" react1.sbom.json react2.sbom.json java.sbom.json
   ```

   Output: Creates `combined_sbom.json` with metadata name `MyProject` and version `1.0`.

3. **Combine with debug output**:
   ```bash
   python combine_sboms.py --debug --name "MyProject" react1.sbom.json react2.sbom.json java.sbom.json
   ```
   Output: Creates `combined_sbom.json` and prints detailed logs for each component/package.

#### Output Format

The output `combined_sbom.json` is a CycloneDX JSON SBOM:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
  "metadata": {
    "timestamp": "2025-07-07T15:35:00Z",
    "component": {
      "type": "application",
      "name": "MyProject",
      "version": "1.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "accepts",
      "version": "2.0.0",
      "bom-ref": "9e15c855-b72e-49b8-9c11-40a07b9bea83",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    ...
  ]
}
```

#### Notes

- Supports CycloneDX and SPDX JSON SBOMs.
- SPDX packages are converted to CycloneDX components, mapping `licenseConcluded`/`licenseDeclared` to `licenses[].license.id`.
- Deduplicates components based on `name` and `version` (case-sensitive), keeping the first occurrence.
- If `--name` or `--version` is not provided, uses metadata from the first valid SBOM (CycloneDX: `metadata.component.name/version`; SPDX: `metadata.name`/`name` and `metadata.versionInfo`).
- Outputs `combined_sbom.json` in the current directory.

## Troubleshooting

### Common Issues

- **Invalid JSON**: Ensure input SBOMs are valid JSON (use a JSON validator or text editor like VS Code).
- **Unsupported Format**: SBOMs must be CycloneDX (`bomFormat: "CycloneDX"`) or SPDX (`spdxVersion` present). Check the SBOM's top-level structure.
- **Encoding Issues**: Both scripts try UTF-8, UTF-8 with BOM, and Latin-1. If a file fails to decode, check its encoding with:
  ```bash
  pip install chardet
  python -c "import chardet; with open('sbom.json', 'rb') as f: print(chardet.detect(f.read()))"
  ```
- **No Licenses Found** (`extract_licenses.py`): Use `--debug` to check if components/packages have valid `licenses`, `licenseConcluded`, or `licenseDeclared` fields.
- **Missing Components** (`combine_sboms.py`): Use `--debug` to verify component additions and check for duplicates.

### Getting Help

If you encounter issues:

1. Run with `--debug` to see detailed logs.
2. Check input SBOMs for valid structure and license fields.
3. Share console output and, if possible, anonymized SBOM snippets (e.g., top-level structure or a component/package).

## License

The `extract_licenses.py` and `combine_sboms.py` scripts are licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
