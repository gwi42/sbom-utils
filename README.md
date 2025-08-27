# SBOM Tools

This repository provides tools for working with Software Bill of Materials (SBOM) files in CycloneDX or SPDX JSON formats. The tools are implemented in Python (`extract_licenses.py`, `combine_sboms.py`) and TypeScript (`extract_licenses.ts`, `combine_sboms.ts`) with identical functionality:

1. **Extract Licenses**: Extracts a unique list of licenses from one or more SBOM files and saves them as Markdown files.
2. **Combine SBOMs**: Combines multiple SBOM files into a single CycloneDX JSON SBOM, deduplicating components based on name and version.

Both implementations support UTF-8, UTF-8 with BOM, and Latin-1 encodings for input files and include error handling for invalid JSON or unsupported SBOM formats.

## Installation

### General Requirements

-   **Input Files**: SBOMs must be valid CycloneDX (`bomFormat: "CycloneDX"`) or SPDX (`spdxVersion` present) JSON.
-   Ensure the runtime (Python or Node.js) is installed and accessible from your command line.
-   Place SBOM files in your working directory (e.g., `C:\sbom\`).

### Python Installation

-   **Runtime**: Python 3.6 or later.
-   **Steps**:
    1. Save `extract_licenses.py` and `combine_sboms.py` in your working directory.
    2. Verify Python is in your PATH: `python --version`

### Node.js Installation

-   **Runtime**: Node.js 14.x or later (tested with 22.18.0).

#### Global installation

```bash
npm install -g @gwi42/sbom-utils@1.0.4
```

#### Project dev dependency

1. Install project dependency
    ```bash
    npm install --save-dev @gwi42/sbom-utils@1.0.4
    ```
2. Add a script to `package.json` to run `extract-licenses` or `combine-sboms`. Example:
    ```json
    {
        "scripts": {
            "extract-licenses": "extract-licenses --file sbom.json"
        }
    }
    ```
3. Run the script:
    ```bash
    npm run extract-licenses
    ```

## Extract Licenses

### Purpose

Extracts a unique list of licenses from one or more SBOM files and saves them as Markdown files. Each output file includes the SBOM's name and version (from `metadata.component` for CycloneDX or `metadata.name`/`name` and `metadata.versionInfo` for SPDX) and a bulleted list of licenses.

### Syntax

```bash
<command> [--all|-a | --file|-f <filename>]
```

#### Options

-   `--all` or `-a`: Process all `.json` files in the current directory.
-   `--file <filename>` or `-f <filename>`: Process a single specified SBOM file.
-   _Default_: If no arguments are provided, processes all `.json` files in the current directory.

### Examples

1. **Process all JSON SBOMs**:

    ```bash
    <command> -a
    ```

    Output: Creates a `.md` file for each `.json` file (e.g., `sbom.json` → `sbom.md`).

2. **Process a single SBOM**:

    ```bash
    <command> --file "sbom.json"
    ```

    Output: Creates `sbom.md`.

### Output Format

For an SBOM file `sbom.json`, the output `sbom.md` may look like this:

```markdown
# Application 1.0

## Used Licenses

-   Apache-2.0
-   MIT
-   BSD-3-Clause
```

### Notes

-   Supports CycloneDX (`components[].licenses[].license.name|id|expression`) and SPDX (`packages[].licenseConcluded|licenseDeclared`, excluding `NOASSERTION`).
-   Outputs one Markdown file per input SBOM, named `<input_filename>.md`.

### Python Usage

#### Command

```bash
python extract_licenses.py [--all|-a | --file|-f <filename>]
```

### Node.js Usage

#### CLI usage (Global Installation)

Should work, if nvm folder is present in the PATH var (e.g. `C:\Users\<user>\AppData\Roaming\nvm\v22.18.0`)

```bash
extract-licenses [--all|-a | --file|-f <filename>]
```

#### npx Command (No Installation or Dev Dependency)

```bash
npx -p @gwi42/sbom-utils@1.0.4 extract-licenses [--all|-a | --file|-f <filename>]
```

#### Project Dev Dependency

Add to `package.json`:

```json
{
    "scripts": {
        "extract-licenses": "extract-licenses --file sbom.json"
    }
}
```

Run:

```bash
npm run extract-licenses
```

## Combine SBOMs

### Purpose

Combines multiple SBOM files (CycloneDX or SPDX JSON) into a single CycloneDX JSON SBOM. Components/packages are deduplicated based on `name` and `version`, keeping the first occurrence. The combined SBOM's metadata uses a specified project name and version or defaults to values from the first valid SBOM.

### Syntax

```bash
<command> [--debug] [--trace] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...
```

#### Options

-   `--debug`: Enable detailed logging (e.g., file reading).
-   `--trace`: Enable detailed logging (e.g., component additions, duplicates).
-   `--name <project_name>`: Set the project name in the combined SBOM's metadata (default: `Combined Project` or first SBOM's metadata name).
-   `--version <version>`: Set the version in the combined SBOM's metadata (default: `1.0.0` or first SBOM's metadata version).
-   `<sbom_file1> <sbom_file2> ...`: List of SBOM files to combine (at least one required).

### Examples

1. **Combine multiple SBOMs**:

    ```bash
    <command> react1.sbom.json react2.sbom.json java.sbom.json
    ```

    Output: Creates `combined_sbom.json`.

2. **Combine with custom metadata**:

    ```bash
    <command> --name "MyProject" --version "1.0" react1.sbom.json react2.sbom.json
    ```

    Output: Creates `combined_sbom.json`.

### Output Format

The output `combined_sbom.json` is a CycloneDX JSON SBOM:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
    "metadata": {
        "timestamp": "2025-08-20T15:19:00Z",
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
            "licenses": [{ "license": { "id": "MIT" } }]
        }
    ]
}
```

### Notes

-   Supports CycloneDX and SPDX JSON SBOMs.
-   SPDX packages are converted to CycloneDX components, mapping `licenseConcluded`/`licenseDeclared` to `licenses[].license.id`.
-   Deduplicates components based on `name` and `version` (case-sensitive), keeping the first occurrence.
-   If `--name` or `--version` is not provided, uses metadata from the first valid SBOM.
-   Outputs `combined_sbom.json` in the current directory.

### Python Usage

#### Command

```bash
python combine_sboms.py [--debug] [--trace] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...
```

### Node.js Usage

#### Command (Global Installation)

```bash
combine-sboms [--debug] [--trace] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...
```

#### npx Command (No Installation or Dev Dependency)

```bash
npx -p @gwi42/sbom-utils@1.0.4 combine-sboms [--debug] [--trace] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...
```

#### Project Dev Dependency

Add to `package.json`:

```json
{
    "scripts": {
        "combine-sboms": "combine-sboms react1.sbom.json react2.sbom.json"
    }
}
```

Run:

```bash
npm run combine-sboms
```

## License

See the [LICENSE](LICENSE) file for details.
