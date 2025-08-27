#!/usr/bin/env node
import { randomUUID } from 'crypto'
import { existsSync } from 'fs'
import { readFile, writeFile } from 'fs/promises'

interface Component {
    type: string
    name: string
    group?: string
    version: string
    'bom-ref'?: string
    author?: string
    description?: string
    licenses?: Array<{ license: { id: string } } | { expression: string }>
    purl?: string
    externalReferences?: Array<{ url: string; type: string; comment: string }>
    properties?: Array<{ name: string; value: string }>
}

interface SbomData {
    bomFormat?: string
    spdxVersion?: string
    components?: Component[]
    packages?: Array<{
        name: string
        versionInfo: string
        SPDXID?: string
        licenseConcluded?: string
        licenseDeclared?: string
    }>
    metadata?: {
        component?: { name?: string; version?: string }
        name?: string
        versionInfo?: string
    }
    name?: string
}

interface CombinedSbom {
    bomFormat: string
    specVersion: string
    version: number
    serialNumber: string
    metadata: {
        timestamp: string
        component: { type: string; name: string; version: string }
    }
    components: Component[]
}

function sanitizeComponent(component: Component): Component {
    return {
        type: component.type,
        name: component.name,
        group: component.group,
        version: component.version,
        'bom-ref': component['bom-ref'],
        author: component.author,
        description: component.description,
        purl: component['purl'],
        externalReferences: component.externalReferences,
        properties: component.properties,
        licenses: component.licenses
            ?.map((lic, idx) => {
                if ('license' in lic && lic.license?.id) {
                    return {
                        license: {
                            id: lic.license.id,
                        },
                    }
                } else if ('expression' in lic && typeof lic.expression === 'string') {
                    return {
                        expression: lic.expression,
                    }
                } else {
                    console.warn(
                        `⚠️ Skipping malformed license in component ${component.name}@${component.version} (index ${idx})`
                    )
                    return undefined
                }
            })
            .filter((l): l is { license: { id: string } } | { expression: string } => !!l),
    }
}

async function readSbom(sbomFile: string, debug: boolean = false): Promise<[SbomData, string]> {
    try {
        // Try UTF-8 first
        let fileContent: string
        try {
            fileContent = await readFile(sbomFile, { encoding: 'utf8' })
            if (debug) {
                console.log(`Successfully read ${sbomFile} with encoding: utf-8`)
            }
        } catch (error: any) {
            if (error.code === 'ERR_INVALID_CHAR') {
                // Fallback to UTF-8-BOM or similar by stripping BOM
                const buffer = await readFile(sbomFile)
                fileContent = buffer.toString('utf8').replace(/^\uFEFF/, '')
                if (debug) {
                    console.log(`Successfully read ${sbomFile} with BOM-stripped utf-8`)
                }
            } else {
                throw error
            }
        }

        const sbomData: SbomData = JSON.parse(fileContent)

        if (sbomData.bomFormat === 'CycloneDX') {
            return [sbomData, 'CycloneDX']
        } else if (sbomData.spdxVersion) {
            return [sbomData, 'SPDX']
        } else {
            console.log(`Unsupported SBOM format in ${sbomFile}. Expected CycloneDX or SPDX.`)
            return [{}, 'unknown']
        }
    } catch (error: any) {
        if (error.code === 'ENOENT') {
            console.log(`Error: File '${sbomFile}' not found`)
        } else if (error instanceof SyntaxError) {
            console.log(`Error: '${sbomFile}' is not a valid JSON file: ${error.message}`)
        } else {
            console.log(`Error processing SBOM file ${sbomFile}: ${error.message}`)
        }
        return [{}, 'unknown']
    }
}

function getMetadataFromSbom(sbomData: SbomData, sbomFormat: string, debug: boolean = false): [string, string] {
    let name = 'Combined Project'
    let version = '1.0.0'

    if (sbomFormat === 'CycloneDX') {
        if (sbomData.metadata?.component) {
            name = sbomData.metadata.component.name ?? name
            version = sbomData.metadata.component.version ?? version
            if (debug) {
                console.log(`Extracted metadata from CycloneDX: name=${name}, version=${version}`)
            }
        }
    } else if (sbomFormat === 'SPDX') {
        name = sbomData.name ?? name
        if (sbomData.metadata) {
            name = sbomData.metadata.name ?? name
            version = sbomData.metadata.versionInfo ?? version
        }
        if (debug) {
            console.log(`Extracted metadata from SPDX: name=${name}, version=${version}`)
        }
    }

    return [name, version]
}

function convertSpdxToCycloneDxPackage(
    packageData: NonNullable<SbomData['packages']>[number],
    debug: boolean = false
): Component {
    const component: Component = {
        type: 'library',
        name: packageData.name ?? 'unnamed',
        version: packageData.versionInfo ?? 'unknown',
        'bom-ref': packageData.SPDXID ?? randomUUID(),
    }

    const licenses: Array<{ license: { id: string } }> = []
    if (packageData.licenseConcluded && packageData.licenseConcluded !== 'NOASSERTION') {
        licenses.push({ license: { id: packageData.licenseConcluded } })
        if (debug) {
            console.log(
                `Converted SPDX licenseConcluded ${packageData.licenseConcluded} to CycloneDX format for ${component.name}`
            )
        }
    }
    if (packageData.licenseDeclared && packageData.licenseDeclared !== 'NOASSERTION') {
        licenses.push({ license: { id: packageData.licenseDeclared } })
        if (debug) {
            console.log(
                `Converted SPDX licenseDeclared ${packageData.licenseDeclared} to CycloneDX format for ${component.name}`
            )
        }
    }
    if (licenses.length > 0) {
        component.licenses = licenses
    }

    return component
}

async function combineSboms(
    sbomFiles: string[],
    projectName: string,
    projectVersion: string,
    debug: boolean = false,
    trace: boolean = false
): Promise<[CombinedSbom, string, string]> {
    const combinedComponents: { [key: string]: Component } = {}
    let metadataName = projectName
    let metadataVersion = projectVersion

    // Extract metadata from the first valid SBOM if not provided
    if (!projectName || !projectVersion) {
        for (const sbomFile of sbomFiles) {
            const [sbomData, sbomFormat] = await readSbom(sbomFile, debug)
            if (Object.keys(sbomData).length > 0) {
                const [name, version] = getMetadataFromSbom(sbomData, sbomFormat, debug)
                if (!projectName) metadataName = name
                if (!projectVersion) metadataVersion = version
                break
            }
        }
        if (!metadataName || !metadataVersion) {
            console.log('Warning: No valid SBOMs found to extract metadata. Using defaults.')
        }
    }

    for (const sbomFile of sbomFiles) {
        const [sbomData, sbomFormat] = await readSbom(sbomFile, debug)
        if (debug) {
            console.log(
                `📄 ${sbomFile} contains components:`,
                Array.isArray(sbomData.components),
                sbomData.components?.length ?? 0
            )
        }
        if (Object.keys(sbomData).length === 0) {
            if (debug) {
                console.log(`📦 ${sbomFile} has ${sbomData.components?.length ?? 0} components`)
            }
            continue
        }

        if (sbomFormat === 'CycloneDX') {
            const components = sbomData.components ?? []
            for (const component of components) {
                const name = component.name ?? 'unnamed'
                const version = component.version ?? 'unknown'
                const key = `${name}:${version}`

                if (component.licenses) {
                    for (const lic of component.licenses) {
                        if ('acknowlegement' in (lic ?? {})) {
                            console.log(
                                `⚠️ Found unexpected 'acknowlegement' in component ${name}@${version} from ${sbomFile}`
                            )
                        }
                        if (!lic) {
                            console.warn(`⚠️ License object missing in component ${name}@${version} from ${sbomFile}`)
                        }
                    }
                }

                if (!combinedComponents[key]) {
                    combinedComponents[key] = sanitizeComponent(component)
                    if (trace) {
                        console.log(`Added CycloneDX component: ${name} ${version} from ${sbomFile}`)
                    }
                } else if (trace) {
                    console.log(`Skipped duplicate component: ${name} ${version} from ${sbomFile}`)
                }
            }
        } else if (sbomFormat === 'SPDX') {
            const packages = sbomData.packages ?? []
            for (const pkg of packages) {
                const component = convertSpdxToCycloneDxPackage(pkg, debug)
                const name = component.name
                const version = component.version
                const key = `${name}:${version}`
                if (!combinedComponents[key]) {
                    combinedComponents[key] = sanitizeComponent(component)
                    if (trace) {
                        console.log(`Added converted SPDX package: ${name} ${version} from ${sbomFile}`)
                    }
                } else if (trace) {
                    console.log(`Skipped duplicate package: ${name} ${version} from ${sbomFile}`)
                }
            }
        }
    }

    const combinedSbom: CombinedSbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        version: 1,
        serialNumber: `urn:uuid:${randomUUID()}`,
        metadata: {
            timestamp: new Date().toISOString(),
            component: {
                type: 'application',
                name: metadataName,
                version: metadataVersion,
            },
        },
        components: Object.values(combinedComponents),
    }

    if (debug) {
        console.log(`Combined ${Object.keys(combinedComponents).length} unique components into SBOM`)
    }

    return [combinedSbom, metadataName, metadataVersion]
}

async function main(): Promise<void> {
    let debug = false
    let trace = false
    let projectName = ''
    let projectVersion = ''

    const args = process.argv.slice(2)
    if (args.includes('--debug')) {
        debug = true
        args.splice(args.indexOf('--debug'), 1)
    }

    if (args.includes('--trace')) {
        debug = true
        trace = true
        args.splice(args.indexOf('--trace'), 1)
    }

    let nameIndex = args.indexOf('--name')
    if (nameIndex !== -1) {
        if (nameIndex + 1 < args.length) {
            projectName = args[nameIndex + 1]
            args.splice(nameIndex, 2)
        } else {
            console.log('Error: --name requires a project name')
            process.exit(1)
        }
    }

    let versionIndex = args.indexOf('--version')
    if (versionIndex !== -1) {
        if (versionIndex + 1 < args.length) {
            projectVersion = args[versionIndex + 1]
            args.splice(versionIndex, 2)
        } else {
            console.log('Error: --version requires a version')
            process.exit(1)
        }
    }

    if (args.length === 0) {
        console.log(
            'Usage: tsx combine_sboms.ts [--debug] [--trace] [--name <project_name>] [--version <version>] <sbom_file1> <sbom_file2> ...'
        )
        process.exit(1)
    }

    const sbomFiles = args
    for (const sbomFile of sbomFiles) {
        if (!existsSync(sbomFile)) {
            console.log(`Error: File '${sbomFile}' does not exist`)
            process.exit(1)
        }
    }

    const [combinedSbom, metadataName, metadataVersion] = await combineSboms(
        sbomFiles,
        projectName,
        projectVersion,
        debug,
        trace
    )

    const outputFile = 'combined_sbom.json'
    try {
        await writeFile(outputFile, JSON.stringify(combinedSbom, null, 2), {
            encoding: 'utf-8',
        })
        console.log(`Combined SBOM saved to ${outputFile} (name: ${metadataName}, version: ${metadataVersion})`)
    } catch (error: any) {
        console.log(`Error writing to ${outputFile}: ${error.message}`)
        process.exit(1)
    }
}

main().catch((error) => {
    console.error(`Error: ${error.message}`)
    process.exit(1)
})
