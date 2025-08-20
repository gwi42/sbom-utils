#!/usr/bin/env node
import { existsSync, readdirSync } from 'fs'
import { readFile, writeFile } from 'fs/promises'

interface Component {
    type?: string
    name?: string
    version?: string
    licenses?: Array<{
        license: {
            id?: string
            name?: string
            expression?: string
        }
    }>
}

interface SbomData {
    bomFormat?: string
    spdxVersion?: string
    components?: Component[]
    packages?: Array<{
        name: string
        versionInfo?: string
        SPDXID?: string
        licenseConcluded?: string
        licenseDeclared?: string
    }>
    metadata?: {
        component?: {
            name?: string
            version?: string
            licenses?: Array<{ license: { id?: string; name?: string; expression?: string } }>
        }
        name?: string
        versionInfo?: string
    }
    name?: string
}

function normalizeLicense(license: string): string {
    const licenseLower = license.toLowerCase()
    if (licenseLower.includes('lesser general public licen')) {
        return 'GNU Lesser General Public License'
    }
    return license
}

async function extractLicenses(sbomFile: string): Promise<[Set<string>, string, string, Set<string>]> {
    try {
        let fileContent: string
        try {
            fileContent = await readFile(sbomFile, { encoding: 'utf8' })
        } catch (error: any) {
            if (error.code === 'ERR_INVALID_CHAR') {
                const buffer = await readFile(sbomFile)
                fileContent = buffer.toString('utf8').replace(/^\uFEFF/, '')
            } else {
                throw error
            }
        }

        const sbomData: SbomData = JSON.parse(fileContent)
        const licenses: Set<string> = new Set()
        const componentLicenses: Set<string> = new Set()
        let sbomName = 'Unknown SBOM'
        let sbomVersion = 'Unknown Version'

        if (sbomData.bomFormat === 'CycloneDX') {
            const metadataLicenses = sbomData.metadata?.component?.licenses ?? []
            for (const licenseEntry of metadataLicenses) {
                const { id, name, expression } = licenseEntry.license ?? {}
                const value = name || id || expression
                if (value) {
                    componentLicenses.add(normalizeLicense(value))
                }
            }

            const components = sbomData.components ?? []
            for (const component of components) {
                for (const licenseEntry of component.licenses ?? []) {
                    const { id, name, expression } = licenseEntry.license ?? {}
                    const value = name || id || expression
                    if (value) {
                        licenses.add(normalizeLicense(value))
                    }
                }
            }

            sbomName = sbomData.metadata?.component?.name ?? 'Unknown SBOM'
            sbomVersion = sbomData.metadata?.component?.version ?? 'Unknown Version'
        } else if (sbomData.spdxVersion) {
            for (const pkg of sbomData.packages ?? []) {
                if (pkg.licenseConcluded && pkg.licenseConcluded !== 'NOASSERTION') {
                    licenses.add(normalizeLicense(pkg.licenseConcluded))
                }
                if (pkg.licenseDeclared && pkg.licenseDeclared !== 'NOASSERTION') {
                    licenses.add(normalizeLicense(pkg.licenseDeclared))
                }
            }

            sbomName = sbomData.name ?? sbomData.metadata?.name ?? 'Unknown SBOM'
            sbomVersion = sbomData.metadata?.versionInfo ?? 'Unknown Version'
        }

        return [licenses, sbomName, sbomVersion, componentLicenses]
    } catch (error: any) {
        console.error(`Failed to process SBOM file ${sbomFile}: ${error.message}`)
        return [new Set(), 'Unknown SBOM', 'Unknown Version', new Set()]
    }
}

async function processFile(sbomFile: string): Promise<void> {
    const [licenses, sbomName, sbomVersion, componentLicenses] = await extractLicenses(sbomFile)

    const outputFile = sbomFile.replace(/\.json$/, '.md')
    let markdownContent = `# ${sbomName} ${sbomVersion}\n\n`

    markdownContent += '## License of this component\n\n'
    if (componentLicenses.size > 0) {
        for (const license of [...componentLicenses].sort()) {
            markdownContent += `- ${license}\n`
        }
    } else {
        markdownContent += 'No license found for this component.\n'
    }

    markdownContent += '\n## Licenses of used 3rd party libraries\n\n'
    if (licenses.size > 0) {
        for (const license of [...licenses].sort()) {
            markdownContent += `- ${license}\n`
        }
    } else {
        markdownContent += 'No dependencies found, no licenses used.\n'
    }

    try {
        await writeFile(outputFile, markdownContent, { encoding: 'utf-8' })
        console.log(`Licenses saved to ${outputFile}`)
    } catch (error: any) {
        console.log(`Error writing to ${outputFile}: ${error.message}`)
    }
}

async function main(): Promise<void> {
    const args = process.argv.slice(2)

    if (args.length === 0 || (args.length === 1 && (args[0] === '--all' || args[0] === '-a'))) {
        const jsonFiles = readdirSync('.').filter((file) => file.endsWith('.json'))
        if (!jsonFiles.length) {
            console.log('No JSON files found in the current directory')
            process.exit(1)
        }
        for (const sbomFile of jsonFiles) {
            await processFile(sbomFile)
        }
    } else if (args.length === 2 && (args[0] === '--file' || args[0] === '-f')) {
        const sbomFile = args[1]
        if (!existsSync(sbomFile)) {
            console.log(`Error: File '${sbomFile}' does not exist`)
            process.exit(1)
        }
        await processFile(sbomFile)
    } else {
        console.log('Usage: extract-licenses [--all|-a | --file|-f <filename>]')
        process.exit(1)
    }
}

main().catch((error) => {
    console.error(`Error: ${error.message}`)
    process.exit(1)
})
