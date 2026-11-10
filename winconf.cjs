'use strict';

// Sets the version resource and the icon of the Windows executable that `npm run build-dist`
// builds with @yao-pkg/pkg. Usage: node winconf.cjs [path-to-exe], the default being the
// build-dist output. test/package/pkg-smoke.cjs runs it on a freshly built executable.

const { load } = require('resedit/cjs');
const path = require('path');
const PackageData = require('./package.json');

const { readFileSync, writeFileSync, renameSync, existsSync } = require('fs');

const options = {
    exe: process.argv[2] || path.join(__dirname, 'ee-dist', 'mailauth-win-x64.exe'),
    version: PackageData.version,
    properties: {
        LegalCopyright: 'Postal Systems OÜ',
        FileDescription: 'mailauth provides a command-line utility for email authentication',
        ProductName: 'mailauth'
    },
    icon: path.join(__dirname, 'assets', 'mailauth.ico')
};

const language = {
    lang: 1033,
    codepage: 1200
};

/**
 * Offset of the payload pkg appends after the last PE section.
 *
 * pkg addresses that payload by absolute file offset, so rewriting the resources is only safe
 * while .rsrc still fits the raw allocation the linker gave it. Once it does not, the section
 * grows, the payload slides down the file, and the executable dies on startup with a
 * SyntaxError out of readPrelude. Nothing else catches it: the file is still a well formed
 * executable that signs and hashes like a good build (the Windows binaries of mailauth 7.3.0 to
 * 8.0.5 were such executables, with a 165 KB uncompressed icon).
 */
function payloadOffset(executable) {
    return executable.getAllSections().reduce((offset, section) => Math.max(offset, section.info.pointerToRawData + section.info.sizeOfRawData), 0);
}

function resourceSection(executable) {
    return executable.getAllSections().find(section => section.info.name === '.rsrc');
}

load()
    .then(ResEdit => {
        for (const file of [options.exe, options.icon]) {
            if (!existsSync(file)) {
                throw new Error(`File not found: ${file}`);
            }
        }

        const original = readFileSync(options.exe);
        const executable = ResEdit.NtExecutable.from(original);
        const res = ResEdit.NtExecutableResource.from(executable);
        const vi = ResEdit.Resource.VersionInfo.fromEntries(res.entries)[0];
        if (!vi) {
            throw new Error('No version info found in executable');
        }

        // Remove original filename
        vi.removeStringValue(language, 'OriginalFilename');
        vi.removeStringValue(language, 'InternalName');

        // Product and file version, the first three numbers of the package version
        const version = options.version
            .split('.')
            .map(v => Number(v) || 0)
            .slice(0, 3);
        vi.setProductVersion(...version, 0, language.lang);
        vi.setFileVersion(...version, 0, language.lang);

        vi.setStringValues(language, options.properties);
        vi.outputToResourceEntries(res.entries);

        const iconFile = ResEdit.Data.IconFile.from(readFileSync(options.icon));
        ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
            res.entries,
            1,
            language.lang,
            iconFile.icons.map(item => item.data)
        );

        // The allocation is read before the edit, as that is the budget the linker set
        const offsetBefore = payloadOffset(executable);
        const allocated = resourceSection(executable).info.sizeOfRawData;
        res.outputResource(executable);
        const offsetAfter = payloadOffset(executable);
        const rsrc = resourceSection(executable);
        const updated = Buffer.from(executable.generate());

        // Refuse to write an executable whose payload moved, see payloadOffset()
        if (offsetAfter !== offsetBefore || !original.subarray(offsetBefore).equals(updated.subarray(offsetAfter))) {
            throw new Error(
                `Rewriting the resources moved the appended pkg payload (${offsetBefore} -> ${offsetAfter}), which produces an executable that cannot start. ` +
                    `The resources need ${rsrc.info.virtualSize} bytes but only ${allocated} are allocated for .rsrc, ` +
                    `shrink ${options.icon} by at least ${rsrc.info.virtualSize - allocated} bytes, PNG-compressing its largest members.`
            );
        }

        // Written beside the target and renamed into place, so a half-written file never
        // looks like a finished build
        const tmpPath = `${options.exe}.tmp`;
        writeFileSync(tmpPath, updated);
        renameSync(tmpPath, options.exe);

        console.log(`Updated ${options.exe}`);
        console.log(`  Version: ${version.join('.')}`);
        console.log(
            `  Resources: ${rsrc.info.virtualSize} of ${rsrc.info.sizeOfRawData} bytes allocated for .rsrc (${rsrc.info.sizeOfRawData - rsrc.info.virtualSize} spare)`
        );
    })
    .catch(err => {
        console.error('Error modifying Windows executable:', err);
        process.exit(1);
    });
