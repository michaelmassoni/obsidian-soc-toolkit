import { readFileSync, writeFileSync } from "fs";

const targetVersion = process.argv[2];

if (!targetVersion) {
    console.error("Please provide a target version");
    process.exit(1);
}

// Read manifest.json
const manifest = JSON.parse(readFileSync("manifest.json", "utf8"));
manifest.version = targetVersion;
writeFileSync("manifest.json", JSON.stringify(manifest, null, "\t"));

// Read versions.json
const versions = JSON.parse(readFileSync("versions.json", "utf8"));
versions[targetVersion] = manifest.minAppVersion;
writeFileSync("versions.json", JSON.stringify(versions, null, "\t")); 