# SOC Toolkit for Obsidian

An Obsidian plugin that provides a collection of tools for SOC analysts and cybersecurity professionals. It checks the reputation of IP addresses, domains and URLs using VirusTotal and AbuseIPDB, and defangs and refangs them.

## Features

- **Reputation Analysis**
  - Scans notes for IPv4 and IPv6 addresses, domains and URLs, including defanged ones (e.g. `8[.]8[.]8[.]8`, `evil[.]com`, `hxxps://evil[.]com/login`)
  - Checks IPs with VirusTotal and AbuseIPDB, and domains and URLs with VirusTotal
  - URLs are only looked up, never submitted for scanning
  - Caches results to minimise API calls, and skips IOCs that are already annotated
  - Never sends private or reserved addresses (e.g. `10.0.0.0/8`, `192.168.0.0/16`, `fe80::/10`), or domains you list in settings, to third parties
  - Customisable output format for each indicator type, with a preview
  - Optional links from each annotation to the full VirusTotal or AbuseIPDB report
  - Right-click context menu and command palette support for checking highlighted text

- **Defanging and Refanging**
  - Defang or refang IPs, domains and URLs in the current note or highlighted area with a single command
  - Right-click menu options for defanging and refanging, shown only when they apply
  - Supports both full defanging and last-dot defanging
  - Maintains original note formatting, and leaves links, wikilinks, frontmatter and report links in annotations working

## Installation

You can now install this plugin directly from within Obsidian:

1. Open Obsidian settings
2. Go to "Community plugins"
3. Click "Browse"
4. Search for "SOC Toolkit"
5. Click "Install" and then "Enable"

## Configuration

Before you will be able to run reputation checks, you need to first configure your API keys:

1. Get a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Get an AbuseIPDB API key from [AbuseIPDB](https://www.abuseipdb.com/account/api)
3. Open Obsidian settings
4. Go to Community Plugins > SOC Toolkit
5. For each API key, choose an existing secret or create a new one and paste your key into it (keys are kept in Obsidian's secret storage, not in the plugin's settings file)
6. Click "Test keys" to ensure both API keys are valid and working
7. (Recommended) Add your organisation's domains under Indicators > "Never look up", so they're never sent to third parties
8. (Recommended) Set your desired keybindings in Obsidian Hotkeys settings
9. (Optional) Choose which indicator types to detect, and customise the output for each under Output (IPs, Domains, URLs)

The free VirusTotal and AbuseIPDB APIs are for non-commercial use. If you're using the plugin for work, check whether your organisation needs its own licensed keys.

## Usage

### Reputation Analysis

1. Open a note containing IP addresses, domains or URLs (regular or defanged)
2. Use one of the following methods to check their reputation:
   - Press your defined hotkey for "Check reputation in current note"
   - Highlight what you wish to check, and then press your defined hotkey for "Check reputation in highlighted area"
   - Highlight what you wish to check, and then open the right-click menu and select "Check reputation"
   - Open the command palette (Ctrl/Cmd + P) and search for "Check reputation"
3. The plugin will add reputation data below each line. You can configure the output in the plugin settings.

The first IOC on each line is checked. Lines that already have an annotation underneath are skipped, so re-running a check only looks up new IOCs.

When checking a whole note, link targets, wikilinks and frontmatter are ignored, as are domains that look like filenames (e.g. `notes.md`, `script.sh`) unless they're defanged. Highlight text to check these anyway.

### Defanging and Refanging

1. Open a note containing IP addresses, domains or URLs
2. Use one of the following methods to defang them:
   - Press your defined hotkey for "Defang IOCs in current note" or "Defang IOCs in highlighted area"
   - Highlight IOCs, right-click and select "Defang IOCs"
   - Open the command palette (Ctrl/Cmd + P) and search for "Defang IOCs"
3. The plugin will defang them (e.g. `hxxps://evil[.]com/login`) while maintaining the original formatting

Refanging works the same way, using the "Refang IOCs in current note" and "Refang IOCs in highlighted area" commands or the "Refang IOCs" right-click option. This is handy for pasting IOCs into other tools.

## Example

Before:
```
IOCs involved in incident:
- 8.8.8.8
- login-verify[.]com
- hxxps://login-verify[.]com/auth
```

After checking reputation:
```
IOCs involved in incident:
- 8.8.8.8
  - VirusTotal: 0/94 vendors flagged as malicious
  - AbuseIPDB: 0% confidence of abuse, last reported 2d ago
- login-verify[.]com
  - VirusTotal: 7/94 vendors flagged as malicious, domain age 12d
- hxxps://login-verify[.]com/auth
  - VirusTotal: 9/95 vendors flagged as malicious
```

## Privacy

This plugin:
- Sends IP addresses to VirusTotal and AbuseIPDB, and domains and URLs to VirusTotal, for reputation checking
- Never sends private or reserved IP addresses, or domains on your "Never look up" list
- Only looks URLs up; it never submits them for scanning
- Stores API keys in Obsidian's secret storage (requires Obsidian 1.11.4 or later); keys saved by older versions are moved there automatically
- Caches results locally to minimise API calls

## Roadmap

- [x] IP reputation checking
- [x] IP defanging
- [x] URL and domain defanging
- [x] Domain/URL reputation analysis
- [ ] More providers (e.g. URLhaus)
- [ ] File hash analysis

## License

This project is licensed under the GPLv3 License - see the LICENSE file for details.
