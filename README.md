# SOC Toolkit for Obsidian

An Obsidian plugin that provides a collection of tools for SOC analysts and cybersecurity professionals. Currently includes IP reputation analysis using VirusTotal and AbuseIPDB APIs, and IP defanging. 

## Features

- **IP Reputation Analysis**
  - Scans notes for both IPv4 and IPv6 addresses
  - Supports defanged IP addresses (e.g. `8[.]8[.]8[.]8` or `8.8.8[.]8`)
  - Checks IP reputation using VirusTotal and AbuseIPDB APIs
  - Caches results to minimise API calls
  - Customisable output format for both APIs
  - Example output preview
  - Right-click context menu for quick IP checks
  - Command palette support for checking highlighted IPs

- **IP Defanging**
  - Defang IPs in current note with a single command
  - Right-click menu option for defanging IPs
  - Supports both full defanging and last-dot defanging
  - Maintains original note formatting

## Installation

You can now install this plugin directly from within Obsidian:

1. Open Obsidian settings
2. Go to "Community plugins"
3. Click "Browse"
4. Search for "SOC Toolkit"
5. Click "Install" and then "Enable"

## Configuration

Before you will be able to run IP reputation checks, you need to first configure your API keys:

1. Get a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Get an AbuseIPDB API key from [AbuseIPDB](https://www.abuseipdb.com/account/api)
3. Open Obsidian settings
4. Go to Community Plugins > SOC Toolkit
5. Enter your API keys
6. Click "Test keys" to ensure both API keys are valid and working
7. (Recommended) Set your desired keybindings in Obsidian Hotkeys settings
8. (Optional) Adjust the cache duration (default: 24 hours)

## Usage

### IP Reputation Analysis

1. Open a note containing IP addresses (regular or defanged)
2. Use one of the following methods to check IP reputation:
   - Press your defined hotkey for "Check IP reputation in current note"
   - Highlight IPs you wish to check, and then press your defined hotkey for "Check IP reputation in highlighted area"
   - Highlight IPs you wish to check, and then open right-click menu and select "Check IP Reputation" 
   - Open the command palette (Ctrl/Cmd + P) and search for "Check IP reputation in current note"
3. The plugin will add reputation data below each IP address. You can configure the output in the plugin settings.

### IP Defanging

1. Open a note containing IP addresses
2. Use one of the following methods to defang IPs:
   - Press your defined hotkey for "Defang IPs in current note"
   - Right-click on an IP and select "Defang IP"
   - Open the command palette (Ctrl/Cmd + P) and search for "Defang IPs in current note"
3. The plugin will defang the IP address(es) while maintaining the original formatting

## Example

Before:
```
IPs involved in incident:
- 8.8.8.8
- 2001:4860:4860::8888
```

After running the plugin:
```
IPs involved in incident:
- 8[.]8[.]8[.]8
  - VirusTotal: 0/94 vendors flagged as malicious
  - AbuseIPDB: 0% confidence of abuse, last reported today
- 2001[:]4860[:]4860::8888
  - VirusTotal: 0/94 vendors flagged as malicious
  - AbuseIPDB: 0% confidence of abuse, last reported 66d ago
```

## Privacy

This plugin:
- Sends IP addresses to VirusTotal and AbuseIPDB for reputation checking
- Stores API keys locally in your Obsidian settings
- Caches results locally to minimise API calls

## Roadmap

- [x] IP reputation checking
- [x] IP defanging
- [ ] URL defanging
- [ ] Domain/URL reputation analysis
- [ ] File hash analysis

## License

This project is licensed under the GPLv3 License - see the LICENSE file for details. 