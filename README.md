# IP Reputation Checker for Obsidian

This Obsidian plugin scans your notes for public IPv4 addresses and checks their reputation using VirusTotal and AbuseIPDB APIs.

## Features

- Automatically detects public IPv4 addresses in your notes
- Checks IP reputation using VirusTotal and AbuseIPDB APIs
- Adds inline annotations with reputation data
- Caches results to minimize API calls
- Configurable cache duration
- Command palette integration

## Installation

1. Download the latest release from the releases page
2. Extract the zip file into your Obsidian vault's `.obsidian/plugins` folder
3. Enable the plugin in Obsidian settings

## Configuration

Before using the plugin, you need to configure your API keys:

1. Get a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Get an AbuseIPDB API key from [AbuseIPDB](https://www.abuseipdb.com/account/api)
3. Open Obsidian settings
4. Go to Community Plugins > IP Reputation Checker
5. Enter your API keys
6. (Optional) Adjust the cache duration (default: 24 hours)

## Usage

1. Open a note containing IP addresses
2. Open the command palette (Ctrl/Cmd + P)
3. Search for "Check IP Reputation in Current Note"
4. The plugin will scan the note and add reputation data below each IP address

## Example

Before:
```
Found suspicious IP: 185.220.101.22
```

After running the plugin:
```
Found suspicious IP: 185.220.101.22
  - VirusTotal: 15/94 vendors flagged as malicious
  - AbuseIPDB: 75% confidence of abuse, last reported 2d ago
```

## Development

1. Clone this repository
2. Run `npm install` to install dependencies
3. Run `npm run dev` to start development mode
4. Make your changes
5. Run `npm run build` to create a production build

## License

GPLv3 License 