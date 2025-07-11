import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, request, Menu, MenuItem } from 'obsidian';

/**
 * Interface for storing IP reputation data from both VirusTotal and AbuseIPDB
 */
interface IPReputationData {
    virustotal: {
        maliciousCount: number;
        totalVendors: number;
        lastChecked: number;
        harmlessCount: number;
        suspiciousCount: number;
        timeoutCount: number;
        undetectedCount: number;
        lastAnalysisDate: string;
        country: string;
        asOwner: string;
        asn: string;
        network: string;
        tags: string[];
    };
    abuseipdb: {
        confidenceScore: number;
        lastReported: string;
        lastChecked: number;
        totalReports: number;
        numDistinctUsers: number;
        lastReportedAt: string;
        isPublic: boolean;
        isWhitelisted: boolean;
        countryCode: string;
        countryName: string;
        usageType: string;
        domain: string;
        hostnames: string[];
    };
}

/**
 * Country code to name mapping
 */
const COUNTRY_CODES: { [key: string]: string } = {
    'AF': 'Afghanistan',
    'AL': 'Albania',
    'DZ': 'Algeria',
    'AD': 'Andorra',
    'AO': 'Angola',
    'AG': 'Antigua and Barbuda',
    'AR': 'Argentina',
    'AM': 'Armenia',
    'AU': 'Australia',
    'AT': 'Austria',
    'AZ': 'Azerbaijan',
    'BS': 'Bahamas',
    'BH': 'Bahrain',
    'BD': 'Bangladesh',
    'BB': 'Barbados',
    'BY': 'Belarus',
    'BE': 'Belgium',
    'BZ': 'Belize',
    'BJ': 'Benin',
    'BT': 'Bhutan',
    'BO': 'Bolivia',
    'BA': 'Bosnia and Herzegovina',
    'BW': 'Botswana',
    'BR': 'Brazil',
    'BN': 'Brunei',
    'BG': 'Bulgaria',
    'BF': 'Burkina Faso',
    'BI': 'Burundi',
    'KH': 'Cambodia',
    'CM': 'Cameroon',
    'CA': 'Canada',
    'CV': 'Cape Verde',
    'CF': 'Central African Republic',
    'TD': 'Chad',
    'CL': 'Chile',
    'CN': 'China',
    'CO': 'Colombia',
    'KM': 'Comoros',
    'CG': 'Congo',
    'CR': 'Costa Rica',
    'HR': 'Croatia',
    'CU': 'Cuba',
    'CY': 'Cyprus',
    'CZ': 'Czech Republic',
    'DK': 'Denmark',
    'DJ': 'Djibouti',
    'DM': 'Dominica',
    'DO': 'Dominican Republic',
    'EC': 'Ecuador',
    'EG': 'Egypt',
    'SV': 'El Salvador',
    'GQ': 'Equatorial Guinea',
    'ER': 'Eritrea',
    'EE': 'Estonia',
    'ET': 'Ethiopia',
    'FJ': 'Fiji',
    'FI': 'Finland',
    'FR': 'France',
    'GA': 'Gabon',
    'GM': 'Gambia',
    'GE': 'Georgia',
    'DE': 'Germany',
    'GH': 'Ghana',
    'GR': 'Greece',
    'GD': 'Grenada',
    'GT': 'Guatemala',
    'GN': 'Guinea',
    'GW': 'Guinea-Bissau',
    'GY': 'Guyana',
    'HK': 'Hong Kong',
    'HT': 'Haiti',
    'HN': 'Honduras',
    'HU': 'Hungary',
    'IS': 'Iceland',
    'IN': 'India',
    'ID': 'Indonesia',
    'IR': 'Iran',
    'IQ': 'Iraq',
    'IE': 'Ireland',
    'IL': 'Israel',
    'IT': 'Italy',
    'JM': 'Jamaica',
    'JP': 'Japan',
    'JO': 'Jordan',
    'KZ': 'Kazakhstan',
    'KE': 'Kenya',
    'KI': 'Kiribati',
    'KP': 'North Korea',
    'KR': 'South Korea',
    'KW': 'Kuwait',
    'KG': 'Kyrgyzstan',
    'LA': 'Laos',
    'LV': 'Latvia',
    'LB': 'Lebanon',
    'LS': 'Lesotho',
    'LR': 'Liberia',
    'LY': 'Libya',
    'LI': 'Liechtenstein',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'MG': 'Madagascar',
    'MW': 'Malawi',
    'MY': 'Malaysia',
    'MV': 'Maldives',
    'ML': 'Mali',
    'MT': 'Malta',
    'MH': 'Marshall Islands',
    'MR': 'Mauritania',
    'MU': 'Mauritius',
    'MX': 'Mexico',
    'FM': 'Micronesia',
    'MD': 'Moldova',
    'MC': 'Monaco',
    'MN': 'Mongolia',
    'ME': 'Montenegro',
    'MA': 'Morocco',
    'MZ': 'Mozambique',
    'MM': 'Myanmar',
    'NA': 'Namibia',
    'NR': 'Nauru',
    'NP': 'Nepal',
    'NL': 'Netherlands',
    'NZ': 'New Zealand',
    'NI': 'Nicaragua',
    'NE': 'Niger',
    'NG': 'Nigeria',
    'NO': 'Norway',
    'OM': 'Oman',
    'PK': 'Pakistan',
    'PW': 'Palau',
    'PS': 'Palestine',
    'PA': 'Panama',
    'PG': 'Papua New Guinea',
    'PY': 'Paraguay',
    'PE': 'Peru',
    'PH': 'Philippines',
    'PL': 'Poland',
    'PT': 'Portugal',
    'QA': 'Qatar',
    'RO': 'Romania',
    'RU': 'Russia',
    'RW': 'Rwanda',
    'KN': 'Saint Kitts and Nevis',
    'LC': 'Saint Lucia',
    'VC': 'Saint Vincent and the Grenadines',
    'WS': 'Samoa',
    'SM': 'San Marino',
    'ST': 'Sao Tome and Principe',
    'SA': 'Saudi Arabia',
    'SN': 'Senegal',
    'RS': 'Serbia',
    'SC': 'Seychelles',
    'SL': 'Sierra Leone',
    'SG': 'Singapore',
    'SK': 'Slovakia',
    'SI': 'Slovenia',
    'SB': 'Solomon Islands',
    'SO': 'Somalia',
    'ZA': 'South Africa',
    'SS': 'South Sudan',
    'ES': 'Spain',
    'LK': 'Sri Lanka',
    'SD': 'Sudan',
    'SR': 'Suriname',
    'SZ': 'Swaziland',
    'SE': 'Sweden',
    'CH': 'Switzerland',
    'SY': 'Syria',
    'TW': 'Taiwan',
    'TJ': 'Tajikistan',
    'TZ': 'Tanzania',
    'TH': 'Thailand',
    'TL': 'Timor-Leste',
    'TG': 'Togo',
    'TO': 'Tonga',
    'TT': 'Trinidad and Tobago',
    'TN': 'Tunisia',
    'TR': 'Turkey',
    'TM': 'Turkmenistan',
    'TV': 'Tuvalu',
    'UG': 'Uganda',
    'UA': 'Ukraine',
    'AE': 'United Arab Emirates',
    'GB': 'United Kingdom',
    'US': 'United States',
    'UY': 'Uruguay',
    'UZ': 'Uzbekistan',
    'VU': 'Vanuatu',
    'VA': 'Vatican City',
    'VE': 'Venezuela',
    'VN': 'Vietnam',
    'YE': 'Yemen',
    'ZM': 'Zambia',
    'ZW': 'Zimbabwe'
};

/**
 * Plugin settings interface
 */
interface IPSettings {
    virustotalApiKey: string;
    abuseipdbApiKey: string;
    cacheDuration: number; // in hours
    defangingMethod: 'all-dots' | 'last-dot'; // new setting
    outputFormat: {
        virustotal: {
            enabled: boolean;
            format: string;
            description: string;
        };
        abuseipdb: {
            enabled: boolean;
            format: string;
            description: string;
        };
    };
}

/**
 * Default plugin settings
 */
const DEFAULT_SETTINGS: IPSettings = {
    virustotalApiKey: '',
    abuseipdbApiKey: '',
    cacheDuration: 24,
    defangingMethod: 'all-dots', // default to replacing all dots
    outputFormat: {
        virustotal: {
            enabled: true,
            format: '{maliciousCount}/{totalVendors} vendors flagged as malicious',
            description: `Available fields:
- {maliciousCount}: Number of vendors that flagged the IP as malicious
- {totalVendors}: Total number of vendors that analyzed the IP
- {harmlessCount}: Number of vendors that flagged the IP as harmless
- {suspiciousCount}: Number of vendors that flagged the IP as suspicious
- {timeoutCount}: Number of vendors that timed out while analyzing
- {undetectedCount}: Number of vendors that didn't detect anything
- {lastAnalysisDate}: Date of the last analysis
- {country}: Country where the IP is located
- {asOwner}: Autonomous System owner
- {asn}: Autonomous System Number
- {network}: Network/CIDR block
- {tags}: List of tags associated with the IP`
        },
        abuseipdb: {
            enabled: true,
            format: '{confidenceScore}% confidence of abuse, last reported {lastReported}',
            description: `Available fields:
- {confidenceScore}: Confidence score of abuse (0-100)
- {lastReported}: Time since the IP was last reported
- {totalReports}: Total number of reports for this IP
- {numDistinctUsers}: Number of distinct users who reported this IP
- {lastReportedAt}: Raw timestamp of the last report
- {isPublic}: Whether the IP is public
- {isWhitelisted}: Whether the IP is whitelisted
- {countryCode}: Two-letter country code
- {countryName}: Full country name
- {usageType}: Type of usage (e.g., "Data Center", "ISP")
- {domain}: Associated domain name
- {hostnames}: List of associated hostnames`
        }
    }
}

/**
 * Main plugin class for IP Reputation Checker
 */
export default class IPReputationPlugin extends Plugin {
    settings: IPSettings;
    ipCache: Map<string, IPReputationData> = new Map();

    async onload() {
        await this.loadSettings();

        // Register the command to check IP reputation
        this.addCommand({
            id: 'check-ip-reputation',
            name: 'Check IP reputation in current note',
            callback: () => this.checkIPReputation()
        });

        // Add command to check IP reputation in highlighted area
        this.addCommand({
            id: 'check-ip-reputation-highlighted',
            name: 'Check IP reputation in highlighted area',
            callback: async () => {
                const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
                if (!activeView) {
                    new Notice('No active note found');
                    return;
                }
                const editor = activeView.editor;
                const selectedText = editor.getSelection();
                if (!selectedText) {
                    new Notice('No text selected');
                    return;
                }

                // Split selection into lines and process each line
                const lines = selectedText.split('\n');
                let checkedCount = 0;
                let errorCount = 0;
                const annotatedLines: string[] = [];
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];
                    const ip = this.findIP(line);
                    if (ip) {
                        try {
                            const reputation = await this.getIPReputation(ip);
                            // Annotate this line (copy logic from updateNoteWithReputation, but only for this line)
                            const fullyDefangedIP = ip.replace(/\./g, '[.]');
                            const lastDotDefangedIP = ip.replace(/\.(?=[^.]*$)/, '[.]');
                            const plainIP = ip;
                            let annotatedLine = line;
                            // Check if this line contains any version of our IP
                            if (line.includes(plainIP) || line.includes(fullyDefangedIP) || line.includes(lastDotDefangedIP)) {
                                // Always add annotation for each detected IP in selection
                                let annotation = '\n';
                                if (this.settings.outputFormat.virustotal.enabled) {
                                    const vtFormat = this.settings.outputFormat.virustotal.format;
                                    const vtOutput = vtFormat
                                        .replace('{maliciousCount}', reputation.virustotal.maliciousCount.toString())
                                        .replace('{totalVendors}', reputation.virustotal.totalVendors.toString())
                                        .replace('{harmlessCount}', reputation.virustotal.harmlessCount.toString())
                                        .replace('{suspiciousCount}', reputation.virustotal.suspiciousCount.toString())
                                        .replace('{timeoutCount}', reputation.virustotal.timeoutCount.toString())
                                        .replace('{undetectedCount}', reputation.virustotal.undetectedCount.toString())
                                        .replace('{lastAnalysisDate}', reputation.virustotal.lastAnalysisDate)
                                        .replace('{country}', reputation.virustotal.country)
                                        .replace('{asOwner}', reputation.virustotal.asOwner)
                                        .replace('{asn}', reputation.virustotal.asn)
                                        .replace('{network}', reputation.virustotal.network)
                                        .replace('{tags}', reputation.virustotal.tags.length > 0 ? reputation.virustotal.tags.join(', ') : 'N/A');
                                    annotation += `  - VirusTotal: ${vtOutput}\n`;
                                }
                                if (this.settings.outputFormat.abuseipdb.enabled) {
                                    const abuseFormat = this.settings.outputFormat.abuseipdb.format;
                                    let abuseOutput = abuseFormat
                                        .replace('{confidenceScore}', reputation.abuseipdb.confidenceScore.toString())
                                        .replace('{totalReports}', reputation.abuseipdb.totalReports.toString())
                                        .replace('{numDistinctUsers}', reputation.abuseipdb.numDistinctUsers.toString())
                                        .replace('{lastReportedAt}', reputation.abuseipdb.lastReportedAt)
                                        .replace('{isPublic}', reputation.abuseipdb.isPublic.toString())
                                        .replace('{isWhitelisted}', reputation.abuseipdb.isWhitelisted.toString())
                                        .replace('{countryCode}', reputation.abuseipdb.countryCode)
                                        .replace('{countryName}', reputation.abuseipdb.countryName)
                                        .replace('{usageType}', reputation.abuseipdb.usageType)
                                        .replace('{domain}', reputation.abuseipdb.domain)
                                        .replace('{hostnames}', reputation.abuseipdb.hostnames.join(', '));
                                    if (reputation.abuseipdb.totalReports > 0) {
                                        abuseOutput = abuseOutput.replace('{lastReported}', this.getTimeAgo(reputation.abuseipdb.lastReported));
                                    } else {
                                        abuseOutput = abuseOutput.replace(/,?\s*last reported \{lastReported\}/, '');
                                    }
                                    annotation += `  - AbuseIPDB: ${abuseOutput}`;
                                }
                                annotatedLine += annotation;
                            }
                            annotatedLines.push(annotatedLine);
                            checkedCount++;
                        } catch (error) {
                            console.error(`Error checking IP ${ip}:`, error);
                            annotatedLines.push(line);
                            errorCount++;
                        }
                    } else {
                        annotatedLines.push(line);
                    }
                }
                // Replace the selection with the annotated lines
                editor.replaceSelection(annotatedLines.join('\n'));
                new Notice(`Checked ${checkedCount} IPs${errorCount > 0 ? ` (${errorCount} errors)` : ''}`);
            }
        });

        // Add command to defang IPs in current note
        this.addCommand({
            id: 'defang-ips',
            name: 'Defang IPs in current note',
            callback: () => this.defangIPsInNote()
        });

        // Add command to defang IPs in highlighted area
        this.addCommand({
            id: 'defang-ips-highlighted',
            name: 'Defang IPs in highlighted area',
            callback: () => this.defangIPsInHighlighted()
        });

        // Add right-click menu items
        this.registerEvent(
            this.app.workspace.on('editor-menu', (menu: Menu, editor: Editor, view: MarkdownView) => {
                const selectedText = editor.getSelection();
                if (selectedText) {
                    const ip = this.findIP(selectedText);
                    if (ip) {
                        menu.addItem((item: MenuItem) => {
                            item
                                .setTitle('Check IP reputation')
                                .setIcon('search')
                                .onClick(async () => {
                                    try {
                                        const reputation = await this.getIPReputation(ip);
                                        this.updateNoteWithReputation(editor, ip, reputation);
                                        new Notice(`Checked reputation for ${ip}`);
                                    } catch (error) {
                                        console.error(`Error checking IP ${ip}:`, error);
                                        new Notice(`Error checking IP ${ip}`);
                                    }
                                });
                        });

                        menu.addItem((item: MenuItem) => {
                            item
                                .setTitle('Defang IP address(es)')
                                .setIcon('shield')
                                .onClick(() => {
                                    this.defangIPsInHighlighted();
                                });
                        });
                    }
                }
            })
        );

        // Add settings tab
        this.addSettingTab(new IPSettingTab(this.app, this));
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }

    /**
     * Refang a defanged IP address
     * @param ip The defanged IP address
     * @returns The refanged IP address
     */
    private refangIP(ip: string): string {
        // Handle IPv6 addresses
        if (ip.includes('[:]')) {
            // Replace [:] with :
            return ip.replace(/\[:\]/g, ':');
        }
        
        // Handle IPv4 addresses
        return ip.replace(/\[\.\]/g, '.');
    }

    /**
     * Check if a string is a valid IP address (including defanged)
     * @param text The text to check
     * @returns The matched IP address or null
     */
    private findIP(text: string): string | null {
        // First try to match a defanged IP
        const defangedIPv4Regex = /\b(?:\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3})\b/;
        const defangedIPv4LastDotRegex = /\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\[\.\]\d{1,3})\b/;
        const defangedIPv6Regex = /\b(?:[0-9a-fA-F]{1,4}\[:\]\d{1,4}\[:\]\d{1,4}\[:\]\d{1,4}\[:\]\d{1,4}\[:\]\d{1,4}\[:\]\d{1,4}\[:\]\d{1,4})\b/;
        
        // Try to match a defanged IP
        let match = defangedIPv4Regex.exec(text) || 
                   defangedIPv4LastDotRegex.exec(text) || 
                   defangedIPv6Regex.exec(text);
        if (match) {
            const refanged = this.refangIP(match[0]);
            return refanged;
        }

        // If no defanged IP found, try to match a regular IP
        const ipv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
        const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b|\bfe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}\b|\b::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b/;
        
        match = ipv4Regex.exec(text) || ipv6Regex.exec(text);
        if (match) {
            return match[0];
        }

        return null;
    }

    /**
     * Check IP reputation in the current note
     */
    private async checkIPReputation() {
        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!activeView) {
            new Notice('No active note found');
            return;
        }

        const editor = activeView.editor;
        const content = editor.getValue();

        const lines = content.split('\n');
        let checkedCount = 0;
        let errorCount = 0;

        for (const line of lines) {
            const ip = this.findIP(line);

            if (ip) {
                try {
                    const reputation = await this.getIPReputation(ip);
                    this.updateNoteWithReputation(editor, ip, reputation);
                    checkedCount++;
                } catch (error) {
                    console.error(`Error checking IP ${ip}:`, error);
                    errorCount++;
                }
            }
        }

        if (checkedCount > 0 || errorCount > 0) {
            new Notice(`Checked ${checkedCount} IPs${errorCount > 0 ? `, ${errorCount} errors` : ''}`);
        } else {
            new Notice('No valid IP addresses found in note');
        }
    }

    /**
     * Defang IPs in the current note
     */
    private defangIPsInNote() {
        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!activeView) {
            new Notice('No active note found');
            return;
        }

        const editor = activeView.editor;
        const content = editor.getValue();
        const ipv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b|\bfe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}\b|\b::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b/g;

        let newContent = content;
        let defangedCount = 0;

        // Process IPv4 addresses
        newContent = newContent.replace(ipv4Regex, (match) => {
            defangedCount++;
            return this.defangIP(match);
        });

        // Process IPv6 addresses
        newContent = newContent.replace(ipv6Regex, (match) => {
            defangedCount++;
            return this.defangIP(match);
        });

        if (defangedCount > 0) {
            editor.setValue(newContent);
            new Notice(`Defanged ${defangedCount} IP address(es)`);
        } else {
            new Notice('No IP addresses found to defang');
        }
    }

    /**
     * Defang IPs in the highlighted area
     */
    private defangIPsInHighlighted() {
        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!activeView) {
            new Notice('No active note found');
            return;
        }

        const editor = activeView.editor;
        const selectedText = editor.getSelection();
        if (!selectedText) {
            new Notice('No text selected');
            return;
        }

        const ipv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b|\bfe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}\b|\b::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b/g;

        let newText = selectedText;
        let defangedCount = 0;

        // Process IPv4 addresses
        newText = newText.replace(ipv4Regex, (match) => {
            defangedCount++;
            return this.defangIP(match);
        });

        // Process IPv6 addresses
        newText = newText.replace(ipv6Regex, (match) => {
            defangedCount++;
            return this.defangIP(match);
        });

        if (defangedCount > 0) {
            editor.replaceSelection(newText);
            new Notice(`Defanged ${defangedCount} IP address(es)`);
        } else {
            new Notice('No IP addresses found to defang');
        }
    }

    /**
     * Defang a single IP address according to the user's settings
     */
    private defangIP(ip: string): string {
        // Handle IPv6 addresses
        if (ip.includes(':')) {
            // Replace only single ':' with '[:]', leave '::' untouched (this is due to how Obsidian handles "[::]" in markdown)
            return ip.replace(/(?<!:):(?!:)/g, '[:]');
        }
        // Handle IPv4 addresses
        return ip.replace(/\./g, '[.]');
    }

    /**
     * Get reputation data for an IP address from both APIs
     */
    private async getIPReputation(ip: string): Promise<IPReputationData> {
        // Check cache first
        const cached = this.ipCache.get(ip);
        if (cached) {
            const now = Date.now();
            const cacheAge = (now - Math.max(cached.virustotal.lastChecked, cached.abuseipdb.lastChecked)) / (1000 * 60 * 60);
            if (cacheAge < this.settings.cacheDuration) {
                // Return a new object to avoid modifying the cached data
                return {
                    virustotal: { ...cached.virustotal },
                    abuseipdb: { ...cached.abuseipdb }
                };
            }
        }

        try {
            const [vtData, abuseData] = await Promise.all([
                this.checkVirusTotal(ip),
                this.checkAbuseIPDB(ip)
            ]);

            // Extract data with fallbacks
            const vtStats = vtData?.data?.attributes?.last_analysis_stats || {};
            const vtResults = vtData?.data?.attributes?.last_analysis_results || {};
            const vtAttributes = vtData?.data?.attributes || {};
            const abuseDataObj = abuseData?.data || {};

            const reputation: IPReputationData = {
                virustotal: {
                    maliciousCount: vtStats.malicious || 0,
                    totalVendors: Object.keys(vtResults).length,
                    lastChecked: Date.now(),
                    harmlessCount: vtStats.harmless || 0,
                    suspiciousCount: vtStats.suspicious || 0,
                    timeoutCount: vtStats.timeout || 0,
                    undetectedCount: vtStats.undetected || 0,
                    lastAnalysisDate: vtAttributes.last_analysis_date || '',
                    country: vtAttributes.country || '',
                    asOwner: vtAttributes.as_owner || '',
                    asn: vtAttributes.asn || '',
                    network: vtAttributes.network || '',
                    tags: vtAttributes.tags || []
                },
                abuseipdb: {
                    confidenceScore: abuseDataObj.abuseConfidenceScore || 0,
                    lastReported: abuseDataObj.lastReportedAt || new Date().toISOString(),
                    lastChecked: Date.now(),
                    totalReports: abuseDataObj.totalReports || 0,
                    numDistinctUsers: abuseDataObj.numDistinctUsers || 0,
                    lastReportedAt: abuseDataObj.lastReportedAt || '',
                    isPublic: abuseDataObj.isPublic || false,
                    isWhitelisted: abuseDataObj.isWhitelisted || false,
                    countryCode: abuseDataObj.countryCode || '',
                    countryName: abuseDataObj.countryCode ? (COUNTRY_CODES[abuseDataObj.countryCode] || abuseDataObj.countryCode) : '',
                    usageType: abuseDataObj.usageType || '',
                    domain: abuseDataObj.domain || '',
                    hostnames: abuseDataObj.hostnames || []
                }
            };

            // Store a copy of the data in cache
            this.ipCache.set(ip, {
                virustotal: { ...reputation.virustotal },
                abuseipdb: { ...reputation.abuseipdb }
            });
            return reputation;
        } catch (error) {
            console.error(`Error getting reputation for IP ${ip}:`, error);
            throw new Error(`Failed to get reputation data: ${error.message}`);
        }
    }

    /**
     * Check IP reputation using VirusTotal API
     */
    private async checkVirusTotal(ip: string) {
        if (!this.settings.virustotalApiKey) {
            throw new Error('VirusTotal API key not configured');
        }

        try {
            const response = await request({
                url: `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
                method: 'GET',
                headers: {
                    'x-apikey': this.settings.virustotalApiKey,
                    'Accept': 'application/json'
                }
            });

            const data = JSON.parse(response);
            if (!data) {
                throw new Error('Empty response from VirusTotal API');
            }

            return data;
        } catch (error) {
            console.error('VirusTotal API error:', error);
            if (error.response) {
                console.error('VirusTotal error response:', error.response);
            }
            throw new Error(`VirusTotal API error: ${error.message}`);
        }
    }

    /**
     * Check IP reputation using AbuseIPDB API
     */
    private async checkAbuseIPDB(ip: string) {
        if (!this.settings.abuseipdbApiKey) {
            throw new Error('AbuseIPDB API key not configured');
        }

        try {
            const response = await request({
                url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
                method: 'GET',
                headers: {
                    'Key': this.settings.abuseipdbApiKey,
                    'Accept': 'application/json'
                }
            });

            const data = JSON.parse(response);
            if (!data) {
                throw new Error('Empty response from AbuseIPDB API');
            }

            return data;
        } catch (error) {
            console.error('AbuseIPDB API error:', error);
            if (error.response) {
                console.error('AbuseIPDB error response:', error.response);
            }
            throw new Error(`AbuseIPDB API error: ${error.message}`);
        }
    }

    /**
     * Get a human-readable time ago string from an ISO date string
     */
    public getTimeAgo(dateString: string): string {
        const date = new Date(dateString);
        const now = new Date();
        const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);
        
        if (diffInSeconds < 60) {
            return 'just now';
        }
        
        const diffInMinutes = Math.floor(diffInSeconds / 60);
        if (diffInMinutes < 60) {
            return `${diffInMinutes}m ago`;
        }
        
        const diffInHours = Math.floor(diffInMinutes / 60);
        if (diffInHours < 24) {
            return `${diffInHours}h ago`;
        }
        
        const diffInDays = Math.floor(diffInHours / 24);
        if (diffInDays < 30) {
            return `${diffInDays}d ago`;
        }
        
        const diffInMonths = Math.floor(diffInDays / 30);
        if (diffInMonths < 12) {
            return `${diffInMonths}mo ago`;
        }
        
        const diffInYears = Math.floor(diffInMonths / 12);
        return `${diffInYears}y ago`;
    }

    /**
     * Update the note with reputation data for an IP address
     */
    private updateNoteWithReputation(editor: Editor, ip: string, reputation: IPReputationData) {
        console.log('Reputation data:', reputation);

        const content = editor.getValue();
        // Create both fully defanged and last-dot-defanged versions of the IP
        const fullyDefangedIP = ip.replace(/\./g, '[.]');
        const lastDotDefangedIP = ip.replace(/\.(?=[^.]*$)/, '[.]');
        const plainIP = ip;
        
        // Split content into lines and process each line
        const lines = content.split('\n');
        let newContent = '';
        let foundIP = false;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Check if this line contains any version of our IP
            if (line.includes(plainIP) || line.includes(fullyDefangedIP) || line.includes(lastDotDefangedIP)) {
                foundIP = true;
                
                // Check if the next line already has an annotation
                const hasAnnotation = i + 1 < lines.length && 
                                    (lines[i + 1].trim().startsWith('- VirusTotal:') || 
                                     lines[i + 1].trim().startsWith('- AbuseIPDB:'));

                if (!hasAnnotation) {
                    let annotation = '\n';
                    
                    if (this.settings.outputFormat.virustotal.enabled) {
                        const vtFormat = this.settings.outputFormat.virustotal.format;
                        const vtOutput = vtFormat
                            .replace('{maliciousCount}', reputation.virustotal.maliciousCount.toString())
                            .replace('{totalVendors}', reputation.virustotal.totalVendors.toString())
                            .replace('{harmlessCount}', reputation.virustotal.harmlessCount.toString())
                            .replace('{suspiciousCount}', reputation.virustotal.suspiciousCount.toString())
                            .replace('{timeoutCount}', reputation.virustotal.timeoutCount.toString())
                            .replace('{undetectedCount}', reputation.virustotal.undetectedCount.toString())
                            .replace('{lastAnalysisDate}', reputation.virustotal.lastAnalysisDate)
                            .replace('{country}', reputation.virustotal.country)
                            .replace('{asOwner}', reputation.virustotal.asOwner)
                            .replace('{asn}', reputation.virustotal.asn)
                            .replace('{network}', reputation.virustotal.network)
                            .replace('{tags}', reputation.virustotal.tags.length > 0 ? reputation.virustotal.tags.join(', ') : 'N/A');
                        annotation += `  - VirusTotal: ${vtOutput}\n`;
                    }

                    if (this.settings.outputFormat.abuseipdb.enabled) {
                        const abuseFormat = this.settings.outputFormat.abuseipdb.format;
                        let abuseOutput = abuseFormat
                            .replace('{confidenceScore}', reputation.abuseipdb.confidenceScore.toString())
                            .replace('{totalReports}', reputation.abuseipdb.totalReports.toString())
                            .replace('{numDistinctUsers}', reputation.abuseipdb.numDistinctUsers.toString())
                            .replace('{lastReportedAt}', reputation.abuseipdb.lastReportedAt)
                            .replace('{isPublic}', reputation.abuseipdb.isPublic.toString())
                            .replace('{isWhitelisted}', reputation.abuseipdb.isWhitelisted.toString())
                            .replace('{countryCode}', reputation.abuseipdb.countryCode)
                            .replace('{countryName}', reputation.abuseipdb.countryName)
                            .replace('{usageType}', reputation.abuseipdb.usageType)
                            .replace('{domain}', reputation.abuseipdb.domain)
                            .replace('{hostnames}', reputation.abuseipdb.hostnames.join(', '));

                        // Only include lastReported if there are reports
                        if (reputation.abuseipdb.totalReports > 0) {
                            abuseOutput = abuseOutput.replace('{lastReported}', this.getTimeAgo(reputation.abuseipdb.lastReported));
                        } else {
                            // Remove the entire "last reported X" phrase when there are no reports
                            abuseOutput = abuseOutput.replace(/,?\s*last reported \{lastReported\}/, '');
                        }

                        annotation += `  - AbuseIPDB: ${abuseOutput}`;
                    }

                    newContent += line + annotation;
                } else {
                    newContent += line;
                }
            } else {
                newContent += line;
            }
            
            // Add newline if not the last line
            if (i < lines.length - 1) {
                newContent += '\n';
            }
        }

        editor.setValue(newContent);
    }

    /**
     * Test the API keys to ensure they are working correctly
     */
    async testApiKeys(): Promise<{ virustotal: boolean; abuseipdb: boolean; errors: { virustotal: string; abuseipdb: string } }> {
        const results = {
            virustotal: false,
            abuseipdb: false,
            errors: {
                virustotal: '',
                abuseipdb: ''
            }
        };

        // Test VirusTotal API
        if (this.settings.virustotalApiKey) {
            try {
                const response = await request({
                    url: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
                    method: 'GET',
                    headers: {
                        'x-apikey': this.settings.virustotalApiKey,
                        'Accept': 'application/json'
                    }
                });

                const data = JSON.parse(response);
                
                if (!data) {
                    results.errors.virustotal = 'Empty response from VirusTotal API';
                } else if (!data.data) {
                    results.errors.virustotal = 'Missing data field in VirusTotal response';
                } else if (!data.data.attributes) {
                    results.errors.virustotal = 'Missing attributes field in VirusTotal response';
                } else if (!data.data.attributes.last_analysis_stats) {
                    results.errors.virustotal = 'Missing last_analysis_stats in VirusTotal response';
                } else {
                    results.virustotal = true;
                }
            } catch (error) {
                console.error('VirusTotal API test error:', error);
                if (error.response) {
                    results.errors.virustotal = `Error ${error.response.status}: ${error.response.data?.errors?.[0]?.detail || error.response.data?.message || 'Unknown error'}`;
                } else if (error.request) {
                    results.errors.virustotal = 'No response received from VirusTotal API';
                } else {
                    results.errors.virustotal = error.message || 'Unknown error';
                }
            }
        } else {
            results.errors.virustotal = 'No API key provided';
        }

        // Test AbuseIPDB API
        if (this.settings.abuseipdbApiKey) {
            try {
                const response = await request({
                    url: 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90',
                    method: 'GET',
                    headers: {
                        'Key': this.settings.abuseipdbApiKey,
                        'Accept': 'application/json'
                    }
                });

                const data = JSON.parse(response);
                
                if (data.data && typeof data.data.abuseConfidenceScore === 'number') {
                    results.abuseipdb = true;
                } else {
                    results.errors.abuseipdb = 'Invalid response format from AbuseIPDB API';
                }
            } catch (error) {
                if (error.response) {
                    results.errors.abuseipdb = `Error ${error.response.status}: ${error.response.data?.errors?.[0]?.detail || error.response.data?.message || 'Unknown error'}`;
                } else if (error.request) {
                    results.errors.abuseipdb = 'No response received from AbuseIPDB API';
                } else {
                    results.errors.abuseipdb = error.message || 'Unknown error';
                }
            }
        } else {
            results.errors.abuseipdb = 'No API key provided';
        }

        return results;
    }
}

/**
 * Settings tab for the plugin
 */
class IPSettingTab extends PluginSettingTab {
    plugin: IPReputationPlugin;

    constructor(app: App, plugin: IPReputationPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const {containerEl} = this;
        containerEl.empty();
        containerEl.addClass('soc-toolkit-plugin');

        // Cache Duration setting
        new Setting(containerEl)
            .setName('Cache duration')
            .setDesc('How long to cache results (in hours)')
            .addText(text => text
                .setPlaceholder('24')
                .setValue(this.plugin.settings.cacheDuration.toString())
                .onChange(async (value) => {
                    const num = parseInt(value);
                    if (!isNaN(num) && num > 0) {
                        this.plugin.settings.cacheDuration = num;
                        await this.plugin.saveSettings();
                    }
                }));

        // Defanging Method setting
        new Setting(containerEl)
            .setName('Defanging method')
            .setDesc('Choose how IP addresses should be defanged')
            .addDropdown(dropdown => dropdown
                .addOption('all-dots', 'Replace all dots with square brackets')
                .addOption('last-dot', 'Replace last dot with square bracket')
                .setValue(this.plugin.settings.defangingMethod)
                .onChange(async (value) => {
                    this.plugin.settings.defangingMethod = value as 'all-dots' | 'last-dot';
                    await this.plugin.saveSettings();
                }));

        // Section heading: API keys
        new Setting(containerEl)
            .setName('API')
            .setHeading();

        // VirusTotal API Key setting
        const vtKeySetting = new Setting(containerEl)
            .setName('VirusTotal API key')
            .setDesc('Enter your VirusTotal API key');
        vtKeySetting.controlEl.addClass('api-key-input');
        vtKeySetting.addText(text => text
            .setPlaceholder('Enter your API key')
            .setValue(this.plugin.settings.virustotalApiKey)
            .onChange(async (value) => {
                this.plugin.settings.virustotalApiKey = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // AbuseIPDB API Key setting
        const abuseKeySetting = new Setting(containerEl)
            .setName('AbuseIPDB API key')
            .setDesc('Enter your AbuseIPDB API key');
        abuseKeySetting.controlEl.addClass('api-key-input');
        abuseKeySetting.addText(text => text
            .setPlaceholder('Enter your API key')
            .setValue(this.plugin.settings.abuseipdbApiKey)
            .onChange(async (value) => {
                this.plugin.settings.abuseipdbApiKey = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // Test API Keys button
        new Setting(containerEl)
            .setName('Test API keys')
            .setDesc('Verify that your API keys are working correctly')
            .addButton(button => button
                .setButtonText('Test keys')
                .onClick(async () => {
                    const results = await this.plugin.testApiKeys();
                    
                    let message = '';
                    
                    // VirusTotal status
                    message += results.virustotal 
                        ? '✅ VirusTotal API key is working\n'
                        : `❌ VirusTotal API key is not working\n${results.errors.virustotal}\n\n`;
                    
                    // AbuseIPDB status
                    message += results.abuseipdb
                        ? '✅ AbuseIPDB API key is working'
                        : `❌ AbuseIPDB API key is not working\n${results.errors.abuseipdb}`;
                    
                    new Notice(message);
                }));

        // Section heading: Output
        new Setting(containerEl)
            .setName('Output')
            .setHeading();

        const exampleContainer = containerEl.createDiv('example-container');
        const exampleContent = exampleContainer.createDiv('example-content');
        this.updateExampleOutput();

        // VirusTotal Output Format
        const vtSetting = new Setting(containerEl)
            .setName('Enable VirusTotal');
        vtSetting.controlEl.addClass('toggle-switch');
        vtSetting.addToggle(toggle => toggle
            .setValue(this.plugin.settings.outputFormat.virustotal.enabled)
            .onChange(async (value) => {
                this.plugin.settings.outputFormat.virustotal.enabled = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // Add VirusTotal format input as a new setting
        const vtFormatSetting = new Setting(containerEl)
            .setName('Customise output')
            .setDesc('Customise the VirusTotal output using the available fields below');
        vtFormatSetting.controlEl.addClass('format-input-container');
        vtFormatSetting.addText(text => text
            .setValue(this.plugin.settings.outputFormat.virustotal.format)
            .onChange(async (value) => {
                this.plugin.settings.outputFormat.virustotal.format = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // Add VirusTotal field tags
        const vtFieldTags = containerEl.createDiv('field-tags');
        const vtFields = [
            { name: '{maliciousCount}', desc: 'Number of vendors that flagged the IP as malicious' },
            { name: '{totalVendors}', desc: 'Total number of vendors that analyzed the IP' },
            { name: '{harmlessCount}', desc: 'Number of vendors that flagged the IP as harmless' },
            { name: '{suspiciousCount}', desc: 'Number of vendors that flagged the IP as suspicious' },
            { name: '{timeoutCount}', desc: 'Number of vendors that timed out while analyzing' },
            { name: '{undetectedCount}', desc: 'Number of vendors that didn\'t detect anything' },
            { name: '{lastAnalysisDate}', desc: 'Date of the last analysis' },
            { name: '{country}', desc: 'Country where the IP is located' },
            { name: '{asOwner}', desc: 'Autonomous System owner' },
            { name: '{asn}', desc: 'Autonomous System Number' },
            { name: '{network}', desc: 'Network/CIDR block' },
            { name: '{tags}', desc: 'List of tags associated with the IP' }
        ];
        vtFields.forEach(field => {
            const tag = vtFieldTags.createEl('span', {
                text: field.name,
                cls: 'field-tag',
                attr: { 'data-description': field.desc }
            });
        });

        // AbuseIPDB Output Format
        const abuseSetting = new Setting(containerEl)
            .setName('Enable AbuseIPDB');
        abuseSetting.controlEl.addClass('toggle-switch');
        abuseSetting.addToggle(toggle => toggle
            .setValue(this.plugin.settings.outputFormat.abuseipdb.enabled)
            .onChange(async (value) => {
                this.plugin.settings.outputFormat.abuseipdb.enabled = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // Add AbuseIPDB format input as a new setting
        const abuseFormatSetting = new Setting(containerEl)
            .setName('Customise output')
            .setDesc('Customise the AbuseIPDB output using the available fields below');
        abuseFormatSetting.controlEl.addClass('format-input-container');
        abuseFormatSetting.addText(text => text
            .setValue(this.plugin.settings.outputFormat.abuseipdb.format)
            .onChange(async (value) => {
                this.plugin.settings.outputFormat.abuseipdb.format = value;
                await this.plugin.saveSettings();
                this.updateExampleOutput();
            }));

        // Add AbuseIPDB field tags
        const abuseFieldTags = containerEl.createDiv('field-tags');
        const abuseFields = [
            { name: '{confidenceScore}', desc: 'Confidence score of abuse (0-100)' },
            { name: '{lastReported}', desc: 'Time since the IP was last reported' },
            { name: '{totalReports}', desc: 'Total number of reports for this IP' },
            { name: '{numDistinctUsers}', desc: 'Number of distinct users who reported this IP' },
            { name: '{lastReportedAt}', desc: 'Raw timestamp of the last report' },
            { name: '{isPublic}', desc: 'Whether the IP is public' },
            { name: '{isWhitelisted}', desc: 'Whether the IP is whitelisted' },
            { name: '{countryCode}', desc: 'Two-letter country code' },
            { name: '{countryName}', desc: 'Full country name' },
            { name: '{usageType}', desc: 'Type of usage (e.g., "Data Center", "ISP")' },
            { name: '{domain}', desc: 'Associated domain name' },
            { name: '{hostnames}', desc: 'List of associated hostnames' }
        ];
        abuseFields.forEach(field => {
            const tag = abuseFieldTags.createEl('span', {
                text: field.name,
                cls: 'field-tag',
                attr: { 'data-description': field.desc }
            });
        });
    }

    private getExampleOutput(): string {
        const exampleData: IPReputationData = {
            virustotal: {
                maliciousCount: 2,
                totalVendors: 94,
                lastChecked: Date.now(),
                harmlessCount: 90,
                suspiciousCount: 1,
                timeoutCount: 0,
                undetectedCount: 1,
                lastAnalysisDate: '2024-03-15T12:00:00Z',
                country: 'United States',
                asOwner: 'Google LLC',
                asn: 'AS15169',
                network: '8.8.8.0/24',
                tags: ['malware', 'botnet']
            },
            abuseipdb: {
                confidenceScore: 75,
                lastReported: '2024-03-15T12:00:00Z',
                lastChecked: Date.now(),
                totalReports: 150,
                numDistinctUsers: 45,
                lastReportedAt: '2024-03-15T12:00:00Z',
                isPublic: true,
                isWhitelisted: false,
                countryCode: 'US',
                countryName: 'United States',
                usageType: 'Data Center',
                domain: 'google.com',
                hostnames: ['dns.google']
            }
        };

        let output = '8.8.8.8\n';
        
        if (this.plugin.settings.outputFormat.virustotal.enabled) {
            const vtFormat = this.plugin.settings.outputFormat.virustotal.format;
            const vtOutput = vtFormat
                .replace('{maliciousCount}', exampleData.virustotal.maliciousCount.toString())
                .replace('{totalVendors}', exampleData.virustotal.totalVendors.toString())
                .replace('{harmlessCount}', exampleData.virustotal.harmlessCount.toString())
                .replace('{suspiciousCount}', exampleData.virustotal.suspiciousCount.toString())
                .replace('{timeoutCount}', exampleData.virustotal.timeoutCount.toString())
                .replace('{undetectedCount}', exampleData.virustotal.undetectedCount.toString())
                .replace('{lastAnalysisDate}', exampleData.virustotal.lastAnalysisDate)
                .replace('{country}', exampleData.virustotal.country)
                .replace('{asOwner}', exampleData.virustotal.asOwner)
                .replace('{asn}', exampleData.virustotal.asn)
                .replace('{network}', exampleData.virustotal.network)
                .replace('{tags}', exampleData.virustotal.tags.join(', '));
            output += `  - VirusTotal: ${vtOutput}\n`;
        }

        if (this.plugin.settings.outputFormat.abuseipdb.enabled) {
            const abuseFormat = this.plugin.settings.outputFormat.abuseipdb.format;
            let abuseOutput = abuseFormat
                .replace('{confidenceScore}', exampleData.abuseipdb.confidenceScore.toString())
                .replace('{totalReports}', exampleData.abuseipdb.totalReports.toString())
                .replace('{numDistinctUsers}', exampleData.abuseipdb.numDistinctUsers.toString())
                .replace('{lastReportedAt}', exampleData.abuseipdb.lastReportedAt)
                .replace('{isPublic}', exampleData.abuseipdb.isPublic.toString())
                .replace('{isWhitelisted}', exampleData.abuseipdb.isWhitelisted.toString())
                .replace('{countryCode}', exampleData.abuseipdb.countryCode)
                .replace('{countryName}', exampleData.abuseipdb.countryName)
                .replace('{usageType}', exampleData.abuseipdb.usageType)
                .replace('{domain}', exampleData.abuseipdb.domain)
                .replace('{hostnames}', exampleData.abuseipdb.hostnames.join(', '));

                // Only include lastReported if there are reports
                if (exampleData.abuseipdb.totalReports > 0) {
                    abuseOutput = abuseOutput.replace('{lastReported}', this.plugin.getTimeAgo(exampleData.abuseipdb.lastReported));
                } else {
                    // Remove the entire "last reported X" phrase when there are no reports
                    abuseOutput = abuseOutput.replace(/,?\s*last reported \{lastReported\}/, '');
                }

            output += `  - AbuseIPDB: ${abuseOutput}`;
        }

        return output;
    }

    private updateExampleOutput() {
        const exampleContent = this.containerEl.querySelector('.example-content');
        if (exampleContent) {
            exampleContent.setText(this.getExampleOutput());
        }
    }
}