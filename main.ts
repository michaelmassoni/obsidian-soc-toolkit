import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, request } from 'obsidian';

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
 * Plugin settings interface
 */
interface IPSettings {
    virustotalApiKey: string;
    abuseipdbApiKey: string;
    cacheDuration: number; // in hours
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
            name: 'Check IP Reputation in Current Note',
            callback: () => this.checkIPReputation()
        });

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
     * Main function to check IP reputation in the current note
     */
    private async checkIPReputation() {
        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!activeView) {
            new Notice('No active note found');
            return;
        }

        const editor = activeView.editor;
        const content = editor.getValue();
        
        // Debug: Log the content being searched
        console.log('Searching content for IPs:', content);
        
        // Simple IPv4 regex
        const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        
        // Simpler IPv6 regex that matches the basic structure
        const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b/g;
        
        // Find all matches
        const ipv4Matches = content.match(ipv4Regex) || [];
        
        // For IPv6, we need to handle the matches more carefully
        let ipv6Matches: string[] = [];
        let match;
        while ((match = ipv6Regex.exec(content)) !== null) {
            // Get the full match
            const fullMatch = match[0];
            
            // If the match ends with a colon, look ahead for the next part
            if (fullMatch.endsWith(':')) {
                const nextPart = content.slice(match.index + fullMatch.length).match(/^[0-9a-fA-F]{1,4}/);
                if (nextPart) {
                    ipv6Matches.push(fullMatch + nextPart[0]);
                }
            } else {
                ipv6Matches.push(fullMatch);
            }
        }
        
        // Debug: Log matches
        console.log('IPv4 matches:', ipv4Matches);
        console.log('IPv6 matches:', ipv6Matches);
        
        // Filter out private/reserved IPv4s
        const publicIPv4s = ipv4Matches.filter(ip => {
            const parts = ip.split('.');
            return !(
                parts[0] === '10' ||
                (parts[0] === '172' && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) ||
                (parts[0] === '192' && parts[1] === '168') ||
                parts[0] === '127' ||
                (parts[0] === '169' && parts[1] === '254')
            );
        });

        // Filter out private/reserved IPv6s
        const publicIPv6s = ipv6Matches.filter(ip => {
            const isPrivate = (
                ip.startsWith('::1') || // localhost
                ip.startsWith('fe80:') || // link-local
                ip.startsWith('fc00:') || // unique local
                ip.startsWith('fd00:') || // unique local
                ip.startsWith('ff00:') || // multicast
                ip.startsWith('2001:db8:') // documentation
            );
            
            // Debug: Log IPv6 filtering
            console.log(`IPv6 ${ip} is ${isPrivate ? 'private' : 'public'}`);
            return !isPrivate;
        });

        // Debug: Log filtered results
        console.log('Public IPv4s:', publicIPv4s);
        console.log('Public IPv6s:', publicIPv6s);

        const uniqueIPs = [...new Set([...publicIPv4s, ...publicIPv6s])];
        
        // Debug: Log final unique IPs
        console.log('Final unique IPs to check:', uniqueIPs);
        
        if (uniqueIPs.length === 0) {
            new Notice('No public IP addresses found in the current note');
            return;
        }

        let checkedCount = 0;
        for (const ip of uniqueIPs) {
            try {
                const reputation = await this.getIPReputation(ip);
                this.updateNoteWithReputation(editor, ip, reputation);
                checkedCount++;
            } catch (error) {
                console.error(`Error checking IP ${ip}:`, error);
                new Notice(`Error checking IP ${ip}`);
            }
        }

        new Notice(`Checked ${checkedCount} IP addresses`);
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
                return cached;
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
                    countryName: abuseDataObj.countryName || '',
                    usageType: abuseDataObj.usageType || '',
                    domain: abuseDataObj.domain || '',
                    hostnames: abuseDataObj.hostnames || []
                }
            };

            this.ipCache.set(ip, reputation);
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
        const content = editor.getValue();
        const ipRegex = new RegExp(`\\b${ip}\\b`, 'g');
        let match;
        let lastIndex = 0;
        let newContent = '';

        while ((match = ipRegex.exec(content)) !== null) {
            newContent += content.slice(lastIndex, match.index + match[0].length);
            
            // Check if there's already an annotation
            const nextLineStart = content.indexOf('\n', match.index);
            const nextLine = nextLineStart !== -1 ? content.slice(nextLineStart + 1) : '';
            const hasAnnotation = nextLine.startsWith('  - VirusTotal:') || nextLine.startsWith('  - AbuseIPDB:');

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
                        .replace('{tags}', reputation.virustotal.tags.join(', '));
                    annotation += `  - VirusTotal: ${vtOutput}\n`;
                }

                if (this.settings.outputFormat.abuseipdb.enabled) {
                    const abuseFormat = this.settings.outputFormat.abuseipdb.format;
                    const abuseOutput = abuseFormat
                        .replace('{confidenceScore}', reputation.abuseipdb.confidenceScore.toString())
                        .replace('{lastReported}', this.getTimeAgo(reputation.abuseipdb.lastReported))
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
                    annotation += `  - AbuseIPDB: ${abuseOutput}`;
                }

                newContent += annotation;
            }

            lastIndex = match.index + match[0].length;
        }

        newContent += content.slice(lastIndex);
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
                console.log('VirusTotal full response:', JSON.stringify(data, null, 2));
                
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
                console.log('AbuseIPDB full response:', JSON.stringify(data, null, 2));
                
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
        containerEl.addClass('ip-reputation-plugin');

        // API Settings section
        containerEl.createEl('h2', { text: 'API Settings' });

        // VirusTotal API Key setting
        const vtKeySetting = new Setting(containerEl)
            .setName('VirusTotal API Key')
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
            .setName('AbuseIPDB API Key')
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
            .setName('Test API Keys')
            .setDesc('Verify that your API keys are working correctly')
            .addButton(button => button
                .setButtonText('Test Keys')
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

        // Cache Duration setting
        new Setting(containerEl)
            .setName('Cache Duration')
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

        // Output Settings Section
        containerEl.createEl('h2', { text: 'Output Settings', cls: 'settings-section-header' });

        // Add example output section
        containerEl.createEl('h3', { text: 'Example Output' });
        const exampleContainer = containerEl.createDiv('example-container');
        const exampleContent = exampleContainer.createDiv('example-content');
        this.updateExampleOutput();

        // Add VirusTotal section heading
        containerEl.createEl('h3', { text: 'VirusTotal' });

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
            .setName('Customise Output')
            .setDesc('Customise the output using the available fields below');
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

        // Add AbuseIPDB section heading
        containerEl.createEl('h3', { text: 'AbuseIPDB' });

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
            .setName('Customise Output')
            .setDesc('Customise the output using the available fields below');
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
            const abuseOutput = abuseFormat
                .replace('{confidenceScore}', exampleData.abuseipdb.confidenceScore.toString())
                .replace('{lastReported}', this.plugin.getTimeAgo(exampleData.abuseipdb.lastReported))
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