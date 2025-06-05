import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, request } from 'obsidian';

/**
 * Interface for storing IP reputation data from both VirusTotal and AbuseIPDB
 */
interface IPReputationData {
    virustotal: {
        maliciousCount: number;
        totalVendors: number;
        lastChecked: number;
    };
    abuseipdb: {
        confidenceScore: number;
        lastReported: string;
        lastChecked: number;
    };
}

/**
 * Plugin settings interface
 */
interface IPSettings {
    virustotalApiKey: string;
    abuseipdbApiKey: string;
    cacheDuration: number; // in hours
}

/**
 * Default plugin settings
 */
const DEFAULT_SETTINGS: IPSettings = {
    virustotalApiKey: '',
    abuseipdbApiKey: '',
    cacheDuration: 24
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
            const abuseDataObj = abuseData?.data || {};

            const reputation: IPReputationData = {
                virustotal: {
                    maliciousCount: vtStats.malicious || 0,
                    totalVendors: Object.keys(vtResults).length,
                    lastChecked: Date.now()
                },
                abuseipdb: {
                    confidenceScore: abuseDataObj.abuseConfidenceScore || 0,
                    lastReported: abuseDataObj.lastReportedAt || new Date().toISOString(),
                    lastChecked: Date.now()
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
                newContent += '\n  - VirusTotal: ' + 
                    `${reputation.virustotal.maliciousCount}/${reputation.virustotal.totalVendors} vendors flagged as malicious\n` +
                    '  - AbuseIPDB: ' +
                    `${reputation.abuseipdb.confidenceScore}% confidence of abuse, ` +
                    `last reported ${this.getTimeAgo(reputation.abuseipdb.lastReported)}`;
            }

            lastIndex = match.index + match[0].length;
        }

        newContent += content.slice(lastIndex);
        editor.setValue(newContent);
    }

    /**
     * Convert a date string to a human-readable time ago format
     */
    private getTimeAgo(dateString: string): string {
        const date = new Date(dateString);
        const now = new Date();
        const diffInDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
        
        if (diffInDays === 0) return 'today';
        if (diffInDays === 1) return 'yesterday';
        return `${diffInDays}d ago`;
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

        containerEl.createEl('h2', {text: 'IP Reputation Settings'});

        // VirusTotal API Key setting
        new Setting(containerEl)
            .setName('VirusTotal API Key')
            .setDesc('Enter your VirusTotal API key')
            .addText(text => text
                .setPlaceholder('Enter your API key')
                .setValue(this.plugin.settings.virustotalApiKey)
                .onChange(async (value) => {
                    this.plugin.settings.virustotalApiKey = value;
                    await this.plugin.saveSettings();
                }));

        // AbuseIPDB API Key setting
        new Setting(containerEl)
            .setName('AbuseIPDB API Key')
            .setDesc('Enter your AbuseIPDB API key')
            .addText(text => text
                .setPlaceholder('Enter your API key')
                .setValue(this.plugin.settings.abuseipdbApiKey)
                .onChange(async (value) => {
                    this.plugin.settings.abuseipdbApiKey = value;
                    await this.plugin.saveSettings();
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
    }
}