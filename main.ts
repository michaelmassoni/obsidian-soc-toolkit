import { App, Editor, EditorChange, MarkdownFileInfo, MarkdownView, Notice, Plugin, PluginSettingTab, SecretComponent, SettingGroup, requestUrl, Menu, MenuItem, setTooltip } from 'obsidian';

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
        countryCode: string;
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

let regionNames: Intl.DisplayNames | null = null;

/**
 * Get a country's English name from its two-letter code, falling back to the code itself
 */
function countryName(code: string): string {
    if (!code) {
        return '';
    }
    try {
        regionNames ??= new Intl.DisplayNames(['en'], { type: 'region' });
        return regionNames.of(code.toUpperCase()) ?? code;
    } catch {
        return code;
    }
}

type VirusTotalReputation = IPReputationData['virustotal'];
type AbuseIPDBReputation = IPReputationData['abuseipdb'];

/**
 * IPv4 addresses, plain or defanged (fully or partially, e.g. 1[.]2[.]3[.]4 or 1.2.3[.]4)
 */
const IPV4_REGEX = /\b\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}\b/g;
const IPV4_PLAIN_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/**
 * IPv6 candidates, plain or defanged with [:]. These over-match (e.g. 12:30:45), so every
 * match must be checked with isValidIPv6. The embedded IPv4 alternative comes first so
 * that ::ffff:1.2.3.4 isn't cut off at the first dot.
 */
const IPV6_REGEX = /(?<![0-9A-Za-z:.[\]])(?:[0-9a-fA-F]{0,4}(?::|\[:\])){2,7}(?:\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}|[0-9a-fA-F]{1,4})?(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])/g;
const IPV6_PLAIN_REGEX = /(?<![0-9A-Za-z:.[\]])(?:[0-9a-fA-F]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{1,4})?(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])/g;

/**
 * Run a global regex over text without sharing lastIndex state between calls
 */
function allMatches(regex: RegExp, text: string): RegExpExecArray[] {
    const re = new RegExp(regex.source, 'g');
    const matches: RegExpExecArray[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
        matches.push(match);
    }
    return matches;
}

/**
 * Turn a (possibly defanged) IP back into its plain form
 */
function refangIP(ip: string): string {
    return ip.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':').toLowerCase();
}

/**
 * Check that every octet of a plain IPv4 string is 0-255
 */
function isValidIPv4(address: string): boolean {
    return address.split('.').every(octet => Number(octet) <= 255);
}

/**
 * Check that a plain IPv6 string has valid groups and at most one '::'
 */
function isValidIPv6(address: string): boolean {
    // An embedded IPv4 address takes up the last two groups
    const addr = address.split('%')[0].replace(/\d{1,3}(?:\.\d{1,3}){3}$/, '0:0');
    const halves = addr.split('::');
    if (halves.length > 2) {
        return false;
    }

    const toGroups = (part: string) => part === '' ? [] : part.split(':');
    const groups = [...toGroups(halves[0]), ...(halves.length === 2 ? toGroups(halves[1]) : [])];
    if (!groups.every(group => /^[0-9a-fA-F]{1,4}$/.test(group))) {
        return false;
    }
    return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/**
 * Find all IP addresses (plain or defanged) in text, in order of appearance, refanged
 */
function findIPs(text: string): string[] {
    const found: { start: number; end: number; ip: string }[] = [];

    for (const match of allMatches(IPV6_REGEX, text)) {
        const ip = refangIP(match[0]);
        if (isValidIPv6(ip)) {
            found.push({ start: match.index, end: match.index + match[0].length, ip });
        }
    }

    for (const match of allMatches(IPV4_REGEX, text)) {
        const start = match.index;
        const end = start + match[0].length;
        // Skip IPv4 addresses embedded in an IPv6 address (e.g. ::ffff:1.2.3.4)
        const ip = refangIP(match[0]);
        if (isValidIPv4(ip) && !found.some(f => start < f.end && end > f.start)) {
            found.push({ start, end, ip });
        }
    }

    return found.sort((a, b) => a.start - b.start).map(f => f.ip);
}

/**
 * Replace {field} placeholders with values. Empty values show as N/A; unknown fields are left as-is.
 */
function fillTemplate(template: string, values: { [field: string]: string }): string {
    return template.replace(/\{(\w+)\}/g, (placeholder, field) =>
        Object.prototype.hasOwnProperty.call(values, field) ? (values[field] || 'N/A') : placeholder);
}

function emptyVirusTotalReputation(): VirusTotalReputation {
    return {
        maliciousCount: 0,
        totalVendors: 0,
        lastChecked: 0,
        harmlessCount: 0,
        suspiciousCount: 0,
        timeoutCount: 0,
        undetectedCount: 0,
        lastAnalysisDate: '',
        country: '',
        countryCode: '',
        asOwner: '',
        asn: '',
        network: '',
        tags: []
    };
}

function emptyAbuseIPDBReputation(): AbuseIPDBReputation {
    return {
        confidenceScore: 0,
        lastReported: '',
        lastChecked: 0,
        totalReports: 0,
        numDistinctUsers: 0,
        lastReportedAt: '',
        isPublic: false,
        isWhitelisted: false,
        countryCode: '',
        countryName: '',
        usageType: '',
        domain: '',
        hostnames: []
    };
}

/**
 * Fields available in the output format strings, shown as tags in the settings
 */
const VIRUSTOTAL_FIELDS = [
    { name: '{maliciousCount}', desc: 'Number of vendors that flagged the IP as malicious' },
    { name: '{totalVendors}', desc: 'Total number of vendors that analyzed the IP' },
    { name: '{harmlessCount}', desc: 'Number of vendors that flagged the IP as harmless' },
    { name: '{suspiciousCount}', desc: 'Number of vendors that flagged the IP as suspicious' },
    { name: '{timeoutCount}', desc: 'Number of vendors that timed out while analyzing' },
    { name: '{undetectedCount}', desc: 'Number of vendors that didn\'t detect anything' },
    { name: '{lastAnalysisDate}', desc: 'Date of the last analysis' },
    { name: '{country}', desc: 'Country where the IP is located' },
    { name: '{countryCode}', desc: 'Two-letter country code' },
    { name: '{asOwner}', desc: 'Autonomous System owner' },
    { name: '{asn}', desc: 'Autonomous System Number' },
    { name: '{network}', desc: 'Network/CIDR block' },
    { name: '{tags}', desc: 'List of tags associated with the IP' }
];

const ABUSEIPDB_FIELDS = [
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

/**
 * Plugin settings interface
 */
type Provider = 'virustotal' | 'abuseipdb';

interface IPSettings {
    // Names of secrets in Obsidian's secret storage, not the API keys themselves
    virustotalSecret: string;
    abuseipdbSecret: string;
    // Plaintext keys saved by older versions, moved into secret storage on load
    virustotalApiKey?: string;
    abuseipdbApiKey?: string;
    cacheDuration: number; // in hours
    defangingMethod: 'all-dots' | 'last-dot';
    outputFormat: {
        virustotal: {
            enabled: boolean;
            format: string;
        };
        abuseipdb: {
            enabled: boolean;
            format: string;
        };
    };
}

/**
 * Default plugin settings
 */
const DEFAULT_SETTINGS: IPSettings = {
    virustotalSecret: '',
    abuseipdbSecret: '',
    cacheDuration: 24,
    defangingMethod: 'all-dots', // default to replacing all dots
    outputFormat: {
        virustotal: {
            enabled: true,
            format: '{maliciousCount}/{totalVendors} vendors flagged as malicious'
        },
        abuseipdb: {
            enabled: true,
            format: '{confidenceScore}% confidence of abuse, last reported {lastReported}'
        }
    }
}

const PROVIDER_NAMES: { [provider in Provider]: string } = {
    virustotal: 'VirusTotal',
    abuseipdb: 'AbuseIPDB'
};

/**
 * Main plugin class for IP Reputation Checker
 */
export default class IPReputationPlugin extends Plugin {
    settings: IPSettings;
    ipCache: Map<string, { virustotal?: VirusTotalReputation; abuseipdb?: AbuseIPDBReputation }> = new Map();
    // Progress notice for the reputation check in progress, if any
    private progressNotice: Notice | null = null;

    async onload() {
        await this.loadSettings();

        // Register the command to check IP reputation
        this.addCommand({
            id: 'check-ip-reputation',
            name: 'Check IP reputation in current note',
            editorCallback: (editor, info) => this.annotateIPs(editor, info, 0, editor.lastLine())
        });

        // Add command to check IP reputation in highlighted area
        this.addCommand({
            id: 'check-ip-reputation-highlighted',
            name: 'Check IP reputation in highlighted area',
            editorCallback: (editor, info) => {
                if (!editor.getSelection()) {
                    new Notice('No text selected');
                    return;
                }
                return this.annotateSelection(editor, info);
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
            this.app.workspace.on('editor-menu', (menu: Menu, editor: Editor, info: MarkdownView | MarkdownFileInfo) => {
                const selectedText = editor.getSelection();
                if (selectedText) {
                    const ip = this.findIP(selectedText);
                    if (ip) {
                        menu.addItem((item: MenuItem) => {
                            item
                                .setTitle('Check IP reputation')
                                .setIcon('search')
                                .onClick(() => this.annotateSelection(editor, info));
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
        const data = await this.loadData() ?? {};
        // Build nested objects explicitly so defaults are never shared or mutated, new defaults
        // reach existing users, and fields from older versions (e.g. description) are dropped
        const outputFormat = (provider: Provider) => ({
            enabled: data.outputFormat?.[provider]?.enabled ?? DEFAULT_SETTINGS.outputFormat[provider].enabled,
            format: data.outputFormat?.[provider]?.format ?? DEFAULT_SETTINGS.outputFormat[provider].format
        });
        this.settings = {
            ...DEFAULT_SETTINGS,
            ...data,
            outputFormat: {
                virustotal: outputFormat('virustotal'),
                abuseipdb: outputFormat('abuseipdb')
            }
        };
        await this.migrateApiKeys();
    }

    /**
     * Move plaintext API keys saved by older versions into Obsidian's secret storage
     */
    private async migrateApiKeys() {
        let migrated = false;

        for (const provider of ['virustotal', 'abuseipdb'] as const) {
            const legacyKey = provider === 'virustotal' ? this.settings.virustotalApiKey : this.settings.abuseipdbApiKey;
            if (legacyKey === undefined) {
                continue;
            }

            if (legacyKey) {
                const secretId = `soc-toolkit-${provider}-api-key`;
                const existing = this.app.secretStorage.getSecret(secretId);
                if (existing !== null && existing !== legacyKey) {
                    // Don't overwrite a different secret; keep using the legacy key until the user picks one
                    console.warn(`SOC Toolkit: secret "${secretId}" already exists, leaving ${provider} API key unmigrated`);
                    continue;
                }
                try {
                    this.app.secretStorage.setSecret(secretId, legacyKey);
                } catch (error) {
                    console.error(`SOC Toolkit: failed to move ${provider} API key into secret storage`, error);
                    continue;
                }
                if (provider === 'virustotal') {
                    this.settings.virustotalSecret = secretId;
                } else {
                    this.settings.abuseipdbSecret = secretId;
                }
            }

            if (provider === 'virustotal') {
                delete this.settings.virustotalApiKey;
            } else {
                delete this.settings.abuseipdbApiKey;
            }
            migrated = true;
        }

        if (migrated) {
            await this.saveSettings();
        }
    }

    /**
     * Get a provider's API key from secret storage (or an unmigrated legacy key)
     */
    private getApiKey(provider: Provider): string {
        const secretId = provider === 'virustotal' ? this.settings.virustotalSecret : this.settings.abuseipdbSecret;
        const legacyKey = provider === 'virustotal' ? this.settings.virustotalApiKey : this.settings.abuseipdbApiKey;
        return (secretId && this.app.secretStorage.getSecret(secretId)) || legacyKey || '';
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }

    /**
     * Find the first IP address (plain or defanged) in text
     * @returns The refanged IP address or null
     */
    private findIP(text: string): string | null {
        return findIPs(text)[0] ?? null;
    }

    /**
     * Get the indentation prefix for the annotation based on the line content
     */
    private getIndentPrefix(line: string): string {
        const leadingWhitespace = line.match(/^\s*/)?.[0] || '';
        const isBulleted = /^\s*[-*+] /.test(line);

        if (isBulleted) {
            return leadingWhitespace + '\t';
        }
        return leadingWhitespace;
    }

    /**
     * Generate the annotation text for the reputation data
     */
    public generateAnnotation(reputation: IPReputationData, indentPrefix: string): string {
        const lines: string[] = [];

        if (this.settings.outputFormat.virustotal.enabled) {
            const vt = reputation.virustotal;
            const vtOutput = fillTemplate(this.settings.outputFormat.virustotal.format, {
                maliciousCount: vt.maliciousCount.toString(),
                totalVendors: vt.totalVendors.toString(),
                harmlessCount: vt.harmlessCount.toString(),
                suspiciousCount: vt.suspiciousCount.toString(),
                timeoutCount: vt.timeoutCount.toString(),
                undetectedCount: vt.undetectedCount.toString(),
                lastAnalysisDate: vt.lastAnalysisDate,
                country: vt.country,
                countryCode: vt.countryCode,
                asOwner: vt.asOwner,
                asn: vt.asn,
                network: vt.network,
                tags: vt.tags.join(', ')
            });
            lines.push(`${indentPrefix}- VirusTotal: ${vtOutput}`);
        }

        if (this.settings.outputFormat.abuseipdb.enabled) {
            const abuse = reputation.abuseipdb;
            const hasReports = abuse.totalReports > 0;
            let abuseFormat = this.settings.outputFormat.abuseipdb.format;
            if (!hasReports) {
                // Drop the default "last reported" phrase; any other use of the field shows "never"
                abuseFormat = abuseFormat.replace(/,?\s*last reported \{lastReported\}/g, '');
            }
            const abuseOutput = fillTemplate(abuseFormat, {
                confidenceScore: abuse.confidenceScore.toString(),
                lastReported: hasReports ? this.getTimeAgo(abuse.lastReported) : 'never',
                totalReports: abuse.totalReports.toString(),
                numDistinctUsers: abuse.numDistinctUsers.toString(),
                lastReportedAt: abuse.lastReportedAt,
                isPublic: abuse.isPublic.toString(),
                isWhitelisted: abuse.isWhitelisted.toString(),
                countryCode: abuse.countryCode,
                countryName: abuse.countryName,
                usageType: abuse.usageType,
                domain: abuse.domain,
                hostnames: abuse.hostnames.join(', ')
            });
            lines.push(`${indentPrefix}- AbuseIPDB: ${abuseOutput}`);
        }

        return lines.length > 0 ? '\n' + lines.join('\n') : '';
    }

    /**
     * Check and annotate IPs on the lines covered by the editor's selection
     */
    private annotateSelection(editor: Editor, info: MarkdownView | MarkdownFileInfo) {
        const from = editor.getCursor('from');
        const to = editor.getCursor('to');
        // A selection ending at the start of a line doesn't include that line
        const lastLine = to.ch === 0 && to.line > from.line ? to.line - 1 : to.line;
        return this.annotateIPs(editor, info, from.line, lastLine);
    }

    /**
     * Check whether the line after lineIndex is an existing annotation
     */
    private hasAnnotation(editor: Editor, lineIndex: number): boolean {
        if (lineIndex >= editor.lineCount() - 1) {
            return false;
        }
        const next = editor.getLine(lineIndex + 1).trim();
        return next.startsWith('- VirusTotal:') || next.startsWith('- AbuseIPDB:');
    }

    /**
     * Look up the IPs on lines fromLine..toLine that aren't annotated yet, then insert all
     * annotations in a single edit so the cursor, scroll position and undo history are kept
     */
    private async annotateIPs(editor: Editor, info: MarkdownView | MarkdownFileInfo, fromLine: number, toLine: number) {
        const file = info.file;

        const ips = new Set<string>();
        let annotatedCount = 0;
        for (let i = fromLine; i <= toLine; i++) {
            const ip = this.findIP(editor.getLine(i));
            if (!ip) {
                continue;
            }
            if (this.hasAnnotation(editor, i)) {
                annotatedCount++;
            } else {
                ips.add(ip);
            }
        }

        if (ips.size === 0) {
            new Notice(annotatedCount > 0 ? 'All IP addresses are already annotated' : 'No valid IP addresses found');
            return;
        }

        const results = new Map<string, IPReputationData>();
        const errors: string[] = [];
        this.progressNotice = new Notice(`Checking ${ips.size} IP address(es)...`, 0);
        try {
            let index = 0;
            for (const ip of ips) {
                index++;
                this.progressNotice.setMessage(`Checking IP ${index} of ${ips.size}...`);
                try {
                    results.set(ip, await this.getIPReputation(ip));
                } catch (error) {
                    console.error(`Error checking IP ${ip}:`, error);
                    errors.push(`${ip}: ${error.message}`);
                }
            }
        } finally {
            this.progressNotice.hide();
            this.progressNotice = null;
        }

        // The lookups can take a while; don't write into a different note if the user switched
        if (info.file !== file) {
            new Notice('The note changed while checking IPs, so no annotations were added');
            return;
        }

        // Re-read the lines, since the note may have been edited during the lookups
        const changes: EditorChange[] = [];
        for (let i = fromLine; i <= Math.min(toLine, editor.lastLine()); i++) {
            const line = editor.getLine(i);
            const ip = this.findIP(line);
            const reputation = ip ? results.get(ip) : undefined;
            if (reputation && !this.hasAnnotation(editor, i)) {
                changes.push({
                    from: { line: i, ch: line.length },
                    text: this.generateAnnotation(reputation, this.getIndentPrefix(line))
                });
            }
        }
        if (changes.length > 0) {
            editor.transaction({ changes });
        }

        let message = `Checked ${results.size} IP address(es)`;
        if (annotatedCount > 0) {
            message += `, skipped ${annotatedCount} already annotated`;
        }
        if (errors.length > 0) {
            message += `\n\n${errors.length} failed:\n${errors.slice(0, 3).join('\n')}`;
            if (errors.length > 3) {
                message += `\n...and ${errors.length - 3} more (see console)`;
            }
        }
        new Notice(message, errors.length > 0 ? 10000 : undefined);
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
        const { text, count } = this.defangIPsInText(editor.getValue());

        if (count > 0) {
            editor.setValue(text);
            new Notice(`Defanged ${count} IP address(es)`);
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

        const { text, count } = this.defangIPsInText(selectedText);

        if (count > 0) {
            editor.replaceSelection(text);
            new Notice(`Defanged ${count} IP address(es)`);
        } else {
            new Notice('No IP addresses found to defang');
        }
    }

    /**
     * Defang every plain IP address in text. Already-defanged addresses are left alone.
     */
    private defangIPsInText(text: string): { text: string; count: number } {
        let count = 0;

        // IPv6 first, so an embedded IPv4 address (::ffff:1.2.3.4) is matched as part of it
        let newText = text.replace(new RegExp(IPV6_PLAIN_REGEX.source, 'g'), (match) => {
            if (!isValidIPv6(match)) {
                return match;
            }
            count++;
            return this.defangIP(match);
        });

        newText = newText.replace(new RegExp(IPV4_PLAIN_REGEX.source, 'g'), (match) => {
            if (!isValidIPv4(match)) {
                return match;
            }
            count++;
            return this.defangIP(match);
        });

        return { text: newText, count };
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
        if (this.settings.defangingMethod === 'last-dot') {
            return ip.replace(/\.(?=\d+$)/, '[.]');
        }
        return ip.replace(/\./g, '[.]');
    }

    /**
     * Get reputation data for an IP address from the enabled APIs
     */
    private async getIPReputation(ip: string): Promise<IPReputationData> {
        const { virustotal: vtOutput, abuseipdb: abuseOutput } = this.settings.outputFormat;
        if (!vtOutput.enabled && !abuseOutput.enabled) {
            throw new Error('Both VirusTotal and AbuseIPDB are disabled in settings');
        }

        // Each provider is cached separately, so enabling one later doesn't reuse empty data
        const cached = this.ipCache.get(ip) ?? {};
        const maxAge = this.settings.cacheDuration * 60 * 60 * 1000;
        const isFresh = (entry?: { lastChecked: number }) => !!entry && Date.now() - entry.lastChecked < maxAge;

        const [virustotal, abuseipdb] = await Promise.all([
            !vtOutput.enabled ? undefined
                : isFresh(cached.virustotal) ? cached.virustotal
                : this.checkVirusTotal(ip).then(data => this.parseVirusTotal(data)),
            !abuseOutput.enabled ? undefined
                : isFresh(cached.abuseipdb) ? cached.abuseipdb
                : this.checkAbuseIPDB(ip).then(data => this.parseAbuseIPDB(data))
        ]);

        this.ipCache.set(ip, {
            virustotal: virustotal ?? cached.virustotal,
            abuseipdb: abuseipdb ?? cached.abuseipdb
        });

        // Return copies to avoid modifying the cached data
        return {
            virustotal: { ...(virustotal ?? emptyVirusTotalReputation()) },
            abuseipdb: { ...(abuseipdb ?? emptyAbuseIPDBReputation()) }
        };
    }

    private parseVirusTotal(vtData: any): VirusTotalReputation {
        // Extract data with fallbacks
        const vtStats = vtData?.data?.attributes?.last_analysis_stats || {};
        const vtResults = vtData?.data?.attributes?.last_analysis_results || {};
        const vtAttributes = vtData?.data?.attributes || {};

        return {
            maliciousCount: vtStats.malicious || 0,
            totalVendors: Object.keys(vtResults).length,
            lastChecked: Date.now(),
            harmlessCount: vtStats.harmless || 0,
            suspiciousCount: vtStats.suspicious || 0,
            timeoutCount: vtStats.timeout || 0,
            undetectedCount: vtStats.undetected || 0,
            // VirusTotal returns a Unix timestamp in seconds
            lastAnalysisDate: vtAttributes.last_analysis_date
                ? new Date(vtAttributes.last_analysis_date * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
                : '',
            country: countryName(vtAttributes.country || ''),
            countryCode: vtAttributes.country || '',
            asOwner: vtAttributes.as_owner || '',
            asn: vtAttributes.asn ? String(vtAttributes.asn) : '',
            network: vtAttributes.network || '',
            tags: vtAttributes.tags || []
        };
    }

    private parseAbuseIPDB(abuseData: any): AbuseIPDBReputation {
        const abuseDataObj = abuseData?.data || {};

        return {
            confidenceScore: abuseDataObj.abuseConfidenceScore || 0,
            lastReported: abuseDataObj.lastReportedAt || new Date().toISOString(),
            lastChecked: Date.now(),
            totalReports: abuseDataObj.totalReports || 0,
            numDistinctUsers: abuseDataObj.numDistinctUsers || 0,
            lastReportedAt: abuseDataObj.lastReportedAt || '',
            isPublic: abuseDataObj.isPublic || false,
            isWhitelisted: abuseDataObj.isWhitelisted || false,
            countryCode: abuseDataObj.countryCode || '',
            countryName: countryName(abuseDataObj.countryCode || ''),
            usageType: abuseDataObj.usageType || '',
            domain: abuseDataObj.domain || '',
            hostnames: abuseDataObj.hostnames || []
        };
    }

    /**
     * Make a GET request to a reputation API and return the parsed JSON, with readable errors
     */
    private async apiGet(provider: Provider, url: string, headers: Record<string, string>) {
        const name = PROVIDER_NAMES[provider];

        let response;
        try {
            response = await requestUrl({ url, method: 'GET', headers: { ...headers, 'Accept': 'application/json' }, throw: false });
        } catch (error) {
            throw new Error(`Couldn't reach ${name} (${error.message})`);
        }

        let data;
        try {
            data = response.json;
        } catch {
            data = null;
        }

        if (response.status >= 200 && response.status < 300 && data) {
            return data;
        }
        switch (response.status) {
            case 401:
            case 403:
                throw new Error(`${name} rejected the API key (${response.status})`);
            case 429:
                throw new Error(`${name} rate limit or quota reached (429)`);
        }
        // VirusTotal errors look like { error: { message } }, AbuseIPDB like { errors: [{ detail }] }
        const detail = data?.error?.message || data?.errors?.[0]?.detail || 'unexpected response';
        throw new Error(`${name} error ${response.status}: ${detail}`);
    }

    /**
     * Check IP reputation using VirusTotal API
     */
    private async checkVirusTotal(ip: string) {
        const apiKey = this.getApiKey('virustotal');
        if (!apiKey) {
            throw new Error('No VirusTotal API key set');
        }
        return this.apiGet('virustotal', `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
            'x-apikey': apiKey
        });
    }

    /**
     * Check IP reputation using AbuseIPDB API
     */
    private async checkAbuseIPDB(ip: string) {
        const apiKey = this.getApiKey('abuseipdb');
        if (!apiKey) {
            throw new Error('No AbuseIPDB API key set');
        }
        return this.apiGet('abuseipdb', `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
            'Key': apiKey
        });
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
     * Test the API keys to ensure they are working correctly
     */
    async testApiKeys(): Promise<{ virustotal: boolean; abuseipdb: boolean; errors: { virustotal: string; abuseipdb: string } }> {
        const test = async (check: () => Promise<any>, isValid: (data: any) => boolean) => {
            try {
                return isValid(await check()) ? '' : 'Unexpected response format';
            } catch (error) {
                console.error('API key test error:', error);
                return error.message || 'Unknown error';
            }
        };

        const [virustotal, abuseipdb] = await Promise.all([
            test(() => this.checkVirusTotal('8.8.8.8'), data => !!data?.data?.attributes?.last_analysis_stats),
            test(() => this.checkAbuseIPDB('8.8.8.8'), data => typeof data?.data?.abuseConfidenceScore === 'number')
        ]);

        return {
            virustotal: !virustotal,
            abuseipdb: !abuseipdb,
            errors: { virustotal, abuseipdb }
        };
    }
}

/**
 * Settings tab for the plugin
 */
class IPSettingTab extends PluginSettingTab {
    plugin: IPReputationPlugin;
    private previewEl: HTMLElement | null = null;

    constructor(app: App, plugin: IPReputationPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.addClass('soc-toolkit-settings');

        new SettingGroup(containerEl)
            .addSetting(setting => setting
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
                    })))
            .addSetting(setting => setting
                .setName('Defanging method')
                .setDesc('Choose how IPv4 addresses should be defanged')
                .addDropdown(dropdown => dropdown
                    .addOption('all-dots', 'Replace all dots (1[.]2[.]3[.]4)')
                    .addOption('last-dot', 'Replace last dot (1.2.3[.]4)')
                    .setValue(this.plugin.settings.defangingMethod)
                    .onChange(async (value) => {
                        this.plugin.settings.defangingMethod = value as 'all-dots' | 'last-dot';
                        await this.plugin.saveSettings();
                    })));

        new SettingGroup(containerEl)
            .setHeading('API keys')
            .addSetting(setting => setting
                .setName('VirusTotal API key')
                .setDesc('Choose or create the secret that holds your VirusTotal API key')
                .addComponent(el => new SecretComponent(this.app, el)
                    .setValue(this.plugin.settings.virustotalSecret)
                    .onChange(async (value) => {
                        this.plugin.settings.virustotalSecret = value ?? '';
                        await this.plugin.saveSettings();
                    })))
            .addSetting(setting => setting
                .setName('AbuseIPDB API key')
                .setDesc('Choose or create the secret that holds your AbuseIPDB API key')
                .addComponent(el => new SecretComponent(this.app, el)
                    .setValue(this.plugin.settings.abuseipdbSecret)
                    .onChange(async (value) => {
                        this.plugin.settings.abuseipdbSecret = value ?? '';
                        await this.plugin.saveSettings();
                    })))
            .addSetting(setting => setting
                .setName('Test API keys')
                .setDesc('Verify that your API keys are working correctly')
                .addButton(button => button
                    .setButtonText('Test keys')
                    .onClick(async () => {
                        const results = await this.plugin.testApiKeys();

                        const status = (provider: Provider) => results[provider]
                            ? `✅ ${PROVIDER_NAMES[provider]} API key is working`
                            : `❌ ${results.errors[provider]}`;

                        new Notice(`${status('virustotal')}\n${status('abuseipdb')}`, 10000);
                    })));

        new SettingGroup(containerEl)
            .setHeading('Output')
            .addSetting(setting => {
                setting
                    .setName('Preview')
                    .setDesc('How annotations will appear under an IP in your notes');
                setting.settingEl.addClass('soc-toolkit-wide');
                this.previewEl = setting.settingEl.createEl('pre', { cls: 'soc-toolkit-preview' });
            });
        this.updateExampleOutput();

        this.addProviderGroup(containerEl, 'VirusTotal', 'virustotal', VIRUSTOTAL_FIELDS);
        this.addProviderGroup(containerEl, 'AbuseIPDB', 'abuseipdb', ABUSEIPDB_FIELDS);
    }

    /**
     * Add the enable toggle and output format settings for one reputation provider
     */
    private addProviderGroup(
        containerEl: HTMLElement,
        title: string,
        provider: Provider,
        fields: { name: string; desc: string }[]
    ) {
        const output = this.plugin.settings.outputFormat[provider];

        new SettingGroup(containerEl)
            .setHeading(title)
            .addSetting(setting => setting
                .setName(`Enable ${title}`)
                .setDesc(`Look up IPs in ${title} and include the result in annotations`)
                .addToggle(toggle => toggle
                    .setValue(output.enabled)
                    .onChange(async (value) => {
                        output.enabled = value;
                        await this.plugin.saveSettings();
                        this.updateExampleOutput();
                    })))
            .addSetting(setting => {
                setting
                    .setName('Output format')
                    .setDesc('Hover over a field below to see what it contains')
                    .addText(text => text
                        .setValue(output.format)
                        .onChange(async (value) => {
                            output.format = value;
                            await this.plugin.saveSettings();
                            this.updateExampleOutput();
                        }));
                setting.settingEl.addClass('soc-toolkit-wide');

                const fieldTags = setting.settingEl.createDiv('soc-toolkit-field-tags');
                fields.forEach(field => {
                    const tag = fieldTags.createSpan({ text: field.name, cls: 'soc-toolkit-field-tag' });
                    setTooltip(tag, field.desc);
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
                lastAnalysisDate: '2024-03-15 12:00 UTC',
                country: 'United States',
                countryCode: 'US',
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

        return '8.8.8.8' + this.plugin.generateAnnotation(exampleData, '  ');
    }

    private updateExampleOutput() {
        this.previewEl?.setText(this.getExampleOutput());
    }
}
