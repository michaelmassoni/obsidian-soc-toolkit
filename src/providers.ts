import { requestUrl } from 'obsidian';
import { IOC, IOCType } from './ioc';
import { countryName, fillTemplate, formatDate, formatDuration, formatTimestamp, getTimeAgo } from './format';

/**
 * Reputation providers. Each one says which IOC types it supports, which template fields it
 * offers, and how to look an IOC up.
 */

export type ProviderId = 'virustotal' | 'abuseipdb';

export interface LookupResult {
    // Values for the {field} placeholders in the output format
    fields: { [field: string]: string };
    reportUrl?: string;
    // The provider has no record of this IOC
    notFound?: boolean;
    lastChecked: number;
}

export interface LookupContext {
    apiKey: string;
    // Defangs IOCs inside output values (e.g. a redirect target), so annotations don't add live links
    defang: (text: string) => string;
}

export interface FieldInfo {
    name: string;
    desc: string;
}

export interface Provider {
    id: ProviderId;
    name: string;
    types: IOCType[];
    fields: { [type in IOCType]?: FieldInfo[] };
    defaultFormats: { [type in IOCType]?: string };
    // Sample results for the settings preview
    examples: { [type in IOCType]?: LookupResult };
    lookup(ioc: Pick<IOC, 'type' | 'value'>, context: LookupContext): Promise<LookupResult>;
    // Turn a result into annotation text; defaults to filling in the format's fields
    render?(format: string, result: LookupResult): string;
}

/**
 * Make a GET request to a reputation API and return the parsed JSON, with readable errors.
 * Returns null for a 404 when allowNotFound is set.
 */
async function apiGet(name: string, url: string, headers: Record<string, string>, allowNotFound = false): Promise<any> {
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
        case 404:
            if (allowNotFound) {
                return null;
            }
            break;
        case 429:
            throw new Error(`${name} rate limit or quota reached (429)`);
    }
    // VirusTotal errors look like { error: { message } }, AbuseIPDB like { errors: [{ detail }] }
    const detail = data?.error?.message || data?.errors?.[0]?.detail || 'unexpected response';
    throw new Error(`${name} error ${response.status}: ${detail}`);
}

function requireKey(name: string, apiKey: string) {
    if (!apiKey) {
        throw new Error(`No ${name} API key set`);
    }
}

function unique(values: string[]): string[] {
    return [...new Set(values.filter(Boolean))];
}

// ----- VirusTotal -----

const VT_ANALYSIS_FIELDS: FieldInfo[] = [
    { name: '{maliciousCount}', desc: 'Number of vendors that flagged it as malicious' },
    { name: '{totalVendors}', desc: 'Total number of vendors that analysed it' },
    { name: '{harmlessCount}', desc: 'Number of vendors that flagged it as harmless' },
    { name: '{suspiciousCount}', desc: 'Number of vendors that flagged it as suspicious' },
    { name: '{timeoutCount}', desc: 'Number of vendors that timed out while analysing' },
    { name: '{undetectedCount}', desc: 'Number of vendors that didn\'t detect anything' },
    { name: '{lastAnalysisDate}', desc: 'Date of the last analysis' },
    { name: '{reputation}', desc: 'Community reputation score (negative suggests malicious)' },
    { name: '{tags}', desc: 'Tags VirusTotal has assigned' }
];

function vtAnalysisFields(attributes: any): { [field: string]: string } {
    const stats = attributes.last_analysis_stats || {};
    return {
        maliciousCount: String(stats.malicious || 0),
        totalVendors: String(Object.keys(attributes.last_analysis_results || {}).length),
        harmlessCount: String(stats.harmless || 0),
        suspiciousCount: String(stats.suspicious || 0),
        timeoutCount: String(stats.timeout || 0),
        undetectedCount: String(stats.undetected || 0),
        lastAnalysisDate: formatTimestamp(attributes.last_analysis_date),
        reputation: typeof attributes.reputation === 'number' ? String(attributes.reputation) : '',
        categories: unique(Object.values(attributes.categories || {}) as string[]).join(', '),
        tags: (attributes.tags || []).join(', ')
    };
}

/**
 * VirusTotal identifies a URL by its unpadded base64url encoding
 */
function vtUrlId(url: string): string {
    const bytes = new TextEncoder().encode(url);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const VT_API = 'https://www.virustotal.com/api/v3';
const VT_GUI = 'https://www.virustotal.com/gui';

const virustotal: Provider = {
    id: 'virustotal',
    name: 'VirusTotal',
    types: ['ip', 'domain', 'url'],
    fields: {
        ip: [
            ...VT_ANALYSIS_FIELDS,
            { name: '{country}', desc: 'Country where the IP is located' },
            { name: '{countryCode}', desc: 'Two-letter country code' },
            { name: '{asOwner}', desc: 'Autonomous System owner' },
            { name: '{asn}', desc: 'Autonomous System Number' },
            { name: '{network}', desc: 'Network/CIDR block' }
        ],
        domain: [
            ...VT_ANALYSIS_FIELDS,
            { name: '{categories}', desc: 'Categories assigned by web filtering vendors' },
            { name: '{registrar}', desc: 'Company the domain was registered with' },
            { name: '{created}', desc: 'Date the domain was registered' },
            { name: '{domainAge}', desc: 'Time since the domain was registered, e.g. 12d' },
            { name: '{resolvesTo}', desc: 'IP addresses the domain resolved to (defanged)' },
            { name: '{popularity}', desc: 'Best rank in popularity lists, e.g. #120 (Tranco)' }
        ],
        url: [
            ...VT_ANALYSIS_FIELDS,
            { name: '{categories}', desc: 'Categories assigned by web filtering vendors' },
            { name: '{finalUrl}', desc: 'Where the URL ends up after redirects (defanged)' },
            { name: '{title}', desc: 'Page title' },
            { name: '{responseCode}', desc: 'HTTP status code of the last response' },
            { name: '{targetedBrand}', desc: 'Brand the page impersonates, from phishing detection' },
            { name: '{timesSubmitted}', desc: 'Number of times the URL has been submitted to VirusTotal' },
            { name: '{firstSeen}', desc: 'Date the URL was first submitted' }
        ]
    },
    defaultFormats: {
        ip: '{maliciousCount}/{totalVendors} vendors flagged as malicious',
        domain: '{maliciousCount}/{totalVendors} vendors flagged as malicious, domain age {domainAge}',
        url: '{maliciousCount}/{totalVendors} vendors flagged as malicious'
    },
    examples: {
        ip: {
            fields: {
                maliciousCount: '2', totalVendors: '94', harmlessCount: '90', suspiciousCount: '1', timeoutCount: '0',
                undetectedCount: '1', lastAnalysisDate: '2024-03-15 12:00 UTC', reputation: '-5', tags: 'malware, botnet',
                country: 'United States', countryCode: 'US', asOwner: 'Google LLC', asn: '15169', network: '8.8.8.0/24'
            },
            reportUrl: `${VT_GUI}/ip-address/8.8.8.8`,
            lastChecked: 0
        },
        domain: {
            fields: {
                maliciousCount: '7', totalVendors: '94', harmlessCount: '60', suspiciousCount: '2', timeoutCount: '0',
                undetectedCount: '25', lastAnalysisDate: '2024-03-15 12:00 UTC', reputation: '-12', tags: '',
                categories: 'phishing, newly registered', registrar: 'NameCheap, Inc.', created: '2024-03-03',
                domainAge: '12d', resolvesTo: '203[.]0[.]113[.]10', popularity: ''
            },
            reportUrl: `${VT_GUI}/domain/example.com`,
            lastChecked: 0
        },
        url: {
            fields: {
                maliciousCount: '9', totalVendors: '95', harmlessCount: '58', suspiciousCount: '1', timeoutCount: '0',
                undetectedCount: '27', lastAnalysisDate: '2024-03-15 12:00 UTC', reputation: '-3', tags: '',
                categories: 'phishing', finalUrl: 'hxxps://example[.]com/login/verify', title: 'Sign in to your account',
                responseCode: '200', targetedBrand: 'Microsoft', timesSubmitted: '4', firstSeen: '2024-03-14'
            },
            reportUrl: `${VT_GUI}/url/example`,
            lastChecked: 0
        }
    },

    async lookup(ioc, { apiKey, defang }) {
        requireKey('VirusTotal', apiKey);
        const headers = { 'x-apikey': apiKey };
        const lastChecked = Date.now();

        if (ioc.type === 'ip') {
            const data = await apiGet('VirusTotal', `${VT_API}/ip_addresses/${encodeURIComponent(ioc.value)}`, headers);
            const attributes = data?.data?.attributes || {};
            return {
                fields: {
                    ...vtAnalysisFields(attributes),
                    country: countryName(attributes.country || ''),
                    countryCode: attributes.country || '',
                    asOwner: attributes.as_owner || '',
                    asn: attributes.asn ? String(attributes.asn) : '',
                    network: attributes.network || ''
                },
                reportUrl: `${VT_GUI}/ip-address/${ioc.value}`,
                lastChecked
            };
        }

        if (ioc.type === 'domain') {
            const data = await apiGet('VirusTotal', `${VT_API}/domains/${encodeURIComponent(ioc.value)}`, headers, true);
            const reportUrl = `${VT_GUI}/domain/${ioc.value}`;
            if (!data) {
                return { fields: {}, reportUrl, notFound: true, lastChecked };
            }
            const attributes = data.data?.attributes || {};
            const created: number | undefined = attributes.creation_date;
            const ranks = Object.entries(attributes.popularity_ranks || {}) as [string, any][];
            const best = ranks.sort((a, b) => a[1].rank - b[1].rank)[0];
            const addresses = (attributes.last_dns_records || []).filter((record: any) => record.type === 'A' || record.type === 'AAAA')
                .map((record: any) => defang(String(record.value)));
            return {
                fields: {
                    ...vtAnalysisFields(attributes),
                    registrar: attributes.registrar || '',
                    created: formatDate(created),
                    domainAge: created ? formatDuration(Date.now() / 1000 - created) : '',
                    resolvesTo: unique(addresses).slice(0, 3).join(', '),
                    popularity: best ? `#${best[1].rank} (${best[0]})` : ''
                },
                reportUrl,
                lastChecked
            };
        }

        // Only look up what VirusTotal already has; a URL is never submitted for scanning
        const data = await apiGet('VirusTotal', `${VT_API}/urls/${vtUrlId(ioc.value)}`, headers, true);
        if (!data) {
            return { fields: {}, reportUrl: `${VT_GUI}/search/${encodeURIComponent(ioc.value)}`, notFound: true, lastChecked };
        }
        const attributes = data.data?.attributes || {};
        return {
            fields: {
                ...vtAnalysisFields(attributes),
                finalUrl: attributes.last_final_url ? defang(attributes.last_final_url) : '',
                title: attributes.title || '',
                responseCode: attributes.last_http_response_code ? String(attributes.last_http_response_code) : '',
                targetedBrand: attributes.main_brand || (Object.values(attributes.targeted_brand || {})[0] as string) || '',
                timesSubmitted: attributes.times_submitted ? String(attributes.times_submitted) : '',
                firstSeen: formatDate(attributes.first_submission_date)
            },
            reportUrl: `${VT_GUI}/url/${data.data?.id || vtUrlId(ioc.value)}`,
            lastChecked
        };
    }
};

// ----- AbuseIPDB -----

const abuseipdb: Provider = {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    types: ['ip'],
    fields: {
        ip: [
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
        ]
    },
    defaultFormats: {
        ip: '{confidenceScore}% confidence of abuse, last reported {lastReported}'
    },
    examples: {
        ip: {
            fields: {
                confidenceScore: '75', lastReported: '2d ago', totalReports: '150', numDistinctUsers: '45',
                lastReportedAt: '2024-03-15T12:00:00Z', isPublic: 'true', isWhitelisted: 'false', countryCode: 'US',
                countryName: 'United States', usageType: 'Data Center', domain: 'google.com', hostnames: 'dns.google'
            },
            reportUrl: 'https://www.abuseipdb.com/check/8.8.8.8',
            lastChecked: 0
        }
    },

    async lookup(ioc, { apiKey }) {
        requireKey('AbuseIPDB', apiKey);
        const data = await apiGet('AbuseIPDB', `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90`, {
            'Key': apiKey
        });
        const report = data?.data || {};
        return {
            fields: {
                confidenceScore: String(report.abuseConfidenceScore || 0),
                lastReported: report.totalReports > 0 && report.lastReportedAt ? getTimeAgo(report.lastReportedAt) : '',
                totalReports: String(report.totalReports || 0),
                numDistinctUsers: String(report.numDistinctUsers || 0),
                lastReportedAt: report.lastReportedAt || '',
                isPublic: String(report.isPublic || false),
                isWhitelisted: String(report.isWhitelisted || false),
                countryCode: report.countryCode || '',
                countryName: countryName(report.countryCode || ''),
                usageType: report.usageType || '',
                domain: report.domain || '',
                hostnames: (report.hostnames || []).join(', ')
            },
            reportUrl: `https://www.abuseipdb.com/check/${ioc.value}`,
            lastChecked: Date.now()
        };
    },

    render(format, result) {
        if (result.fields.lastReported) {
            return fillTemplate(format, result.fields);
        }
        // Never reported: drop the default "last reported" phrase; any other use of the field shows "never"
        return fillTemplate(format.replace(/,?\s*last reported \{lastReported\}/g, ''), { ...result.fields, lastReported: 'never' });
    }
};

export const PROVIDERS: Provider[] = [virustotal, abuseipdb];
