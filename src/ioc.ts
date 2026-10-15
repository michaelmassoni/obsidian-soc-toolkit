import { TLDS } from './tlds';

/**
 * Detecting, validating, defanging and refanging indicators of compromise (IOCs)
 */

export type IOCType = 'ip' | 'domain' | 'url';
export const IOC_TYPES: IOCType[] = ['ip', 'domain', 'url'];

export interface IOC {
    type: IOCType;
    // Refanged and normalised, e.g. for lookups and cache keys
    value: string;
    // As written in the text
    raw: string;
    start: number;
    end: number;
}

export interface DetectOptions {
    types: { [type in IOCType]: boolean };
    // Whole-note scans skip link targets, wikilinks, frontmatter and bare domains that look like filenames
    wholeNote: boolean;
}

export interface TransformOptions extends DetectOptions {
    defangingMethod: 'all-dots' | 'last-dot';
}

export type IOCTransform = 'defang' | 'refang';

// ----- IP addresses -----

/**
 * IPv4 addresses, plain or defanged (fully or partially, e.g. 1[.]2[.]3[.]4 or 1.2.3[.]4)
 */
const IPV4_REGEX = /\b\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}\b/g;

/**
 * IPv6 candidates, plain or defanged with [:]. These over-match (e.g. 12:30:45), so every
 * match must be checked with isValidIPv6. The embedded IPv4 alternative comes first so
 * that ::ffff:1.2.3.4 isn't cut off at the first dot.
 */
const IPV6_REGEX = /(?<![0-9A-Za-z:.[\]])(?:[0-9a-fA-F]{0,4}(?::|\[:\])){2,7}(?:\d{1,3}(?:(?:\.|\[\.\])\d{1,3}){3}|[0-9a-fA-F]{1,4})?(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])/g;

/**
 * Check that every octet of a plain IPv4 string is 0-255
 */
export function isValidIPv4(address: string): boolean {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address) && address.split('.').every(octet => Number(octet) <= 255);
}

/**
 * Check that a plain IPv6 string has valid groups and at most one '::'
 */
export function isValidIPv6(address: string): boolean {
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
 * Private, loopback, link-local, documentation and other special-use IPv4 ranges. They have no
 * public reputation and shouldn't be sent to third-party APIs.
 */
const RESERVED_IPV4_RANGES: [string, number][] = [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4], // multicast
    ['240.0.0.0', 4] // reserved, including broadcast
];

function ipv4ToNumber(address: string): number {
    return address.split('.').reduce((total, octet) => total * 256 + Number(octet), 0);
}

function isReservedIPv4(address: string): boolean {
    const ip = ipv4ToNumber(address);
    return RESERVED_IPV4_RANGES.some(([base, prefix]) => {
        const size = 2 ** (32 - prefix);
        return Math.floor(ip / size) === Math.floor(ipv4ToNumber(base) / size);
    });
}

/**
 * Expand a valid plain IPv6 address into its eight 16-bit groups
 */
function ipv6Groups(address: string): number[] {
    const addr = address.split('%')[0].replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/, (_, a, b, c, d) =>
        `${(Number(a) * 256 + Number(b)).toString(16)}:${(Number(c) * 256 + Number(d)).toString(16)}`);
    const [head, tail] = addr.split('::');
    const toNumbers = (part: string | undefined) => part ? part.split(':').map(group => parseInt(group, 16)) : [];
    const headGroups = toNumbers(head);
    const tailGroups = toNumbers(tail);
    const zeros = tail === undefined ? [] : new Array(8 - headGroups.length - tailGroups.length).fill(0);
    return [...headGroups, ...zeros, ...tailGroups];
}

function isReservedIPv6(address: string): boolean {
    const groups = ipv6Groups(address);
    // ::/96 covers unspecified (::), loopback (::1) and deprecated IPv4-compatible addresses
    if (groups.slice(0, 6).every(group => group === 0)) {
        return true;
    }
    // IPv4-mapped (::ffff:1.2.3.4): judge by the embedded IPv4 address
    if (groups.slice(0, 5).every(group => group === 0) && groups[5] === 0xffff) {
        return isReservedIPv4([groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join('.'));
    }
    return (groups[0] & 0xfe00) === 0xfc00 // unique local (fc00::/7)
        || (groups[0] & 0xffc0) === 0xfe80 // link-local (fe80::/10)
        || (groups[0] & 0xff00) === 0xff00 // multicast (ff00::/8)
        || (groups[0] === 0x2001 && groups[1] === 0x0db8) // documentation (2001:db8::/32)
        || (groups[0] === 0x0100 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0); // discard (100::/64)
}

/**
 * Check whether a plain IP address is private or otherwise not publicly routable
 */
export function isReservedIP(ip: string): boolean {
    return ip.includes(':') ? isReservedIPv6(ip) : isReservedIPv4(ip);
}

// ----- Domains -----

const DOT = String.raw`(?:\.|\[\.\]|\(\.\))`;
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const TLD = '(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})';

/**
 * Domains, plain or defanged with [.] or (.). Candidates are checked against the IANA TLD list.
 */
const DOMAIN_REGEX = new RegExp(String.raw`(?<![\w.\-\]\)/\\])(?:${LABEL}${DOT})+${TLD}(?![\w-]|${DOT}[a-z0-9])`, 'gi');

/**
 * TLDs that are also common file extensions. In whole-note scans, plain domains ending in
 * one of these (notes.md, script.sh) are ignored unless they're defanged.
 */
const FILE_EXTENSION_TLDS = new Set([
    'ac', 'ai', 'am', 'app', 'cab', 'cc', 'do', 'in', 'java', 'md', 'mk', 'ml', 'mobi', 'mov', 'ms', 'nu',
    'one', 'pl', 'pm', 'ps', 'py', 'rs', 'sc', 'sh', 'so', 'st', 'sv', 'tf', 'ws', 'zip'
]);

export function isValidDomain(domain: string): boolean {
    const labels = domain.split('.');
    return domain.length <= 253 && labels.length >= 2 && TLDS.has(labels[labels.length - 1]);
}

/**
 * Domains that never have a public reputation: documentation domains and .arpa (e.g. home.arpa).
 * Internal suffixes like .local or .corp aren't real TLDs, so they're never detected at all.
 */
export function isReservedDomain(domain: string): boolean {
    return /(?:^|\.)example\.(?:com|net|org)$/.test(domain) || domain.endsWith('.arpa');
}

// ----- URLs -----

const SCHEME = '(?:h(?:tt|xx)ps?|f(?:t|x)p)';
const SCHEME_SEPARATOR = String.raw`(?::\/\/|\[:\]\/\/|\[:\/\/\])`;
const URL_BODY = String.raw`(?:\[\.\]|\(\.\)|\[:\]|[^\s<>"'\x60\[\]()])+`;

/**
 * URLs, plain or defanged (hxxps://, [:]//, [://], [.], (.))
 */
const URL_REGEX = new RegExp(String.raw`\b${SCHEME}${SCHEME_SEPARATOR}${URL_BODY}`, 'gi');

/**
 * The host of a refanged URL, if it's a valid public-looking domain or IP
 */
export function urlHost(url: string): string | null {
    let hostname: string;
    try {
        hostname = new URL(url).hostname.toLowerCase();
    } catch {
        return null;
    }
    if (isValidIPv4(hostname) || isValidDomain(hostname)) {
        return hostname;
    }
    const ipv6 = hostname.replace(/^\[|\]$/g, '');
    return isValidIPv6(ipv6) ? ipv6 : null;
}

// ----- Defanging and refanging -----

const DEFANG_MARKERS = /\[\.\]|\(\.\)|\[:\]|\[:\/\/\]|^(?:hxxp|fxp)/i;

export function isDefanged(raw: string): boolean {
    return DEFANG_MARKERS.test(raw);
}

/**
 * Undo defanging, keeping the original case
 */
export function refangText(raw: string): string {
    return raw
        .replace(/^hxxp/i, 'http')
        .replace(/^fxp/i, 'ftp')
        .replace(/\[:\/\/\]|\[:\]\/\//, '://')
        .replace(/\[\.\]|\(\.\)/g, '.')
        .replace(/\[:\]/g, ':');
}

function defangDots(value: string, method: TransformOptions['defangingMethod']): string {
    return method === 'last-dot' ? value.replace(/\.(?=[^.]*$)/, '[.]') : value.replace(/\./g, '[.]');
}

/**
 * Defang a plain IOC according to the defanging method
 */
export function defangIOC(type: IOCType, value: string, method: TransformOptions['defangingMethod']): string {
    if (type === 'url') {
        // hxxps://evil[.]com/path: defang the scheme and host, leave the path alone
        return value
            .replace(/^http/i, 'hxxp')
            .replace(/^ftp/i, 'fxp')
            .replace(/^([a-z]+:\/\/)([^/?#:]+)/i, (_, scheme, host) =>
                scheme + (isValidIPv4(host) || isValidDomain(host.toLowerCase()) ? defangDots(host, method) : host));
    }
    if (type === 'ip' && value.includes(':')) {
        // Replace only single ':' with '[:]', leave '::' untouched (this is due to how Obsidian handles "[::]" in markdown)
        // An embedded IPv4 address (::ffff:1.2.3.4) is defanged like any other
        return value.replace(/(?<!:):(?!:)/g, '[:]')
            .replace(/\d{1,3}(?:\.\d{1,3}){3}$/, ipv4 => defangDots(ipv4, method));
    }
    return defangDots(value, method);
}

// ----- Detection -----

/**
 * Report links in annotations. They're never treated as IOCs, so the links keep working.
 */
const PROVIDER_LINK_REGEX = /\]\(https:\/\/www\.(?:virustotal|abuseipdb)\.com\/[^)\s]*\)/g;

/**
 * Parts of a note that are references rather than IOCs: link targets, autolinks, wikilinks
 * and frontmatter. Whole-note scans leave these alone so defanging doesn't break links.
 */
const REFERENCE_REGEXES = [
    /\]\([^)\s]*\)/g, // [text](target) and ![image](target)
    /<[a-z]+:\/\/[^>\s]+>/gi, // <https://autolink>
    /\[\[[^\]]*\]\]/g, // [[wikilink]]
    /^---\n[\s\S]*?\n---(?=\n|$)/g // frontmatter
];

/**
 * Run a global regex over text without sharing lastIndex state between calls
 */
function allMatches(regex: RegExp, text: string): RegExpExecArray[] {
    const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
    const matches: RegExpExecArray[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
        matches.push(match);
    }
    return matches;
}

/**
 * Find the IOCs in text, in order of appearance. URLs take priority over the domains and IPs
 * inside them, and IPs over domains.
 */
export function findIOCs(text: string, options: DetectOptions): IOC[] {
    const excludeRegexes = options.wholeNote ? [PROVIDER_LINK_REGEX, ...REFERENCE_REGEXES] : [PROVIDER_LINK_REGEX];
    const excluded = excludeRegexes.flatMap(regex => allMatches(regex, text))
        .map(match => ({ start: match.index, end: match.index + match[0].length }));
    const found: IOC[] = [];
    const add = (type: IOCType, raw: string, start: number, value: string) => {
        const end = start + raw.length;
        if (![...excluded, ...found].some(range => start < range.end && end > range.start)) {
            found.push({ type, value, raw, start, end });
        }
    };

    if (options.types.url) {
        for (const match of allMatches(URL_REGEX, text)) {
            // Drop trailing punctuation, e.g. the full stop ending a sentence
            const raw = match[0].replace(/[.,;:!?]+$/, '');
            const value = refangText(raw).replace(/^[a-z]+:\/\/[^/?#]*/i, prefix => prefix.toLowerCase());
            if (urlHost(value)) {
                add('url', raw, match.index, value);
            }
        }
    }

    if (options.types.ip) {
        for (const match of allMatches(IPV6_REGEX, text)) {
            const value = refangText(match[0]).toLowerCase();
            if (isValidIPv6(value)) {
                add('ip', match[0], match.index, value);
            }
        }
        for (const match of allMatches(IPV4_REGEX, text)) {
            const value = refangText(match[0]);
            if (isValidIPv4(value)) {
                add('ip', match[0], match.index, value);
            }
        }
    }

    if (options.types.domain) {
        for (const match of allMatches(DOMAIN_REGEX, text)) {
            const value = refangText(match[0]).toLowerCase();
            const tld = value.slice(value.lastIndexOf('.') + 1);
            const looksLikeFile = options.wholeNote && !isDefanged(match[0]) && FILE_EXTENSION_TLDS.has(tld);
            if (isValidDomain(value) && !looksLikeFile) {
                add('domain', match[0], match.index, value);
            }
        }
    }

    return found.sort((a, b) => a.start - b.start);
}

/**
 * Find the edits that defang plain IOCs (or refang defanged ones) in text, as offsets into text.
 * Partly defanged IOCs (e.g. 1.2.3[.]4) count as defanged, so defanging leaves them alone.
 */
export function iocTransformEdits(text: string, transform: IOCTransform, options: TransformOptions): { start: number; end: number; text: string }[] {
    return findIOCs(text, options).flatMap(ioc => {
        const defanged = isDefanged(ioc.raw);
        if (transform === 'refang' && defanged) {
            return [{ start: ioc.start, end: ioc.end, text: refangText(ioc.raw) }];
        }
        if (transform === 'defang' && !defanged) {
            const replacement = defangIOC(ioc.type, ioc.raw, options.defangingMethod);
            return replacement !== ioc.raw ? [{ start: ioc.start, end: ioc.end, text: replacement }] : [];
        }
        return [];
    });
}

/**
 * Apply edits from iocTransformEdits to text
 */
export function applyEdits(text: string, edits: { start: number; end: number; text: string }[]): string {
    return [...edits].sort((a, b) => b.start - a.start)
        .reduce((result, edit) => result.slice(0, edit.start) + edit.text + result.slice(edit.end), text);
}

/**
 * Check whether an IOC may be sent to third-party APIs: it isn't private or reserved and isn't
 * covered by the user's never-look-up domains (which include their subdomains)
 */
export function isLookupAllowed(ioc: Pick<IOC, 'type' | 'value'>, neverLookUp: string[]): boolean {
    const host = ioc.type === 'url' ? urlHost(ioc.value) : ioc.value;
    if (!host) {
        return false;
    }
    if (isValidIPv4(host) || isValidIPv6(host)) {
        return !isReservedIP(host);
    }
    return !isReservedDomain(host) && !neverLookUp.some(domain => host === domain || host.endsWith('.' + domain));
}
