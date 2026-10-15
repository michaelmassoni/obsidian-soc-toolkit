/**
 * Formatting helpers for annotation output
 */

/**
 * Replace {field} placeholders with values. Empty values show as N/A; unknown fields are left as-is.
 */
export function fillTemplate(template: string, values: { [field: string]: string }): string {
    return template.replace(/\{(\w+)\}/g, (placeholder, field) =>
        Object.prototype.hasOwnProperty.call(values, field) ? (values[field] || 'N/A') : placeholder);
}

let regionNames: Intl.DisplayNames | null = null;

/**
 * Get a country's English name from its two-letter code, falling back to the code itself
 */
export function countryName(code: string): string {
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

/**
 * Format a Unix timestamp (in seconds) as e.g. "2024-03-15 12:00 UTC", or "" if missing
 */
export function formatTimestamp(seconds: number | undefined): string {
    return seconds ? new Date(seconds * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
}

/**
 * Format a Unix timestamp (in seconds) as a date, e.g. "2024-03-15", or "" if missing
 */
export function formatDate(seconds: number | undefined): string {
    return seconds ? new Date(seconds * 1000).toISOString().slice(0, 10) : '';
}

/**
 * Format a duration in seconds compactly, e.g. "45m", "12d", "5mo", "3y"
 */
export function formatDuration(totalSeconds: number): string {
    const minutes = Math.floor(totalSeconds / 60);
    if (minutes < 60) {
        return `${Math.max(minutes, 0)}m`;
    }
    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        return `${hours}h`;
    }
    const days = Math.floor(hours / 24);
    if (days < 30) {
        return `${days}d`;
    }
    const months = Math.floor(days / 30);
    if (months < 12) {
        return `${months}mo`;
    }
    return `${Math.floor(months / 12)}y`;
}

/**
 * Get a human-readable time ago string from an ISO date string, e.g. "3d ago"
 */
export function getTimeAgo(dateString: string): string {
    const seconds = Math.floor((Date.now() - new Date(dateString).getTime()) / 1000);
    return seconds < 60 ? 'just now' : `${formatDuration(seconds)} ago`;
}
