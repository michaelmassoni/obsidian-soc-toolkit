import { Editor, EditorChange, MarkdownFileInfo, MarkdownView, Menu, MenuItem, Notice, Plugin } from 'obsidian';
import { DetectOptions, IOC, IOCTransform, IOCType, applyEdits, findIOCs, iocTransformEdits, isLookupAllowed } from './src/ioc';
import { fillTemplate } from './src/format';
import { LookupResult, PROVIDERS, ProviderId } from './src/providers';
import { DEFAULT_SETTINGS, SOCSettingTab, SOCSettings, TYPE_LABELS, normalizeSettings } from './src/settings';

/**
 * A reputation line written by this plugin, with or without a link on the provider name
 */
const PROVIDER_NAMES = PROVIDERS.map(provider => provider.name).join('|');
const ANNOTATION_REGEX = new RegExp(String.raw`^\s*- (?:\[(?:${PROVIDER_NAMES})\]\([^)]*\)|(?:${PROVIDER_NAMES})):`);

/**
 * Main plugin class for SOC Toolkit
 */
export default class SOCToolkitPlugin extends Plugin {
    settings: SOCSettings = DEFAULT_SETTINGS;
    // Results per IOC ("type:value"), per provider
    cache: Map<string, Map<ProviderId, LookupResult>> = new Map();
    // Progress notice for the reputation check in progress, if any
    private progressNotice: Notice | null = null;

    async onload() {
        await this.loadSettings();

        // Command IDs are kept from when the plugin only handled IPs, so existing hotkeys keep working
        this.addCommand({
            id: 'check-ip-reputation',
            name: 'Check reputation in current note',
            editorCallback: (editor, info) => this.annotateIOCs(editor, info, 0, editor.lastLine(), true)
        });

        this.addCommand({
            id: 'check-ip-reputation-highlighted',
            name: 'Check reputation in highlighted area',
            editorCallback: (editor, info) => {
                if (!editor.getSelection()) {
                    new Notice('No text selected');
                    return;
                }
                return this.annotateSelection(editor, info);
            }
        });

        // Defang and refang commands, for the whole note or the highlighted area
        this.addCommand({
            id: 'defang-ips',
            name: 'Defang IOCs in current note',
            editorCallback: (editor) => this.transformIOCs(editor, 'defang', false)
        });

        this.addCommand({
            id: 'defang-ips-highlighted',
            name: 'Defang IOCs in highlighted area',
            editorCallback: (editor) => this.transformIOCs(editor, 'defang', true)
        });

        this.addCommand({
            id: 'refang-ips',
            name: 'Refang IOCs in current note',
            editorCallback: (editor) => this.transformIOCs(editor, 'refang', false)
        });

        this.addCommand({
            id: 'refang-ips-highlighted',
            name: 'Refang IOCs in highlighted area',
            editorCallback: (editor) => this.transformIOCs(editor, 'refang', true)
        });

        // Add right-click menu items, only offering the actions that apply to the selection
        this.registerEvent(
            this.app.workspace.on('editor-menu', (menu: Menu, editor: Editor, info: MarkdownView | MarkdownFileInfo) => {
                const selectedText = editor.getSelection();
                if (!selectedText) {
                    return;
                }

                if (findIOCs(selectedText, this.detectOptions(false)).length > 0) {
                    menu.addItem((item: MenuItem) => {
                        item
                            .setTitle('Check reputation')
                            .setIcon('search')
                            .onClick(() => this.annotateSelection(editor, info));
                    });
                }

                if (this.transformEdits(selectedText, 'defang', false).length > 0) {
                    menu.addItem((item: MenuItem) => {
                        item
                            .setTitle('Defang IOCs')
                            .setIcon('shield')
                            .onClick(() => this.transformIOCs(editor, 'defang', true));
                    });
                }

                if (this.transformEdits(selectedText, 'refang', false).length > 0) {
                    menu.addItem((item: MenuItem) => {
                        item
                            .setTitle('Refang IOCs')
                            .setIcon('shield-off')
                            .onClick(() => this.transformIOCs(editor, 'refang', true));
                    });
                }
            })
        );

        // Add settings tab
        this.addSettingTab(new SOCSettingTab(this.app, this));
    }

    async loadSettings() {
        this.settings = normalizeSettings(await this.loadData());
        await this.migrateApiKeys();
    }

    async saveSettings() {
        await this.saveData(this.settings);
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
    private getApiKey(provider: ProviderId): string {
        const secretId = provider === 'virustotal' ? this.settings.virustotalSecret : this.settings.abuseipdbSecret;
        const legacyKey = provider === 'virustotal' ? this.settings.virustotalApiKey : this.settings.abuseipdbApiKey;
        return (secretId && this.app.secretStorage.getSecret(secretId)) || legacyKey || '';
    }

    private detectOptions(wholeNote: boolean): DetectOptions {
        return { types: this.settings.detect, wholeNote };
    }

    private transformEdits(text: string, transform: IOCTransform, wholeNote: boolean) {
        return iocTransformEdits(text, transform, { ...this.detectOptions(wholeNote), defangingMethod: this.settings.defangingMethod });
    }

    /**
     * Defang every IOC in text, whatever types are enabled. Used for IOCs in lookup results.
     */
    private defangText = (text: string): string =>
        applyEdits(text, iocTransformEdits(text, 'defang', {
            types: { ip: true, domain: true, url: true },
            wholeNote: false,
            defangingMethod: this.settings.defangingMethod
        }));

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
     * Generate the annotation lines for an IOC from each enabled provider's result
     */
    public generateAnnotation(type: IOCType, results: Map<ProviderId, LookupResult>, indentPrefix: string): string {
        const lines: string[] = [];

        for (const provider of PROVIDERS) {
            const output = this.settings.outputFormat[provider.id][type];
            const result = results.get(provider.id);
            if (!output?.enabled || !result) {
                continue;
            }
            const label = this.settings.includeLinks && result.reportUrl
                ? `[${provider.name}](${result.reportUrl})`
                : provider.name;
            const text = result.notFound
                ? `not found in ${provider.name}`
                : provider.render ? provider.render(output.format, result) : fillTemplate(output.format, result.fields);
            lines.push(`${indentPrefix}- ${label}: ${text}`);
        }

        return lines.length > 0 ? '\n' + lines.join('\n') : '';
    }

    /**
     * Check and annotate IOCs on the lines covered by the editor's selection
     */
    private annotateSelection(editor: Editor, info: MarkdownView | MarkdownFileInfo) {
        const from = editor.getCursor('from');
        const to = editor.getCursor('to');
        // A selection ending at the start of a line doesn't include that line
        const lastLine = to.ch === 0 && to.line > from.line ? to.line - 1 : to.line;
        return this.annotateIOCs(editor, info, from.line, lastLine, false);
    }

    /**
     * Check whether the line after lineIndex is an existing annotation
     */
    private hasAnnotation(editor: Editor, lineIndex: number): boolean {
        return lineIndex < editor.lastLine() && ANNOTATION_REGEX.test(editor.getLine(lineIndex + 1));
    }

    /**
     * The first IOC on a line, ignoring annotation lines and (for whole notes) frontmatter
     */
    private findLineIOC(editor: Editor, lineIndex: number, wholeNote: boolean, frontmatterEnd: number): IOC | null {
        const line = editor.getLine(lineIndex);
        if (ANNOTATION_REGEX.test(line) || (wholeNote && lineIndex <= frontmatterEnd)) {
            return null;
        }
        return findIOCs(line, this.detectOptions(wholeNote))[0] ?? null;
    }

    /**
     * The last line of the note's frontmatter, or -1 if it has none
     */
    private frontmatterEnd(editor: Editor): number {
        if (editor.getLine(0) !== '---') {
            return -1;
        }
        for (let i = 1; i <= editor.lastLine(); i++) {
            if (editor.getLine(i) === '---') {
                return i;
            }
        }
        return -1;
    }

    /**
     * Look up the first IOC on each line in fromLine..toLine that isn't annotated yet, then insert
     * all annotations in a single edit so the cursor, scroll position and undo history are kept
     */
    private async annotateIOCs(editor: Editor, info: MarkdownView | MarkdownFileInfo, fromLine: number, toLine: number, wholeNote: boolean) {
        const file = info.file;
        const frontmatterEnd = wholeNote ? this.frontmatterEnd(editor) : -1;

        const iocs = new Map<string, IOC>();
        let annotatedCount = 0;
        let excludedCount = 0;
        for (let i = fromLine; i <= toLine; i++) {
            const ioc = this.findLineIOC(editor, i, wholeNote, frontmatterEnd);
            if (!ioc) {
                continue;
            }
            if (!isLookupAllowed(ioc, this.settings.neverLookUp)) {
                excludedCount++;
            } else if (this.hasAnnotation(editor, i)) {
                annotatedCount++;
            } else {
                iocs.set(`${ioc.type}:${ioc.value}`, ioc);
            }
        }

        const skipped: string[] = [];
        if (annotatedCount > 0) {
            skipped.push(`${annotatedCount} already annotated`);
        }
        if (excludedCount > 0) {
            skipped.push(`${excludedCount} private or excluded`);
        }

        if (iocs.size === 0) {
            new Notice(skipped.length > 0
                ? `No new IOCs to check (skipped ${skipped.join(', ')})`
                : 'No IOCs found');
            return;
        }

        const results = new Map<string, Map<ProviderId, LookupResult>>();
        const errors: string[] = [];
        this.progressNotice = new Notice(`Checking ${iocs.size} IOC(s)...`, 0);
        try {
            let index = 0;
            for (const [key, ioc] of iocs) {
                index++;
                this.progressNotice.setMessage(`Checking ${index} of ${iocs.size}...`);
                try {
                    results.set(key, await this.getReputation(ioc));
                } catch (error) {
                    console.error(`Error checking ${ioc.value}:`, error);
                    errors.push(`${this.defangText(ioc.value)}: ${error.message}`);
                }
            }
        } finally {
            this.progressNotice.hide();
            this.progressNotice = null;
        }

        // The lookups can take a while; don't write into a different note if the user switched
        if (info.file !== file) {
            new Notice('The note changed while checking IOCs, so no annotations were added');
            return;
        }

        // Re-read the lines, since the note may have been edited during the lookups
        const changes: EditorChange[] = [];
        for (let i = fromLine; i <= Math.min(toLine, editor.lastLine()); i++) {
            const ioc = this.findLineIOC(editor, i, wholeNote, frontmatterEnd);
            const result = ioc ? results.get(`${ioc.type}:${ioc.value}`) : undefined;
            if (ioc && result && !this.hasAnnotation(editor, i)) {
                const line = editor.getLine(i);
                changes.push({
                    from: { line: i, ch: line.length },
                    text: this.generateAnnotation(ioc.type, result, this.getIndentPrefix(line))
                });
            }
        }
        if (changes.length > 0) {
            editor.transaction({ changes });
        }

        let message = `Checked ${results.size} IOC(s)`;
        if (skipped.length > 0) {
            message += `, skipped ${skipped.join(', ')}`;
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
     * Defang or refang the IOCs in the note or the selection, as a single edit
     */
    private transformIOCs(editor: Editor, transform: IOCTransform, selectionOnly: boolean) {
        let text = editor.getValue();
        let offset = 0;
        if (selectionOnly) {
            text = editor.getSelection();
            if (!text) {
                new Notice('No text selected');
                return;
            }
            offset = editor.posToOffset(editor.getCursor('from'));
        }

        const edits = this.transformEdits(text, transform, !selectionOnly);
        if (edits.length === 0) {
            new Notice(transform === 'defang' ? 'No IOCs found to defang' : 'No defanged IOCs found');
            return;
        }

        // Edit only the IOCs themselves, so the cursor and the rest of the note are untouched
        editor.transaction({
            changes: edits.map(edit => ({
                from: editor.offsetToPos(offset + edit.start),
                to: editor.offsetToPos(offset + edit.end),
                text: edit.text
            }))
        });
        new Notice(`${transform === 'defang' ? 'Defanged' : 'Refanged'} ${edits.length} IOC(s)`);
    }

    /**
     * Get results for an IOC from each enabled provider that supports its type, using the cache
     */
    private async getReputation(ioc: IOC): Promise<Map<ProviderId, LookupResult>> {
        const providers = PROVIDERS.filter(provider => this.settings.outputFormat[provider.id][ioc.type]?.enabled);
        if (providers.length === 0) {
            throw new Error(`No providers are enabled for ${TYPE_LABELS[ioc.type].plural}`);
        }

        const key = `${ioc.type}:${ioc.value}`;
        const cached = this.cache.get(key) ?? new Map<ProviderId, LookupResult>();
        const maxAge = this.settings.cacheDuration * 60 * 60 * 1000;

        const results = await Promise.all(providers.map(async provider => {
            const entry = cached.get(provider.id);
            if (entry && Date.now() - entry.lastChecked < maxAge) {
                return [provider.id, entry] as const;
            }
            const result = await provider.lookup(ioc, { apiKey: this.getApiKey(provider.id), defang: this.defangText });
            return [provider.id, result] as const;
        }));

        for (const [id, result] of results) {
            cached.set(id, result);
        }
        this.cache.set(key, cached);
        return new Map(results);
    }

    /**
     * Test the API keys with a lookup of 8.8.8.8. Returns an error message per provider, or '' if it worked.
     */
    async testApiKeys(): Promise<{ [provider in ProviderId]: string }> {
        const entries = await Promise.all(PROVIDERS.map(async provider => {
            try {
                await provider.lookup({ type: 'ip', value: '8.8.8.8' }, { apiKey: this.getApiKey(provider.id), defang: this.defangText });
                return [provider.id, ''] as const;
            } catch (error) {
                console.error(`${provider.name} API key test error:`, error);
                return [provider.id, error.message || 'Unknown error'] as const;
            }
        }));
        const errors = {} as { [provider in ProviderId]: string };
        for (const [id, error] of entries) {
            errors[id] = error;
        }
        return errors;
    }
}
