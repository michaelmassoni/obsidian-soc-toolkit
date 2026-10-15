import { App, Notice, PluginSettingTab, SecretComponent, SettingGroup, ToggleComponent, setTooltip } from 'obsidian';
import type SOCToolkitPlugin from '../main';
import { IOC_TYPES, IOCType } from './ioc';
import { PROVIDERS, Provider, ProviderId } from './providers';

export interface FormatSetting {
    enabled: boolean;
    format: string;
}

export interface SOCSettings {
    // Names of secrets in Obsidian's secret storage, not the API keys themselves
    virustotalSecret: string;
    abuseipdbSecret: string;
    // Plaintext keys saved by older versions, moved into secret storage on load
    virustotalApiKey?: string;
    abuseipdbApiKey?: string;
    cacheDuration: number; // in hours
    defangingMethod: 'all-dots' | 'last-dot';
    includeLinks: boolean; // link the provider name in annotations to its report
    detect: { [type in IOCType]: boolean };
    // Domains (and their subdomains) that are never sent to third parties
    neverLookUp: string[];
    // Per provider, per IOC type it supports
    outputFormat: { [provider in ProviderId]: { [type in IOCType]?: FormatSetting } };
}

export const TYPE_LABELS: { [type in IOCType]: { tab: string; plural: string; example: string } } = {
    ip: { tab: 'IPs', plural: 'IP addresses', example: '8.8.8.8' },
    domain: { tab: 'Domains', plural: 'domains', example: 'example.com' },
    url: { tab: 'URLs', plural: 'URLs', example: 'https://example.com/login' }
};

function defaultOutputFormat(): SOCSettings['outputFormat'] {
    const outputFormat = {} as SOCSettings['outputFormat'];
    for (const provider of PROVIDERS) {
        outputFormat[provider.id] = {};
        for (const type of provider.types) {
            outputFormat[provider.id][type] = { enabled: true, format: provider.defaultFormats[type] ?? '' };
        }
    }
    return outputFormat;
}

export const DEFAULT_SETTINGS: SOCSettings = {
    virustotalSecret: '',
    abuseipdbSecret: '',
    cacheDuration: 24,
    defangingMethod: 'all-dots', // default to replacing all dots
    includeLinks: true,
    detect: { ip: true, domain: true, url: true },
    neverLookUp: [],
    outputFormat: defaultOutputFormat()
};

/**
 * Merge saved settings with the defaults. Nested objects are built fresh so defaults are never
 * shared or mutated, new defaults reach existing users, and old fields are dropped or migrated.
 */
export function normalizeSettings(data: any): SOCSettings {
    data = data ?? {};
    const outputFormat = defaultOutputFormat();
    for (const provider of PROVIDERS) {
        let saved = data.outputFormat?.[provider.id] ?? {};
        // Before 1.8.0 each provider had a single { enabled, format } for IPs
        if (typeof saved.format === 'string' || typeof saved.enabled === 'boolean') {
            saved = { ip: saved };
        }
        for (const type of provider.types) {
            const defaults = outputFormat[provider.id][type] as FormatSetting;
            outputFormat[provider.id][type] = {
                enabled: saved[type]?.enabled ?? defaults.enabled,
                format: saved[type]?.format ?? defaults.format
            };
        }
    }

    return {
        ...DEFAULT_SETTINGS,
        ...data,
        detect: { ...DEFAULT_SETTINGS.detect, ...data.detect },
        neverLookUp: Array.isArray(data.neverLookUp) ? data.neverLookUp : [],
        outputFormat
    };
}

/**
 * Parse the never-look-up text box: one domain per line (or comma separated), ignoring "*." prefixes
 */
function parseDomainList(value: string): string[] {
    return value.split(/[\s,]+/)
        .map(domain => domain.trim().toLowerCase().replace(/^\*?\.+/, '').replace(/\.+$/, ''))
        .filter(Boolean);
}

/**
 * Settings tab for the plugin
 */
export class SOCSettingTab extends PluginSettingTab {
    plugin: SOCToolkitPlugin;
    private previewEl: HTMLElement | null = null;
    // The IOC type whose output settings are shown
    private activeType: IOCType = 'ip';

    constructor(app: App, plugin: SOCToolkitPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        const settings = this.plugin.settings;
        containerEl.empty();
        containerEl.addClass('soc-toolkit-settings');

        new SettingGroup(containerEl)
            .addSetting(setting => setting
                .setName('Cache duration')
                .setDesc('How long to cache results (in hours)')
                .addText(text => text
                    .setPlaceholder('24')
                    .setValue(settings.cacheDuration.toString())
                    .onChange(async (value) => {
                        const num = parseInt(value);
                        if (!isNaN(num) && num > 0) {
                            settings.cacheDuration = num;
                            await this.plugin.saveSettings();
                        }
                    })))
            .addSetting(setting => setting
                .setName('Defanging method')
                .setDesc('Choose how IPv4 addresses, domains and URLs should be defanged')
                .addDropdown(dropdown => dropdown
                    .addOption('all-dots', 'Replace all dots (1[.]2[.]3[.]4, sub[.]evil[.]com)')
                    .addOption('last-dot', 'Replace last dot (1.2.3[.]4, sub.evil[.]com)')
                    .setValue(settings.defangingMethod)
                    .onChange(async (value) => {
                        settings.defangingMethod = value as SOCSettings['defangingMethod'];
                        await this.plugin.saveSettings();
                    })));

        new SettingGroup(containerEl)
            .setHeading('API keys')
            .addSetting(setting => setting
                .setName('VirusTotal API key')
                .setDesc('Choose or create the secret that holds your VirusTotal API key')
                .addComponent(el => new SecretComponent(this.app, el)
                    .setValue(settings.virustotalSecret)
                    .onChange(async (value) => {
                        settings.virustotalSecret = value ?? '';
                        await this.plugin.saveSettings();
                    })))
            .addSetting(setting => setting
                .setName('AbuseIPDB API key')
                .setDesc('Choose or create the secret that holds your AbuseIPDB API key')
                .addComponent(el => new SecretComponent(this.app, el)
                    .setValue(settings.abuseipdbSecret)
                    .onChange(async (value) => {
                        settings.abuseipdbSecret = value ?? '';
                        await this.plugin.saveSettings();
                    })))
            .addSetting(setting => setting
                .setName('Test API keys')
                .setDesc('Verify that your API keys are working correctly')
                .addButton(button => button
                    .setButtonText('Test keys')
                    .onClick(async () => {
                        const results = await this.plugin.testApiKeys();
                        const lines = PROVIDERS.map(provider => results[provider.id]
                            ? `❌ ${results[provider.id]}`
                            : `✅ ${provider.name} API key is working`);
                        new Notice(lines.join('\n'), 10000);
                    })));

        new SettingGroup(containerEl)
            .setHeading('Indicators')
            .addSetting(setting => setting
                .setName('IP addresses')
                .setDesc('Detect IPv4 and IPv6 addresses. Private and reserved addresses are never looked up.')
                .addToggle(toggle => this.bindDetect(toggle, 'ip')))
            .addSetting(setting => setting
                .setName('Domains')
                .setDesc('Detect domains. When checking a whole note, domains that look like filenames (e.g. notes.md) are ignored unless they\'re defanged or highlighted.')
                .addToggle(toggle => this.bindDetect(toggle, 'domain')))
            .addSetting(setting => setting
                .setName('URLs')
                .setDesc('Detect URLs. They\'re only looked up, never submitted for scanning. When checking or defanging a whole note, link targets are left alone.')
                .addToggle(toggle => this.bindDetect(toggle, 'url')))
            .addSetting(setting => {
                setting
                    .setName('Never look up')
                    .setDesc('Domains that are never sent to third parties, along with their subdomains and URLs on them. One per line, e.g. your organisation\'s domains.')
                    .addTextArea(text => text
                        .setPlaceholder('example.org\ncorp.example.com')
                        .setValue(settings.neverLookUp.join('\n'))
                        .onChange(async (value) => {
                            settings.neverLookUp = parseDomainList(value);
                            await this.plugin.saveSettings();
                        }));
                setting.settingEl.addClass('soc-toolkit-wide');
            });

        new SettingGroup(containerEl)
            .setHeading('Output')
            .addSetting(setting => setting
                .setName('Link to reports')
                .setDesc('Make the provider name in each annotation a link to its full report')
                .addToggle(toggle => toggle
                    .setValue(settings.includeLinks)
                    .onChange(async (value) => {
                        settings.includeLinks = value;
                        await this.plugin.saveSettings();
                        this.updateExampleOutput();
                    })))
            .addSetting(setting => {
                setting
                    .setName('Output for')
                    .setDesc('Choose which indicator type\'s output to preview and customise below');
                const tabs = setting.controlEl.createDiv({ cls: 'soc-toolkit-tabs', attr: { role: 'tablist' } });
                for (const type of IOC_TYPES) {
                    const active = type === this.activeType;
                    const tab = tabs.createEl('button', {
                        text: TYPE_LABELS[type].tab,
                        cls: active ? 'soc-toolkit-tab is-active' : 'soc-toolkit-tab',
                        attr: { role: 'tab', 'aria-selected': String(active) }
                    });
                    tab.addEventListener('click', () => {
                        if (type !== this.activeType) {
                            this.activeType = type;
                            this.redisplay();
                        }
                    });
                }
            })
            .addSetting(setting => {
                setting
                    .setName('Preview')
                    .setDesc(`How annotations will appear under ${TYPE_LABELS[this.activeType].plural} in your notes`);
                setting.settingEl.addClass('soc-toolkit-wide');
                this.previewEl = setting.settingEl.createEl('pre', { cls: 'soc-toolkit-preview' });
            });
        this.updateExampleOutput();

        for (const provider of PROVIDERS.filter(p => p.types.includes(this.activeType))) {
            this.addProviderGroup(containerEl, provider, this.activeType);
        }
    }

        private bindDetect(toggle: ToggleComponent, type: IOCType) {
        return toggle
            .setValue(this.plugin.settings.detect[type])
            .onChange(async (value) => {
                this.plugin.settings.detect[type] = value;
                await this.plugin.saveSettings();
            });
    }

    /**
     * Re-render after switching tabs, keeping the scroll position
     */
    private redisplay() {
        const scrollTop = this.containerEl.scrollTop;
        this.display();
        this.containerEl.scrollTop = scrollTop;
    }

    /**
     * Add the enable toggle and output format settings for one provider and IOC type
     */
    private addProviderGroup(containerEl: HTMLElement, provider: Provider, type: IOCType) {
        const output = this.plugin.settings.outputFormat[provider.id][type] as FormatSetting;

        new SettingGroup(containerEl)
            .setHeading(provider.name)
            .addSetting(setting => setting
                .setName(`Enable ${provider.name}`)
                .setDesc(`Look up ${TYPE_LABELS[type].plural} in ${provider.name} and include the result in annotations`)
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
                (provider.fields[type] ?? []).forEach(field => {
                    const tag = fieldTags.createSpan({ text: field.name, cls: 'soc-toolkit-field-tag' });
                    setTooltip(tag, field.desc);
                });
            });
    }

    private getExampleOutput(): string {
        const type = this.activeType;
        const results = new Map(PROVIDERS
            .filter(provider => provider.examples[type])
            .map(provider => [provider.id, provider.examples[type]!]));
        const example = TYPE_LABELS[type].example;
        return example + (this.plugin.generateAnnotation(type, results, '  ') || '\n  (no providers enabled)');
    }

    private updateExampleOutput() {
        this.previewEl?.setText(this.getExampleOutput());
    }
}
