/**
 * CyberDuel AI — Extension Settings Store
 * Manages user preferences: protection toggle, telemetry privacy mode, cloud analysis fallback, and backend endpoint.
 */

import { ExtensionSettings } from '../types/storage';

export class SettingsStore {
  private static readonly SETTINGS_KEY = 'cyberduel_settings';

  private static memorySettings: ExtensionSettings | null = null;

  public static async getSettings(): Promise<ExtensionSettings> {
    const liveBackendUrl = 'https://cyberduel-ai-pabz.onrender.com';

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const data = await chrome.storage.local.get(this.SETTINGS_KEY);
      if (data && data[this.SETTINGS_KEY]) {
        const stored = data[this.SETTINGS_KEY] as ExtensionSettings;
        const url = (stored.backend_base_url || '').trim().replace(/\/+$/, '');
        // Auto-migrate stale endpoints (cyberduel-ai-1, localhost, or empty)
        if (
          !url ||
          url.includes('cyberduel-ai-1.onrender.com') ||
          url.includes('localhost')
        ) {
          stored.backend_base_url = liveBackendUrl;
          await this.saveSettings(stored);
        }
        return stored;
      }
    }

    if (this.memorySettings) {
      return this.memorySettings;
    }

    const defaultBackendUrl =
      typeof import.meta !== 'undefined' &&
      import.meta.env &&
      import.meta.env.VITE_BACKEND_URL
        ? String(import.meta.env.VITE_BACKEND_URL).trim()
        : liveBackendUrl;

    const defaultSettings: ExtensionSettings = {
      protection_enabled: true,
      telemetry_mode: 'full_url',
      cloud_analysis_enabled: true,
      backend_base_url: defaultBackendUrl,
      update_check_interval_minutes: 30,
      client_id: this.generateClientId(),
      channel: 'stable',
    };

    await this.saveSettings(defaultSettings);
    return defaultSettings;
  }

  public static async updateSettings(
    partial: Partial<ExtensionSettings>
  ): Promise<ExtensionSettings> {
    const current = await this.getSettings();
    const updated: ExtensionSettings = {
      ...current,
      ...partial,
    };

    // Guarantee client_id is not overwritten with empty
    if (!updated.client_id) {
      updated.client_id = current.client_id || this.generateClientId();
    }

    await this.saveSettings(updated);
    return updated;
  }

  private static async saveSettings(settings: ExtensionSettings): Promise<void> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [this.SETTINGS_KEY]: settings });
    } else {
      this.memorySettings = settings;
    }
  }

  private static generateClientId(): string {
    return 'ext-' + Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
  }
}

