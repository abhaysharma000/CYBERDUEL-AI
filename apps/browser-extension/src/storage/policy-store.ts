/**
 * CyberDuel AI — Local Policy Store
 * Manages versioned local policy persistence, staged transitions, rollbacks, and recovery in chrome.storage.local.
 */

import { PolicyBundle, ReleaseManifest } from '../types/contracts';
import { BoundedContinuationToken, RecentEvaluation, StoredPolicyState } from '../types/storage';
import { FACTORY_POLICY_BUNDLE } from './factory-policy';

export class PolicyStore {
  private static readonly STORAGE_KEY = 'cyberduel_policy_state';
  private static readonly RECENT_EVALS_KEY = 'cyberduel_recent_evals';
  private static readonly TOKENS_KEY = 'cyberduel_continuation_tokens';

  // In-memory fallback cache for environments without chrome.storage
  private static memoryState: StoredPolicyState | null = null;
  private static memoryEvals: RecentEvaluation[] = [];
  private static memoryTokens: BoundedContinuationToken[] = [];

  public static async getState(): Promise<StoredPolicyState> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const data = await chrome.storage.local.get(this.STORAGE_KEY);
      if (data && data[this.STORAGE_KEY]) {
        return data[this.STORAGE_KEY] as StoredPolicyState;
      }
    }

    if (this.memoryState) {
      return this.memoryState;
    }

    // Initialize with Factory Default Policy
    const initialState: StoredPolicyState = {
      active_policy: FACTORY_POLICY_BUNDLE,
      active_manifest: null,
      sequence_number: FACTORY_POLICY_BUNDLE.sequence_number,
      last_verified_at: new Date().toISOString(),
      installation_status: 'installed',
      previous_policy: null,
      previous_manifest: null,
      last_update_check_at: null,
      last_update_status: 'idle',
    };

    await this.saveState(initialState);
    return initialState;
  }

  public static async commitNewPolicy(
    newPolicy: PolicyBundle,
    manifest: ReleaseManifest
  ): Promise<StoredPolicyState> {
    const current = await this.getState();

    const nextState: StoredPolicyState = {
      active_policy: newPolicy,
      active_manifest: manifest,
      sequence_number: manifest.sequence_number,
      last_verified_at: new Date().toISOString(),
      installation_status: 'installed',
      previous_policy: current.active_policy,
      previous_manifest: current.active_manifest,
      last_update_check_at: new Date().toISOString(),
      last_update_status: 'installed',
      last_error_message: null,
    };

    await this.saveState(nextState);
    return nextState;
  }

  public static async rollbackToPrevious(): Promise<StoredPolicyState | null> {
    const current = await this.getState();
    if (!current.previous_policy) {
      return null;
    }

    const rolledBackState: StoredPolicyState = {
      active_policy: current.previous_policy,
      active_manifest: current.previous_manifest || null,
      sequence_number: current.previous_policy.sequence_number,
      last_verified_at: new Date().toISOString(),
      installation_status: 'rolled_back',
      previous_policy: null,
      previous_manifest: null,
      last_update_status: 'idle',
      last_error_message: 'Rolled back to previous verified policy version.',
    };

    await this.saveState(rolledBackState);
    return rolledBackState;
  }

  public static async resetToFactory(): Promise<StoredPolicyState> {
    const factoryState: StoredPolicyState = {
      active_policy: FACTORY_POLICY_BUNDLE,
      active_manifest: null,
      sequence_number: FACTORY_POLICY_BUNDLE.sequence_number,
      last_verified_at: new Date().toISOString(),
      installation_status: 'installed',
      previous_policy: null,
      previous_manifest: null,
      last_update_status: 'idle',
    };
    await this.saveState(factoryState);
    return factoryState;
  }

  public static async recordUpdateStatus(
    status: 'idle' | 'checking' | 'downloading' | 'verified' | 'installed' | 'error',
    errorMessage?: string | null
  ): Promise<void> {
    const current = await this.getState();
    current.last_update_status = status;
    current.last_update_check_at = new Date().toISOString();
    if (errorMessage !== undefined) {
      current.last_error_message = errorMessage;
    }
    await this.saveState(current);
  }

  public static async addRecentEvaluation(evalData: RecentEvaluation): Promise<void> {
    const evals = await this.getRecentEvaluations();
    evals.unshift(evalData);
    // Keep max 20 recent evaluations in privacy-conscious ring buffer
    const trimmed = evals.slice(0, 20);

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [this.RECENT_EVALS_KEY]: trimmed });
    } else {
      this.memoryEvals = trimmed;
    }
  }

  public static async getRecentEvaluations(): Promise<RecentEvaluation[]> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const data = await chrome.storage.local.get(this.RECENT_EVALS_KEY);
      return (data[this.RECENT_EVALS_KEY] as RecentEvaluation[]) || [];
    }
    return this.memoryEvals;
  }

  public static async createContinuationToken(targetUrlSha256: string): Promise<string> {
    const token = 'tok_' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
    const now = Date.now();
    const entry: BoundedContinuationToken = {
      token,
      target_url_sha256: targetUrlSha256,
      created_at: now,
      expires_at: now + 60 * 1000, // Valid for exactly 60 seconds
    };

    let tokens = await this.getTokens();
    // Prune expired tokens
    tokens = tokens.filter((t) => t.expires_at > now);
    tokens.push(entry);

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [this.TOKENS_KEY]: tokens });
    } else {
      this.memoryTokens = tokens;
    }

    return token;
  }

  public static async validateAndConsumeContinuationToken(
    token: string,
    targetUrlSha256: string
  ): Promise<boolean> {
    const now = Date.now();
    let tokens = await this.getTokens();
    const matchingIdx = tokens.findIndex(
      (t) => t.token === token && t.target_url_sha256 === targetUrlSha256 && t.expires_at > now
    );

    if (matchingIdx === -1) {
      return false;
    }

    // Single-use token: consume immediately
    tokens.splice(matchingIdx, 1);
    tokens = tokens.filter((t) => t.expires_at > now);

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [this.TOKENS_KEY]: tokens });
    } else {
      this.memoryTokens = tokens;
    }

    return true;
  }

  private static async getTokens(): Promise<BoundedContinuationToken[]> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const data = await chrome.storage.local.get(this.TOKENS_KEY);
      return (data[this.TOKENS_KEY] as BoundedContinuationToken[]) || [];
    }
    return this.memoryTokens;
  }

  private static async saveState(state: StoredPolicyState): Promise<void> {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [this.STORAGE_KEY]: state });
    } else {
      this.memoryState = state;
    }
  }
}

