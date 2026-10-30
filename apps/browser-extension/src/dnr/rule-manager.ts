/**
 * CyberDuel AI — DNR Rule Manager
 * Atomically updates browser dynamic rules with rollback support on failure.
 */

import { DNRCompiler } from './compiler';
import { PolicyBundle } from '../types/contracts';

export class DNRRuleManager {
  /**
   * Install compiled rules from a policy bundle into chrome.declarativeNetRequest.
   */
  public static async installPolicyRules(policy: PolicyBundle): Promise<number> {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest) {
      // Mock environment (unit tests or non-browser context)
      const compiled = DNRCompiler.compile(policy);
      return compiled.length;
    }

    const compiledRules = DNRCompiler.compile(policy);

    // Get current dynamic rules to identify existing CyberDuel rules
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIdsToRemove = existingRules
      .filter((r) => r.id >= DNRCompiler.BASE_RULE_ID && r.id < DNRCompiler.BASE_RULE_ID + DNRCompiler.MAX_DYNAMIC_RULES)
      .map((r) => r.id);

    try {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingIdsToRemove,
        addRules: compiledRules as unknown as chrome.declarativeNetRequest.Rule[],
      });
      return compiledRules.length;
    } catch (err) {
      // Rollback: try to restore previous rules if possible
      try {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: compiledRules.map((r) => r.id),
          addRules: existingRules,
        });
      } catch {
        // Suppress secondary rollback error
      }
      throw new Error(`Failed to install DNR rules: ${err}`);
    }
  }

  /**
   * Clear all CyberDuel dynamic rules.
   */
  public static async clearAllRules(): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest) {
      return;
    }

    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const ruleIdsToRemove = existingRules
      .filter((r) => r.id >= DNRCompiler.BASE_RULE_ID && r.id < DNRCompiler.BASE_RULE_ID + DNRCompiler.MAX_DYNAMIC_RULES)
      .map((r) => r.id);

    if (ruleIdsToRemove.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ruleIdsToRemove,
      });
    }
  }
}
