/**
 * CyberDuel AI — Declarative Net Request (DNR) Rule Compiler
 * Compiles policy bundle threat indicators into deterministic Chrome DNR dynamic rules.
 */

import { PolicyBundle } from '../types/contracts';

export interface DNRRule {
  id: number;
  priority: number;
  action: {
    type: 'block' | 'redirect';
    redirect?: {
      extensionPath?: string;
      url?: string;
    };
  };
  condition: {
    urlFilter: string;
    resourceTypes: string[];
    isUrlFilterCaseSensitive?: boolean;
  };
}

export class DNRCompiler {
  public static readonly BASE_RULE_ID = 10000;
  public static readonly MAX_DYNAMIC_RULES = 5000;

  public static compile(policy: PolicyBundle): DNRRule[] {
    const rules: DNRRule[] = [];
    let currentId = this.BASE_RULE_ID;

    // 1. Compile Threat Indicators with action 'block'
    if (policy.threat_indicators) {
      for (const indicator of policy.threat_indicators) {
        if (indicator.action !== 'block') {
          continue;
        }

        if (rules.length >= this.MAX_DYNAMIC_RULES) {
          break;
        }

        let urlFilter = '';
        if (indicator.type === 'domain') {
          urlFilter = `||${indicator.value}^`;
        } else if (indicator.type === 'prefix') {
          urlFilter = indicator.value;
        } else {
          continue;
        }

        rules.push({
          id: currentId++,
          priority: 10,
          action: {
            type: 'block',
          },
          condition: {
            urlFilter,
            resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest'],
            isUrlFilterCaseSensitive: false,
          },
        });
      }
    }

    return rules;
  }
}

