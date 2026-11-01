/**
 * CyberDuel AI — Content Script Link Guard
 * Intercepts user-initiated link clicks and redirects suspicious/malicious destinations to the warning interface.
 */

import { EvaluateURLRequest, EvaluateURLResponse } from '../types/messages';

(() => {
  // Prevent duplicate execution if injected multiple times
  if ((window as unknown as { __CYBERDUEL_LINK_GUARD_INSTALLED__?: boolean }).__CYBERDUEL_LINK_GUARD_INSTALLED__) {
    return;
  }
  (window as unknown as { __CYBERDUEL_LINK_GUARD_INSTALLED__?: boolean }).__CYBERDUEL_LINK_GUARD_INSTALLED__ = true;

  document.addEventListener('click', handleLinkClick, true);

  // 1. Real-Time In-Page Link Scanner
  const scannedHrefs = new Set<string>();

  function scanDomLinks() {
    try {
      const anchors = document.querySelectorAll<HTMLAnchorElement>('a[href]');
      let newLinksCount = 0;

      for (let i = 0; i < anchors.length; i++) {
        const href = anchors[i].href;
        if (
          href &&
          (href.startsWith('http://') || href.startsWith('https://')) &&
          !scannedHrefs.has(href)
        ) {
          scannedHrefs.add(href);
          newLinksCount++;
        }
      }

      if (newLinksCount > 0 && chrome.runtime?.id) {
        chrome.runtime.sendMessage({
          type: 'RECORD_LINKS_SCANNED_REQUEST',
          count: newLinksCount,
          timestamp: new Date().toISOString(),
        });
      }
    } catch {
      // Ignore context errors
    }
  }

  // Scan immediately on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanDomLinks);
  } else {
    scanDomLinks();
  }

  // Scan dynamically injected links (SPA / infinite scroll)
  let scanTimer: number | null = null;
  const observer = new MutationObserver(() => {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = window.setTimeout(scanDomLinks, 1000);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
      }
    });
  }

  function handleLinkClick(event: MouseEvent) {
    // 1. Only process primary mouse clicks (left click)
    if (event.button !== 0) {
      return;
    }

    // 2. Ignore clicks with modifier keys (Ctrl/Cmd/Shift/Alt) to respect power user intentions
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }

    // 3. Find closest anchor tag
    const target = event.target as HTMLElement | null;
    if (!target) return;

    const anchor = target.closest('a');
    if (!anchor || !anchor.href) {
      return;
    }

    const href = anchor.href.trim();

    // 4. Ignore non-web schemes and same-page fragments
    if (
      href.startsWith('#') ||
      href.startsWith('javascript:') ||
      href.startsWith('data:') ||
      href.startsWith('blob:') ||
      href.startsWith('mailto:') ||
      href.startsWith('tel:')
    ) {
      return;
    }

    // Ignore download links
    if (anchor.hasAttribute('download')) {
      return;
    }

    // Check scheme: only http and https
    if (!href.startsWith('http://') && !href.startsWith('https://')) {
      return;
    }

    // Same-origin same-path hash navigation
    try {
      const destUrl = new URL(href);
      if (
        destUrl.origin === window.location.origin &&
        destUrl.pathname === window.location.pathname &&
        destUrl.search === window.location.search &&
        destUrl.hash
      ) {
        return;
      }
    } catch {
      return;
    }

    // 5. Query service worker for local threat evaluation
    const request: EvaluateURLRequest = {
      type: 'EVALUATE_URL_REQUEST',
      url: href,
      source: 'content_script',
      timestamp: new Date().toISOString(),
    };

    try {
      chrome.runtime.sendMessage(request, (response: EvaluateURLResponse) => {
        if (chrome.runtime.lastError || !response || !response.result) {
          // If background worker unreachable, do not break regular browsing
          return;
        }

        const decision = response.result.decision;
        if (decision === 'block' || decision === 'warn') {
          // Prevent standard navigation
          event.preventDefault();
          event.stopPropagation();

          // Build warning page destination
          const warningUrl = chrome.runtime.getURL(
            `warning.html?url=${encodeURIComponent(href)}&decision=${decision}&score=${response.result.risk_score}&reason=${encodeURIComponent(
              response.result.explanation
            )}&policy=${encodeURIComponent(response.result.policy_version)}`
          );

          window.location.href = warningUrl;
        }
      });
    } catch {
      // In case context invalidated, allow normal navigation
    }
  }
})();

