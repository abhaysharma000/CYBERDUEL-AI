/**
 * CyberDuel AI — Update HTTP Client
 * Interfaces with Prompt 6 API routes: /updates/check, /manifests, /artifacts, /ack, /trust-anchors.
 */

import {
  PolicyBundle,
  ReleaseManifest,
  TrustAnchorSet,
  UpdateAcknowledgement,
  UpdateCheckRequest,
  UpdateCheckResponse,
} from '../types/contracts';

export class UpdateClient {
  private baseUrl: string;

  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  public setBaseUrl(url: string): void {
    this.baseUrl = url.replace(/\/+$/, '');
  }

  public async checkForUpdates(request: UpdateCheckRequest): Promise<UpdateCheckResponse> {
    const url = `${this.baseUrl}/api/v1/updates/check`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      throw new Error(`Update check failed with status ${res.status}: ${res.statusText}`);
    }

    return (await res.json()) as UpdateCheckResponse;
  }

  public async fetchManifest(versionOrId: string): Promise<ReleaseManifest> {
    const url = `${this.baseUrl}/api/v1/updates/manifests/${encodeURIComponent(versionOrId)}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch manifest '${versionOrId}': ${res.status}`);
    }

    return (await res.json()) as ReleaseManifest;
  }

  public async fetchArtifact(digest: string): Promise<{ rawText: string; bundle: PolicyBundle }> {
    const url = `${this.baseUrl}/api/v1/updates/artifacts/${encodeURIComponent(digest)}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch artifact '${digest}': ${res.status}`);
    }

    const rawText = await res.text();
    const bundle = JSON.parse(rawText) as PolicyBundle;
    return { rawText, bundle };
  }

  public async sendAcknowledgement(ack: UpdateAcknowledgement): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/api/v1/updates/ack`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(ack),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  public async fetchTrustAnchors(): Promise<TrustAnchorSet> {
    const url = `${this.baseUrl}/api/v1/updates/trust-anchors`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch trust anchors: ${res.status}`);
    }

    return (await res.json()) as TrustAnchorSet;
  }
}

